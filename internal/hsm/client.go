package hsm

import (
	"errors"
	"fmt"
	"sync"

	"github.com/miekg/pkcs11"
)

// Config configures a PKCS#11 Client.
type Config struct {
	// ModulePath is the filesystem path to the vendor PKCS#11 shared library
	// (.so / .dylib / .dll). Required.
	ModulePath string

	// PIN is the user PIN used for C_Login. If empty, no login is performed —
	// which only works for slots that permit public-session operations.
	PIN string
}

// Client wraps and unwraps DEKs through a PKCS#11 module using
// CKM_RSA_PKCS_OAEP with SHA-256. It loads the module once at construction
// and opens a fresh session per operation (sufficient given the short-lived
// nature of a SOPS-driven keyservice process).
type Client struct {
	cfg Config
	ctx *pkcs11.Ctx
	mu  sync.Mutex
}

// NewClient loads the PKCS#11 module and calls C_Initialize.
// The returned Client must be Close()d to release the module.
func NewClient(cfg Config) (*Client, error) {
	if cfg.ModulePath == "" {
		return nil, errors.New("pkcs11 module path is required")
	}
	ctx := pkcs11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load pkcs11 module %q", cfg.ModulePath)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("C_Initialize: %w", err)
	}
	return &Client{cfg: cfg, ctx: ctx}, nil
}

// Close finalizes and unloads the PKCS#11 module.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx == nil {
		return
	}
	_ = c.ctx.Finalize()
	c.ctx.Destroy()
	c.ctx = nil
}

// Encrypt wraps plaintext with the RSA public key identified by keyURI.
func (c *Client) Encrypt(keyURI string, plaintext []byte) ([]byte, error) {
	ref, err := ParseKeyURI(keyURI)
	if err != nil {
		return nil, err
	}
	return c.withSession(ref.SlotID, func(session pkcs11.SessionHandle) ([]byte, error) {
		handle, err := findKey(c.ctx, session, ref.Label, pkcs11.CKO_PUBLIC_KEY)
		if err != nil {
			return nil, err
		}
		if err := c.ctx.EncryptInit(session, oaepMech(ref), handle); err != nil {
			return nil, fmt.Errorf("C_EncryptInit: %w", err)
		}
		ct, err := c.ctx.Encrypt(session, plaintext)
		if err != nil {
			return nil, fmt.Errorf("C_Encrypt: %w", err)
		}
		return ct, nil
	})
}

// Decrypt unwraps ciphertext with the RSA private key identified by keyURI.
func (c *Client) Decrypt(keyURI string, ciphertext []byte) ([]byte, error) {
	ref, err := ParseKeyURI(keyURI)
	if err != nil {
		return nil, err
	}
	return c.withSession(ref.SlotID, func(session pkcs11.SessionHandle) ([]byte, error) {
		handle, err := findKey(c.ctx, session, ref.Label, pkcs11.CKO_PRIVATE_KEY)
		if err != nil {
			return nil, err
		}
		if err := c.ctx.DecryptInit(session, oaepMech(ref), handle); err != nil {
			return nil, fmt.Errorf("C_DecryptInit: %w", err)
		}
		pt, err := c.ctx.Decrypt(session, ciphertext)
		if err != nil {
			return nil, fmt.Errorf("C_Decrypt: %w", err)
		}
		return pt, nil
	})
}

func (c *Client) withSession(slotID uint, fn func(pkcs11.SessionHandle) ([]byte, error)) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx == nil {
		return nil, errors.New("hsm client is closed")
	}

	session, err := c.ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("C_OpenSession slot %d: %w", slotID, err)
	}
	defer c.ctx.CloseSession(session)

	if c.cfg.PIN != "" {
		if err := c.ctx.Login(session, pkcs11.CKU_USER, c.cfg.PIN); err != nil {
			var pkErr pkcs11.Error
			if !errors.As(err, &pkErr) || pkErr != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
				return nil, fmt.Errorf("C_Login: %w", err)
			}
		}
		defer c.ctx.Logout(session)
	}

	return fn(session)
}

func oaepMech(ref KeyRef) []*pkcs11.Mechanism {
	return []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, &pkcs11.OAEPParams{
			HashAlg:    ref.HashAlg,
			MGF:        ref.MGF,
			SourceType: pkcs11.CKZ_DATA_SPECIFIED,
		}),
	}
}

func findKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, label string, class uint) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("C_FindObjectsInit: %w", err)
	}
	handles, _, err := ctx.FindObjects(session, 2)
	finalErr := ctx.FindObjectsFinal(session)
	if err != nil {
		return 0, fmt.Errorf("C_FindObjects: %w", err)
	}
	if finalErr != nil {
		return 0, fmt.Errorf("C_FindObjectsFinal: %w", finalErr)
	}
	switch len(handles) {
	case 0:
		return 0, fmt.Errorf("no key with label %q and class %d", label, class)
	case 1:
		return handles[0], nil
	default:
		return 0, fmt.Errorf("multiple keys with label %q and class %d", label, class)
	}
}
