// Package hsm bridges SOPS keyservice Encrypt/Decrypt requests to a
// PKCS#11 hardware security module via RSA-OAEP wrap/unwrap.
package hsm

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/pkcs11"
)

// KeyRef identifies the RSA wrap keypair on an HSM and the OAEP hash used
// to wrap against it.
//
// Carried in SOPS's KmsKey.arn field as a simplified pkcs11: URI:
//
//	pkcs11:slot=0;label=clef-dek-wrapper
//	pkcs11:slot=0;label=clef-dek-wrapper;hash=sha256
//
// hash is a clef-specific attribute (not part of RFC 7512) that pins the
// OAEP hash/MGF1 algorithm. Defaults to sha256. The same value must be used
// for Encrypt and Decrypt on a given ciphertext, so it is pinned in the URI
// rather than being a process-wide flag.
//
// The module path is supplied separately via CLEF_PKCS11_MODULE so a single
// keyservice process always targets one HSM library.
type KeyRef struct {
	SlotID  uint
	Label   string
	HashAlg uint // PKCS#11 CKM_SHA* mechanism
	MGF     uint // PKCS#11 CKG_MGF1_SHA* mechanism
}

var hashAliases = map[string]struct {
	hash uint
	mgf  uint
}{
	"sha1":   {pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1},
	"sha256": {pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256},
	"sha384": {pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384},
	"sha512": {pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512},
}

// ParseKeyURI parses a pkcs11: URI into a KeyRef. slot/slot-id and
// label/object are required; hash is optional (default sha256). Unknown
// attributes are ignored for forward compatibility.
func ParseKeyURI(uri string) (KeyRef, error) {
	if !strings.HasPrefix(uri, "pkcs11:") {
		return KeyRef{}, fmt.Errorf("expected pkcs11: prefix, got %q", uri)
	}
	rest := strings.TrimPrefix(uri, "pkcs11:")

	ref := KeyRef{
		HashAlg: pkcs11.CKM_SHA256,
		MGF:     pkcs11.CKG_MGF1_SHA256,
	}
	var slotSet bool
	for _, part := range strings.Split(rest, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return KeyRef{}, fmt.Errorf("malformed attribute %q", part)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "slot", "slot-id":
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return KeyRef{}, fmt.Errorf("invalid slot %q: %w", v, err)
			}
			ref.SlotID = uint(n)
			slotSet = true
		case "label", "object":
			ref.Label = v
		case "hash":
			h, ok := hashAliases[strings.ToLower(v)]
			if !ok {
				return KeyRef{}, fmt.Errorf("unsupported hash %q (want sha1|sha256|sha384|sha512)", v)
			}
			ref.HashAlg = h.hash
			ref.MGF = h.mgf
		}
	}
	if !slotSet {
		return KeyRef{}, errors.New("missing slot/slot-id")
	}
	if ref.Label == "" {
		return KeyRef{}, errors.New("missing label/object")
	}
	return ref, nil
}
