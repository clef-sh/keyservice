package hsm

import (
	"testing"

	"github.com/miekg/pkcs11"
)

func TestParseKeyURI(t *testing.T) {
	cases := []struct {
		name    string
		uri     string
		want    KeyRef
		wantErr bool
	}{
		{
			name: "slot and label default to sha256",
			uri:  "pkcs11:slot=0;label=clef-dek-wrapper",
			want: KeyRef{
				SlotID:  0,
				Label:   "clef-dek-wrapper",
				HashAlg: pkcs11.CKM_SHA256,
				MGF:     pkcs11.CKG_MGF1_SHA256,
			},
		},
		{
			name: "slot-id and object aliases",
			uri:  "pkcs11:slot-id=3;object=my-key",
			want: KeyRef{
				SlotID:  3,
				Label:   "my-key",
				HashAlg: pkcs11.CKM_SHA256,
				MGF:     pkcs11.CKG_MGF1_SHA256,
			},
		},
		{
			name: "hash=sha1 selects SHA-1 OAEP and MGF1-SHA1",
			uri:  "pkcs11:slot=0;label=k;hash=sha1",
			want: KeyRef{
				SlotID:  0,
				Label:   "k",
				HashAlg: pkcs11.CKM_SHA_1,
				MGF:     pkcs11.CKG_MGF1_SHA1,
			},
		},
		{
			name: "hash=SHA384 is case-insensitive",
			uri:  "pkcs11:slot=0;label=k;hash=SHA384",
			want: KeyRef{
				SlotID:  0,
				Label:   "k",
				HashAlg: pkcs11.CKM_SHA384,
				MGF:     pkcs11.CKG_MGF1_SHA384,
			},
		},
		{
			name: "unknown attrs are ignored",
			uri:  "pkcs11:slot=1;label=k;token=whatever;type=private",
			want: KeyRef{
				SlotID:  1,
				Label:   "k",
				HashAlg: pkcs11.CKM_SHA256,
				MGF:     pkcs11.CKG_MGF1_SHA256,
			},
		},
		{
			name: "whitespace around keys and values is trimmed",
			uri:  "pkcs11: slot = 2 ; label = k ",
			want: KeyRef{
				SlotID:  2,
				Label:   "k",
				HashAlg: pkcs11.CKM_SHA256,
				MGF:     pkcs11.CKG_MGF1_SHA256,
			},
		},
		{
			name:    "wrong scheme",
			uri:     "arn:aws:kms:...",
			wantErr: true,
		},
		{
			name:    "missing slot",
			uri:     "pkcs11:label=k",
			wantErr: true,
		},
		{
			name:    "missing label",
			uri:     "pkcs11:slot=0",
			wantErr: true,
		},
		{
			name:    "non-numeric slot",
			uri:     "pkcs11:slot=abc;label=k",
			wantErr: true,
		},
		{
			name:    "malformed attribute",
			uri:     "pkcs11:slot=0;label",
			wantErr: true,
		},
		{
			name:    "unsupported hash",
			uri:     "pkcs11:slot=0;label=k;hash=md5",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseKeyURI(tc.uri)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
