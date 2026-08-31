package ndabi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type bundleControlManifest struct {
	Authority struct {
		RootKeyHex    string `json:"root_key_hex"`
		Generation    string `json:"generation"`
		Session       string `json:"session"`
		ExpiresUnixUS string `json:"expires_unix_us"`
		TenantHex     string `json:"tenant_hex"`
		PrincipalHex  string `json:"principal_hex"`
		Purpose       uint32 `json:"purpose"`
		CapabilityHex string `json:"capability_digest_hex"`
		Engine        uint32 `json:"engine"`
		Profile       uint32 `json:"profile"`
		SchemaHex     string `json:"schema_digest_hex"`
		PolicyHex     string `json:"policy_digest_hex"`
		PlanHex       string `json:"plan_digest_hex"`
	} `json:"authority"`
	BundleControls struct {
		Valid []struct {
			ID       string `json:"id"`
			Kind     string `json:"kind"`
			FrameHex string `json:"frame_hex"`
			Decoded  struct {
				Nonce           string `json:"nonce"`
				DeadlineUnixUS  string `json:"deadline_unix_us"`
				ExpiryUnixUS    string `json:"expiry_unix_us"`
				Opcode          uint16 `json:"opcode"`
				GraphHandle     uint32 `json:"graph_handle"`
				ResultShape     uint32 `json:"result_shape"`
				BundleHandle    uint32 `json:"bundle_handle"`
				BundleSlotCount uint32 `json:"bundle_slot_count"`
				ValuesHex       string `json:"values_hex"`
			} `json:"decoded"`
		} `json:"valid"`
		Invalid []struct {
			ID            string `json:"id"`
			FrameHex      string `json:"frame_hex"`
			ExpectedError string `json:"expected_error"`
		} `json:"invalid"`
	} `json:"bundle_controls"`
}

func TestBundleControlConformanceVectors(t *testing.T) {
	manifest := loadBundleControlManifest(t)
	authority := bundleControlAuthority(t, manifest)
	for _, vector := range manifest.BundleControls.Valid {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			decoded, err := DecodeBundleControl(decodeHex(t, vector.FrameHex), authority, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			expectedKind := uint8(5)
			expectedDeadline := vector.Decoded.ExpiryUnixUS
			if vector.Kind == "removal" {
				expectedKind = 7
				expectedDeadline = vector.Decoded.DeadlineUnixUS
			}
			if decoded.Kind != expectedKind || decoded.Nonce != parseU64(t, vector.Decoded.Nonce) ||
				decoded.DeadlineUnixUS != parseU64(t, expectedDeadline) ||
				decoded.Opcode != vector.Decoded.Opcode || decoded.GraphHandle != vector.Decoded.GraphHandle ||
				decoded.ResultShape != vector.Decoded.ResultShape || decoded.BundleHandle != vector.Decoded.BundleHandle ||
				decoded.BundleSlotCount != vector.Decoded.BundleSlotCount ||
				string(decoded.Values) != string(decodeHex(t, vector.Decoded.ValuesHex)) {
				t.Fatal("the decoded bundle control differs")
			}
		})
	}
	for _, vector := range manifest.BundleControls.Invalid {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			_, err := DecodeBundleControl(decodeHex(t, vector.FrameHex), authority, 1<<20)
			if err == nil || err.Error() != vector.ExpectedError {
				t.Fatalf("DecodeBundleControl returned %v, expected %s", err, vector.ExpectedError)
			}
		})
	}
}

func loadBundleControlManifest(t *testing.T) bundleControlManifest {
	t.Helper()
	bytes, err := os.ReadFile(filepath.Join("..", "..", "v0.1", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest bundleControlManifest
	if err := json.Unmarshal(bytes, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func bundleControlAuthority(t *testing.T, manifest bundleControlManifest) Authority {
	t.Helper()
	var authority Authority
	copyExact(t, authority.RootKey[:], manifest.Authority.RootKeyHex)
	copyExact(t, authority.Tenant[:], manifest.Authority.TenantHex)
	copyExact(t, authority.Principal[:], manifest.Authority.PrincipalHex)
	copyExact(t, authority.CapabilityDigest[:], manifest.Authority.CapabilityHex)
	copyExact(t, authority.SchemaDigest[:], manifest.Authority.SchemaHex)
	copyExact(t, authority.PolicyDigest[:], manifest.Authority.PolicyHex)
	copyExact(t, authority.PlanDigest[:], manifest.Authority.PlanHex)
	authority.Generation = parseU64(t, manifest.Authority.Generation)
	authority.Session = parseU64(t, manifest.Authority.Session)
	authority.ExpiresUnixUS = parseU64(t, manifest.Authority.ExpiresUnixUS)
	authority.Purpose = manifest.Authority.Purpose
	authority.Engine = manifest.Authority.Engine
	authority.Profile = manifest.Authority.Profile
	return authority
}
