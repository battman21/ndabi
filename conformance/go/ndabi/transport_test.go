package ndabi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type transportVectorManifest struct {
	ClockUnixUS         string `json:"clock_unix_us"`
	MaximumPayloadBytes uint32 `json:"maximum_payload_bytes"`
	Authority           struct {
		RootKeyHex       string `json:"root_key_hex"`
		Generation       string `json:"generation"`
		Session          string `json:"session"`
		ExpiresUnixUS    string `json:"expires_unix_us"`
		ContextDigestHex string `json:"context_digest_hex"`
	} `json:"authority"`
	Valid []struct {
		ID         string `json:"id"`
		Direction  string `json:"direction"`
		Kind       uint8  `json:"kind"`
		FrameHex   string `json:"frame_hex"`
		PayloadHex string `json:"payload_hex"`
		Decoded    struct {
			ErrorCode           uint16 `json:"error_code"`
			CorrelationNonce    string `json:"correlation_nonce"`
			Sequence            uint32 `json:"sequence"`
			Rows                uint32 `json:"rows"`
			ResultShape         uint32 `json:"result_shape"`
			Features            uint32 `json:"features"`
			Auxiliary           uint32 `json:"auxiliary"`
			ExecutionReceiptHex string `json:"execution_receipt_hex"`
		} `json:"decoded"`
	} `json:"valid"`
	Invalid []struct {
		ID            string `json:"id"`
		Direction     string `json:"direction"`
		FrameHex      string `json:"frame_hex"`
		ExpectedError string `json:"expected_error"`
	} `json:"invalid"`
}

func TestTransportConformanceVectors(t *testing.T) {
	manifest := loadTransportManifest(t)
	authority := transportManifestAuthority(t, manifest)
	now := parseU64(t, manifest.ClockUnixUS)
	for _, vector := range manifest.Valid {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			decoded, err := DecodeTransport(
				decodeHex(t, vector.FrameHex),
				authority,
				transportDirection(t, vector.Direction),
				manifest.MaximumPayloadBytes,
				now,
			)
			if err != nil {
				t.Fatal(err)
			}
			wantReceipt := decodeHex(t, vector.Decoded.ExecutionReceiptHex)
			if decoded.Kind != vector.Kind ||
				decoded.Fields.ErrorCode != vector.Decoded.ErrorCode ||
				decoded.Fields.CorrelationNonce != parseU64(t, vector.Decoded.CorrelationNonce) ||
				decoded.Fields.Sequence != vector.Decoded.Sequence ||
				decoded.Fields.Rows != vector.Decoded.Rows ||
				decoded.Fields.ResultShape != vector.Decoded.ResultShape ||
				decoded.Fields.Features != vector.Decoded.Features ||
				decoded.Fields.Auxiliary != vector.Decoded.Auxiliary ||
				string(decoded.Fields.ExecutionReceipt[:]) != string(wantReceipt) ||
				string(decoded.Payload) != string(decodeHex(t, vector.PayloadHex)) {
				t.Fatal("the decoded transport frame differs")
			}
		})
	}
	for _, vector := range manifest.Invalid {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			_, err := DecodeTransport(
				decodeHex(t, vector.FrameHex),
				authority,
				transportDirection(t, vector.Direction),
				manifest.MaximumPayloadBytes,
				now,
			)
			if err == nil || err.Error() != vector.ExpectedError {
				t.Fatalf("DecodeTransport returned %v, expected %s", err, vector.ExpectedError)
			}
		})
	}
}

func TestEveryTransportBitMutationRefuses(t *testing.T) {
	manifest := loadTransportManifest(t)
	authority := transportManifestAuthority(t, manifest)
	now := parseU64(t, manifest.ClockUnixUS)
	for _, vector := range manifest.Valid {
		frame := decodeHex(t, vector.FrameHex)
		direction := transportDirection(t, vector.Direction)
		for byteIndex := range frame {
			for bit := uint(0); bit < 8; bit++ {
				mutated := append([]byte(nil), frame...)
				mutated[byteIndex] ^= 1 << bit
				if _, err := DecodeTransport(mutated, authority, direction, manifest.MaximumPayloadBytes, now); err == nil {
					t.Fatalf("%s accepted mutation at byte %d bit %d", vector.ID, byteIndex, bit)
				}
			}
		}
	}
}

func TestTransportDecoderRefusesAnUnrepresentableMaximum(t *testing.T) {
	manifest := loadTransportManifest(t)
	_, err := DecodeTransport(
		decodeHex(t, manifest.Valid[0].FrameHex),
		transportManifestAuthority(t, manifest),
		transportDirection(t, manifest.Valid[0].Direction),
		^uint32(0),
		parseU64(t, manifest.ClockUnixUS),
	)
	if err != ErrTransportPayloadTooLarge {
		t.Fatalf("DecodeTransport returned %v", err)
	}
}

func loadTransportManifest(t *testing.T) transportVectorManifest {
	t.Helper()
	path := filepath.Join("..", "..", "v0.2", "transport-vectors.json")
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest transportVectorManifest
	if err := json.Unmarshal(bytes, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func transportManifestAuthority(t *testing.T, manifest transportVectorManifest) TransportAuthority {
	t.Helper()
	var authority TransportAuthority
	copyExact(t, authority.RootKey[:], manifest.Authority.RootKeyHex)
	copyExact(t, authority.ContextDigest[:], manifest.Authority.ContextDigestHex)
	authority.Generation = parseU64(t, manifest.Authority.Generation)
	authority.Session = parseU64(t, manifest.Authority.Session)
	authority.ExpiresUnixUS = parseU64(t, manifest.Authority.ExpiresUnixUS)
	return authority
}

func transportDirection(t *testing.T, value string) uint8 {
	t.Helper()
	switch value {
	case "client-to-server":
		return 1
	case "server-to-client":
		return 2
	default:
		t.Fatalf("unknown transport direction %s", value)
		return 0
	}
}
