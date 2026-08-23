package ndabi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type vectorManifest struct {
	ClockUnixUS  uint64 `json:"clock_unix_us"`
	ServerLimits struct {
		MaximumResultBytes uint32 `json:"maximum_result_bytes"`
		MaximumRows        uint32 `json:"maximum_rows"`
	} `json:"server_limits"`
	Authority struct {
		RootKeyHex          string `json:"root_key_hex"`
		Generation          uint64 `json:"generation"`
		Session             uint64 `json:"session"`
		ExpiresUnixUS       uint64 `json:"expires_unix_us"`
		TenantHex           string `json:"tenant_hex"`
		PrincipalHex        string `json:"principal_hex"`
		Purpose             uint32 `json:"purpose"`
		CapabilityDigestHex string `json:"capability_digest_hex"`
		Engine              uint32 `json:"engine"`
		Profile             uint32 `json:"profile"`
		SchemaDigestHex     string `json:"schema_digest_hex"`
		PolicyDigestHex     string `json:"policy_digest_hex"`
		PlanDigestHex       string `json:"plan_digest_hex"`
		ContextDigestHex    string `json:"context_digest_hex"`
	} `json:"authority"`
	Valid []struct {
		ID       string `json:"id"`
		FrameHex string `json:"frame_hex"`
		Decoded  struct {
			Nonce          uint64 `json:"nonce"`
			DeadlineUnixUS uint64 `json:"deadline_unix_us"`
			ResultBudget   uint32 `json:"result_budget"`
			RowBudget      uint32 `json:"row_budget"`
			Operation      struct {
				Opcode      uint16 `json:"opcode"`
				PlanHandle  uint32 `json:"plan_handle"`
				ResultShape uint32 `json:"result_shape"`
				First       int64  `json:"first"`
				Second      int64  `json:"second"`
				Third       uint32 `json:"third"`
			} `json:"operation"`
			Items []Item `json:"items"`
		} `json:"decoded"`
		ResultHex  string `json:"result_hex"`
		Rows       uint32 `json:"rows"`
		ReceiptHex string `json:"receipt_hex"`
	} `json:"valid"`
	Invalid []struct {
		ID            string `json:"id"`
		FrameHex      string `json:"frame_hex"`
		ExpectedError string `json:"expected_error"`
	} `json:"invalid"`
	Sequences []struct {
		ID      string `json:"id"`
		FrameID string `json:"frame_id"`
	} `json:"sequences"`
}

func TestConformanceVectors(t *testing.T) {
	manifest := loadManifest(t)
	authority := manifestAuthority(t, manifest)
	limits := Limits{
		MaximumResultBytes: manifest.ServerLimits.MaximumResultBytes,
		MaximumRows:        manifest.ServerLimits.MaximumRows,
	}

	wantContext := decodeHex(t, manifest.Authority.ContextDigestHex)
	gotContext := ContextDigest(authority)
	if string(gotContext[:]) != string(wantContext) {
		t.Fatal("the independent context digest differs")
	}

	for _, vector := range manifest.Valid {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			frame := decodeHex(t, vector.FrameHex)
			pending, err := Verify(frame, authority, limits, NewReplayStore(), manifest.ClockUnixUS)
			if err != nil {
				t.Fatalf("Verify returned %v", err)
			}
			if pending.Nonce != vector.Decoded.Nonce ||
				pending.DeadlineUnixUS != vector.Decoded.DeadlineUnixUS ||
				pending.ResultBudget != vector.Decoded.ResultBudget ||
				pending.RowBudget != vector.Decoded.RowBudget ||
				pending.Operation.Opcode != vector.Decoded.Operation.Opcode ||
				pending.Operation.PlanHandle != vector.Decoded.Operation.PlanHandle ||
				pending.Operation.ResultShape != vector.Decoded.Operation.ResultShape {
				t.Fatal("the decoded header differs")
			}
			if len(vector.Decoded.Items) == 0 {
				want := Item{
					First:  vector.Decoded.Operation.First,
					Second: vector.Decoded.Operation.Second,
					Third:  vector.Decoded.Operation.Third,
				}
				if len(pending.Items) != 1 || pending.Items[0] != want {
					t.Fatal("the decoded single operands differ")
				}
			} else if !equalItems(pending.Items, vector.Decoded.Items) {
				t.Fatal("the decoded batch operands differ")
			}
			result := decodeHex(t, vector.ResultHex)
			receipt := Receipt(frame, authority, pending.Nonce, vector.Rows, result)
			if hex.EncodeToString(receipt[:]) != vector.ReceiptHex {
				t.Fatal("the independent receipt differs")
			}
			changed := append([]byte(nil), result...)
			changed[0] ^= 1
			changedReceipt := Receipt(frame, authority, pending.Nonce, vector.Rows, changed)
			if changedReceipt == receipt {
				t.Fatal("a result mutation retained the receipt")
			}
		})
	}

	for _, vector := range manifest.Invalid {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			_, err := Verify(
				decodeHex(t, vector.FrameHex),
				authority,
				limits,
				NewReplayStore(),
				manifest.ClockUnixUS,
			)
			if err == nil || err.Error() != vector.ExpectedError {
				t.Fatalf("Verify returned %v, expected %s", err, vector.ExpectedError)
			}
		})
	}
}

func TestEverySingleBitMutationRefuses(t *testing.T) {
	manifest := loadManifest(t)
	authority := manifestAuthority(t, manifest)
	limits := Limits{
		MaximumResultBytes: manifest.ServerLimits.MaximumResultBytes,
		MaximumRows:        manifest.ServerLimits.MaximumRows,
	}
	for _, vector := range manifest.Valid {
		frame := decodeHex(t, vector.FrameHex)
		for byteIndex := range frame {
			for bit := uint(0); bit < 8; bit++ {
				mutated := append([]byte(nil), frame...)
				mutated[byteIndex] ^= 1 << bit
				if _, err := Verify(mutated, authority, limits, NewReplayStore(), manifest.ClockUnixUS); err == nil {
					t.Fatalf("%s accepted mutation at byte %d bit %d", vector.ID, byteIndex, bit)
				}
			}
		}
	}
}

func TestReplayRequiresPostExecutionCommit(t *testing.T) {
	manifest := loadManifest(t)
	authority := manifestAuthority(t, manifest)
	limits := Limits{
		MaximumResultBytes: manifest.ServerLimits.MaximumResultBytes,
		MaximumRows:        manifest.ServerLimits.MaximumRows,
	}
	for _, sequence := range manifest.Sequences {
		sequence := sequence
		t.Run(sequence.ID, func(t *testing.T) {
			vector := findValid(t, manifest, sequence.FrameID)
			frame := decodeHex(t, vector.FrameHex)
			store := NewReplayStore()
			first, err := Verify(frame, authority, limits, store, manifest.ClockUnixUS)
			if err != nil {
				t.Fatalf("the first admission returned %v", err)
			}
			if _, err := Verify(frame, authority, limits, store, manifest.ClockUnixUS); err != nil {
				t.Fatalf("verification changed replay state: %v", err)
			}
			if err := store.Commit(first); err != nil {
				t.Fatalf("Commit returned %v", err)
			}
			if _, err := Verify(frame, authority, limits, store, manifest.ClockUnixUS); !errors.Is(err, ErrReplay) {
				t.Fatalf("the replay returned %v", err)
			}
			if err := store.Commit(first); !errors.Is(err, ErrReplayConflict) {
				t.Fatalf("the duplicate commit returned %v", err)
			}
		})
	}
}

func TestInvalidAuthorityAndReplayStoreRefuse(t *testing.T) {
	manifest := loadManifest(t)
	authority := manifestAuthority(t, manifest)
	frame := decodeHex(t, manifest.Valid[0].FrameHex)
	limits := Limits{
		MaximumResultBytes: manifest.ServerLimits.MaximumResultBytes,
		MaximumRows:        manifest.ServerLimits.MaximumRows,
	}
	if _, err := Verify(frame, authority, limits, nil, manifest.ClockUnixUS); !errors.Is(err, ErrReplayStoreUnavailable) {
		t.Fatalf("a nil replay store returned %v", err)
	}
	zeroKey := authority
	zeroKey.RootKey = [32]byte{}
	if _, err := Verify(frame, zeroKey, limits, NewReplayStore(), manifest.ClockUnixUS); !errors.Is(err, ErrZeroKey) {
		t.Fatalf("a zero root key returned %v", err)
	}
	zeroIdentity := authority
	zeroIdentity.Session = 0
	if _, err := Verify(frame, zeroIdentity, limits, NewReplayStore(), manifest.ClockUnixUS); !errors.Is(err, ErrZeroIdentity) {
		t.Fatalf("a zero session returned %v", err)
	}
	zeroDigest := authority
	zeroDigest.PolicyDigest = [32]byte{}
	if _, err := Verify(frame, zeroDigest, limits, NewReplayStore(), manifest.ClockUnixUS); !errors.Is(err, ErrZeroDigest) {
		t.Fatalf("a zero policy digest returned %v", err)
	}
	var zeroValueStore ReplayStore
	pending, err := Verify(frame, authority, limits, &zeroValueStore, manifest.ClockUnixUS)
	if err != nil {
		t.Fatalf("the zero-value store admission returned %v", err)
	}
	if err := zeroValueStore.Commit(pending); err != nil {
		t.Fatalf("the zero-value store commit returned %v", err)
	}
	if err := (*ReplayStore)(nil).Commit(pending); !errors.Is(err, ErrReplayStoreUnavailable) {
		t.Fatalf("a nil replay commit returned %v", err)
	}
}

func TestConcurrentReplayCommitAcceptsOneExecution(t *testing.T) {
	manifest := loadManifest(t)
	authority := manifestAuthority(t, manifest)
	frame := decodeHex(t, manifest.Valid[0].FrameHex)
	limits := Limits{
		MaximumResultBytes: manifest.ServerLimits.MaximumResultBytes,
		MaximumRows:        manifest.ServerLimits.MaximumRows,
	}
	store := NewReplayStore()
	first, err := Verify(frame, authority, limits, store, manifest.ClockUnixUS)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Verify(frame, authority, limits, store, manifest.ClockUnixUS)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, pending := range []Pending{first, second} {
		wait.Add(1)
		go func(candidate Pending) {
			defer wait.Done()
			results <- store.Commit(candidate)
		}(pending)
	}
	wait.Wait()
	close(results)
	accepted := 0
	conflicted := 0
	for result := range results {
		switch {
		case result == nil:
			accepted++
		case errors.Is(result, ErrReplayConflict):
			conflicted++
		default:
			t.Fatalf("the concurrent commit returned %v", result)
		}
	}
	if accepted != 1 || conflicted != 1 {
		t.Fatalf("accepted %d commits and refused %d commits", accepted, conflicted)
	}
}

func loadManifest(t *testing.T) vectorManifest {
	t.Helper()
	path := filepath.Join("..", "..", "v0.1", "vectors.json")
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest vectorManifest
	if err := json.Unmarshal(bytes, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func manifestAuthority(t *testing.T, manifest vectorManifest) Authority {
	t.Helper()
	var authority Authority
	copyExact(t, authority.RootKey[:], manifest.Authority.RootKeyHex)
	copyExact(t, authority.Tenant[:], manifest.Authority.TenantHex)
	copyExact(t, authority.Principal[:], manifest.Authority.PrincipalHex)
	copyExact(t, authority.CapabilityDigest[:], manifest.Authority.CapabilityDigestHex)
	copyExact(t, authority.SchemaDigest[:], manifest.Authority.SchemaDigestHex)
	copyExact(t, authority.PolicyDigest[:], manifest.Authority.PolicyDigestHex)
	copyExact(t, authority.PlanDigest[:], manifest.Authority.PlanDigestHex)
	authority.Generation = manifest.Authority.Generation
	authority.Session = manifest.Authority.Session
	authority.ExpiresUnixUS = manifest.Authority.ExpiresUnixUS
	authority.Purpose = manifest.Authority.Purpose
	authority.Engine = manifest.Authority.Engine
	authority.Profile = manifest.Authority.Profile
	return authority
}

func copyExact(t *testing.T, destination []byte, encoded string) {
	t.Helper()
	decoded := decodeHex(t, encoded)
	if len(decoded) != len(destination) {
		t.Fatalf("decoded %d bytes, expected %d", len(decoded), len(destination))
	}
	copy(destination, decoded)
}

func decodeHex(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func equalItems(first []Item, second []Item) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func findValid(t *testing.T, manifest vectorManifest, id string) struct {
	ID       string `json:"id"`
	FrameHex string `json:"frame_hex"`
	Decoded  struct {
		Nonce          uint64 `json:"nonce"`
		DeadlineUnixUS uint64 `json:"deadline_unix_us"`
		ResultBudget   uint32 `json:"result_budget"`
		RowBudget      uint32 `json:"row_budget"`
		Operation      struct {
			Opcode      uint16 `json:"opcode"`
			PlanHandle  uint32 `json:"plan_handle"`
			ResultShape uint32 `json:"result_shape"`
			First       int64  `json:"first"`
			Second      int64  `json:"second"`
			Third       uint32 `json:"third"`
		} `json:"operation"`
		Items []Item `json:"items"`
	} `json:"decoded"`
	ResultHex  string `json:"result_hex"`
	Rows       uint32 `json:"rows"`
	ReceiptHex string `json:"receipt_hex"`
} {
	t.Helper()
	for _, vector := range manifest.Valid {
		if vector.ID == id {
			return vector
		}
	}
	t.Fatalf("missing valid vector %s", id)
	panic("unreachable")
}
