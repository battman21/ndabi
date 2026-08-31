package ndabi

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type stateVectorManifest struct {
	Schema string `json:"schema"`
	Cases  []struct {
		ID       string `json:"id"`
		Features uint32 `json:"features"`
		Action   string `json:"action"`
		Expected string `json:"expected"`
	} `json:"cases"`
}

func TestSharedTransportStateVectors(t *testing.T) {
	path := filepath.Join("..", "..", "v0.2", "state-vectors.json")
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest stateVectorManifest
	if err := json.Unmarshal(bytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != "ndabi-transport-state-conformance-v0.2" || len(manifest.Cases) == 0 {
		t.Fatal("the shared state manifest is invalid")
	}
	for _, vector := range manifest.Cases {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			actual := applyStateVector(t, vector.Features, vector.Action)
			if vector.Expected == "Accepted" {
				if actual != nil {
					t.Fatalf("state vector returned %v", actual)
				}
				return
			}
			if actual == nil || actual.Error() != vector.Expected {
				t.Fatalf("state vector returned %v, expected %s", actual, vector.Expected)
			}
		})
	}
}

func applyStateVector(t *testing.T, features uint32, action string) error {
	t.Helper()
	if action == "negotiate" {
		_ = readySequence(t, features)
		return nil
	}
	if action == "accept-feature-escalation" {
		sequence := provisionedSequence(t, features)
		if err := sequence.Apply(negotiationFrame(1, features, 2, 2, 1024), 1); err != nil {
			return err
		}
		return sequence.Apply(negotiationFrame(2, FeatureCancellation, 2, 0, 1024), 2)
	}
	sequence := readySequence(t, features)
	switch action {
	case "result-before-registration":
		return sequence.Apply(TransportFrame{Kind: 3, Fields: TransportFields{CorrelationNonce: 1}}, 2)
	case "cancel-feature-disabled":
		return sequence.Apply(TransportFrame{Kind: 5, Fields: TransportFields{CorrelationNonce: 1}}, 1)
	case "bundle-before-control":
		return sequence.Apply(TransportFrame{Kind: 9, Fields: TransportFields{CorrelationNonce: 1}, Payload: make([]byte, 48)}, 2)
	case "result-wrong-direction":
		return sequence.Apply(TransportFrame{Kind: 3, Fields: TransportFields{CorrelationNonce: 1}}, 1)
	case "hello-after-ready":
		return sequence.Apply(negotiationFrame(1, features, 2, 2, 1024), 1)
	default:
		return errors.New("UnknownStateVectorAction")
	}
}
