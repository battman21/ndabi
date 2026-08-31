package ndabi

import (
	"encoding/binary"
	"testing"

	"github.com/zeebo/blake3"
)

func TestSequenceAcceptsExactResultsAndRefusesReceiptReplay(t *testing.T) {
	sequence := readySequence(t, knownFeatures)
	request := []byte("authenticated request one")
	if err := sequence.RegisterRequest(request, sequencePending(1, 17, 32, 4)); err != nil {
		t.Fatal(err)
	}
	result := []byte("exact result")
	receipt := sequence.receipt(blake3.Sum256(request), 1, 2, blake3.Sum256(result))
	frame := TransportFrame{Kind: 3, Fields: TransportFields{
		CorrelationNonce: 1,
		Rows:             2,
		ResultShape:      17,
		ExecutionReceipt: receipt,
	}, Payload: result}
	changed := frame
	changed.Fields.ExecutionReceipt[0] ^= 1
	if err := sequence.Apply(changed, 2); err != ErrReceiptMismatch {
		t.Fatalf("changed receipt returned %v", err)
	}
	if err := sequence.Apply(frame, 2); err != nil {
		t.Fatal(err)
	}
	if err := sequence.Apply(frame, 2); err != ErrUnknownCorrelation {
		t.Fatalf("replayed result returned %v", err)
	}
}

func TestSequenceEnforcesStreamingOrderBudgetsAndExactReceipt(t *testing.T) {
	sequence := readySequence(t, FeatureStreaming)
	request := []byte("authenticated stream request")
	if err := sequence.RegisterRequest(request, sequencePending(1, 17, 6, 4)); err != nil {
		t.Fatal(err)
	}
	start := TransportFrame{Kind: 6, Fields: TransportFields{
		CorrelationNonce: 1,
		Rows:             ^uint32(0),
		ResultShape:      17,
	}}
	if err := sequence.Apply(start, 2); err != nil {
		t.Fatal(err)
	}
	emptyEnd := TransportFrame{Kind: 8, Fields: TransportFields{
		CorrelationNonce: 1,
		Sequence:         1,
		Rows:             0,
		ResultShape:      17,
		ExecutionReceipt: [32]byte{1},
	}}
	if err := sequence.Apply(emptyEnd, 2); err != ErrConnectionState {
		t.Fatalf("empty stream returned %v", err)
	}
	wrong := TransportFrame{Kind: 7, Fields: TransportFields{CorrelationNonce: 1, Sequence: 2}, Payload: []byte("abc")}
	if err := sequence.Apply(wrong, 2); err != ErrSequenceMismatch {
		t.Fatalf("wrong sequence returned %v", err)
	}
	chunk := TransportFrame{Kind: 7, Fields: TransportFields{CorrelationNonce: 1, Sequence: 1}, Payload: []byte("abcdef")}
	if err := sequence.Apply(chunk, 2); err != nil {
		t.Fatal(err)
	}
	resultDigest := blake3.Sum256([]byte("abcdef"))
	receipt := sequence.receipt(blake3.Sum256(request), 1, 2, resultDigest)
	end := TransportFrame{Kind: 8, Fields: TransportFields{
		CorrelationNonce: 1,
		Sequence:         2,
		Rows:             2,
		ResultShape:      17,
		ExecutionReceipt: receipt,
	}}
	if err := sequence.Apply(end, 2); err != nil {
		t.Fatal(err)
	}
}

func TestSequenceRequiresCancellationBeforeCodeSeven(t *testing.T) {
	sequence := readySequence(t, FeatureCancellation)
	if err := sequence.RegisterRequest([]byte("request"), sequencePending(1, 17, 32, 4)); err != nil {
		t.Fatal(err)
	}
	refusal := TransportFrame{Kind: 4, Fields: TransportFields{ErrorCode: 7, CorrelationNonce: 1}}
	if err := sequence.Apply(refusal, 2); err != ErrConnectionState {
		t.Fatalf("premature cancellation returned %v", err)
	}
	cancel := TransportFrame{Kind: 5, Fields: TransportFields{CorrelationNonce: 1}}
	if err := sequence.Apply(cancel, 1); err != nil {
		t.Fatal(err)
	}
	if err := sequence.Apply(cancel, 1); err != ErrConnectionState {
		t.Fatalf("duplicate cancellation returned %v", err)
	}
	if err := sequence.Apply(refusal, 2); err != nil {
		t.Fatal(err)
	}
}

func TestSequenceMatchesBundleAcknowledgements(t *testing.T) {
	sequence := readySequence(t, FeatureOperandBundles)
	digest := [32]byte{9}
	if err := sequence.RegisterBundleControl(9, 1, 11, 17, 13, 2_000_000, digest); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 48)
	binary.LittleEndian.PutUint32(payload[0:4], 13)
	binary.LittleEndian.PutUint32(payload[4:8], 11)
	binary.LittleEndian.PutUint64(payload[8:16], 2_000_000)
	copy(payload[16:48], digest[:])
	frame := TransportFrame{Kind: 9, Fields: TransportFields{CorrelationNonce: 1, ResultShape: 17}, Payload: payload}
	changed := frame
	changed.Payload = append([]byte(nil), payload...)
	changed.Payload[16] ^= 1
	if err := sequence.Apply(changed, 2); err != ErrOutputShape {
		t.Fatalf("changed digest returned %v", err)
	}
	if err := sequence.Apply(frame, 2); err != nil {
		t.Fatal(err)
	}
	if err := sequence.Apply(frame, 2); err != ErrUnknownCorrelation {
		t.Fatalf("replayed acknowledgement returned %v", err)
	}
}

func TestSequenceRefusesNegotiationFeatureEscalation(t *testing.T) {
	sequence := provisionedSequence(t, FeatureStreaming)
	hello := negotiationFrame(1, FeatureStreaming, 2, 2, 1024)
	if err := sequence.Apply(hello, 1); err != nil {
		t.Fatal(err)
	}
	accept := negotiationFrame(2, FeatureCancellation, 2, 0, 1024)
	if err := sequence.Apply(accept, 2); err != ErrConnectionState {
		t.Fatalf("feature escalation returned %v", err)
	}
}

func provisionedSequence(t *testing.T, features uint32) *TransportSequence {
	t.Helper()
	authority := TransportAuthority{
		RootKey:       [32]byte{1},
		Generation:    2,
		Session:       3,
		ExpiresUnixUS: 4,
		ContextDigest: [32]byte{5},
	}
	sequence, err := NewTransportSequence(authority, TransportSequenceConfig{
		Features:          features,
		MaximumFrameBytes: 4096,
		MaximumChunkBytes: 1024,
		MaximumInFlight:   4,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sequence
}

func readySequence(t *testing.T, features uint32) *TransportSequence {
	t.Helper()
	sequence := provisionedSequence(t, features)
	if err := sequence.Apply(negotiationFrame(1, features, 2, 2, 1024), 1); err != nil {
		t.Fatal(err)
	}
	if err := sequence.Apply(negotiationFrame(2, features, 2, 0, 1024), 2); err != nil {
		t.Fatal(err)
	}
	return sequence
}

func negotiationFrame(kind uint8, features uint32, first uint16, second uint16, chunk uint32) TransportFrame {
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint16(payload[0:2], first)
	binary.LittleEndian.PutUint16(payload[2:4], second)
	binary.LittleEndian.PutUint32(payload[4:8], chunk)
	return TransportFrame{
		Kind: kind,
		Fields: TransportFields{
			Features:  features,
			Auxiliary: 4096,
		},
		Payload: payload,
	}
}

func sequencePending(nonce uint64, resultShape uint32, resultBudget uint32, rowBudget uint32) Pending {
	return Pending{
		nonce:        nonce,
		resultBudget: resultBudget,
		rowBudget:    rowBudget,
		operation:    Operation{ResultShape: resultShape},
	}
}
