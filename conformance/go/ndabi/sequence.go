package ndabi

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"github.com/zeebo/blake3"
)

const (
	FeatureStreaming      = uint32(1)
	FeatureCancellation   = uint32(2)
	FeatureOperandBundles = uint32(4)
	knownFeatures         = FeatureStreaming | FeatureCancellation | FeatureOperandBundles
)

var (
	ErrConnectionState       = errors.New("ConnectionState")
	ErrFeatureNotNegotiated  = errors.New("FeatureNotNegotiated")
	ErrOutputShape           = errors.New("OutputShape")
	ErrReceiptMismatch       = errors.New("ReceiptMismatch")
	ErrRequestLimitExceeded  = errors.New("RequestLimitExceeded")
	ErrResultBudgetExceeded  = errors.New("ResultBudgetExceeded")
	ErrRowBudgetExceeded     = errors.New("RowBudgetExceeded")
	ErrSequenceMismatch      = errors.New("SequenceMismatch")
	ErrTransportConfig       = errors.New("TransportConfiguration")
	ErrUnknownCorrelation    = errors.New("UnknownCorrelation")
	transportReceiptDomainV2 = []byte("ndabi/wire/v2/execution-receipt")
)

type transportPhase uint8

const (
	phaseProvisioned transportPhase = iota
	phaseHello
	phaseReady
	phaseRefused
)

// TransportSequenceConfig fixes the local transport limits.
type TransportSequenceConfig struct {
	Features          uint32
	MaximumFrameBytes uint32
	MaximumChunkBytes uint32
	MaximumInFlight   uint32
}

type transportOffer struct {
	features          uint32
	maximumFrameBytes uint32
	maximumChunkBytes uint32
}

type sequenceRequest struct {
	requestDigest [32]byte
	resultShape   uint32
	resultBudget  uint32
	rowBudget     uint32
	cancelled     bool
	stream        *sequenceStream
}

type sequenceStream struct {
	nextSequence  uint32
	receivedBytes uint64
	expectedRows  *uint32
	digest        *blake3.Hasher
}

type sequenceBundle struct {
	acknowledgement uint8
	graphHandle     uint32
	resultShape     uint32
	bundleHandle    uint32
	expiryUnixUS    uint64
	bundleDigest    [32]byte
}

// TransportSequence independently enforces the v0.2 connection state after frame decoding.
type TransportSequence struct {
	authority           TransportAuthority
	config              TransportSequenceConfig
	phase               transportPhase
	offer               transportOffer
	negotiatedFeatures  uint32
	negotiatedFrame     uint32
	negotiatedChunk     uint32
	requests            map[uint64]*sequenceRequest
	bundles             map[uint64]sequenceBundle
	lastRegisteredNonce uint64
}

// NewTransportSequence creates one provisioned independent state machine.
func NewTransportSequence(authority TransportAuthority, config TransportSequenceConfig) (*TransportSequence, error) {
	if isZero(authority.RootKey[:]) {
		return nil, ErrZeroKey
	}
	if authority.Generation == 0 || authority.Session == 0 || authority.ExpiresUnixUS == 0 ||
		isZero(authority.ContextDigest[:]) {
		return nil, ErrZeroIdentity
	}
	if config.Features&^knownFeatures != 0 ||
		config.MaximumFrameBytes < transportMinBytes+8 ||
		config.MaximumChunkBytes == 0 ||
		config.MaximumChunkBytes > config.MaximumFrameBytes-transportMinBytes ||
		config.MaximumInFlight == 0 {
		return nil, ErrTransportConfig
	}
	return &TransportSequence{
		authority: authority,
		config:    config,
		requests:  make(map[uint64]*sequenceRequest),
		bundles:   make(map[uint64]sequenceBundle),
	}, nil
}

// RegisterRequest records fields returned by the authenticated v0.1 verifier.
func (sequence *TransportSequence) RegisterRequest(
	requestFrame []byte,
	pending Pending,
) error {
	if sequence.phase != phaseReady {
		return ErrConnectionState
	}
	nonce := pending.Nonce()
	resultShape := pending.Operation().ResultShape
	resultBudget := pending.ResultBudget()
	rowBudget := pending.RowBudget()
	if len(requestFrame) == 0 || nonce == 0 || nonce <= sequence.lastRegisteredNonce ||
		resultShape == 0 || resultBudget == 0 || rowBudget == 0 {
		return ErrNonCanonicalFrame
	}
	if len(sequence.requests)+len(sequence.bundles) >= int(sequence.config.MaximumInFlight) {
		return ErrRequestLimitExceeded
	}
	sequence.requests[nonce] = &sequenceRequest{
		requestDigest: blake3.Sum256(requestFrame),
		resultShape:   resultShape,
		resultBudget:  resultBudget,
		rowBudget:     rowBudget,
	}
	sequence.lastRegisteredNonce = nonce
	return nil
}

// RegisterBundleControl records an authenticated bundle control before its acknowledgement.
func (sequence *TransportSequence) RegisterBundleControl(
	acknowledgement uint8,
	nonce uint64,
	graphHandle uint32,
	resultShape uint32,
	bundleHandle uint32,
	expiryUnixUS uint64,
	bundleDigest [32]byte,
) error {
	if sequence.phase != phaseReady {
		return ErrConnectionState
	}
	if sequence.negotiatedFeatures&FeatureOperandBundles == 0 {
		return ErrFeatureNotNegotiated
	}
	if (acknowledgement != 9 && acknowledgement != 10) || nonce == 0 ||
		nonce <= sequence.lastRegisteredNonce || graphHandle == 0 || resultShape == 0 ||
		bundleHandle == 0 || (acknowledgement == 9 && expiryUnixUS == 0) {
		return ErrNonCanonicalFrame
	}
	if (acknowledgement == 9 && isZero(bundleDigest[:])) ||
		(acknowledgement == 10 && !isZero(bundleDigest[:])) {
		return ErrNonCanonicalFrame
	}
	if len(sequence.requests)+len(sequence.bundles) >= int(sequence.config.MaximumInFlight) {
		return ErrRequestLimitExceeded
	}
	sequence.bundles[nonce] = sequenceBundle{
		acknowledgement: acknowledgement,
		graphHandle:     graphHandle,
		resultShape:     resultShape,
		bundleHandle:    bundleHandle,
		expiryUnixUS:    expiryUnixUS,
		bundleDigest:    bundleDigest,
	}
	sequence.lastRegisteredNonce = nonce
	return nil
}

// Apply accepts one authenticated and semantically decoded transport frame.
func (sequence *TransportSequence) Apply(frame TransportFrame, direction uint8) error {
	if direction != 1 && direction != 2 {
		return ErrUnsupportedFrame
	}
	switch sequence.phase {
	case phaseProvisioned:
		return sequence.applyHello(frame, direction)
	case phaseHello:
		return sequence.applyAccept(frame, direction)
	case phaseReady:
		return sequence.applyReady(frame, direction)
	default:
		return ErrConnectionState
	}
}

func (sequence *TransportSequence) applyHello(frame TransportFrame, direction uint8) error {
	if direction != 1 || frame.Kind != 1 || len(frame.Payload) != 8 {
		return ErrConnectionState
	}
	minimumMajor := binary.LittleEndian.Uint16(frame.Payload[0:2])
	maximumMajor := binary.LittleEndian.Uint16(frame.Payload[2:4])
	maximumChunk := binary.LittleEndian.Uint32(frame.Payload[4:8])
	if minimumMajor > 2 || maximumMajor < 2 || frame.Fields.Features&^knownFeatures != 0 ||
		frame.Fields.Features&^sequence.config.Features != 0 ||
		frame.Fields.Auxiliary > sequence.config.MaximumFrameBytes ||
		maximumChunk > sequence.config.MaximumChunkBytes {
		return ErrTransportConfig
	}
	sequence.offer = transportOffer{frame.Fields.Features, frame.Fields.Auxiliary, maximumChunk}
	sequence.phase = phaseHello
	return nil
}

func (sequence *TransportSequence) applyAccept(frame TransportFrame, direction uint8) error {
	if direction != 2 {
		return ErrConnectionState
	}
	if frame.Kind == 4 && frame.Fields.CorrelationNonce == 0 {
		sequence.phase = phaseRefused
		return nil
	}
	if frame.Kind != 2 || len(frame.Payload) != 8 {
		return ErrConnectionState
	}
	maximumChunk := binary.LittleEndian.Uint32(frame.Payload[4:8])
	if binary.LittleEndian.Uint16(frame.Payload[0:2]) != 2 ||
		binary.LittleEndian.Uint16(frame.Payload[2:4]) != 0 ||
		frame.Fields.Features&^sequence.offer.features != 0 ||
		frame.Fields.Auxiliary < transportMinBytes+8 ||
		frame.Fields.Auxiliary > sequence.offer.maximumFrameBytes ||
		maximumChunk > sequence.offer.maximumChunkBytes ||
		maximumChunk > frame.Fields.Auxiliary-transportMinBytes {
		return ErrConnectionState
	}
	sequence.negotiatedFeatures = frame.Fields.Features
	sequence.negotiatedFrame = frame.Fields.Auxiliary
	sequence.negotiatedChunk = maximumChunk
	sequence.phase = phaseReady
	return nil
}

func (sequence *TransportSequence) applyReady(frame TransportFrame, direction uint8) error {
	if uint64(transportMinBytes)+uint64(len(frame.Payload)) > uint64(sequence.negotiatedFrame) {
		return ErrLengthMismatch
	}
	if frame.Kind == 5 {
		return sequence.applyCancel(frame, direction)
	}
	if direction != 2 {
		return ErrConnectionState
	}
	switch frame.Kind {
	case 3:
		return sequence.applyResult(frame)
	case 4:
		return sequence.applyError(frame)
	case 6:
		return sequence.applyStreamStart(frame)
	case 7:
		return sequence.applyStreamChunk(frame)
	case 8:
		return sequence.applyStreamEnd(frame)
	case 9, 10:
		return sequence.applyBundle(frame)
	default:
		return ErrConnectionState
	}
}

func (sequence *TransportSequence) applyCancel(frame TransportFrame, direction uint8) error {
	if direction != 1 {
		return ErrConnectionState
	}
	if sequence.negotiatedFeatures&FeatureCancellation == 0 {
		return ErrFeatureNotNegotiated
	}
	request := sequence.requests[frame.Fields.CorrelationNonce]
	if request == nil {
		return ErrUnknownCorrelation
	}
	if request.cancelled {
		return ErrConnectionState
	}
	request.cancelled = true
	return nil
}

func (sequence *TransportSequence) applyResult(frame TransportFrame) error {
	request := sequence.requests[frame.Fields.CorrelationNonce]
	if request == nil {
		return ErrUnknownCorrelation
	}
	if request.stream != nil {
		return ErrConnectionState
	}
	if frame.Fields.ResultShape != request.resultShape {
		return ErrOutputShape
	}
	if frame.Fields.Rows > request.rowBudget {
		return ErrRowBudgetExceeded
	}
	if len(frame.Payload) > int(request.resultBudget) {
		return ErrResultBudgetExceeded
	}
	digest := blake3.Sum256(frame.Payload)
	expected := sequence.receipt(request.requestDigest, frame.Fields.CorrelationNonce, frame.Fields.Rows, digest)
	if subtle.ConstantTimeCompare(expected[:], frame.Fields.ExecutionReceipt[:]) != 1 {
		return ErrReceiptMismatch
	}
	delete(sequence.requests, frame.Fields.CorrelationNonce)
	return nil
}

func (sequence *TransportSequence) applyError(frame TransportFrame) error {
	nonce := frame.Fields.CorrelationNonce
	if nonce == 0 {
		return ErrConnectionState
	}
	if request := sequence.requests[nonce]; request != nil {
		if frame.Fields.ErrorCode == 7 && !request.cancelled {
			return ErrConnectionState
		}
		delete(sequence.requests, nonce)
		return nil
	}
	if _, present := sequence.bundles[nonce]; present {
		if frame.Fields.ErrorCode == 7 {
			return ErrConnectionState
		}
		delete(sequence.bundles, nonce)
		return nil
	}
	return ErrUnknownCorrelation
}

func (sequence *TransportSequence) applyStreamStart(frame TransportFrame) error {
	if sequence.negotiatedFeatures&FeatureStreaming == 0 {
		return ErrFeatureNotNegotiated
	}
	request := sequence.requests[frame.Fields.CorrelationNonce]
	if request == nil {
		return ErrUnknownCorrelation
	}
	if request.stream != nil {
		return ErrConnectionState
	}
	if frame.Fields.ResultShape != request.resultShape {
		return ErrOutputShape
	}
	var expectedRows *uint32
	if frame.Fields.Rows != ^uint32(0) {
		if frame.Fields.Rows > request.rowBudget {
			return ErrRowBudgetExceeded
		}
		rows := frame.Fields.Rows
		expectedRows = &rows
	}
	request.stream = &sequenceStream{nextSequence: 1, expectedRows: expectedRows, digest: blake3.New()}
	return nil
}

func (sequence *TransportSequence) applyStreamChunk(frame TransportFrame) error {
	request := sequence.requests[frame.Fields.CorrelationNonce]
	if request == nil {
		return ErrUnknownCorrelation
	}
	if request.stream == nil {
		return ErrConnectionState
	}
	stream := request.stream
	if frame.Fields.Sequence != stream.nextSequence {
		return ErrSequenceMismatch
	}
	nextBytes := stream.receivedBytes + uint64(len(frame.Payload))
	if nextBytes < stream.receivedBytes || len(frame.Payload) > int(sequence.negotiatedChunk) ||
		nextBytes > uint64(request.resultBudget) {
		return ErrResultBudgetExceeded
	}
	if stream.nextSequence == ^uint32(0) {
		return ErrSequenceMismatch
	}
	_, _ = stream.digest.Write(frame.Payload)
	stream.receivedBytes = nextBytes
	stream.nextSequence++
	return nil
}

func (sequence *TransportSequence) applyStreamEnd(frame TransportFrame) error {
	request := sequence.requests[frame.Fields.CorrelationNonce]
	if request == nil {
		return ErrUnknownCorrelation
	}
	if request.stream == nil || request.stream.receivedBytes == 0 {
		return ErrConnectionState
	}
	stream := request.stream
	if frame.Fields.Sequence != stream.nextSequence {
		return ErrSequenceMismatch
	}
	if frame.Fields.ResultShape != request.resultShape {
		return ErrOutputShape
	}
	if frame.Fields.Rows > request.rowBudget {
		return ErrRowBudgetExceeded
	}
	if stream.expectedRows != nil && frame.Fields.Rows != *stream.expectedRows {
		return ErrOutputShape
	}
	var digest [32]byte
	copy(digest[:], stream.digest.Sum(nil))
	expected := sequence.receipt(request.requestDigest, frame.Fields.CorrelationNonce, frame.Fields.Rows, digest)
	if subtle.ConstantTimeCompare(expected[:], frame.Fields.ExecutionReceipt[:]) != 1 {
		return ErrReceiptMismatch
	}
	delete(sequence.requests, frame.Fields.CorrelationNonce)
	return nil
}

func (sequence *TransportSequence) applyBundle(frame TransportFrame) error {
	if sequence.negotiatedFeatures&FeatureOperandBundles == 0 {
		return ErrFeatureNotNegotiated
	}
	bundle, present := sequence.bundles[frame.Fields.CorrelationNonce]
	if !present {
		return ErrUnknownCorrelation
	}
	if frame.Kind != bundle.acknowledgement || frame.Fields.ResultShape != bundle.resultShape {
		return ErrOutputShape
	}
	if (frame.Kind == 9 && len(frame.Payload) != 48) || (frame.Kind == 10 && len(frame.Payload) != 8) {
		return ErrNonCanonicalFrame
	}
	graphHandle := binary.LittleEndian.Uint32(frame.Payload[4:8])
	if binary.LittleEndian.Uint32(frame.Payload[0:4]) != bundle.bundleHandle || graphHandle != bundle.graphHandle {
		return ErrOutputShape
	}
	if frame.Kind == 9 && binary.LittleEndian.Uint64(frame.Payload[8:16]) != bundle.expiryUnixUS {
		return ErrOutputShape
	}
	if frame.Kind == 9 && subtle.ConstantTimeCompare(frame.Payload[16:48], bundle.bundleDigest[:]) != 1 {
		return ErrOutputShape
	}
	delete(sequence.bundles, frame.Fields.CorrelationNonce)
	return nil
}

func (sequence *TransportSequence) receipt(
	requestDigest [32]byte,
	nonce uint64,
	rows uint32,
	resultDigest [32]byte,
) [32]byte {
	receiptKey := deriveTransportMaterial(sequence.authority, receiptKeyDomain)
	hasher, err := blake3.NewKeyed(receiptKey[:])
	if err != nil {
		panic("the fixed receipt key has an invalid length")
	}
	write(hasher, transportReceiptDomainV2)
	write(hasher, sequence.authority.ContextDigest[:])
	write(hasher, requestDigest[:])
	writeU64(hasher, nonce)
	writeU32(hasher, rows)
	write(hasher, resultDigest[:])
	output := digest(hasher)
	clear(receiptKey[:])
	return output
}

func deriveTransportMaterial(authority TransportAuthority, domain []byte) [32]byte {
	hasher, err := blake3.NewKeyed(authority.RootKey[:])
	if err != nil {
		panic("the fixed transport root key has an invalid length")
	}
	write(hasher, domain)
	writeU64(hasher, authority.Generation)
	writeU64(hasher, authority.Session)
	writeU64(hasher, authority.ExpiresUnixUS)
	write(hasher, authority.ContextDigest[:])
	return digest(hasher)
}
