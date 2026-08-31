// Package ndabi independently decodes the NDABI v0.1 request and v0.2 transport frames.
// It does not call the Rust implementation or a database adapter.
package ndabi

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/zeebo/blake3"
)

const (
	singleFrameBytes   = 160
	batchHeaderBytes   = 128
	tagBytes           = 32
	batchOperandBytes  = 20
	maxBatchOperations = 4096
	transportMinBytes  = 160
	maximumErrorCode   = 10
)

var (
	ErrAuthenticationFailed     = errors.New("AuthenticationFailed")
	ErrAuthorityMismatch        = errors.New("AuthorityMismatch")
	ErrBatchLimitExceeded       = errors.New("BatchLimitExceeded")
	ErrBatchTooSmall            = errors.New("BatchTooSmall")
	ErrBudgetExceeded           = errors.New("BudgetExceeded")
	ErrDeadlineBeyondAuthority  = errors.New("DeadlineBeyondAuthority")
	ErrExpired                  = errors.New("Expired")
	ErrLengthMismatch           = errors.New("LengthMismatch")
	ErrNonCanonicalFrame        = errors.New("NonCanonicalFrame")
	ErrReplay                   = errors.New("Replay")
	ErrReplayConflict           = errors.New("ReplayConflict")
	ErrReplayStoreUnavailable   = errors.New("ReplayStoreUnavailable")
	ErrTransportPayloadTooLarge = errors.New("TransportPayloadTooLarge")
	ErrUnsupportedFrame         = errors.New("UnsupportedFrame")
	ErrZeroDigest               = errors.New("ZeroDigest")
	ErrZeroIdentity             = errors.New("ZeroIdentity")
	ErrZeroKey                  = errors.New("ZeroKey")
	ErrZeroOperationField       = errors.New("ZeroOperationField")
)

var (
	magic                = [4]byte{'N', 'D', 'B', 'I'}
	contextDomain        = []byte("ndabi/wire/v1/context")
	frameKeyDomain       = []byte("ndabi/wire/v1/session-key")
	receiptKeyDomain     = []byte("ndabi/wire/v1/receipt-key")
	singleFrameDomain    = []byte("ndabi/wire/v1/frame")
	batchFrameDomain     = []byte("ndabi/wire/v1/batch-frame")
	receiptDomain        = []byte("ndabi/wire/v1/receipt")
	transportKeyDomain   = []byte("ndabi/wire/v2/transport-key")
	transportFrameDomain = []byte("ndabi/wire/v2/transport-frame")
	registerBundleDomain = []byte("ndabi/wire/v1/register-operand-bundle")
	removeBundleDomain   = []byte("ndabi/wire/v1/drop-operand-bundle")
)

// Authority contains the public context and the shared test authority.
// A production implementation must obtain the root key through protected custody.
type Authority struct {
	RootKey          [32]byte
	Generation       uint64
	Session          uint64
	ExpiresUnixUS    uint64
	Tenant           [16]byte
	Principal        [16]byte
	Purpose          uint32
	CapabilityDigest [32]byte
	Engine           uint32
	Profile          uint32
	SchemaDigest     [32]byte
	PolicyDigest     [32]byte
	PlanDigest       [32]byte
}

// Limits bounds result bytes and rows before backend execution.
type Limits struct {
	MaximumResultBytes uint32
	MaximumRows        uint32
}

// Operation identifies one registered plan and its result shape.
type Operation struct {
	Opcode      uint16
	PlanHandle  uint32
	ResultShape uint32
}

// Item contains one fixed-width operand tuple.
type Item struct {
	First  int64
	Second int64
	Third  uint32
}

// Pending is authenticated and admitted work. Commit its nonce only after successful execution.
type Pending struct {
	nonce          uint64
	deadlineUnixUS uint64
	resultBudget   uint32
	rowBudget      uint32
	operation      Operation
	items          []Item
	replayKey      string
	previousNonce  uint64
	acceptedNonce  uint64
}

// TransportAuthority binds transport frames to one provisioned authority.
type TransportAuthority struct {
	RootKey       [32]byte
	Generation    uint64
	Session       uint64
	ExpiresUnixUS uint64
	ContextDigest [32]byte
}

// TransportFields contains the authenticated common transport fields.
type TransportFields struct {
	ErrorCode        uint16
	CorrelationNonce uint64
	Sequence         uint32
	Rows             uint32
	ResultShape      uint32
	Features         uint32
	Auxiliary        uint32
	ExecutionReceipt [32]byte
}

// TransportFrame contains one authenticated v0.2 transport message.
type TransportFrame struct {
	Kind    uint8
	Fields  TransportFields
	Payload []byte
}

// BundleControl contains authenticated registration or removal metadata.
type BundleControl struct {
	Kind            uint8
	Nonce           uint64
	DeadlineUnixUS  uint64
	Opcode          uint16
	GraphHandle     uint32
	ResultShape     uint32
	BundleHandle    uint32
	BundleSlotCount uint32
	Values          []byte
	authenticated   bool
	contextDigest   [32]byte
	session         uint64
	generation      uint64
	controlBinding  [32]byte
}

// DecodeBundleControl authenticates one complete bundle registration or removal frame.
func DecodeBundleControl(frame []byte, authority Authority, maximumValueBytes uint32) (BundleControl, error) {
	if isZero(authority.RootKey[:]) {
		return BundleControl{}, ErrZeroKey
	}
	if authority.Generation == 0 || authority.Session == 0 || authority.ExpiresUnixUS == 0 ||
		isZero(authority.Tenant[:]) || isZero(authority.Principal[:]) || authority.Purpose == 0 ||
		authority.Engine == 0 || authority.Profile == 0 {
		return BundleControl{}, ErrZeroIdentity
	}
	if isZero(authority.CapabilityDigest[:]) || isZero(authority.SchemaDigest[:]) ||
		isZero(authority.PolicyDigest[:]) || isZero(authority.PlanDigest[:]) {
		return BundleControl{}, ErrZeroDigest
	}
	if maximumValueBytes > ^uint32(0)-singleFrameBytes {
		return BundleControl{}, ErrTransportPayloadTooLarge
	}
	if len(frame) < singleFrameBytes || uint64(len(frame)) > uint64(singleFrameBytes)+uint64(maximumValueBytes) {
		return BundleControl{}, ErrLengthMismatch
	}
	var domain []byte
	switch frame[6] {
	case 5:
		domain = registerBundleDomain
	case 7:
		domain = removeBundleDomain
	default:
		return BundleControl{}, ErrUnsupportedFrame
	}
	context := ContextDigest(authority)
	frameKey := deriveKey(authority.RootKey, frameKeyDomain, authority, context)
	tagOffset := len(frame) - tagBytes
	expectedTag := keyedDigest(frameKey, domain, frame[:tagOffset])
	authenticated := subtle.ConstantTimeCompare(expectedTag[:], frame[tagOffset:]) == 1
	clear(frameKey[:])
	clear(expectedTag[:])
	if !authenticated {
		return BundleControl{}, ErrAuthenticationFailed
	}
	if string(frame[0:4]) != string(magic[:]) || frame[4] != 1 || frame[5] != 0 || frame[7] != 1 {
		return BundleControl{}, ErrUnsupportedFrame
	}
	if binary.LittleEndian.Uint16(frame[8:10]) != 0 ||
		binary.LittleEndian.Uint32(frame[12:16]) != uint32(len(frame)) {
		return BundleControl{}, ErrNonCanonicalFrame
	}
	if binary.LittleEndian.Uint64(frame[16:24]) != authority.Session ||
		binary.LittleEndian.Uint64(frame[24:32]) != authority.Generation ||
		subtle.ConstantTimeCompare(frame[96:128], context[:]) != 1 {
		return BundleControl{}, ErrAuthorityMismatch
	}
	control := BundleControl{
		Kind:           frame[6],
		Nonce:          binary.LittleEndian.Uint64(frame[32:40]),
		DeadlineUnixUS: binary.LittleEndian.Uint64(frame[40:48]),
		Opcode:         binary.LittleEndian.Uint16(frame[10:12]),
		GraphHandle:    binary.LittleEndian.Uint32(frame[56:60]),
		ResultShape:    binary.LittleEndian.Uint32(frame[60:64]),
		BundleHandle:   binary.LittleEndian.Uint32(frame[64:68]),
		authenticated:  true,
		contextDigest:  context,
		session:        authority.Session,
		generation:     authority.Generation,
	}
	if control.Nonce == 0 || control.Opcode == 0 || control.GraphHandle == 0 ||
		control.ResultShape == 0 || control.BundleHandle == 0 {
		return BundleControl{}, ErrZeroOperationField
	}
	if control.DeadlineUnixUS == 0 || control.DeadlineUnixUS > authority.ExpiresUnixUS {
		return BundleControl{}, ErrDeadlineBeyondAuthority
	}
	if control.Kind == 5 {
		if !allZero(frame[68:96]) || binary.LittleEndian.Uint32(frame[48:52]) != uint32(tagOffset-128) {
			return BundleControl{}, ErrNonCanonicalFrame
		}
		control.BundleSlotCount = binary.LittleEndian.Uint32(frame[52:56])
		control.Values = append([]byte(nil), frame[128:tagOffset]...)
		control.controlBinding = bundleControlBinding(control)
		return control, nil
	}
	if len(frame) != singleFrameBytes || !allZero(frame[48:56]) || !allZero(frame[68:96]) {
		return BundleControl{}, ErrNonCanonicalFrame
	}
	control.controlBinding = bundleControlBinding(control)
	return control, nil
}

func bundleControlBinding(control BundleControl) [32]byte {
	hasher := blake3.New()
	write(hasher, []byte{control.Kind})
	writeU64(hasher, control.Nonce)
	writeU64(hasher, control.DeadlineUnixUS)
	var opcode [2]byte
	binary.LittleEndian.PutUint16(opcode[:], control.Opcode)
	write(hasher, opcode[:])
	writeU32(hasher, control.GraphHandle)
	writeU32(hasher, control.ResultShape)
	writeU32(hasher, control.BundleHandle)
	writeU32(hasher, control.BundleSlotCount)
	write(hasher, control.Values)
	return digest(hasher)
}

// Nonce returns the authenticated replay nonce.
func (pending Pending) Nonce() uint64 { return pending.nonce }

// DeadlineUnixUS returns the authenticated execution deadline.
func (pending Pending) DeadlineUnixUS() uint64 { return pending.deadlineUnixUS }

// ResultBudget returns the authenticated result-byte limit.
func (pending Pending) ResultBudget() uint32 { return pending.resultBudget }

// RowBudget returns the authenticated row limit.
func (pending Pending) RowBudget() uint32 { return pending.rowBudget }

// Operation returns the authenticated operation by value.
func (pending Pending) Operation() Operation { return pending.operation }

// Items returns a copy of the authenticated operands.
func (pending Pending) Items() []Item { return append([]Item(nil), pending.items...) }

// ReplayStore stores the last accepted nonce for each authority generation.
type ReplayStore struct {
	mu     sync.Mutex
	nonces map[string]uint64
}

// NewReplayStore creates an empty process-local replay store.
func NewReplayStore() *ReplayStore {
	return &ReplayStore{nonces: make(map[string]uint64)}
}

// Commit advances replay state after successful backend execution.
func (store *ReplayStore) Commit(pending Pending) error {
	if store == nil {
		return ErrReplayStoreUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.nonces == nil {
		store.nonces = make(map[string]uint64)
	}
	if store.nonces[pending.replayKey] != pending.previousNonce ||
		pending.previousNonce == ^uint64(0) ||
		pending.acceptedNonce != pending.previousNonce+1 {
		return ErrReplayConflict
	}
	store.nonces[pending.replayKey] = pending.acceptedNonce
	return nil
}

// ContextDigest derives the authority context identity.
func ContextDigest(authority Authority) [32]byte {
	hasher := blake3.New()
	write(hasher, contextDomain)
	write(hasher, authority.Tenant[:])
	write(hasher, authority.Principal[:])
	writeU32(hasher, authority.Purpose)
	write(hasher, authority.CapabilityDigest[:])
	writeU32(hasher, authority.Engine)
	writeU32(hasher, authority.Profile)
	write(hasher, authority.SchemaDigest[:])
	write(hasher, authority.PolicyDigest[:])
	write(hasher, authority.PlanDigest[:])
	return digest(hasher)
}

// Verify authenticates a complete frame before it interprets semantic fields.
func Verify(frame []byte, authority Authority, limits Limits, replay *ReplayStore, nowUnixUS uint64) (Pending, error) {
	if replay == nil {
		return Pending{}, ErrReplayStoreUnavailable
	}
	if isZero(authority.RootKey[:]) {
		return Pending{}, ErrZeroKey
	}
	if authority.Generation == 0 || authority.Session == 0 || authority.ExpiresUnixUS == 0 ||
		isZero(authority.Tenant[:]) || isZero(authority.Principal[:]) || authority.Purpose == 0 ||
		authority.Engine == 0 || authority.Profile == 0 {
		return Pending{}, ErrZeroIdentity
	}
	if isZero(authority.CapabilityDigest[:]) || isZero(authority.SchemaDigest[:]) ||
		isZero(authority.PolicyDigest[:]) || isZero(authority.PlanDigest[:]) {
		return Pending{}, ErrZeroDigest
	}
	var domain []byte
	switch {
	case len(frame) == singleFrameBytes:
		domain = singleFrameDomain
	case len(frame) >= singleFrameBytes+2*batchOperandBytes &&
		len(frame) <= singleFrameBytes+maxBatchOperations*batchOperandBytes:
		domain = batchFrameDomain
	default:
		return Pending{}, ErrLengthMismatch
	}

	contextDigest := ContextDigest(authority)
	frameKey := deriveKey(authority.RootKey, frameKeyDomain, authority, contextDigest)
	tagOffset := len(frame) - tagBytes
	expectedTag := keyedDigest(frameKey, domain, frame[:tagOffset])
	authenticated := subtle.ConstantTimeCompare(expectedTag[:], frame[tagOffset:]) == 1
	clear(frameKey[:])
	clear(expectedTag[:])
	if !authenticated {
		return Pending{}, ErrAuthenticationFailed
	}

	if string(frame[0:4]) != string(magic[:]) || frame[4] != 1 || frame[5] != 0 || frame[7] != 1 {
		return Pending{}, ErrUnsupportedFrame
	}
	pending := Pending{
		nonce:          binary.LittleEndian.Uint64(frame[32:40]),
		deadlineUnixUS: binary.LittleEndian.Uint64(frame[40:48]),
		resultBudget:   binary.LittleEndian.Uint32(frame[48:52]),
		rowBudget:      binary.LittleEndian.Uint32(frame[52:56]),
		operation: Operation{
			Opcode:      binary.LittleEndian.Uint16(frame[10:12]),
			PlanHandle:  binary.LittleEndian.Uint32(frame[56:60]),
			ResultShape: binary.LittleEndian.Uint32(frame[60:64]),
		},
		replayKey: replayKey(authority, contextDigest),
	}
	pending.acceptedNonce = pending.nonce
	batchCount := uint32(0)

	switch frame[6] {
	case 1:
		if len(frame) != singleFrameBytes {
			return Pending{}, ErrUnsupportedFrame
		}
		if binary.LittleEndian.Uint16(frame[8:10]) != 0 ||
			binary.LittleEndian.Uint32(frame[12:16]) != singleFrameBytes ||
			!allZero(frame[84:96]) {
			return Pending{}, ErrNonCanonicalFrame
		}
		pending.items = []Item{{
			First:  int64(binary.LittleEndian.Uint64(frame[64:72])),
			Second: int64(binary.LittleEndian.Uint64(frame[72:80])),
			Third:  binary.LittleEndian.Uint32(frame[80:84]),
		}}
	case 2:
		if len(frame) == singleFrameBytes {
			return Pending{}, ErrUnsupportedFrame
		}
		if binary.LittleEndian.Uint16(frame[8:10]) != 0 ||
			binary.LittleEndian.Uint32(frame[12:16]) != uint32(len(frame)) ||
			binary.LittleEndian.Uint32(frame[68:72]) != batchOperandBytes ||
			!allZero(frame[76:96]) {
			return Pending{}, ErrNonCanonicalFrame
		}
		batchCount = binary.LittleEndian.Uint32(frame[64:68])
	default:
		return Pending{}, ErrUnsupportedFrame
	}

	if binary.LittleEndian.Uint64(frame[16:24]) != authority.Session ||
		binary.LittleEndian.Uint64(frame[24:32]) != authority.Generation ||
		subtle.ConstantTimeCompare(frame[96:128], contextDigest[:]) != 1 {
		return Pending{}, ErrAuthorityMismatch
	}
	if frame[6] == 2 {
		if batchCount < 2 {
			return Pending{}, ErrBatchTooSmall
		}
		if batchCount > maxBatchOperations {
			return Pending{}, ErrBatchLimitExceeded
		}
		payloadBytes := batchCount * batchOperandBytes
		if binary.LittleEndian.Uint32(frame[72:76]) != payloadBytes ||
			singleFrameBytes+int(payloadBytes) != len(frame) {
			return Pending{}, ErrNonCanonicalFrame
		}
		pending.items = make([]Item, 0, batchCount)
		for offset := batchHeaderBytes; offset < tagOffset; offset += batchOperandBytes {
			pending.items = append(pending.items, Item{
				First:  int64(binary.LittleEndian.Uint64(frame[offset : offset+8])),
				Second: int64(binary.LittleEndian.Uint64(frame[offset+8 : offset+16])),
				Third:  binary.LittleEndian.Uint32(frame[offset+16 : offset+20]),
			})
		}
	}
	if pending.deadlineUnixUS <= nowUnixUS || pending.deadlineUnixUS > authority.ExpiresUnixUS {
		return Pending{}, ErrExpired
	}
	if pending.resultBudget == 0 || pending.resultBudget > limits.MaximumResultBytes ||
		pending.rowBudget == 0 || pending.rowBudget > limits.MaximumRows {
		return Pending{}, ErrBudgetExceeded
	}
	pending.previousNonce = replay.lastNonce(pending.replayKey)
	if pending.previousNonce == ^uint64(0) || pending.nonce != pending.previousNonce+1 {
		return Pending{}, ErrReplay
	}
	if pending.operation.Opcode == 0 || pending.operation.PlanHandle == 0 || pending.operation.ResultShape == 0 {
		return Pending{}, ErrZeroOperationField
	}
	return pending, nil
}

// Receipt derives the symmetric execution receipt for exact result bytes.
func Receipt(frame []byte, authority Authority, nonce uint64, rows uint32, result []byte) [32]byte {
	contextDigest := ContextDigest(authority)
	receiptKey := deriveKey(authority.RootKey, receiptKeyDomain, authority, contextDigest)
	frameDigest := blake3.Sum256(frame)
	hasher, err := blake3.NewKeyed(receiptKey[:])
	if err != nil {
		panic("the fixed receipt key has an invalid length")
	}
	write(hasher, receiptDomain)
	write(hasher, contextDigest[:])
	write(hasher, frameDigest[:])
	writeU64(hasher, nonce)
	writeU32(hasher, rows)
	write(hasher, result)
	output := digest(hasher)
	clear(receiptKey[:])
	return output
}

// DecodeTransport authenticates one complete v0.2 transport frame before semantic interpretation.
func DecodeTransport(
	frame []byte,
	authority TransportAuthority,
	direction uint8,
	maximumPayloadBytes uint32,
	nowUnixUS uint64,
) (TransportFrame, error) {
	if isZero(authority.RootKey[:]) {
		return TransportFrame{}, ErrZeroKey
	}
	if authority.Generation == 0 || authority.Session == 0 || authority.ExpiresUnixUS == 0 ||
		isZero(authority.ContextDigest[:]) {
		return TransportFrame{}, ErrZeroIdentity
	}
	if direction != 1 && direction != 2 {
		return TransportFrame{}, ErrUnsupportedFrame
	}
	if maximumPayloadBytes > ^uint32(0)-transportMinBytes {
		return TransportFrame{}, ErrTransportPayloadTooLarge
	}
	if len(frame) < transportMinBytes || uint64(len(frame)) > uint64(transportMinBytes)+uint64(maximumPayloadBytes) {
		return TransportFrame{}, ErrLengthMismatch
	}

	transportKey := deriveTransportKey(authority)
	tagOffset := len(frame) - tagBytes
	expectedTag := transportTag(transportKey, direction, frame[:tagOffset])
	authenticated := subtle.ConstantTimeCompare(expectedTag[:], frame[tagOffset:]) == 1
	clear(transportKey[:])
	clear(expectedTag[:])
	if !authenticated {
		return TransportFrame{}, ErrAuthenticationFailed
	}
	if string(frame[0:4]) != "NDBT" || frame[4] != 2 || frame[5] != 0 || frame[7] != 0 {
		return TransportFrame{}, ErrUnsupportedFrame
	}
	kind := frame[6]
	if kind < 1 || kind > 10 {
		return TransportFrame{}, ErrUnsupportedFrame
	}
	payloadBytes := binary.LittleEndian.Uint32(frame[44:48])
	if binary.LittleEndian.Uint16(frame[10:12]) != 0 ||
		binary.LittleEndian.Uint32(frame[12:16]) != uint32(len(frame)) ||
		uint64(transportMinBytes)+uint64(payloadBytes) != uint64(len(frame)) {
		return TransportFrame{}, ErrNonCanonicalFrame
	}
	if binary.LittleEndian.Uint64(frame[16:24]) != authority.Session ||
		binary.LittleEndian.Uint64(frame[24:32]) != authority.Generation ||
		subtle.ConstantTimeCompare(frame[64:96], authority.ContextDigest[:]) != 1 {
		return TransportFrame{}, ErrAuthorityMismatch
	}
	if nowUnixUS >= authority.ExpiresUnixUS {
		return TransportFrame{}, ErrExpired
	}
	fields := TransportFields{
		ErrorCode:        binary.LittleEndian.Uint16(frame[8:10]),
		CorrelationNonce: binary.LittleEndian.Uint64(frame[32:40]),
		Sequence:         binary.LittleEndian.Uint32(frame[40:44]),
		Rows:             binary.LittleEndian.Uint32(frame[48:52]),
		ResultShape:      binary.LittleEndian.Uint32(frame[52:56]),
		Features:         binary.LittleEndian.Uint32(frame[56:60]),
		Auxiliary:        binary.LittleEndian.Uint32(frame[60:64]),
	}
	copy(fields.ExecutionReceipt[:], frame[96:128])
	payload := append([]byte(nil), frame[128:tagOffset]...)
	if err := validateTransportSemantics(kind, fields, payload); err != nil {
		return TransportFrame{}, err
	}
	return TransportFrame{Kind: kind, Fields: fields, Payload: payload}, nil
}

func deriveTransportKey(authority TransportAuthority) [32]byte {
	hasher, err := blake3.NewKeyed(authority.RootKey[:])
	if err != nil {
		panic("the fixed transport root key has an invalid length")
	}
	write(hasher, transportKeyDomain)
	writeU64(hasher, authority.Generation)
	writeU64(hasher, authority.Session)
	writeU64(hasher, authority.ExpiresUnixUS)
	write(hasher, authority.ContextDigest[:])
	return digest(hasher)
}

func transportTag(key [32]byte, direction uint8, authenticated []byte) [32]byte {
	hasher, err := blake3.NewKeyed(key[:])
	if err != nil {
		panic("the fixed transport key has an invalid length")
	}
	write(hasher, transportFrameDomain)
	write(hasher, []byte{direction})
	write(hasher, authenticated)
	return digest(hasher)
}

func validateTransportSemantics(kind uint8, fields TransportFields, payload []byte) error {
	receiptIsZero := isZero(fields.ExecutionReceipt[:])
	terminalZero := fields.Features == 0 && fields.Auxiliary == 0
	switch kind {
	case 1:
		if fields.ErrorCode != 0 || fields.CorrelationNonce != 0 || fields.Sequence != 0 || fields.Rows != 0 ||
			fields.ResultShape != 0 || fields.Auxiliary < uint32(transportMinBytes+len(payload)) || !receiptIsZero || len(payload) != 8 {
			return ErrNonCanonicalFrame
		}
		minimumMajor := binary.LittleEndian.Uint16(payload[0:2])
		maximumMajor := binary.LittleEndian.Uint16(payload[2:4])
		maximumChunk := binary.LittleEndian.Uint32(payload[4:8])
		if minimumMajor == 0 || maximumMajor < minimumMajor || maximumChunk == 0 ||
			maximumChunk > fields.Auxiliary-transportMinBytes {
			return ErrNonCanonicalFrame
		}
	case 2:
		if fields.ErrorCode != 0 || fields.CorrelationNonce != 0 || fields.Sequence != 0 || fields.Rows != 0 ||
			fields.ResultShape != 0 || fields.Auxiliary < uint32(transportMinBytes+len(payload)) || !receiptIsZero || len(payload) != 8 {
			return ErrNonCanonicalFrame
		}
		maximumChunk := binary.LittleEndian.Uint32(payload[4:8])
		if binary.LittleEndian.Uint16(payload[0:2]) != 2 || binary.LittleEndian.Uint16(payload[2:4]) != 0 ||
			maximumChunk == 0 || maximumChunk > fields.Auxiliary-transportMinBytes {
			return ErrNonCanonicalFrame
		}
	case 3:
		if fields.ErrorCode != 0 || fields.CorrelationNonce == 0 || fields.Sequence != 0 || fields.ResultShape == 0 ||
			!terminalZero || receiptIsZero {
			return ErrNonCanonicalFrame
		}
	case 4:
		if fields.ErrorCode < 1 || fields.ErrorCode > maximumErrorCode || fields.Sequence != 0 || fields.Rows != 0 ||
			fields.ResultShape != 0 || !terminalZero || !receiptIsZero || len(payload) != 0 {
			return ErrNonCanonicalFrame
		}
	case 5:
		if fields.ErrorCode != 0 || fields.CorrelationNonce == 0 || fields.Sequence != 0 || fields.Rows != 0 ||
			fields.ResultShape != 0 || !terminalZero || !receiptIsZero || len(payload) != 0 {
			return ErrNonCanonicalFrame
		}
	case 6:
		if fields.ErrorCode != 0 || fields.CorrelationNonce == 0 || fields.Sequence != 0 || fields.ResultShape == 0 ||
			!terminalZero || !receiptIsZero || len(payload) != 0 {
			return ErrNonCanonicalFrame
		}
	case 7:
		if fields.ErrorCode != 0 || fields.CorrelationNonce == 0 || fields.Sequence == 0 || fields.Rows != 0 ||
			fields.ResultShape != 0 || !terminalZero || !receiptIsZero || len(payload) == 0 {
			return ErrNonCanonicalFrame
		}
	case 8:
		if fields.ErrorCode != 0 || fields.CorrelationNonce == 0 || fields.Sequence == 0 || fields.ResultShape == 0 ||
			!terminalZero || receiptIsZero || len(payload) != 0 {
			return ErrNonCanonicalFrame
		}
	case 9:
		if fields.ErrorCode != 0 || fields.CorrelationNonce == 0 || fields.Sequence != 0 || fields.Rows != 0 ||
			fields.ResultShape == 0 || !terminalZero || !receiptIsZero || len(payload) != 48 {
			return ErrNonCanonicalFrame
		}
		if binary.LittleEndian.Uint32(payload[0:4]) == 0 || binary.LittleEndian.Uint32(payload[4:8]) == 0 ||
			binary.LittleEndian.Uint64(payload[8:16]) == 0 || isZero(payload[16:48]) {
			return ErrNonCanonicalFrame
		}
	case 10:
		if fields.ErrorCode != 0 || fields.CorrelationNonce == 0 || fields.Sequence != 0 || fields.Rows != 0 ||
			fields.ResultShape == 0 || !terminalZero || !receiptIsZero || len(payload) != 8 {
			return ErrNonCanonicalFrame
		}
		if binary.LittleEndian.Uint32(payload[0:4]) == 0 || binary.LittleEndian.Uint32(payload[4:8]) == 0 {
			return ErrNonCanonicalFrame
		}
	}
	return nil
}

func deriveKey(root [32]byte, domain []byte, authority Authority, context [32]byte) [32]byte {
	hasher, err := blake3.NewKeyed(root[:])
	if err != nil {
		panic("the fixed root key has an invalid length")
	}
	write(hasher, domain)
	writeU64(hasher, authority.Generation)
	writeU64(hasher, authority.Session)
	writeU64(hasher, authority.ExpiresUnixUS)
	write(hasher, context[:])
	return digest(hasher)
}

func keyedDigest(key [32]byte, domain []byte, content []byte) [32]byte {
	hasher, err := blake3.NewKeyed(key[:])
	if err != nil {
		panic("the fixed frame key has an invalid length")
	}
	write(hasher, domain)
	write(hasher, content)
	return digest(hasher)
}

func replayKey(authority Authority, context [32]byte) string {
	buffer := make([]byte, 48)
	copy(buffer, context[:])
	binary.LittleEndian.PutUint64(buffer[32:40], authority.Session)
	binary.LittleEndian.PutUint64(buffer[40:48], authority.Generation)
	return string(buffer)
}

func (store *ReplayStore) lastNonce(key string) uint64 {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.nonces[key]
}

func allZero(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}

func isZero(value []byte) bool {
	return allZero(value)
}

type byteWriter interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func write(writer byteWriter, value []byte) {
	if _, err := writer.Write(value); err != nil {
		panic("the BLAKE3 writer refused an in-memory write")
	}
}

func writeU32(writer byteWriter, value uint32) {
	var buffer [4]byte
	binary.LittleEndian.PutUint32(buffer[:], value)
	write(writer, buffer[:])
}

func writeU64(writer byteWriter, value uint64) {
	var buffer [8]byte
	binary.LittleEndian.PutUint64(buffer[:], value)
	write(writer, buffer[:])
}

func digest(writer byteWriter) [32]byte {
	var output [32]byte
	copy(output[:], writer.Sum(nil))
	return output
}
