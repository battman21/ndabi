// Package ndabi independently decodes the NDABI v0.1 RFC-candidate frames.
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
)

var (
	ErrAuthenticationFailed   = errors.New("AuthenticationFailed")
	ErrAuthorityMismatch      = errors.New("AuthorityMismatch")
	ErrBatchLimitExceeded     = errors.New("BatchLimitExceeded")
	ErrBatchTooSmall          = errors.New("BatchTooSmall")
	ErrBudgetExceeded         = errors.New("BudgetExceeded")
	ErrExpired                = errors.New("Expired")
	ErrLengthMismatch         = errors.New("LengthMismatch")
	ErrNonCanonicalFrame      = errors.New("NonCanonicalFrame")
	ErrReplay                 = errors.New("Replay")
	ErrReplayConflict         = errors.New("ReplayConflict")
	ErrReplayStoreUnavailable = errors.New("ReplayStoreUnavailable")
	ErrUnsupportedFrame       = errors.New("UnsupportedFrame")
	ErrZeroDigest             = errors.New("ZeroDigest")
	ErrZeroIdentity           = errors.New("ZeroIdentity")
	ErrZeroKey                = errors.New("ZeroKey")
	ErrZeroOperationField     = errors.New("ZeroOperationField")
)

var (
	magic             = [4]byte{'N', 'D', 'B', 'I'}
	contextDomain     = []byte("ndabi/wire/v1/context")
	frameKeyDomain    = []byte("ndabi/wire/v1/session-key")
	receiptKeyDomain  = []byte("ndabi/wire/v1/receipt-key")
	singleFrameDomain = []byte("ndabi/wire/v1/frame")
	batchFrameDomain  = []byte("ndabi/wire/v1/batch-frame")
	receiptDomain     = []byte("ndabi/wire/v1/receipt")
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
	Nonce          uint64
	PreviousNonce  uint64
	DeadlineUnixUS uint64
	ResultBudget   uint32
	RowBudget      uint32
	Operation      Operation
	Items          []Item
	replayKey      string
}

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
	if store.nonces[pending.replayKey] != pending.PreviousNonce ||
		pending.PreviousNonce == ^uint64(0) ||
		pending.Nonce != pending.PreviousNonce+1 {
		return ErrReplayConflict
	}
	store.nonces[pending.replayKey] = pending.Nonce
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
		Nonce:          binary.LittleEndian.Uint64(frame[32:40]),
		DeadlineUnixUS: binary.LittleEndian.Uint64(frame[40:48]),
		ResultBudget:   binary.LittleEndian.Uint32(frame[48:52]),
		RowBudget:      binary.LittleEndian.Uint32(frame[52:56]),
		Operation: Operation{
			Opcode:      binary.LittleEndian.Uint16(frame[10:12]),
			PlanHandle:  binary.LittleEndian.Uint32(frame[56:60]),
			ResultShape: binary.LittleEndian.Uint32(frame[60:64]),
		},
		replayKey: replayKey(authority, contextDigest),
	}
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
		pending.Items = []Item{{
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
		pending.Items = make([]Item, 0, batchCount)
		for offset := batchHeaderBytes; offset < tagOffset; offset += batchOperandBytes {
			pending.Items = append(pending.Items, Item{
				First:  int64(binary.LittleEndian.Uint64(frame[offset : offset+8])),
				Second: int64(binary.LittleEndian.Uint64(frame[offset+8 : offset+16])),
				Third:  binary.LittleEndian.Uint32(frame[offset+16 : offset+20]),
			})
		}
	}
	if pending.DeadlineUnixUS <= nowUnixUS || pending.DeadlineUnixUS > authority.ExpiresUnixUS {
		return Pending{}, ErrExpired
	}
	if pending.ResultBudget == 0 || pending.ResultBudget > limits.MaximumResultBytes ||
		pending.RowBudget == 0 || pending.RowBudget > limits.MaximumRows {
		return Pending{}, ErrBudgetExceeded
	}
	pending.PreviousNonce = replay.lastNonce(pending.replayKey)
	if pending.PreviousNonce == ^uint64(0) || pending.Nonce != pending.PreviousNonce+1 {
		return Pending{}, ErrReplay
	}
	if pending.Operation.Opcode == 0 || pending.Operation.PlanHandle == 0 || pending.Operation.ResultShape == 0 {
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
