import { blake3 } from "@noble/hashes/blake3.js";

const SINGLE_FRAME_BYTES = 160;
const BATCH_HEADER_BYTES = 128;
const TAG_BYTES = 32;
const BATCH_OPERAND_BYTES = 20;
const MAX_BATCH_OPERATIONS = 4096;
const TRANSPORT_MIN_FRAME_BYTES = 160;
const MAXIMUM_ERROR_CODE = 10;
const MAXIMUM_U32 = 0xffff_ffff;
const MAXIMUM_U64 = 0xffff_ffff_ffff_ffffn;
const textEncoder = new TextEncoder();

const CONTEXT_DOMAIN = textEncoder.encode("ndabi/wire/v1/context");
const FRAME_KEY_DOMAIN = textEncoder.encode("ndabi/wire/v1/session-key");
const RECEIPT_KEY_DOMAIN = textEncoder.encode("ndabi/wire/v1/receipt-key");
const SINGLE_FRAME_DOMAIN = textEncoder.encode("ndabi/wire/v1/frame");
const BATCH_FRAME_DOMAIN = textEncoder.encode("ndabi/wire/v1/batch-frame");
const RECEIPT_DOMAIN = textEncoder.encode("ndabi/wire/v1/receipt");
const TRANSPORT_KEY_DOMAIN = textEncoder.encode("ndabi/wire/v2/transport-key");
const TRANSPORT_FRAME_DOMAIN = textEncoder.encode("ndabi/wire/v2/transport-frame");

export interface Authority {
  rootKey: Uint8Array;
  generation: bigint;
  session: bigint;
  expiresUnixUS: bigint;
  tenant: Uint8Array;
  principal: Uint8Array;
  purpose: number;
  capabilityDigest: Uint8Array;
  engine: number;
  profile: number;
  schemaDigest: Uint8Array;
  policyDigest: Uint8Array;
  planDigest: Uint8Array;
}

export interface Limits {
  maximumResultBytes: number;
  maximumRows: number;
}

export interface Operation {
  readonly opcode: number;
  readonly planHandle: number;
  readonly resultShape: number;
}

export interface Item {
  readonly first: bigint;
  readonly second: bigint;
  readonly third: number;
}

export interface Pending {
  readonly nonce: bigint;
  readonly deadlineUnixUS: bigint;
  readonly resultBudget: number;
  readonly rowBudget: number;
  readonly operation: Operation;
  readonly items: readonly Item[];
}

export interface TransportAuthority {
  rootKey: Uint8Array;
  generation: bigint;
  session: bigint;
  expiresUnixUS: bigint;
  contextDigest: Uint8Array;
}

export type TransportDirection = 1 | 2;

export interface TransportFields {
  readonly errorCode: number;
  readonly correlationNonce: bigint;
  readonly sequence: number;
  readonly rows: number;
  readonly resultShape: number;
  readonly features: number;
  readonly auxiliary: number;
  readonly executionReceipt: Uint8Array;
}

export interface TransportFrame {
  readonly kind: number;
  readonly fields: TransportFields;
  readonly payload: Uint8Array;
}

interface Admission {
  replayKey: string;
  previousNonce: bigint;
  acceptedNonce: bigint;
}

const admissions = new WeakMap<Pending, Admission>();

export function assertVerifiedPending(pending: Pending): void {
  if (!admissions.has(pending)) refuse("InvalidPending");
}

export class ReplayStore {
  readonly #nonces = new Map<string, bigint>();

  lastNonce(key: string): bigint {
    return this.#nonces.get(key) ?? 0n;
  }

  commit(pending: Pending): void {
    const admission = admissions.get(pending);
    if (admission === undefined) refuse("InvalidPending");
    const current = this.lastNonce(admission.replayKey);
    if (current !== admission.previousNonce || current === 0xffffffffffffffffn || admission.acceptedNonce !== current + 1n) {
      refuse("ReplayConflict");
    }
    this.#nonces.set(admission.replayKey, admission.acceptedNonce);
  }
}

export function contextDigest(authority: Authority): Uint8Array {
  return blake3(
    concatenate(
      CONTEXT_DOMAIN,
      authority.tenant,
      authority.principal,
      encodeU32(authority.purpose),
      authority.capabilityDigest,
      encodeU32(authority.engine),
      encodeU32(authority.profile),
      authority.schemaDigest,
      authority.policyDigest,
      authority.planDigest,
    ),
  );
}

export function verify(
  frame: Uint8Array,
  authority: Authority,
  limits: Limits,
  replay: ReplayStore,
  nowUnixUS: bigint,
): Pending {
  validateAuthority(authority);
  if (!(replay instanceof ReplayStore)) refuse("ReplayStoreUnavailable");

  let frameDomain: Uint8Array;
  if (frame.length === SINGLE_FRAME_BYTES) {
    frameDomain = SINGLE_FRAME_DOMAIN;
  } else if (
    frame.length >= SINGLE_FRAME_BYTES + 2 * BATCH_OPERAND_BYTES &&
    frame.length <= SINGLE_FRAME_BYTES + MAX_BATCH_OPERATIONS * BATCH_OPERAND_BYTES
  ) {
    frameDomain = BATCH_FRAME_DOMAIN;
  } else {
    refuse("LengthMismatch");
  }

  const context = contextDigest(authority);
  const frameKey = deriveKey(authority.rootKey, FRAME_KEY_DOMAIN, authority, context);
  const tagOffset = frame.length - TAG_BYTES;
  const expectedTag = blake3(concatenate(frameDomain, frame.subarray(0, tagOffset)), { key: frameKey });
  const authenticated = constantTimeEqual(expectedTag, frame.subarray(tagOffset));
  frameKey.fill(0);
  expectedTag.fill(0);
  if (!authenticated) refuse("AuthenticationFailed");

  if (
    frame[0] !== 0x4e ||
    frame[1] !== 0x44 ||
    frame[2] !== 0x42 ||
    frame[3] !== 0x49 ||
    frame[4] !== 1 ||
    frame[5] !== 0 ||
    frame[7] !== 1
  ) {
    refuse("UnsupportedFrame");
  }

  const view = dataView(frame);
  const operation: Operation = {
    opcode: view.getUint16(10, true),
    planHandle: view.getUint32(56, true),
    resultShape: view.getUint32(60, true),
  };
  const pending = {
    nonce: view.getBigUint64(32, true),
    deadlineUnixUS: view.getBigUint64(40, true),
    resultBudget: view.getUint32(48, true),
    rowBudget: view.getUint32(52, true),
    operation,
    items: [] as Item[],
  };
  const replayKey = replayIdentity(authority, context);

  let batchCount = 0;
  if (frame[6] === 1) {
    if (frame.length !== SINGLE_FRAME_BYTES) refuse("UnsupportedFrame");
    if (view.getUint16(8, true) !== 0 || view.getUint32(12, true) !== SINGLE_FRAME_BYTES || !allZero(frame.subarray(84, 96))) {
      refuse("NonCanonicalFrame");
    }
    pending.items.push({
      first: view.getBigInt64(64, true),
      second: view.getBigInt64(72, true),
      third: view.getUint32(80, true),
    });
  } else if (frame[6] === 2) {
    if (frame.length === SINGLE_FRAME_BYTES) refuse("UnsupportedFrame");
    if (
      view.getUint16(8, true) !== 0 ||
      view.getUint32(12, true) !== frame.length ||
      view.getUint32(68, true) !== BATCH_OPERAND_BYTES ||
      !allZero(frame.subarray(76, 96))
    ) {
      refuse("NonCanonicalFrame");
    }
    batchCount = view.getUint32(64, true);
  } else {
    refuse("UnsupportedFrame");
  }

  if (
    view.getBigUint64(16, true) !== authority.session ||
    view.getBigUint64(24, true) !== authority.generation ||
    !constantTimeEqual(frame.subarray(96, 128), context)
  ) {
    refuse("AuthorityMismatch");
  }

  if (frame[6] === 2) {
    if (batchCount < 2) refuse("BatchTooSmall");
    if (batchCount > MAX_BATCH_OPERATIONS) refuse("BatchLimitExceeded");
    const payloadBytes = batchCount * BATCH_OPERAND_BYTES;
    if (view.getUint32(72, true) !== payloadBytes || SINGLE_FRAME_BYTES + payloadBytes !== frame.length) {
      refuse("NonCanonicalFrame");
    }
    for (let offset = BATCH_HEADER_BYTES; offset < tagOffset; offset += BATCH_OPERAND_BYTES) {
      pending.items.push({
        first: view.getBigInt64(offset, true),
        second: view.getBigInt64(offset + 8, true),
        third: view.getUint32(offset + 16, true),
      });
    }
  }

  if (pending.deadlineUnixUS <= nowUnixUS || pending.deadlineUnixUS > authority.expiresUnixUS) refuse("Expired");
  if (
    pending.resultBudget === 0 ||
    pending.resultBudget > limits.maximumResultBytes ||
    pending.rowBudget === 0 ||
    pending.rowBudget > limits.maximumRows
  ) {
    refuse("BudgetExceeded");
  }
  const previousNonce = replay.lastNonce(replayKey);
  if (previousNonce === 0xffffffffffffffffn || pending.nonce !== previousNonce + 1n) refuse("Replay");
  if (operation.opcode === 0 || operation.planHandle === 0 || operation.resultShape === 0) refuse("ZeroOperationField");
  Object.freeze(pending.operation);
  for (const item of pending.items) Object.freeze(item);
  Object.freeze(pending.items);
  Object.freeze(pending);
  admissions.set(pending, { replayKey, previousNonce, acceptedNonce: pending.nonce });
  return pending;
}

export function receipt(
  frame: Uint8Array,
  authority: Authority,
  nonce: bigint,
  rows: number,
  result: Uint8Array,
): Uint8Array {
  const context = contextDigest(authority);
  const receiptKey = deriveKey(authority.rootKey, RECEIPT_KEY_DOMAIN, authority, context);
  const output = blake3(
    concatenate(RECEIPT_DOMAIN, context, blake3(frame), encodeU64(nonce), encodeU32(rows), result),
    { key: receiptKey },
  );
  receiptKey.fill(0);
  return output;
}

export function decodeTransport(
  frame: Uint8Array,
  authority: TransportAuthority,
  direction: TransportDirection,
  maximumPayloadBytes: number,
  nowUnixUS: bigint,
): TransportFrame {
  validateTransportAuthority(authority);
  if (direction !== 1 && direction !== 2) refuse("UnsupportedFrame");
  if (!Number.isInteger(maximumPayloadBytes) || maximumPayloadBytes < 0) refuse("LengthMismatch");
  if (maximumPayloadBytes > MAXIMUM_U32 - TRANSPORT_MIN_FRAME_BYTES) refuse("TransportPayloadTooLarge");
  if (nowUnixUS < 0n || nowUnixUS > MAXIMUM_U64) refuse("InvalidAuthorityWidth");
  if (frame.length < TRANSPORT_MIN_FRAME_BYTES || frame.length > TRANSPORT_MIN_FRAME_BYTES + maximumPayloadBytes) {
    refuse("LengthMismatch");
  }

  const tagOffset = frame.length - TAG_BYTES;
  const transportKey = blake3(
    concatenate(
      TRANSPORT_KEY_DOMAIN,
      encodeU64(authority.generation),
      encodeU64(authority.session),
      encodeU64(authority.expiresUnixUS),
      authority.contextDigest,
    ),
    { key: authority.rootKey },
  );
  const expectedTag = blake3(
    concatenate(TRANSPORT_FRAME_DOMAIN, Uint8Array.of(direction), frame.subarray(0, tagOffset)),
    { key: transportKey },
  );
  const authenticated = constantTimeEqual(expectedTag, frame.subarray(tagOffset));
  transportKey.fill(0);
  expectedTag.fill(0);
  if (!authenticated) refuse("AuthenticationFailed");

  if (
    frame[0] !== 0x4e ||
    frame[1] !== 0x44 ||
    frame[2] !== 0x42 ||
    frame[3] !== 0x54 ||
    frame[4] !== 2 ||
    frame[5] !== 0 ||
    frame[7] !== 0
  ) {
    refuse("UnsupportedFrame");
  }
  const kind = frame[6];
  if (kind < 1 || kind > 10) refuse("UnsupportedFrame");

  const view = dataView(frame);
  const payloadBytes = view.getUint32(44, true);
  if (
    view.getUint16(10, true) !== 0 ||
    view.getUint32(12, true) !== frame.length ||
    TRANSPORT_MIN_FRAME_BYTES + payloadBytes !== frame.length
  ) {
    refuse("NonCanonicalFrame");
  }
  if (
    view.getBigUint64(16, true) !== authority.session ||
    view.getBigUint64(24, true) !== authority.generation ||
    !constantTimeEqual(frame.subarray(64, 96), authority.contextDigest)
  ) {
    refuse("AuthorityMismatch");
  }
  if (nowUnixUS >= authority.expiresUnixUS) refuse("Expired");

  const fields: TransportFields = {
    errorCode: view.getUint16(8, true),
    correlationNonce: view.getBigUint64(32, true),
    sequence: view.getUint32(40, true),
    rows: view.getUint32(48, true),
    resultShape: view.getUint32(52, true),
    features: view.getUint32(56, true),
    auxiliary: view.getUint32(60, true),
    executionReceipt: frame.slice(96, 128),
  };
  const payload = frame.slice(128, tagOffset);
  validateTransportSemantics(kind, fields, payload);
  Object.freeze(fields);
  return Object.freeze({ kind, fields, payload });
}

function validateTransportAuthority(authority: TransportAuthority): void {
  if (authority.rootKey.length !== 32 || authority.contextDigest.length !== 32) refuse("InvalidAuthorityWidth");
  if (
    authority.generation < 0n || authority.generation > MAXIMUM_U64 ||
    authority.session < 0n || authority.session > MAXIMUM_U64 ||
    authority.expiresUnixUS < 0n || authority.expiresUnixUS > MAXIMUM_U64
  ) refuse("InvalidAuthorityWidth");
  if (allZero(authority.rootKey)) refuse("ZeroKey");
  if (
    authority.generation === 0n ||
    authority.session === 0n ||
    authority.expiresUnixUS === 0n ||
    allZero(authority.contextDigest)
  ) {
    refuse("ZeroIdentity");
  }
}

function validateTransportSemantics(kind: number, fields: TransportFields, payload: Uint8Array): void {
  const receiptIsZero = allZero(fields.executionReceipt);
  const commonZero = fields.errorCode === 0;
  const terminalZero = fields.features === 0 && fields.auxiliary === 0;
  if (kind === 1) {
    if (
      !commonZero || fields.correlationNonce !== 0n || fields.sequence !== 0 || fields.rows !== 0 ||
      fields.resultShape !== 0 || fields.auxiliary < TRANSPORT_MIN_FRAME_BYTES + payload.length ||
      !receiptIsZero || payload.length !== 8
    ) refuse("NonCanonicalFrame");
    const view = dataView(payload);
    const minimumMajor = view.getUint16(0, true);
    const maximumMajor = view.getUint16(2, true);
    const maximumChunk = view.getUint32(4, true);
    if (
      minimumMajor === 0 || maximumMajor < minimumMajor || maximumChunk === 0 ||
      maximumChunk > fields.auxiliary - TRANSPORT_MIN_FRAME_BYTES
    ) refuse("NonCanonicalFrame");
    return;
  }
  if (kind === 2) {
    if (
      !commonZero || fields.correlationNonce !== 0n || fields.sequence !== 0 || fields.rows !== 0 ||
      fields.resultShape !== 0 || fields.auxiliary < TRANSPORT_MIN_FRAME_BYTES + payload.length ||
      !receiptIsZero || payload.length !== 8
    ) refuse("NonCanonicalFrame");
    const view = dataView(payload);
    const maximumChunk = view.getUint32(4, true);
    if (
      view.getUint16(0, true) !== 2 || view.getUint16(2, true) !== 0 || maximumChunk === 0 ||
      maximumChunk > fields.auxiliary - TRANSPORT_MIN_FRAME_BYTES
    ) refuse("NonCanonicalFrame");
    return;
  }
  if (kind === 3) {
    if (
      !commonZero || fields.correlationNonce === 0n || fields.sequence !== 0 || fields.resultShape === 0 ||
      !terminalZero || receiptIsZero
    ) refuse("NonCanonicalFrame");
    return;
  }
  if (kind === 4) {
    if (
      fields.errorCode < 1 || fields.errorCode > MAXIMUM_ERROR_CODE || fields.sequence !== 0 ||
      fields.rows !== 0 || fields.resultShape !== 0 || !terminalZero || !receiptIsZero || payload.length !== 0
    ) refuse("NonCanonicalFrame");
    return;
  }
  if (kind === 5) {
    if (
      !commonZero || fields.correlationNonce === 0n || fields.sequence !== 0 || fields.rows !== 0 ||
      fields.resultShape !== 0 || !terminalZero || !receiptIsZero || payload.length !== 0
    ) refuse("NonCanonicalFrame");
    return;
  }
  if (kind === 6) {
    if (
      !commonZero || fields.correlationNonce === 0n || fields.sequence !== 0 || fields.resultShape === 0 ||
      !terminalZero || !receiptIsZero || payload.length !== 0
    ) refuse("NonCanonicalFrame");
    return;
  }
  if (kind === 7) {
    if (
      !commonZero || fields.correlationNonce === 0n || fields.sequence === 0 || fields.rows !== 0 ||
      fields.resultShape !== 0 || !terminalZero || !receiptIsZero || payload.length === 0
    ) refuse("NonCanonicalFrame");
    return;
  }
  if (kind === 8) {
    if (
      !commonZero || fields.correlationNonce === 0n || fields.sequence === 0 || fields.resultShape === 0 ||
      !terminalZero || receiptIsZero || payload.length !== 0
    ) refuse("NonCanonicalFrame");
    return;
  }
  if (kind === 9) {
    if (
      !commonZero || fields.correlationNonce === 0n || fields.sequence !== 0 || fields.rows !== 0 ||
      fields.resultShape === 0 || !terminalZero || !receiptIsZero || payload.length !== 48
    ) refuse("NonCanonicalFrame");
    const view = dataView(payload);
    if (
      view.getUint32(0, true) === 0 || view.getUint32(4, true) === 0 || view.getBigUint64(8, true) === 0n ||
      allZero(payload.subarray(16, 48))
    ) refuse("NonCanonicalFrame");
    return;
  }
  if (
    !commonZero || fields.correlationNonce === 0n || fields.sequence !== 0 || fields.rows !== 0 ||
    fields.resultShape === 0 || !terminalZero || !receiptIsZero || payload.length !== 8
  ) refuse("NonCanonicalFrame");
  const view = dataView(payload);
  if (view.getUint32(0, true) === 0 || view.getUint32(4, true) === 0) refuse("NonCanonicalFrame");
}

function validateAuthority(authority: Authority): void {
  if (authority.rootKey.length !== 32) refuse("InvalidAuthorityWidth");
  if (authority.tenant.length !== 16 || authority.principal.length !== 16) refuse("InvalidAuthorityWidth");
  for (const digest of [authority.capabilityDigest, authority.schemaDigest, authority.policyDigest, authority.planDigest]) {
    if (digest.length !== 32) refuse("InvalidAuthorityWidth");
  }
  if (allZero(authority.rootKey)) refuse("ZeroKey");
  if (
    authority.generation === 0n ||
    authority.session === 0n ||
    authority.expiresUnixUS === 0n ||
    allZero(authority.tenant) ||
    allZero(authority.principal) ||
    authority.purpose === 0 ||
    authority.engine === 0 ||
    authority.profile === 0
  ) {
    refuse("ZeroIdentity");
  }
  if (
    allZero(authority.capabilityDigest) ||
    allZero(authority.schemaDigest) ||
    allZero(authority.policyDigest) ||
    allZero(authority.planDigest)
  ) {
    refuse("ZeroDigest");
  }
}

function deriveKey(root: Uint8Array, domain: Uint8Array, authority: Authority, context: Uint8Array): Uint8Array {
  return blake3(
    concatenate(
      domain,
      encodeU64(authority.generation),
      encodeU64(authority.session),
      encodeU64(authority.expiresUnixUS),
      context,
    ),
    { key: root },
  );
}

function replayIdentity(authority: Authority, context: Uint8Array): string {
  return `${toHex(context)}:${authority.session}:${authority.generation}`;
}

function dataView(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function encodeU32(value: number): Uint8Array {
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, true);
  return output;
}

function encodeU64(value: bigint): Uint8Array {
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigUint64(0, value, true);
  return output;
}

function concatenate(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function constantTimeEqual(first: Uint8Array, second: Uint8Array): boolean {
  if (first.length !== second.length) return false;
  let difference = 0;
  for (let index = 0; index < first.length; index += 1) difference |= first[index] ^ second[index];
  return difference === 0;
}

function allZero(value: Uint8Array): boolean {
  let combined = 0;
  for (const byte of value) combined |= byte;
  return combined === 0;
}

function toHex(value: Uint8Array): string {
  let output = "";
  for (const byte of value) output += byte.toString(16).padStart(2, "0");
  return output;
}

function refuse(name: string): never {
  throw new Error(name);
}
