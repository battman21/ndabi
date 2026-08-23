import { blake3 } from "@noble/hashes/blake3.js";

const SINGLE_FRAME_BYTES = 160;
const BATCH_HEADER_BYTES = 128;
const TAG_BYTES = 32;
const BATCH_OPERAND_BYTES = 20;
const MAX_BATCH_OPERATIONS = 4096;
const textEncoder = new TextEncoder();

const CONTEXT_DOMAIN = textEncoder.encode("ndabi/wire/v1/context");
const FRAME_KEY_DOMAIN = textEncoder.encode("ndabi/wire/v1/session-key");
const RECEIPT_KEY_DOMAIN = textEncoder.encode("ndabi/wire/v1/receipt-key");
const SINGLE_FRAME_DOMAIN = textEncoder.encode("ndabi/wire/v1/frame");
const BATCH_FRAME_DOMAIN = textEncoder.encode("ndabi/wire/v1/batch-frame");
const RECEIPT_DOMAIN = textEncoder.encode("ndabi/wire/v1/receipt");

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

interface Admission {
  replayKey: string;
  previousNonce: bigint;
  acceptedNonce: bigint;
}

const admissions = new WeakMap<Pending, Admission>();

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
