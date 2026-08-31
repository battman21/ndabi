import { blake3 } from "@noble/hashes/blake3.js";

import {
  assertVerifiedBundleControl,
  assertVerifiedPending,
  type BundleControl,
  type Pending,
  type TransportAuthority,
  type TransportDirection,
  type TransportFrame,
} from "./decoder.js";

export const FEATURE_STREAMING = 1;
export const FEATURE_CANCELLATION = 2;
export const FEATURE_OPERAND_BUNDLES = 4;
const KNOWN_FEATURES = FEATURE_STREAMING | FEATURE_CANCELLATION | FEATURE_OPERAND_BUNDLES;
const TRANSPORT_MIN_FRAME_BYTES = 160;
const MAXIMUM_U32 = 0xffff_ffff;
const RECEIPT_KEY_DOMAIN = new TextEncoder().encode("ndabi/wire/v1/receipt-key");
const TRANSPORT_RECEIPT_DOMAIN = new TextEncoder().encode("ndabi/wire/v2/execution-receipt");

export interface TransportSequenceConfig {
  readonly features: number;
  readonly maximumFrameBytes: number;
  readonly maximumChunkBytes: number;
  readonly maximumInFlight: number;
}

interface BundleExpectation {
  readonly acknowledgement: 9 | 10;
  readonly graphHandle: number;
  readonly resultShape: number;
  readonly bundleHandle: number;
  readonly expiryUnixUS: bigint;
  readonly bundleDigest: Uint8Array;
}

interface Offer {
  features: number;
  maximumFrameBytes: number;
  maximumChunkBytes: number;
}

interface RequestState {
  requestDigest: Uint8Array;
  resultShape: number;
  resultBudget: number;
  rowBudget: number;
  cancelled: boolean;
  stream?: StreamState;
}

interface StreamState {
  nextSequence: number;
  receivedBytes: number;
  expectedRows?: number;
  digest: ReturnType<typeof blake3.create>;
}

type Phase = "provisioned" | "hello" | "ready" | "refused";

export class TransportSequence {
  readonly #authority: TransportAuthority;
  readonly #config: TransportSequenceConfig;
  #phase: Phase = "provisioned";
  #offer?: Offer;
  #negotiatedFeatures = 0;
  #negotiatedFrameBytes = 0;
  #negotiatedChunkBytes = 0;
  readonly #requests = new Map<bigint, RequestState>();
  readonly #bundles = new Map<bigint, BundleExpectation>();
  #lastRegisteredNonce = 0n;

  constructor(authority: TransportAuthority, config: TransportSequenceConfig) {
    validateAuthority(authority);
    if (
      !isU32(config.features) ||
      (config.features & ~KNOWN_FEATURES) !== 0 ||
      !isU32(config.maximumFrameBytes) || config.maximumFrameBytes < TRANSPORT_MIN_FRAME_BYTES + 8 ||
      !isU32(config.maximumChunkBytes) || config.maximumChunkBytes === 0 ||
      config.maximumChunkBytes > config.maximumFrameBytes - TRANSPORT_MIN_FRAME_BYTES ||
      !isU32(config.maximumInFlight) || config.maximumInFlight === 0
    ) refuse("TransportConfiguration");
    this.#authority = cloneAuthority(authority);
    this.#config = Object.freeze({ ...config });
  }

  registerRequest(requestFrame: Uint8Array, pending: Pending): void {
    assertVerifiedPending(pending);
    if (this.#phase !== "ready") refuse("ConnectionState");
    if (
      requestFrame.length === 0 || pending.nonce === 0n || pending.nonce <= this.#lastRegisteredNonce ||
      pending.operation.resultShape === 0 || pending.resultBudget === 0 || pending.rowBudget === 0
    ) refuse("NonCanonicalFrame");
    this.#requireCapacity();
    this.#requests.set(pending.nonce, {
      requestDigest: blake3(requestFrame),
      resultShape: pending.operation.resultShape,
      resultBudget: pending.resultBudget,
      rowBudget: pending.rowBudget,
      cancelled: false,
    });
    this.#lastRegisteredNonce = pending.nonce;
  }

  registerBundleControl(control: BundleControl, bundleDigest: Uint8Array): void {
    assertVerifiedBundleControl(control, this.#authority);
    if (this.#phase !== "ready") refuse("ConnectionState");
    this.#requireFeature(FEATURE_OPERAND_BUNDLES);
    const acknowledgement = control.kind === 5 ? 9 : 10;
    const digestIsZero = allZero(bundleDigest);
    if (
      control.nonce === 0n || control.nonce <= this.#lastRegisteredNonce ||
      control.graphHandle === 0 || control.resultShape === 0 || control.bundleHandle === 0 ||
      (acknowledgement === 9 && (control.deadlineUnixUS === 0n || digestIsZero)) ||
      (acknowledgement === 10 && !digestIsZero)
    ) refuse("NonCanonicalFrame");
    this.#requireCapacity();
    this.#bundles.set(control.nonce, Object.freeze({
      acknowledgement,
      graphHandle: control.graphHandle,
      resultShape: control.resultShape,
      bundleHandle: control.bundleHandle,
      expiryUnixUS: control.deadlineUnixUS,
      bundleDigest: bundleDigest.slice(),
    }));
    this.#lastRegisteredNonce = control.nonce;
  }

  apply(frame: TransportFrame, direction: TransportDirection): void {
    if (this.#phase === "provisioned") return this.#applyHello(frame, direction);
    if (this.#phase === "hello") return this.#applyAccept(frame, direction);
    if (this.#phase === "ready") return this.#applyReady(frame, direction);
    refuse("ConnectionState");
  }

  resultReceipt(nonce: bigint, rows: number, result: Uint8Array): Uint8Array {
    const request = this.#request(nonce);
    return this.#receipt(request.requestDigest, nonce, rows, blake3(result));
  }

  streamReceipt(nonce: bigint, rows: number): Uint8Array {
    const request = this.#request(nonce);
    if (request.stream === undefined) refuse("ConnectionState");
    return this.#receipt(request.requestDigest, nonce, rows, request.stream.digest.clone().digest());
  }

  #applyHello(frame: TransportFrame, direction: TransportDirection): void {
    if (direction !== 1 || frame.kind !== 1 || frame.payload.length !== 8) refuse("ConnectionState");
    const view = dataView(frame.payload);
    const minimumMajor = view.getUint16(0, true);
    const maximumMajor = view.getUint16(2, true);
    const maximumChunkBytes = view.getUint32(4, true);
    if (
      minimumMajor > 2 || maximumMajor < 2 || (frame.fields.features & ~KNOWN_FEATURES) !== 0 ||
      (frame.fields.features & ~this.#config.features) !== 0 ||
      frame.fields.auxiliary > this.#config.maximumFrameBytes ||
      maximumChunkBytes > this.#config.maximumChunkBytes
    ) refuse("TransportConfiguration");
    this.#offer = {
      features: frame.fields.features,
      maximumFrameBytes: frame.fields.auxiliary,
      maximumChunkBytes,
    };
    this.#phase = "hello";
  }

  #applyAccept(frame: TransportFrame, direction: TransportDirection): void {
    if (direction !== 2) refuse("ConnectionState");
    if (frame.kind === 4 && frame.fields.correlationNonce === 0n) {
      this.#phase = "refused";
      return;
    }
    if (frame.kind !== 2 || frame.payload.length !== 8 || this.#offer === undefined) refuse("ConnectionState");
    const view = dataView(frame.payload);
    const maximumChunkBytes = view.getUint32(4, true);
    if (
      view.getUint16(0, true) !== 2 || view.getUint16(2, true) !== 0 ||
      (frame.fields.features & ~this.#offer.features) !== 0 ||
      frame.fields.auxiliary < TRANSPORT_MIN_FRAME_BYTES + 8 ||
      frame.fields.auxiliary > this.#offer.maximumFrameBytes ||
      maximumChunkBytes > this.#offer.maximumChunkBytes ||
      maximumChunkBytes > frame.fields.auxiliary - TRANSPORT_MIN_FRAME_BYTES
    ) refuse("ConnectionState");
    this.#negotiatedFeatures = frame.fields.features;
    this.#negotiatedFrameBytes = frame.fields.auxiliary;
    this.#negotiatedChunkBytes = maximumChunkBytes;
    this.#phase = "ready";
  }

  #applyReady(frame: TransportFrame, direction: TransportDirection): void {
    if (TRANSPORT_MIN_FRAME_BYTES + frame.payload.length > this.#negotiatedFrameBytes) refuse("LengthMismatch");
    if (frame.kind === 5) return this.#applyCancel(frame, direction);
    if (direction !== 2) refuse("ConnectionState");
    if (frame.kind === 3) return this.#applyResult(frame);
    if (frame.kind === 4) return this.#applyError(frame);
    if (frame.kind === 6) return this.#applyStreamStart(frame);
    if (frame.kind === 7) return this.#applyStreamChunk(frame);
    if (frame.kind === 8) return this.#applyStreamEnd(frame);
    if (frame.kind === 9 || frame.kind === 10) return this.#applyBundle(frame);
    refuse("ConnectionState");
  }

  #applyCancel(frame: TransportFrame, direction: TransportDirection): void {
    if (direction !== 1) refuse("ConnectionState");
    this.#requireFeature(FEATURE_CANCELLATION);
    const request = this.#request(frame.fields.correlationNonce);
    if (request.cancelled) refuse("ConnectionState");
    request.cancelled = true;
  }

  #applyResult(frame: TransportFrame): void {
    const request = this.#request(frame.fields.correlationNonce);
    if (request.stream !== undefined) refuse("ConnectionState");
    if (frame.fields.resultShape !== request.resultShape) refuse("OutputShape");
    if (frame.fields.rows > request.rowBudget) refuse("RowBudgetExceeded");
    if (frame.payload.length > request.resultBudget) refuse("ResultBudgetExceeded");
    const expected = this.#receipt(
      request.requestDigest,
      frame.fields.correlationNonce,
      frame.fields.rows,
      blake3(frame.payload),
    );
    if (!constantTimeEqual(expected, frame.fields.executionReceipt)) refuse("ReceiptMismatch");
    this.#requests.delete(frame.fields.correlationNonce);
  }

  #applyError(frame: TransportFrame): void {
    const nonce = frame.fields.correlationNonce;
    if (nonce === 0n) refuse("ConnectionState");
    const request = this.#requests.get(nonce);
    if (request !== undefined) {
      if (frame.fields.errorCode === 7 && !request.cancelled) refuse("ConnectionState");
      this.#requests.delete(nonce);
      return;
    }
    if (this.#bundles.has(nonce)) {
      if (frame.fields.errorCode === 7) refuse("ConnectionState");
      this.#bundles.delete(nonce);
      return;
    }
    refuse("UnknownCorrelation");
  }

  #applyStreamStart(frame: TransportFrame): void {
    this.#requireFeature(FEATURE_STREAMING);
    const request = this.#request(frame.fields.correlationNonce);
    if (request.stream !== undefined) refuse("ConnectionState");
    if (frame.fields.resultShape !== request.resultShape) refuse("OutputShape");
    if (frame.fields.rows !== MAXIMUM_U32 && frame.fields.rows > request.rowBudget) refuse("RowBudgetExceeded");
    request.stream = {
      nextSequence: 1,
      receivedBytes: 0,
      expectedRows: frame.fields.rows === MAXIMUM_U32 ? undefined : frame.fields.rows,
      digest: blake3.create(),
    };
  }

  #applyStreamChunk(frame: TransportFrame): void {
    const request = this.#request(frame.fields.correlationNonce);
    const stream = request.stream;
    if (stream === undefined) refuse("ConnectionState");
    if (frame.fields.sequence !== stream.nextSequence) refuse("SequenceMismatch");
    const nextBytes = stream.receivedBytes + frame.payload.length;
    if (
      frame.payload.length > this.#negotiatedChunkBytes || nextBytes > request.resultBudget ||
      !Number.isSafeInteger(nextBytes)
    ) refuse("ResultBudgetExceeded");
    if (stream.nextSequence === MAXIMUM_U32) refuse("SequenceMismatch");
    stream.digest.update(frame.payload);
    stream.receivedBytes = nextBytes;
    stream.nextSequence += 1;
  }

  #applyStreamEnd(frame: TransportFrame): void {
    const request = this.#request(frame.fields.correlationNonce);
    const stream = request.stream;
    if (stream === undefined || stream.receivedBytes === 0) refuse("ConnectionState");
    if (frame.fields.sequence !== stream.nextSequence) refuse("SequenceMismatch");
    if (frame.fields.resultShape !== request.resultShape) refuse("OutputShape");
    if (frame.fields.rows > request.rowBudget) refuse("RowBudgetExceeded");
    if (stream.expectedRows !== undefined && frame.fields.rows !== stream.expectedRows) refuse("OutputShape");
    const expected = this.#receipt(
      request.requestDigest,
      frame.fields.correlationNonce,
      frame.fields.rows,
      stream.digest.clone().digest(),
    );
    if (!constantTimeEqual(expected, frame.fields.executionReceipt)) refuse("ReceiptMismatch");
    this.#requests.delete(frame.fields.correlationNonce);
  }

  #applyBundle(frame: TransportFrame): void {
    this.#requireFeature(FEATURE_OPERAND_BUNDLES);
    const control = this.#bundles.get(frame.fields.correlationNonce);
    if (control === undefined) refuse("UnknownCorrelation");
    const expectedBytes = frame.kind === 9 ? 48 : 8;
    if (frame.kind !== control.acknowledgement || frame.payload.length !== expectedBytes) refuse("OutputShape");
    const view = dataView(frame.payload);
    if (
      frame.fields.resultShape !== control.resultShape ||
      view.getUint32(0, true) !== control.bundleHandle || view.getUint32(4, true) !== control.graphHandle ||
      (frame.kind === 9 && (
        view.getBigUint64(8, true) !== control.expiryUnixUS ||
        !constantTimeEqual(frame.payload.subarray(16, 48), control.bundleDigest)
      ))
    ) refuse("OutputShape");
    this.#bundles.delete(frame.fields.correlationNonce);
  }

  #request(nonce: bigint): RequestState {
    const request = this.#requests.get(nonce);
    if (request === undefined) refuse("UnknownCorrelation");
    return request;
  }

  #requireCapacity(): void {
    if (this.#requests.size + this.#bundles.size >= this.#config.maximumInFlight) {
      refuse("RequestLimitExceeded");
    }
  }

  #requireFeature(feature: number): void {
    if ((this.#negotiatedFeatures & feature) === 0) refuse("FeatureNotNegotiated");
  }

  #receipt(requestDigest: Uint8Array, nonce: bigint, rows: number, resultDigest: Uint8Array): Uint8Array {
    const receiptKey = blake3(
      concatenate(
        RECEIPT_KEY_DOMAIN,
        encodeU64(this.#authority.generation),
        encodeU64(this.#authority.session),
        encodeU64(this.#authority.expiresUnixUS),
        this.#authority.contextDigest,
      ),
      { key: this.#authority.rootKey },
    );
    const output = blake3(
      concatenate(
        TRANSPORT_RECEIPT_DOMAIN,
        this.#authority.contextDigest,
        requestDigest,
        encodeU64(nonce),
        encodeU32(rows),
        resultDigest,
      ),
      { key: receiptKey },
    );
    receiptKey.fill(0);
    return output;
  }
}

function validateAuthority(authority: TransportAuthority): void {
  if (authority.rootKey.length !== 32 || allZero(authority.rootKey)) refuse("ZeroKey");
  if (
    authority.contextDigest.length !== 32 || allZero(authority.contextDigest) ||
    authority.generation <= 0n || authority.session <= 0n || authority.expiresUnixUS <= 0n
  ) refuse("ZeroIdentity");
}

function cloneAuthority(authority: TransportAuthority): TransportAuthority {
  return Object.freeze({
    ...authority,
    rootKey: authority.rootKey.slice(),
    contextDigest: authority.contextDigest.slice(),
  });
}

function dataView(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function isU32(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= MAXIMUM_U32;
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
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
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

function refuse(name: string): never {
  throw new Error(name);
}
