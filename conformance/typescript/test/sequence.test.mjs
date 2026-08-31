import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { ReplayStore, decodeBundleControl, verify } from "../dist/decoder.js";
import {
  FEATURE_CANCELLATION,
  FEATURE_OPERAND_BUNDLES,
  FEATURE_STREAMING,
  TransportSequence,
} from "../dist/sequence.js";

const manifest = JSON.parse(readFileSync(new URL("../../v0.1/vectors.json", import.meta.url), "utf8"));
const authority = {
  rootKey: fromHex(manifest.authority.root_key_hex),
  generation: BigInt(manifest.authority.generation),
  session: BigInt(manifest.authority.session),
  expiresUnixUS: BigInt(manifest.authority.expires_unix_us),
  tenant: fromHex(manifest.authority.tenant_hex),
  principal: fromHex(manifest.authority.principal_hex),
  purpose: manifest.authority.purpose,
  capabilityDigest: fromHex(manifest.authority.capability_digest_hex),
  engine: manifest.authority.engine,
  profile: manifest.authority.profile,
  schemaDigest: fromHex(manifest.authority.schema_digest_hex),
  policyDigest: fromHex(manifest.authority.policy_digest_hex),
  planDigest: fromHex(manifest.authority.plan_digest_hex),
};
const limits = {
  maximumResultBytes: manifest.server_limits.maximum_result_bytes,
  maximumRows: manifest.server_limits.maximum_rows,
};
const transportAuthority = {
  rootKey: authority.rootKey,
  generation: authority.generation,
  session: authority.session,
  expiresUnixUS: authority.expiresUnixUS,
  contextDigest: fromHex(manifest.authority.context_digest_hex),
};

test("the TypeScript sequence accepts one exact result and refuses its replay", () => {
  const { sequence, requestFrame, pending } = readyRequest();
  const result = new TextEncoder().encode("exact result");
  const receipt = sequence.resultReceipt(pending.nonce, 2, result);
  const frame = transportFrame(3, pending.nonce, {
    rows: 2,
    resultShape: pending.operation.resultShape,
    executionReceipt: receipt,
  }, result);
  const changed = transportFrame(3, pending.nonce, {
    rows: 2,
    resultShape: pending.operation.resultShape,
    executionReceipt: receipt.slice(),
  }, result);
  changed.fields.executionReceipt[0] ^= 1;
  assert.throws(() => sequence.apply(changed, 2), errorNamed("ReceiptMismatch"));
  sequence.apply(frame, 2);
  assert.throws(() => sequence.apply(frame, 2), errorNamed("UnknownCorrelation"));
  assert.ok(requestFrame.length > 0);
});

test("the TypeScript sequence enforces stream order, bytes, and receipts", () => {
  const { sequence, pending } = readyRequest(FEATURE_STREAMING);
  sequence.apply(transportFrame(6, pending.nonce, {
    rows: 0xffff_ffff,
    resultShape: pending.operation.resultShape,
  }), 2);
  assert.throws(
    () => sequence.apply(transportFrame(8, pending.nonce, {
      sequence: 1,
      resultShape: pending.operation.resultShape,
      executionReceipt: new Uint8Array(32).fill(1),
    }), 2),
    errorNamed("ConnectionState"),
  );
  const chunk = new TextEncoder().encode("stream");
  assert.throws(
    () => sequence.apply(transportFrame(7, pending.nonce, { sequence: 2 }, chunk), 2),
    errorNamed("SequenceMismatch"),
  );
  sequence.apply(transportFrame(7, pending.nonce, { sequence: 1 }, chunk), 2);
  const receipt = sequence.streamReceipt(pending.nonce, 1);
  sequence.apply(transportFrame(8, pending.nonce, {
    sequence: 2,
    rows: 1,
    resultShape: pending.operation.resultShape,
    executionReceipt: receipt,
  }), 2);
});

test("the TypeScript sequence requires cancellation before error seven", () => {
  const { sequence, pending } = readyRequest(FEATURE_CANCELLATION);
  const refusal = transportFrame(4, pending.nonce, { errorCode: 7 });
  assert.throws(() => sequence.apply(refusal, 2), errorNamed("ConnectionState"));
  const cancel = transportFrame(5, pending.nonce);
  sequence.apply(cancel, 1);
  assert.throws(() => sequence.apply(cancel, 1), errorNamed("ConnectionState"));
  sequence.apply(refusal, 2);
});

test("the TypeScript sequence binds bundle acknowledgements to their digest", () => {
  const sequence = readySequence(FEATURE_OPERAND_BUNDLES);
  const control = decodeBundleControl(
    fromHex(manifest.bundle_controls.valid[0].frame_hex),
    authority,
    1 << 20,
  );
  const digest = new Uint8Array(32).fill(9);
  sequence.registerBundleControl(control, digest);
  const payload = new Uint8Array(48);
  const view = new DataView(payload.buffer);
  view.setUint32(0, control.bundleHandle, true);
  view.setUint32(4, control.graphHandle, true);
  view.setBigUint64(8, control.deadlineUnixUS, true);
  payload.set(digest, 16);
  const frame = transportFrame(9, control.nonce, { resultShape: control.resultShape }, payload);
  const changed = transportFrame(9, control.nonce, { resultShape: control.resultShape }, payload.slice());
  changed.payload[16] ^= 1;
  assert.throws(() => sequence.apply(changed, 2), errorNamed("OutputShape"));
  sequence.apply(frame, 2);
  assert.throws(() => sequence.apply(frame, 2), errorNamed("UnknownCorrelation"));
});

test("the TypeScript sequence refuses pending values that bypass verification", () => {
  const sequence = readySequence();
  const forged = {
    nonce: 1n,
    deadlineUnixUS: 2n,
    resultBudget: 16,
    rowBudget: 4,
    operation: { opcode: 1, planHandle: 2, resultShape: 3 },
    items: [],
  };
  assert.throws(
    () => sequence.registerRequest(new Uint8Array([1]), forged),
    errorNamed("InvalidPending"),
  );
});

test("the TypeScript sequence refuses changed decoder-issued bundle controls", () => {
  const sequence = readySequence(FEATURE_OPERAND_BUNDLES);
  const control = decodeBundleControl(
    fromHex(manifest.bundle_controls.valid[0].frame_hex),
    authority,
    1 << 20,
  );
  control.values[0] ^= 1;
  assert.throws(
    () => sequence.registerBundleControl(control, new Uint8Array(32).fill(9)),
    errorNamed("InvalidBundleControl"),
  );
});

function readyRequest(features = FEATURE_STREAMING | FEATURE_CANCELLATION | FEATURE_OPERAND_BUNDLES) {
  const sequence = readySequence(features);
  const vector = manifest.valid[0];
  const requestFrame = fromHex(vector.frame_hex);
  const pending = verify(
    requestFrame,
    authority,
    limits,
    new ReplayStore(),
    BigInt(manifest.clock_unix_us),
  );
  sequence.registerRequest(requestFrame, pending);
  return { sequence, requestFrame, pending };
}

function readySequence(features = FEATURE_STREAMING | FEATURE_CANCELLATION | FEATURE_OPERAND_BUNDLES) {
  const sequence = new TransportSequence(transportAuthority, {
    features,
    maximumFrameBytes: 4096,
    maximumChunkBytes: 1024,
    maximumInFlight: 4,
  });
  sequence.apply(negotiationFrame(1, features, 2, 2), 1);
  sequence.apply(negotiationFrame(2, features, 2, 0), 2);
  return sequence;
}

function negotiationFrame(kind, features, first, second) {
  const payload = new Uint8Array(8);
  const view = new DataView(payload.buffer);
  view.setUint16(0, first, true);
  view.setUint16(2, second, true);
  view.setUint32(4, 1024, true);
  return transportFrame(kind, 0n, { features, auxiliary: 4096 }, payload);
}

function transportFrame(kind, correlationNonce, fields = {}, payload = new Uint8Array()) {
  return {
    kind,
    fields: {
      errorCode: 0,
      correlationNonce,
      sequence: 0,
      rows: 0,
      resultShape: 0,
      features: 0,
      auxiliary: 0,
      executionReceipt: new Uint8Array(32),
      ...fields,
    },
    payload,
  };
}

function errorNamed(name) {
  return (error) => error instanceof Error && error.message === name;
}

function fromHex(value) {
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}
