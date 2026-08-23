import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { ReplayStore, contextDigest, receipt, verify } from "../dist/decoder.js";

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
const now = BigInt(manifest.clock_unix_us);

test("the manifest preserves exact 64-bit values", () => {
  assert.equal(manifest.integer_encoding, "decimal-string-for-64-bit");
  assert.equal(authority.session, 1230066625199609624n);
  assert.equal(toHex(contextDigest(authority)), manifest.authority.context_digest_hex);
});

test("the TypeScript decoder reproduces valid fields and receipts", async (suite) => {
  for (const vector of manifest.valid) {
    await suite.test(vector.id, () => {
      const frame = fromHex(vector.frame_hex);
      const pending = verify(frame, authority, limits, new ReplayStore(), now);
      assert.equal(pending.nonce, BigInt(vector.decoded.nonce));
      assert.equal(pending.deadlineUnixUS, BigInt(vector.decoded.deadline_unix_us));
      assert.equal(pending.resultBudget, vector.decoded.result_budget);
      assert.equal(pending.rowBudget, vector.decoded.row_budget);
      assert.equal(pending.operation.opcode, vector.decoded.operation.opcode);
      assert.equal(pending.operation.planHandle, vector.decoded.operation.plan_handle);
      assert.equal(pending.operation.resultShape, vector.decoded.operation.result_shape);
      const expectedItems = vector.decoded.items ?? [{
        first: vector.decoded.operation.first,
        second: vector.decoded.operation.second,
        third: vector.decoded.operation.third,
      }];
      assert.deepEqual(
        pending.items,
        expectedItems.map((item) => ({ first: BigInt(item.first), second: BigInt(item.second), third: item.third })),
      );
      assert.equal(
        toHex(receipt(frame, authority, pending.nonce, vector.rows, fromHex(vector.result_hex))),
        vector.receipt_hex,
      );
    });
  }
});

test("the TypeScript decoder returns every registered invalid class", async (suite) => {
  for (const vector of manifest.invalid) {
    await suite.test(vector.id, () => {
      assert.throws(
        () => verify(fromHex(vector.frame_hex), authority, limits, new ReplayStore(), now),
        (error) => error instanceof Error && error.message === vector.expected_error,
      );
    });
  }
});

test("the TypeScript decoder refuses every single-bit mutation", () => {
  let mutations = 0;
  for (const vector of manifest.valid) {
    const frame = fromHex(vector.frame_hex);
    for (let byteIndex = 0; byteIndex < frame.length; byteIndex += 1) {
      for (let bit = 0; bit < 8; bit += 1) {
        const mutated = frame.slice();
        mutated[byteIndex] ^= 1 << bit;
        assert.throws(() => verify(mutated, authority, limits, new ReplayStore(), now));
        mutations += 1;
      }
    }
  }
  assert.equal(mutations, 3040);
});

test("the TypeScript replay store commits only after execution", () => {
  for (const sequence of manifest.sequences) {
    const vector = manifest.valid.find((candidate) => candidate.id === sequence.frame_id);
    assert.ok(vector);
    const frame = fromHex(vector.frame_hex);
    const replay = new ReplayStore();
    const pending = verify(frame, authority, limits, replay, now);
    verify(frame, authority, limits, replay, now);
    replay.commit(pending);
    assert.throws(
      () => verify(frame, authority, limits, replay, now),
      (error) => error instanceof Error && error.message === "Replay",
    );
  }
});

test("caller mutation cannot advance TypeScript replay state", () => {
  const vector = manifest.valid[0];
  const frame = fromHex(vector.frame_hex);
  const replay = new ReplayStore();
  const pending = verify(frame, authority, limits, replay, now);
  const replayKey = `${toHex(contextDigest(authority))}:${authority.session}:${authority.generation}`;
  assert.throws(() => {
    pending.nonce = 99n;
  }, TypeError);
  assert.throws(() => {
    pending.items[0].first = 99n;
  }, TypeError);
  replay.commit(pending);
  assert.equal(replay.lastNonce(replayKey), BigInt(vector.decoded.nonce));
  assert.throws(
    () => verify(frame, authority, limits, replay, now),
    (error) => error instanceof Error && error.message === "Replay",
  );
  assert.throws(
    () => replay.commit({ ...pending }),
    (error) => error instanceof Error && error.message === "InvalidPending",
  );
});

function fromHex(value) {
  assert.equal(value.length % 2, 0);
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

function toHex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
