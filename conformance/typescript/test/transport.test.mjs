import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { decodeTransport } from "../dist/decoder.js";

const manifest = JSON.parse(readFileSync(new URL("../../v0.2/transport-vectors.json", import.meta.url), "utf8"));
const authority = {
  rootKey: fromHex(manifest.authority.root_key_hex),
  generation: BigInt(manifest.authority.generation),
  session: BigInt(manifest.authority.session),
  expiresUnixUS: BigInt(manifest.authority.expires_unix_us),
  contextDigest: fromHex(manifest.authority.context_digest_hex),
};
const now = BigInt(manifest.clock_unix_us);

test("the TypeScript decoder reproduces every transport message", async (suite) => {
  for (const vector of manifest.valid) {
    await suite.test(vector.id, () => {
      const decoded = decodeTransport(
        fromHex(vector.frame_hex),
        authority,
        direction(vector.direction),
        manifest.maximum_payload_bytes,
        now,
      );
      assert.equal(decoded.kind, vector.kind);
      assert.equal(decoded.fields.errorCode, vector.decoded.error_code);
      assert.equal(decoded.fields.correlationNonce, BigInt(vector.decoded.correlation_nonce));
      assert.equal(decoded.fields.sequence, vector.decoded.sequence);
      assert.equal(decoded.fields.rows, vector.decoded.rows);
      assert.equal(decoded.fields.resultShape, vector.decoded.result_shape);
      assert.equal(decoded.fields.features, vector.decoded.features);
      assert.equal(decoded.fields.auxiliary, vector.decoded.auxiliary);
      assert.equal(toHex(decoded.fields.executionReceipt), vector.decoded.execution_receipt_hex);
      assert.equal(toHex(decoded.payload), vector.payload_hex);
    });
  }
});

test("the TypeScript decoder refuses every registered transport failure", async (suite) => {
  for (const vector of manifest.invalid) {
    await suite.test(vector.id, () => {
      assert.throws(
        () => decodeTransport(
          fromHex(vector.frame_hex),
          authority,
          direction(vector.direction),
          manifest.maximum_payload_bytes,
          now,
        ),
        (error) => error instanceof Error && error.message === vector.expected_error,
      );
    });
  }
});

test("the TypeScript decoder refuses every transport bit mutation", () => {
  let mutations = 0;
  for (const vector of manifest.valid) {
    const frame = fromHex(vector.frame_hex);
    for (let byteIndex = 0; byteIndex < frame.length; byteIndex += 1) {
      for (let bit = 0; bit < 8; bit += 1) {
        const mutated = frame.slice();
        mutated[byteIndex] ^= 1 << bit;
        assert.throws(() => decodeTransport(
          mutated,
          authority,
          direction(vector.direction),
          manifest.maximum_payload_bytes,
          now,
        ));
        mutations += 1;
      }
    }
  }
  assert.ok(mutations > 10_000);
});

test("the TypeScript decoder refuses an unrepresentable maximum", () => {
  const vector = manifest.valid[0];
  assert.throws(
    () => decodeTransport(fromHex(vector.frame_hex), authority, direction(vector.direction), 0xffff_ffff, now),
    (error) => error instanceof Error && error.message === "TransportPayloadTooLarge",
  );
});

function direction(value) {
  if (value === "client-to-server") return 1;
  if (value === "server-to-client") return 2;
  throw new Error(`unknown transport direction ${value}`);
}

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
