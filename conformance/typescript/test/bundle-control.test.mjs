import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { decodeBundleControl } from "../dist/decoder.js";

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

test("the TypeScript decoder reproduces authenticated bundle controls", async (suite) => {
  for (const vector of manifest.bundle_controls.valid) {
    await suite.test(vector.id, () => {
      const decoded = decodeBundleControl(fromHex(vector.frame_hex), authority, 1 << 20);
      const expected = vector.decoded;
      assert.equal(decoded.kind, vector.kind === "registration" ? 5 : 7);
      assert.equal(decoded.nonce, BigInt(expected.nonce));
      assert.equal(decoded.deadlineUnixUS, BigInt(expected.expiry_unix_us ?? expected.deadline_unix_us));
      assert.equal(decoded.opcode, expected.opcode);
      assert.equal(decoded.graphHandle, expected.graph_handle);
      assert.equal(decoded.resultShape, expected.result_shape);
      assert.equal(decoded.bundleHandle, expected.bundle_handle);
      assert.equal(decoded.bundleSlotCount, expected.bundle_slot_count ?? 0);
      assert.equal(toHex(decoded.values), expected.values_hex ?? "");
    });
  }
});

test("the TypeScript decoder refuses every registered bundle-control failure", async (suite) => {
  for (const vector of manifest.bundle_controls.invalid) {
    await suite.test(vector.id, () => {
      assert.throws(
        () => decodeBundleControl(fromHex(vector.frame_hex), authority, 1 << 20),
        (error) => error instanceof Error && error.message === vector.expected_error,
      );
    });
  }
});

function fromHex(value) {
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

function toHex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
