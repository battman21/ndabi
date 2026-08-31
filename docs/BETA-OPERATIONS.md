# NDABI beta operations

**Status:** Implemented operator procedure for a source-library beta.

NDABI has no standalone product daemon or global installer.
Install only the required crates as pinned Git dependencies.
Keep database deployment, native permissions, and data custody in the consumer system.

## 1. Release custody

Create an annotated, signed beta tag from a clean checkout.
The tag must identify `HEAD`.

```sh
git tag -s v0.2.0-beta.1 -m "NDABI v0.2.0 beta 1"
git verify-tag v0.2.0-beta.1
python3 scripts/create_release_bundle.py \
  --tag v0.2.0-beta.1 \
  --signer-fingerprint AUTHORISED_SIGNER_FINGERPRINT
```

The command creates one source archive, one manifest, and one checksum file.
It refuses a dirty checkout, a tag outside `HEAD`, an unauthorised signer, or changed existing output.
The manifest binds the commit, archive, `Cargo.lock`, toolchain file, licence, and tracked file count.
Use `--allow-unsigned` only for local tool tests.

Publish the signed tag and the three generated files together.
Do not publish a release from `--allow-unsigned` output.

## 2. Consumer installation

Verify the tag before dependency resolution.
Verify both published checksums before archive extraction.

```sh
git fetch --tags https://github.com/battman21/ndabi.git
git verify-tag v0.2.0-beta.1
shasum -a 256 -c ndabi-v0.2.0-beta.1.sha256
```

Pin each required crate to the same signed tag.
Do not use a branch or an unpinned Git revision.

```toml
[dependencies]
ndabi-protocol = { git = "https://github.com/battman21/ndabi", tag = "v0.2.0-beta.1" }
ndabi-transport-rustls = { git = "https://github.com/battman21/ndabi", tag = "v0.2.0-beta.1" }
```

Add only the adapter that the consumer needs.
Retain native PostgreSQL, Supabase, MongoDB, or White Tree permissions.
Run the protocol conformance suite and the selected adapter integration test.

## 3. Certificate custody

Use the certificate-resolver constructors for non-exportable signing keys.
Keep private keys outside configuration files, environment variables, logs, and model context.
Implement the resolver through an audited HSM, KMS, or PKCS#11 provider.
Deliver trust-root and revocation changes through an authenticated operator path.
Test replacement certificates before the old certificate expires.

NDABI fixes TLS 1.3, mutual authentication, server-name verification, `ndabi/2` ALPN, and no early data.
The certificate resolver cannot weaken those controls.

## 4. Upgrade

Record the current tag, registry generation, and consumer commit before the change.
Verify the new signed tag and source checksums.
Update all NDABI crates to the same tag.
Regenerate registered handles when their schemas, policies, implementations, or budgets change.
Run conformance and the affected adapter integration test.
Deploy one bounded consumer instance before wider adoption.

Do not mix frames, bundle handles, or registry generations across incompatible protocol versions.
Do not copy a newer replay-state file into an older implementation.

## 5. Rollback

Restore the previous verified NDABI tag and its matching registry generation.
Keep the latest durable replay state unless a documented migration proves compatibility.
Refuse traffic created for unknown registry generations or protocol versions.
Run conformance and the affected adapter integration test before traffic resumes.

Database data remains under the native database engine.
An NDABI library rollback must not restore, delete, or rewrite database data.

## 6. Removal

Stop the consumer process before removing NDABI dependencies.
Remove the NDABI crates from the consumer manifest.
Remove only consumer-owned derived caches and generated release files.
Retain database data, registry records, replay records, receipts, and audit evidence under their retention policies.
Rebuild the consumer without NDABI.
Verify the native database path before service resumes.

## 7. Beta refusal conditions

Refuse installation when the tag signature or checksum fails.
Refuse startup when registry identity, backend identity, protocol version, or trust roots differ.
Refuse remote traffic when mutual TLS, ALPN, deadlines, budgets, or replay checks fail.
Do not use this beta as a production authority boundary before the independent security review passes.
