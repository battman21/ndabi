# Security policy

NDABI remains an implemented research candidate.
Do not deploy it as a production authority boundary without an independent security review.

Report a suspected vulnerability through a private GitHub security advisory.
Do not include production credentials, customer data, private keys, or database contents.

The Rustls profile accepts external certificate resolvers for non-exportable signing keys.
NDABI does not supply an HSM, KMS, PKCS#11 provider, or certificate revocation service.
The current candidate does not prove production key custody, remote registry administration, or public non-repudiation.
The adapters must retain native database permissions, row policies, and read-only roles.
