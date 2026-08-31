//! Admit one Supabase user token into a bounded NDABI session identity.
//!
//! This crate does not access PostgreSQL or grant a database role.
//! The database adapter must still apply the admitted claims through row-level security.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

mod postgres_graph;
mod postgres_rls;

pub use postgres_graph::{UserReviewBatchGraphBackend, UserReviewOperandBundleBackend};
pub use postgres_rls::UserRangeBackend;

const AUTHENTICATED_ROLE: &str = "authenticated";
const IDENTITY_DOMAIN: &[u8] = b"ndabi/supabase/user-identity/v1";
const TENANT_DOMAIN: &[u8] = b"ndabi/supabase/tenant/v1";

pub struct JwtVerifier {
    key: DecodingKey,
    key_id: String,
    validation: Validation,
    maximum_session_seconds: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AdmittedIdentity {
    issuer: Zeroizing<String>,
    audience: Zeroizing<String>,
    subject: Zeroizing<String>,
    role: Zeroizing<String>,
    token_expires_unix_s: u64,
    session_expires_unix_s: u64,
    session_expires_unix_us: u64,
    canonical_claims: Zeroizing<String>,
    tenant_id: [u8; 16],
    principal_id: [u8; 16],
    identity_digest: [u8; 32],
}

#[derive(Deserialize)]
struct RequiredClaims {
    iss: String,
    aud: Audience,
    sub: String,
    role: String,
    exp: u64,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    Algorithm,
    Audience,
    Claims,
    Clock,
    Expired,
    Issuer,
    Key,
    Role,
    Subject,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Algorithm => "the JWT algorithm is not ES256",
            Self::Audience => "the JWT audience is not authorised",
            Self::Claims => "the JWT claims are invalid",
            Self::Clock => "the system clock is invalid",
            Self::Expired => "the JWT cannot create a live session",
            Self::Issuer => "the JWT issuer is not authorised",
            Self::Key => "the JWT key is not authorised",
            Self::Role => "the JWT role is not authorised",
            Self::Subject => "the JWT subject is invalid",
        })
    }
}

impl std::error::Error for AdmissionError {}

impl JwtVerifier {
    pub fn new_es256(
        public_key_pem: &[u8],
        key_id: &str,
        issuer: &str,
        audience: &str,
        maximum_session_seconds: u64,
    ) -> Result<Self, AdmissionError> {
        if key_id.is_empty()
            || issuer.is_empty()
            || audience.is_empty()
            || maximum_session_seconds == 0
        {
            return Err(AdmissionError::Claims);
        }
        let key = DecodingKey::from_ec_pem(public_key_pem).map_err(|_| AdmissionError::Key)?;
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.leeway = 0;
        validation.validate_nbf = true;
        validation.reject_tokens_expiring_in_less_than = 1;
        Ok(Self {
            key,
            key_id: key_id.to_string(),
            validation,
            maximum_session_seconds,
        })
    }

    pub fn admit(&self, token: &str) -> Result<AdmittedIdentity, AdmissionError> {
        let header = decode_header(token).map_err(|_| AdmissionError::Claims)?;
        if header.alg != Algorithm::ES256 || header.typ.as_deref() != Some("JWT") {
            return Err(AdmissionError::Algorithm);
        }
        if header.kid.as_deref() != Some(self.key_id.as_str()) {
            return Err(AdmissionError::Key);
        }
        let decoded = decode::<Value>(token, &self.key, &self.validation)
            .map_err(|_| AdmissionError::Claims)?;
        let required: RequiredClaims =
            serde_json::from_value(decoded.claims.clone()).map_err(|_| AdmissionError::Claims)?;
        let issuer = self
            .validation
            .iss
            .as_ref()
            .and_then(|values| values.iter().next())
            .ok_or(AdmissionError::Issuer)?;
        if required.iss != *issuer {
            return Err(AdmissionError::Issuer);
        }
        let audience = self
            .validation
            .aud
            .as_ref()
            .and_then(|values| values.iter().next())
            .ok_or(AdmissionError::Audience)?;
        if !required.aud.contains(audience) {
            return Err(AdmissionError::Audience);
        }
        if required.role != AUTHENTICATED_ROLE {
            return Err(AdmissionError::Role);
        }
        if required.sub.is_empty() || required.sub.len() > 255 || required.sub.contains('\0') {
            return Err(AdmissionError::Subject);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AdmissionError::Clock)?
            .as_secs();
        let maximum_expiry = now
            .checked_add(self.maximum_session_seconds)
            .ok_or(AdmissionError::Clock)?;
        let session_expires_unix_s = required.exp.min(maximum_expiry);
        if session_expires_unix_s <= now {
            return Err(AdmissionError::Expired);
        }
        let session_expires_unix_us = session_expires_unix_s
            .checked_mul(1_000_000)
            .ok_or(AdmissionError::Clock)?;
        let canonical_claims =
            serde_json::to_string(&decoded.claims).map_err(|_| AdmissionError::Claims)?;
        let mut digest = blake3::Hasher::new();
        digest.update(IDENTITY_DOMAIN);
        digest.update(canonical_claims.as_bytes());
        let identity_digest = *digest.finalize().as_bytes();
        let mut tenant = blake3::Hasher::new();
        tenant.update(TENANT_DOMAIN);
        tenant.update(required.iss.as_bytes());
        let tenant_digest = *tenant.finalize().as_bytes();
        Ok(AdmittedIdentity {
            issuer: Zeroizing::new(required.iss),
            audience: Zeroizing::new(audience.clone()),
            subject: Zeroizing::new(required.sub),
            role: Zeroizing::new(required.role),
            token_expires_unix_s: required.exp,
            session_expires_unix_s,
            session_expires_unix_us,
            canonical_claims: Zeroizing::new(canonical_claims),
            tenant_id: tenant_digest[0..16]
                .try_into()
                .map_err(|_| AdmissionError::Claims)?,
            principal_id: identity_digest[0..16]
                .try_into()
                .map_err(|_| AdmissionError::Claims)?,
            identity_digest,
        })
    }
}

impl AdmittedIdentity {
    pub fn issuer(&self) -> &str {
        self.issuer.as_str()
    }

    pub fn audience(&self) -> &str {
        self.audience.as_str()
    }

    pub fn subject(&self) -> &str {
        self.subject.as_str()
    }

    pub fn role(&self) -> &str {
        self.role.as_str()
    }

    pub fn token_expires_unix_s(&self) -> u64 {
        self.token_expires_unix_s
    }

    pub fn session_expires_unix_s(&self) -> u64 {
        self.session_expires_unix_s
    }

    pub fn session_expires_unix_us(&self) -> u64 {
        self.session_expires_unix_us
    }

    pub fn canonical_claims(&self) -> &str {
        self.canonical_claims.as_str()
    }

    pub fn identity_digest(&self) -> [u8; 32] {
        self.identity_digest
    }

    pub fn tenant_id(&self) -> [u8; 16] {
        self.tenant_id
    }

    pub fn principal_id(&self) -> [u8; 16] {
        self.principal_id
    }
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use p256::SecretKey;
    use rand_core::OsRng;
    use serde_json::{json, Value};

    use super::*;

    const KEY_ID: &str = "test-es256-key";
    const ISSUER: &str = "https://project.test/auth/v1";
    const AUDIENCE: &str = "authenticated";

    struct Keys {
        encoding: EncodingKey,
        public_pem: String,
    }

    fn keys() -> Keys {
        let secret = SecretKey::random(&mut OsRng);
        let private = secret.to_pkcs8_der().expect("private key");
        let public_pem = secret
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("public key");
        Keys {
            encoding: EncodingKey::from_ec_der(private.as_bytes()),
            public_pem,
        }
    }

    fn claims() -> Value {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "user-1",
            "role": AUTHENTICATED_ROLE,
            "exp": now + 300,
            "app_metadata": {"team": "one"}
        })
    }

    fn token(keys: &Keys, claims: &Value, key_id: &str) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(key_id.to_string());
        encode(&header, claims, &keys.encoding).expect("token")
    }

    fn verifier(keys: &Keys) -> JwtVerifier {
        JwtVerifier::new_es256(keys.public_pem.as_bytes(), KEY_ID, ISSUER, AUDIENCE, 60)
            .expect("verifier")
    }

    #[test]
    fn admission_preserves_custom_claims_and_bounds_the_session() {
        let keys = keys();
        let admitted = verifier(&keys)
            .admit(&token(&keys, &claims(), KEY_ID))
            .expect("admission");
        assert_eq!(admitted.subject(), "user-1");
        assert_eq!(admitted.role(), AUTHENTICATED_ROLE);
        assert!(admitted.canonical_claims().contains("app_metadata"));
        assert!(admitted.session_expires_unix_s() < admitted.token_expires_unix_s());
        assert_ne!(admitted.identity_digest(), [0; 32]);
    }

    #[test]
    fn admission_refuses_changed_authority_fields() {
        let keys = keys();
        let verifier = verifier(&keys);
        for (field, value) in [
            ("iss", json!("https://other.test/auth/v1")),
            ("aud", json!("other")),
            ("role", json!("service_role")),
            ("sub", json!("")),
        ] {
            let mut changed = claims();
            changed[field] = value;
            assert!(verifier.admit(&token(&keys, &changed, KEY_ID)).is_err());
        }
        assert!(verifier
            .admit(&token(&keys, &claims(), "unknown-key"))
            .is_err());

        let mut future = claims();
        future["nbf"] = json!(future["exp"].as_u64().expect("expiry") + 300);
        assert!(verifier.admit(&token(&keys, &future, KEY_ID)).is_err());
    }

    #[test]
    fn admission_refuses_a_changed_signature() {
        let keys = keys();
        let verifier = verifier(&keys);
        let mut changed = token(&keys, &claims(), KEY_ID).into_bytes();
        let last = changed.last_mut().expect("signature byte");
        *last = if *last == b'A' { b'B' } else { b'A' };
        let changed = String::from_utf8(changed).expect("token text");
        assert!(verifier.admit(&changed).is_err());
    }
}
