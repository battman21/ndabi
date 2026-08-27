//! Execute one registered batch graph through one admitted Supabase user session.
//!
//! The session retains one user role and one exact claims document until it closes.
//! Do not return its connection to a generic pool or use transaction pooling.

use ndabi_postgres_v1::{GraphSessionAdmission, ReviewBatchGraphBackend, ReviewBatchGraphProfile};
use ndabi_protocol::{
    BackendIdentity, BoundedOutput, ExecutionLimits, GraphBackend, GraphOperation, GraphRegistry,
    ProtocolError,
};
use postgres::Client;

use crate::AdmittedIdentity;

pub struct UserReviewBatchGraphBackend {
    inner: ReviewBatchGraphBackend,
    tenant: [u8; 16],
    principal: [u8; 16],
    maximum_deadline_unix_us: u64,
}

impl UserReviewBatchGraphBackend {
    pub fn new_registered(
        client: Client,
        profile: ReviewBatchGraphProfile,
        registry: &GraphRegistry,
        user: &AdmittedIdentity,
        maximum_statement_timeout_ms: u32,
    ) -> Result<Self, ProtocolError> {
        let admission = UserGraphAdmission { user };
        let inner = ReviewBatchGraphBackend::new_registered_with_admission(
            client,
            profile,
            registry,
            maximum_statement_timeout_ms,
            &admission,
        )?;
        Ok(Self {
            inner,
            tenant: user.tenant_id(),
            principal: user.principal_id(),
            maximum_deadline_unix_us: user.session_expires_unix_us(),
        })
    }

    pub fn data_queries(&self) -> u64 {
        self.inner.data_queries()
    }
}

impl GraphBackend for UserReviewBatchGraphBackend {
    fn identity(&self) -> BackendIdentity {
        self.inner.identity()
    }

    fn required_tenant(&self) -> Option<[u8; 16]> {
        Some(self.tenant)
    }

    fn required_principal(&self) -> Option<[u8; 16]> {
        Some(self.principal)
    }

    fn maximum_deadline_unix_us(&self) -> Option<u64> {
        Some(self.maximum_deadline_unix_us)
    }

    fn execute_graph(
        &mut self,
        operation: GraphOperation,
        parameters: &[u8],
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        self.inner
            .execute_graph(operation, parameters, limits, output)
    }
}

struct UserGraphAdmission<'a> {
    user: &'a AdmittedIdentity,
}

impl GraphSessionAdmission for UserGraphAdmission<'_> {
    fn configure_and_verify(
        &self,
        client: &mut Client,
        maximum_statement_timeout_ms: u32,
    ) -> Result<(), ProtocolError> {
        if self.user.role() != "authenticated" {
            return Err(ProtocolError::BackendRefused);
        }
        client
            .batch_execute(
                "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY; SET ROLE authenticated",
            )
            .map_err(|_| ProtocolError::BackendRefused)?;
        let timeout = format!("{maximum_statement_timeout_ms}ms");
        client
            .query_one(
                "SELECT set_config('request.jwt.claims',$1,false),set_config('statement_timeout',$2,false)",
                &[&self.user.canonical_claims(), &timeout],
            )
            .map_err(|_| ProtocolError::BackendRefused)?;
        let state = client
            .query_one(
                "SELECT current_user,current_setting('transaction_read_only'),current_setting('request.jwt.claims'),current_setting('row_security'),roles.rolsuper,roles.rolbypassrls FROM pg_roles AS roles WHERE roles.rolname=current_user",
                &[],
            )
            .map_err(|_| ProtocolError::BackendRefused)?;
        let current_user: String = state
            .try_get(0)
            .map_err(|_| ProtocolError::BackendRefused)?;
        let read_only: String = state
            .try_get(1)
            .map_err(|_| ProtocolError::BackendRefused)?;
        let claims: String = state
            .try_get(2)
            .map_err(|_| ProtocolError::BackendRefused)?;
        let row_security: String = state
            .try_get(3)
            .map_err(|_| ProtocolError::BackendRefused)?;
        let superuser: bool = state
            .try_get(4)
            .map_err(|_| ProtocolError::BackendRefused)?;
        let bypass_rls: bool = state
            .try_get(5)
            .map_err(|_| ProtocolError::BackendRefused)?;
        if current_user != "authenticated"
            || read_only != "on"
            || claims != self.user.canonical_claims()
            || row_security != "on"
            || superuser
            || bypass_rls
        {
            return Err(ProtocolError::BackendRefused);
        }
        Ok(())
    }
}
