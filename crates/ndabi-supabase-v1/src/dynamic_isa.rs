//! Execute verified dynamic NDABI programs through one admitted Supabase user session.
//!
//! The retained PostgreSQL session applies the exact JWT claims and the authenticated role.
//! PostgreSQL row-level security remains the data authority for every lowered program.

use ndabi_isa::{Schema, VerifiedOperands, VerifiedProgram};
use ndabi_postgres::isa::{
    DynamicPostgresAuthority, DynamicPostgresBackend, DynamicSessionAdmission, LoweringError,
    PostgresCatalogue,
};
use ndabi_protocol::{
    BackendIdentity, BoundedOutput, DynamicBackend, ExecutionLimits, ProtocolError,
};
use postgres::Client;

use crate::postgres_graph::configure_user_session;
use crate::AdmittedIdentity;

pub struct UserDynamicPostgresBackend {
    inner: DynamicPostgresBackend,
    maximum_deadline_unix_us: u64,
}

impl UserDynamicPostgresBackend {
    pub fn new(
        client: Client,
        identity: BackendIdentity,
        schema: Schema,
        catalogue: PostgresCatalogue,
        granted_capabilities: u64,
        user: &AdmittedIdentity,
    ) -> Result<Self, LoweringError> {
        let admission = UserDynamicAdmission { user };
        let inner = DynamicPostgresBackend::new_with_admission(
            client,
            schema,
            catalogue,
            DynamicPostgresAuthority::new(
                identity,
                granted_capabilities,
                user.tenant_id(),
                user.principal_id(),
            ),
            &admission,
        )?;
        Ok(Self {
            inner,
            maximum_deadline_unix_us: user.session_expires_unix_us(),
        })
    }

    pub fn prepared_programs(&self) -> usize {
        self.inner.prepared_programs()
    }
}

impl DynamicBackend for UserDynamicPostgresBackend {
    fn identity(&self) -> BackendIdentity {
        self.inner.identity()
    }

    fn schema(&self) -> &Schema {
        self.inner.schema()
    }

    fn granted_capabilities(&self) -> u64 {
        self.inner.granted_capabilities()
    }

    fn required_tenant(&self) -> Option<[u8; 16]> {
        self.inner.required_tenant()
    }

    fn required_principal(&self) -> Option<[u8; 16]> {
        self.inner.required_principal()
    }

    fn maximum_deadline_unix_us(&self) -> Option<u64> {
        Some(self.maximum_deadline_unix_us)
    }

    fn execute_dynamic(
        &mut self,
        program: &VerifiedProgram<'_>,
        operands: &VerifiedOperands<'_>,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        self.inner
            .execute_dynamic(program, operands, limits, output)
    }
}

struct UserDynamicAdmission<'a> {
    user: &'a AdmittedIdentity,
}

impl DynamicSessionAdmission for UserDynamicAdmission<'_> {
    fn configure_and_verify(&self, client: &mut Client) -> Result<(), ProtocolError> {
        // A transaction-local deadline replaces a static session timeout for each request.
        configure_user_session(client, self.user, None)
    }
}
