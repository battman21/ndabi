//! Lower verified NDABI programs into PostgreSQL statements.
//!
//! Program bytes contain only numeric handles.
//! A trusted catalogue supplies validated PostgreSQL identifiers outside the program.
//! This module never lowers unverified bytes or copies program bytes into SQL identifiers.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use ndabi_isa::{
    AggregateFunction, Comparison, Instruction, IsaError, JoinKind, ParameterValue, ScalarType,
    Schema, SortDirection, VerifiedOperands, VerifiedProgram,
};
use ndabi_protocol::{
    BackendIdentity, BoundedOutput, DynamicBackend, ExecutionLimits, ProtocolError,
};
use postgres::types::ToSql;
use postgres::{Client, Row, Statement};

pub const MAX_LOWERED_SQL_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PREPARED_DYNAMIC_PROGRAMS: usize = 4_096;
const RESULT_MAGIC: [u8; 4] = *b"NDIR";
const RESULT_HEADER_BYTES: usize = 64;
const RESULT_COLUMN_BYTES: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
struct SqlIdentifier(String);

impl SqlIdentifier {
    fn new(value: impl Into<String>) -> Result<Self, LoweringError> {
        let value = value.into();
        let mut characters = value.bytes();
        let first = characters.next().ok_or(LoweringError::InvalidIdentifier)?;
        if !(first.is_ascii_alphabetic() || first == b'_')
            || characters.any(|value| !(value.is_ascii_alphanumeric() || value == b'_'))
        {
            return Err(LoweringError::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    fn quoted(&self) -> String {
        format!("\"{}\"", self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldBinding {
    field: u32,
    column: SqlIdentifier,
}

impl FieldBinding {
    pub fn new(field: u32, column: impl Into<String>) -> Result<Self, LoweringError> {
        if field == 0 {
            return Err(LoweringError::ZeroHandle);
        }
        Ok(Self {
            field,
            column: SqlIdentifier::new(column)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationBinding {
    relation: u32,
    schema: SqlIdentifier,
    table: SqlIdentifier,
    fields: Vec<FieldBinding>,
}

impl RelationBinding {
    pub fn new(
        relation: u32,
        schema: impl Into<String>,
        table: impl Into<String>,
        mut fields: Vec<FieldBinding>,
    ) -> Result<Self, LoweringError> {
        if relation == 0 {
            return Err(LoweringError::ZeroHandle);
        }
        if fields.is_empty() {
            return Err(LoweringError::CatalogueMismatch);
        }
        fields.sort_unstable_by_key(|field| field.field);
        if fields.windows(2).any(|pair| pair[0].field == pair[1].field) {
            return Err(LoweringError::DuplicateHandle);
        }
        Ok(Self {
            relation,
            schema: SqlIdentifier::new(schema)?,
            table: SqlIdentifier::new(table)?,
            fields,
        })
    }

    fn field(&self, handle: u32) -> Option<&FieldBinding> {
        self.fields
            .binary_search_by_key(&handle, |field| field.field)
            .ok()
            .map(|index| &self.fields[index])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresCatalogue {
    schema_digest: [u8; 32],
    relations: Vec<RelationBinding>,
    field_types: HashMap<u32, ScalarType>,
}

impl PostgresCatalogue {
    pub fn new(
        schema: &Schema,
        mut relations: Vec<RelationBinding>,
    ) -> Result<Self, LoweringError> {
        relations.sort_unstable_by_key(|relation| relation.relation);
        if relations
            .windows(2)
            .any(|pair| pair[0].relation == pair[1].relation)
        {
            return Err(LoweringError::DuplicateHandle);
        }
        if relations.len() != schema.relations().len() {
            return Err(LoweringError::CatalogueMismatch);
        }
        for schema_relation in schema.relations() {
            let relation = relations
                .binary_search_by_key(&schema_relation.handle(), |relation| relation.relation)
                .ok()
                .map(|index| &relations[index])
                .ok_or(LoweringError::CatalogueMismatch)?;
            if relation.fields.len() != schema_relation.fields().len() {
                return Err(LoweringError::CatalogueMismatch);
            }
            for schema_field in schema_relation.fields() {
                relation
                    .field(schema_field.handle())
                    .ok_or(LoweringError::CatalogueMismatch)?;
            }
        }
        let field_types = schema
            .relations()
            .iter()
            .flat_map(|relation| relation.fields())
            .map(|field| (field.handle(), field.scalar_type()))
            .collect();
        Ok(Self {
            schema_digest: schema.digest(),
            relations,
            field_types,
        })
    }

    fn relation(&self, handle: u32) -> Option<&RelationBinding> {
        self.relations
            .binary_search_by_key(&handle, |relation| relation.relation)
            .ok()
            .map(|index| &self.relations[index])
    }

    fn field_type(&self, handle: u32) -> Option<ScalarType> {
        self.field_types.get(&handle).copied()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoweredProgram {
    sql: String,
    parameter_order: Vec<u16>,
    result_fields: Vec<u32>,
    result_types: Vec<ScalarType>,
    program_digest: [u8; 32],
}

impl LoweredProgram {
    pub fn sql(&self) -> &str {
        &self.sql
    }

    pub fn parameter_order(&self) -> &[u16] {
        &self.parameter_order
    }

    pub fn result_fields(&self) -> &[u32] {
        &self.result_fields
    }

    pub fn result_types(&self) -> &[ScalarType] {
        &self.result_types
    }

    pub fn program_digest(&self) -> [u8; 32] {
        self.program_digest
    }
}

#[derive(Clone, Debug)]
enum LoweredNode {
    Rows(Vec<u32>),
    Scalar(String, ScalarType),
    Returned,
}

#[derive(Default)]
struct ParameterMap {
    order: Vec<u16>,
    ordinals: HashMap<u16, usize>,
}

impl ParameterMap {
    fn placeholder(&mut self, parameter: u16) -> String {
        let ordinal = if let Some(ordinal) = self.ordinals.get(&parameter) {
            *ordinal
        } else {
            let ordinal = self.order.len() + 1;
            self.order.push(parameter);
            self.ordinals.insert(parameter, ordinal);
            ordinal
        };
        format!("${ordinal}")
    }
}

pub fn lower_verified_program(
    program: &VerifiedProgram<'_>,
    catalogue: &PostgresCatalogue,
) -> Result<LoweredProgram, LoweringError> {
    if program.schema_digest() != catalogue.schema_digest {
        return Err(LoweringError::CatalogueMismatch);
    }
    let mut nodes = Vec::with_capacity(usize::from(program.instruction_count()));
    let mut common_table_expressions =
        Vec::with_capacity(usize::from(program.instruction_count()).saturating_sub(1));
    let mut parameters = ParameterMap::default();
    let mut returned = None;
    for (index, instruction) in program.instructions().enumerate() {
        let register = index + 1;
        let node = match instruction? {
            Instruction::Scan { relation } => {
                let relation = catalogue
                    .relation(relation)
                    .ok_or(LoweringError::CatalogueMismatch)?;
                let projections = relation
                    .fields
                    .iter()
                    .map(|field| {
                        format!("{} AS {}", field.column.quoted(), field_alias(field.field))
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                common_table_expressions.push(format!(
                    "{} AS NOT MATERIALIZED (SELECT {projections} FROM {}.{})",
                    node_alias(register),
                    relation.schema.quoted(),
                    relation.table.quoted()
                ));
                LoweredNode::Rows(relation.fields.iter().map(|field| field.field).collect())
            }
            Instruction::Filter {
                input,
                field,
                comparison,
                parameter,
            } => {
                let input_fields = rows(&nodes, input)?;
                require_field(&input_fields, field)?;
                let placeholder = parameters.placeholder(parameter);
                common_table_expressions.push(format!(
                    "{} AS NOT MATERIALIZED (SELECT * FROM {} WHERE {} {} {placeholder})",
                    node_alias(register),
                    node_alias(usize::from(input)),
                    field_alias(field),
                    comparison_sql(comparison)
                ));
                LoweredNode::Rows(input_fields)
            }
            Instruction::Project { input, fields } => {
                let input_fields = rows(&nodes, input)?;
                let fields = fields.iter().collect::<Result<Vec<_>, _>>()?;
                for field in &fields {
                    require_field(&input_fields, *field)?;
                }
                common_table_expressions.push(format!(
                    "{} AS NOT MATERIALIZED (SELECT {} FROM {})",
                    node_alias(register),
                    fields
                        .iter()
                        .map(|field| field_alias(*field))
                        .collect::<Vec<_>>()
                        .join(", "),
                    node_alias(usize::from(input))
                ));
                LoweredNode::Rows(fields)
            }
            Instruction::Join {
                left,
                right,
                left_field,
                right_field,
                kind,
            } => {
                let left_fields = rows(&nodes, left)?;
                let right_fields = rows(&nodes, right)?;
                require_field(&left_fields, left_field)?;
                require_field(&right_fields, right_field)?;
                let left_alias = format!("\"l{register}\"");
                let right_alias = format!("\"r{register}\"");
                let mut fields = left_fields.clone();
                fields.extend_from_slice(&right_fields);
                fields.sort_unstable();
                let projections = fields
                    .iter()
                    .map(|field| {
                        let source = if left_fields.binary_search(field).is_ok() {
                            &left_alias
                        } else {
                            &right_alias
                        };
                        format!(
                            "{source}.{} AS {}",
                            field_alias(*field),
                            field_alias(*field)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                common_table_expressions.push(format!(
                    "{} AS NOT MATERIALIZED (SELECT {projections} FROM {} AS {left_alias} {} {} AS {right_alias} ON {left_alias}.{} = {right_alias}.{})",
                    node_alias(register),
                    node_alias(usize::from(left)),
                    join_sql(kind),
                    node_alias(usize::from(right)),
                    field_alias(left_field),
                    field_alias(right_field)
                ));
                LoweredNode::Rows(fields)
            }
            Instruction::Aggregate {
                input,
                field,
                function,
            } => {
                let input_fields = rows(&nodes, input)?;
                require_field(&input_fields, field)?;
                let alias = format!("\"v{register}\"");
                common_table_expressions.push(format!(
                    "{} AS NOT MATERIALIZED (SELECT {} AS {alias} FROM {})",
                    node_alias(register),
                    aggregate_sql(function, field),
                    node_alias(usize::from(input))
                ));
                let input_type = catalogue
                    .field_type(field)
                    .ok_or(LoweringError::CatalogueMismatch)?;
                let result_type = match function {
                    AggregateFunction::Count => ScalarType::U64,
                    AggregateFunction::Sum
                    | AggregateFunction::Minimum
                    | AggregateFunction::Maximum => input_type,
                    AggregateFunction::Average => ScalarType::F64,
                };
                LoweredNode::Scalar(alias, result_type)
            }
            Instruction::Sort { input, terms } => {
                let input_fields = rows(&nodes, input)?;
                let mut seen = HashSet::new();
                let mut order = Vec::with_capacity(terms.len());
                for term in terms.iter() {
                    let term = term?;
                    require_field(&input_fields, term.field)?;
                    if !seen.insert(term.field) {
                        return Err(LoweringError::InvalidProgramShape);
                    }
                    order.push(format!(
                        "{} {}",
                        field_alias(term.field),
                        match term.direction {
                            SortDirection::Ascending => "ASC",
                            SortDirection::Descending => "DESC",
                        }
                    ));
                }
                common_table_expressions.push(format!(
                    "{} AS NOT MATERIALIZED (SELECT * FROM {} ORDER BY {})",
                    node_alias(register),
                    node_alias(usize::from(input)),
                    order.join(", ")
                ));
                LoweredNode::Rows(input_fields)
            }
            Instruction::Limit { input, parameter } => {
                let input_fields = rows(&nodes, input)?;
                let placeholder = parameters.placeholder(parameter);
                common_table_expressions.push(format!(
                    "{} AS NOT MATERIALIZED (SELECT * FROM {} LIMIT {placeholder})",
                    node_alias(register),
                    node_alias(usize::from(input))
                ));
                LoweredNode::Rows(input_fields)
            }
            Instruction::Return { input } => {
                if returned.is_some() {
                    return Err(LoweringError::InvalidProgramShape);
                }
                let output = node(&nodes, input)?;
                let with_clause = format!("WITH {}", common_table_expressions.join(", "));
                returned = Some(match output {
                    LoweredNode::Rows(fields) => LoweredProgram {
                        sql: format!(
                            "{with_clause} SELECT {} FROM {}",
                            fields
                                .iter()
                                .map(|field| field_alias(*field))
                                .collect::<Vec<_>>()
                                .join(", "),
                            node_alias(usize::from(input))
                        ),
                        parameter_order: Vec::new(),
                        result_types: fields
                            .iter()
                            .map(|field| {
                                catalogue
                                    .field_type(*field)
                                    .ok_or(LoweringError::CatalogueMismatch)
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                        result_fields: fields,
                        program_digest: program.digest(),
                    },
                    LoweredNode::Scalar(alias, scalar_type) => LoweredProgram {
                        sql: format!(
                            "{with_clause} SELECT {alias} FROM {}",
                            node_alias(usize::from(input))
                        ),
                        parameter_order: Vec::new(),
                        result_fields: vec![0],
                        result_types: vec![scalar_type],
                        program_digest: program.digest(),
                    },
                    LoweredNode::Returned => return Err(LoweringError::InvalidProgramShape),
                });
                LoweredNode::Returned
            }
        };
        nodes.push(node);
    }
    let mut returned = returned.ok_or(LoweringError::InvalidProgramShape)?;
    returned.parameter_order = parameters.order;
    if returned.sql.len() > MAX_LOWERED_SQL_BYTES {
        return Err(LoweringError::LoweredSqlLimitExceeded);
    }
    Ok(returned)
}

fn node(nodes: &[LoweredNode], register: u16) -> Result<LoweredNode, LoweringError> {
    if register == 0 {
        return Err(LoweringError::InvalidProgramShape);
    }
    nodes
        .get(usize::from(register - 1))
        .cloned()
        .ok_or(LoweringError::InvalidProgramShape)
}

fn rows(nodes: &[LoweredNode], register: u16) -> Result<Vec<u32>, LoweringError> {
    match node(nodes, register)? {
        LoweredNode::Rows(fields) => Ok(fields),
        LoweredNode::Scalar(_, _) | LoweredNode::Returned => {
            Err(LoweringError::InvalidProgramShape)
        }
    }
}

fn require_field(fields: &[u32], field: u32) -> Result<(), LoweringError> {
    fields
        .binary_search(&field)
        .map(|_| ())
        .map_err(|_| LoweringError::CatalogueMismatch)
}

fn field_alias(field: u32) -> String {
    format!("\"f{field}\"")
}

fn node_alias(register: usize) -> String {
    format!("\"n{register}\"")
}

fn comparison_sql(comparison: Comparison) -> &'static str {
    match comparison {
        Comparison::Equal => "=",
        Comparison::NotEqual => "<>",
        Comparison::Less => "<",
        Comparison::LessOrEqual => "<=",
        Comparison::Greater => ">",
        Comparison::GreaterOrEqual => ">=",
    }
}

fn join_sql(kind: JoinKind) -> &'static str {
    match kind {
        JoinKind::Inner => "INNER JOIN",
        JoinKind::Left => "LEFT JOIN",
    }
}

fn aggregate_sql(function: AggregateFunction, field: u32) -> String {
    let field = field_alias(field);
    match function {
        AggregateFunction::Count => format!("COUNT({field})::bigint"),
        AggregateFunction::Sum => format!("SUM({field})"),
        AggregateFunction::Minimum => format!("MIN({field})"),
        AggregateFunction::Maximum => format!("MAX({field})"),
        AggregateFunction::Average => format!("AVG({field})::double precision"),
    }
}

pub struct DynamicPostgresBackend {
    client: Client,
    timeout_statement: Statement,
    identity: BackendIdentity,
    schema: Schema,
    catalogue: PostgresCatalogue,
    granted_capabilities: u64,
    prepared: HashMap<[u8; 32], PreparedDynamicProgram>,
    prepared_order: VecDeque<[u8; 32]>,
    required_tenant: [u8; 16],
    required_principal: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicPostgresAuthority {
    identity: BackendIdentity,
    granted_capabilities: u64,
    required_tenant: [u8; 16],
    required_principal: [u8; 16],
}

impl DynamicPostgresAuthority {
    pub fn new(
        identity: BackendIdentity,
        granted_capabilities: u64,
        required_tenant: [u8; 16],
        required_principal: [u8; 16],
    ) -> Self {
        Self {
            identity,
            granted_capabilities,
            required_tenant,
            required_principal,
        }
    }
}

#[derive(Clone)]
struct PreparedDynamicProgram {
    lowered: LoweredProgram,
    statement: Statement,
}

/// Configure and verify one retained PostgreSQL session before dynamic execution.
///
/// Implementations can attach an external identity and verify database-enforced policy.
/// The caller must not return the configured connection to a generic pool.
pub trait DynamicSessionAdmission {
    fn configure_and_verify(&self, client: &mut Client) -> Result<(), ProtocolError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DirectDynamicAdmission;

impl DynamicSessionAdmission for DirectDynamicAdmission {
    fn configure_and_verify(&self, _client: &mut Client) -> Result<(), ProtocolError> {
        Ok(())
    }
}

impl DynamicPostgresBackend {
    pub fn new(
        client: Client,
        identity: BackendIdentity,
        schema: Schema,
        catalogue: PostgresCatalogue,
        granted_capabilities: u64,
        required_tenant: [u8; 16],
        required_principal: [u8; 16],
    ) -> Result<Self, LoweringError> {
        Self::new_with_admission(
            client,
            schema,
            catalogue,
            DynamicPostgresAuthority::new(
                identity,
                granted_capabilities,
                required_tenant,
                required_principal,
            ),
            &DirectDynamicAdmission,
        )
    }

    pub fn new_with_admission<A: DynamicSessionAdmission>(
        mut client: Client,
        schema: Schema,
        catalogue: PostgresCatalogue,
        authority: DynamicPostgresAuthority,
        admission: &A,
    ) -> Result<Self, LoweringError> {
        if schema.digest() != catalogue.schema_digest {
            return Err(LoweringError::CatalogueMismatch);
        }
        admission
            .configure_and_verify(&mut client)
            .map_err(|_| LoweringError::SessionAdmissionRefused)?;
        // Prepare this once because every request needs a database-side cancellation bound.
        let timeout_statement = client
            .prepare("SELECT set_config('statement_timeout',$1,true)")
            .map_err(|_| LoweringError::SessionAdmissionRefused)?;
        Ok(Self {
            client,
            timeout_statement,
            identity: authority.identity,
            schema,
            catalogue,
            granted_capabilities: authority.granted_capabilities,
            prepared: HashMap::new(),
            prepared_order: VecDeque::new(),
            required_tenant: authority.required_tenant,
            required_principal: authority.required_principal,
        })
    }

    pub fn prepared_programs(&self) -> usize {
        self.prepared.len()
    }

    fn prepare_program(
        &mut self,
        program: &VerifiedProgram<'_>,
    ) -> Result<PreparedDynamicProgram, ProtocolError> {
        if let Some(prepared) = self.prepared.get(&program.digest()) {
            return Ok(prepared.clone());
        }
        if self.prepared.len() >= MAX_PREPARED_DYNAMIC_PROGRAMS {
            let oldest = self
                .prepared_order
                .pop_front()
                .ok_or(ProtocolError::BackendRefused)?;
            self.prepared.remove(&oldest);
        }
        let lowered = lower_verified_program(program, &self.catalogue)
            .map_err(|_| ProtocolError::BackendRefused)?;
        let limit_ordinal = lowered.parameter_order.len() + 1;
        let bounded_sql = format!(
            "SELECT * FROM ({}) AS \"ndabi_bounded\" LIMIT ${limit_ordinal}",
            lowered.sql()
        );
        if bounded_sql.len() > MAX_LOWERED_SQL_BYTES {
            return Err(ProtocolError::BackendRefused);
        }
        let statement = self
            .client
            .prepare(&bounded_sql)
            .map_err(|_| ProtocolError::BackendRefused)?;
        let prepared = PreparedDynamicProgram { lowered, statement };
        self.prepared.insert(program.digest(), prepared.clone());
        self.prepared_order.push_back(program.digest());
        Ok(prepared)
    }
}

impl DynamicBackend for DynamicPostgresBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn schema(&self) -> &Schema {
        &self.schema
    }

    fn granted_capabilities(&self) -> u64 {
        self.granted_capabilities
    }

    fn required_tenant(&self) -> Option<[u8; 16]> {
        Some(self.required_tenant)
    }

    fn required_principal(&self) -> Option<[u8; 16]> {
        Some(self.required_principal)
    }

    fn execute_dynamic(
        &mut self,
        program: &VerifiedProgram<'_>,
        operands: &VerifiedOperands<'_>,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        let prepared = self.prepare_program(program)?;
        let mut parameters = postgres_parameters(operands, prepared.lowered.parameter_order())?;
        parameters.push(Box::new(i64::from(limits.maximum_rows) + 1));
        let references = parameters
            .iter()
            .map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync))
            .collect::<Vec<_>>();
        let remaining_us = limits
            .deadline_unix_us
            .checked_sub(limits.admitted_unix_us)
            .filter(|remaining| *remaining > 0)
            .ok_or(ProtocolError::Expired)?;
        let timeout = format!("{}ms", remaining_us.div_ceil(1_000).max(1));
        let mut transaction = self
            .client
            .build_transaction()
            .read_only(true)
            .start()
            .map_err(|_| ProtocolError::BackendRefused)?;
        transaction
            .query_one(&self.timeout_statement, &[&timeout])
            .map_err(|_| ProtocolError::BackendRefused)?;
        let rows = transaction
            .query(&prepared.statement, &references)
            .map_err(|_| ProtocolError::BackendRefused)?;
        if rows.len() > limits.maximum_rows as usize {
            return Err(ProtocolError::RowBudgetExceeded);
        }
        encode_dynamic_result(&prepared.lowered, &rows, output)?;
        transaction
            .commit()
            .map_err(|_| ProtocolError::BackendRefused)
    }
}

fn postgres_parameters(
    operands: &VerifiedOperands<'_>,
    order: &[u16],
) -> Result<Vec<Box<dyn ToSql + Sync>>, ProtocolError> {
    order
        .iter()
        .map(|index| {
            let value = operands
                .value(*index)
                .map_err(|_| ProtocolError::DynamicOperandsInvalid)?;
            let parameter: Box<dyn ToSql + Sync> = match value {
                ParameterValue::Bool(value) => Box::new(value),
                ParameterValue::I64(value) | ParameterValue::TimestampMicros(value) => {
                    Box::new(value)
                }
                ParameterValue::U64(value) => Box::new(
                    i64::try_from(value).map_err(|_| ProtocolError::DynamicOperandsInvalid)?,
                ),
                ParameterValue::F64(value) => Box::new(value),
                ParameterValue::Bytes(value) => Box::new(value.to_vec()),
                ParameterValue::Utf8(value) => Box::new(value.to_owned()),
            };
            Ok(parameter)
        })
        .collect()
}

fn encode_dynamic_result(
    lowered: &LoweredProgram,
    rows: &[Row],
    output: &mut BoundedOutput,
) -> Result<(), ProtocolError> {
    if lowered.result_fields.len() != lowered.result_types.len() || lowered.result_fields.is_empty()
    {
        return Err(ProtocolError::OutputShape);
    }
    let row_count = u32::try_from(rows.len()).map_err(|_| ProtocolError::RowBudgetExceeded)?;
    let column_count =
        u16::try_from(lowered.result_fields.len()).map_err(|_| ProtocolError::OutputShape)?;
    let mut header = [0_u8; RESULT_HEADER_BYTES];
    header[0..4].copy_from_slice(&RESULT_MAGIC);
    header[4] = 1;
    header[5] = 0;
    header[12..16].copy_from_slice(&row_count.to_le_bytes());
    header[16..18].copy_from_slice(&column_count.to_le_bytes());
    header[32..64].copy_from_slice(&lowered.program_digest);
    output.write(&header)?;
    let mut total = RESULT_HEADER_BYTES;
    for (field, scalar_type) in lowered.result_fields.iter().zip(&lowered.result_types) {
        let mut descriptor = [0_u8; RESULT_COLUMN_BYTES];
        descriptor[0..4].copy_from_slice(&field.to_le_bytes());
        descriptor[4] = *scalar_type as u8;
        output.write(&descriptor)?;
        total = total
            .checked_add(RESULT_COLUMN_BYTES)
            .ok_or(ProtocolError::ResultBudgetExceeded)?;
    }
    let bitmap_bytes = lowered.result_fields.len().div_ceil(8);
    let mut bitmap = vec![0_u8; bitmap_bytes];
    for row in rows {
        bitmap.fill(0);
        for (index, scalar_type) in lowered.result_types.iter().enumerate() {
            if result_is_present(row, index, *scalar_type)? {
                bitmap[index / 8] |= 1 << (index % 8);
            }
        }
        output.write(&bitmap)?;
        total = total
            .checked_add(bitmap.len())
            .ok_or(ProtocolError::ResultBudgetExceeded)?;
        for (index, scalar_type) in lowered.result_types.iter().enumerate() {
            total = total
                .checked_add(write_result_value(row, index, *scalar_type, output)?)
                .ok_or(ProtocolError::ResultBudgetExceeded)?;
        }
    }
    output.patch_u32(
        8,
        u32::try_from(total).map_err(|_| ProtocolError::ResultBudgetExceeded)?,
    )?;
    output.complete_rows(row_count)
}

fn result_is_present(
    row: &Row,
    index: usize,
    scalar_type: ScalarType,
) -> Result<bool, ProtocolError> {
    match scalar_type {
        ScalarType::Bool => row
            .try_get::<_, Option<bool>>(index)
            .map(|value| value.is_some()),
        ScalarType::I64 | ScalarType::U64 | ScalarType::TimestampMicros => row
            .try_get::<_, Option<i64>>(index)
            .map(|value| value.is_some()),
        ScalarType::F64 => row
            .try_get::<_, Option<f64>>(index)
            .map(|value| value.is_some()),
        ScalarType::Bytes => row
            .try_get::<_, Option<&[u8]>>(index)
            .map(|value| value.is_some()),
        ScalarType::Utf8 => row
            .try_get::<_, Option<&str>>(index)
            .map(|value| value.is_some()),
    }
    .map_err(|_| ProtocolError::OutputShape)
}

fn write_result_value(
    row: &Row,
    index: usize,
    scalar_type: ScalarType,
    output: &mut BoundedOutput,
) -> Result<usize, ProtocolError> {
    match scalar_type {
        ScalarType::Bool => match row
            .try_get::<_, Option<bool>>(index)
            .map_err(|_| ProtocolError::OutputShape)?
        {
            Some(value) => {
                output.write(&[u8::from(value)])?;
                Ok(1)
            }
            None => Ok(0),
        },
        ScalarType::I64 | ScalarType::TimestampMicros => match row
            .try_get::<_, Option<i64>>(index)
            .map_err(|_| ProtocolError::OutputShape)?
        {
            Some(value) => {
                output.write(&value.to_le_bytes())?;
                Ok(8)
            }
            None => Ok(0),
        },
        ScalarType::U64 => match row
            .try_get::<_, Option<i64>>(index)
            .map_err(|_| ProtocolError::OutputShape)?
        {
            Some(value) => {
                let value = u64::try_from(value).map_err(|_| ProtocolError::OutputShape)?;
                output.write(&value.to_le_bytes())?;
                Ok(8)
            }
            None => Ok(0),
        },
        ScalarType::F64 => match row
            .try_get::<_, Option<f64>>(index)
            .map_err(|_| ProtocolError::OutputShape)?
        {
            Some(value) if value.is_finite() => {
                let value = if value == 0.0 { 0.0 } else { value };
                output.write(&value.to_bits().to_le_bytes())?;
                Ok(8)
            }
            Some(_) => Err(ProtocolError::OutputShape),
            None => Ok(0),
        },
        ScalarType::Bytes => match row
            .try_get::<_, Option<&[u8]>>(index)
            .map_err(|_| ProtocolError::OutputShape)?
        {
            Some(value) => write_variable_result(value, output),
            None => Ok(0),
        },
        ScalarType::Utf8 => match row
            .try_get::<_, Option<&str>>(index)
            .map_err(|_| ProtocolError::OutputShape)?
        {
            Some(value) => write_variable_result(value.as_bytes(), output),
            None => Ok(0),
        },
    }
}

fn write_variable_result(value: &[u8], output: &mut BoundedOutput) -> Result<usize, ProtocolError> {
    let length = u32::try_from(value.len()).map_err(|_| ProtocolError::ResultBudgetExceeded)?;
    output.write(&length.to_le_bytes())?;
    output.write(value)?;
    value
        .len()
        .checked_add(4)
        .ok_or(ProtocolError::ResultBudgetExceeded)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoweringError {
    CatalogueMismatch,
    DuplicateHandle,
    InvalidIdentifier,
    InvalidProgramShape,
    Isa(IsaError),
    LoweredSqlLimitExceeded,
    SessionAdmissionRefused,
    ZeroHandle,
}

impl fmt::Display for LoweringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CatalogueMismatch => formatter.write_str("the PostgreSQL catalogue differs"),
            Self::DuplicateHandle => formatter.write_str("a PostgreSQL handle is duplicated"),
            Self::InvalidIdentifier => formatter.write_str("a PostgreSQL identifier is invalid"),
            Self::InvalidProgramShape => {
                formatter.write_str("the verified program shape is invalid")
            }
            Self::Isa(error) => write!(formatter, "the verified program decode failed: {error}"),
            Self::LoweredSqlLimitExceeded => {
                formatter.write_str("the lowered PostgreSQL statement exceeds its limit")
            }
            Self::SessionAdmissionRefused => {
                formatter.write_str("the PostgreSQL session admission failed")
            }
            Self::ZeroHandle => formatter.write_str("a PostgreSQL handle is zero"),
        }
    }
}

impl std::error::Error for LoweringError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Isa(error) => Some(error),
            _ => None,
        }
    }
}

impl From<IsaError> for LoweringError {
    fn from(error: IsaError) -> Self {
        Self::Isa(error)
    }
}

#[cfg(test)]
mod tests {
    use ndabi_isa::{
        verify_program, Comparison, Field, ParameterDescriptor, ProgramBuilder, Relation,
        ScalarType, Schema, SortDirection, SortTerm, VerifyLimits,
    };

    use super::*;

    const READ: u64 = 1;

    fn schema() -> Schema {
        Schema::new(vec![Relation::new(
            11,
            READ,
            vec![
                Field::new(101, ScalarType::I64, false, READ).expect("field"),
                Field::new(102, ScalarType::Utf8, false, READ).expect("field"),
                Field::new(103, ScalarType::U64, false, READ).expect("field"),
            ],
        )
        .expect("relation")])
        .expect("schema")
    }

    fn catalogue(schema: &Schema) -> PostgresCatalogue {
        PostgresCatalogue::new(
            schema,
            vec![RelationBinding::new(
                11,
                "public",
                "events",
                vec![
                    FieldBinding::new(101, "event_id").expect("binding"),
                    FieldBinding::new(102, "summary").expect("binding"),
                    FieldBinding::new(103, "created_at").expect("binding"),
                ],
            )
            .expect("binding")],
        )
        .expect("catalogue")
    }

    fn program(schema: &Schema) -> Vec<u8> {
        let mut builder = ProgramBuilder::new(schema.digest(), 32).expect("builder");
        let minimum = builder
            .parameter(ParameterDescriptor::new(ScalarType::I64, 8).expect("parameter"))
            .expect("parameter");
        let limit = builder
            .parameter(ParameterDescriptor::new(ScalarType::U64, 8).expect("parameter"))
            .expect("parameter");
        let scan = builder.scan(11).expect("scan");
        let filter = builder
            .filter(scan, 101, Comparison::GreaterOrEqual, minimum)
            .expect("filter");
        let project = builder.project(filter, &[101, 102]).expect("project");
        let sort = builder
            .sort(
                project,
                &[SortTerm {
                    field: 101,
                    direction: SortDirection::Descending,
                }],
            )
            .expect("sort");
        let limit = builder.limit(sort, limit).expect("limit");
        builder.return_result(limit).expect("return");
        builder.finish().expect("program")
    }

    #[test]
    fn verified_dynamic_program_lowers_through_numeric_catalogue() {
        let schema = schema();
        let program = program(&schema);
        let verified =
            verify_program(&program, &schema, READ, VerifyLimits::default()).expect("verified");
        let lowered = lower_verified_program(&verified, &catalogue(&schema)).expect("lowered");
        assert_eq!(lowered.parameter_order(), &[0, 1]);
        assert_eq!(lowered.result_fields(), &[101, 102]);
        assert!(lowered.sql().contains("FROM \"public\".\"events\""));
        assert!(lowered.sql().contains("\"f101\" >= $1"));
        assert!(lowered.sql().contains("ORDER BY \"f101\" DESC"));
        assert!(lowered.sql().contains("LIMIT $2)"));
        assert!(lowered.sql().ends_with("FROM \"n5\""));
        assert!(!program.windows(6).any(|window| window == b"events"));
        assert!(!program.windows(7).any(|window| window == b"summary"));
    }

    #[test]
    fn catalogue_rejects_identifier_injection_and_schema_drift() {
        assert_eq!(
            FieldBinding::new(101, "event_id;DROP").expect_err("identifier"),
            LoweringError::InvalidIdentifier
        );
        let schema = schema();
        assert_eq!(
            PostgresCatalogue::new(
                &schema,
                vec![RelationBinding::new(
                    11,
                    "public",
                    "events",
                    vec![FieldBinding::new(101, "event_id").expect("binding")],
                )
                .expect("binding")]
            )
            .expect_err("schema drift"),
            LoweringError::CatalogueMismatch
        );
    }

    #[test]
    fn join_and_aggregate_lower_to_one_statement() {
        let schema = Schema::new(vec![
            Relation::new(
                11,
                READ,
                vec![Field::new(101, ScalarType::I64, false, READ).expect("field")],
            )
            .expect("relation"),
            Relation::new(
                12,
                READ,
                vec![Field::new(201, ScalarType::I64, false, READ).expect("field")],
            )
            .expect("relation"),
        ])
        .expect("schema");
        let catalogue = PostgresCatalogue::new(
            &schema,
            vec![
                RelationBinding::new(
                    11,
                    "public",
                    "events",
                    vec![FieldBinding::new(101, "owner_id").expect("binding")],
                )
                .expect("binding"),
                RelationBinding::new(
                    12,
                    "public",
                    "owners",
                    vec![FieldBinding::new(201, "owner_id").expect("binding")],
                )
                .expect("binding"),
            ],
        )
        .expect("catalogue");
        let mut builder = ProgramBuilder::new(schema.digest(), 16).expect("builder");
        let left = builder.scan(11).expect("left scan");
        let right = builder.scan(12).expect("right scan");
        let joined = builder
            .join(left, right, 101, 201, JoinKind::Inner)
            .expect("join");
        let aggregate = builder
            .aggregate(joined, 101, AggregateFunction::Count)
            .expect("aggregate");
        builder.return_result(aggregate).expect("return");
        let program = builder.finish().expect("program");
        let verified =
            verify_program(&program, &schema, READ, VerifyLimits::default()).expect("verified");
        let lowered = lower_verified_program(&verified, &catalogue).expect("lowered");
        assert!(lowered.sql().contains("INNER JOIN"));
        assert!(lowered.sql().contains("COUNT(\"f101\")::bigint"));
        assert_eq!(lowered.parameter_order(), &[]);
        assert_eq!(lowered.result_fields(), &[0]);
        assert_eq!(lowered.result_types(), &[ScalarType::U64]);
    }
}
