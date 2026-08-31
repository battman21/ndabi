//! Define the dynamic NDABI data instruction set.
//!
//! Programs contain numeric handles, typed parameters, and bounded acyclic instructions.
//! Human-readable backend identifiers remain outside the wire program.
//! A backend must accept [`VerifiedProgram`] instead of caller-provided program bytes.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use smallvec::SmallVec;

const MAGIC: [u8; 4] = *b"NDIP";
const VERSION_MAJOR: u8 = 1;
const VERSION_MINOR: u8 = 0;
const HEADER_BYTES: usize = 64;
const PARAMETER_BYTES: usize = 8;
const INSTRUCTION_HEADER_BYTES: usize = 8;
const PROGRAM_DOMAIN: &[u8] = b"ndabi/isa/v1/program";
const SCHEMA_DOMAIN: &[u8] = b"ndabi/isa/v1/schema";
const CACHE_DOMAIN: &[u8] = b"ndabi/isa/v1/cache";
const CAPABILITY_DOMAIN: &[u8] = b"ndabi/isa/v1/capabilities";
const OPERAND_MAGIC: [u8; 4] = *b"NDIV";
const OPERAND_HEADER_BYTES: usize = 64;
const OPERAND_DOMAIN: &[u8] = b"ndabi/isa/v1/operands";
const COMPACT_OPERAND_DOMAIN: &[u8] = b"ndabi/isa/v1/compact-operands";

pub const MAX_PROGRAM_BYTES: usize = 1024 * 1024;
pub const MAX_INSTRUCTIONS: usize = 4_096;
pub const MAX_PARAMETERS: usize = 4_096;
pub const MAX_VARIABLE_VALUE_BYTES: u32 = 1024 * 1024;
pub const MAX_SCHEMA_RELATIONS: usize = 65_535;
pub const MAX_RELATION_FIELDS: usize = 65_535;
pub const MAX_SCHEMA_FIELDS: usize = 1024 * 1024;
pub const MAX_CACHE_ENTRIES: usize = 65_536;

pub fn capability_digest(granted_capabilities: u64) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(CAPABILITY_DOMAIN);
    digest.update(&granted_capabilities.to_le_bytes());
    *digest.finalize().as_bytes()
}

const OP_SCAN: u8 = 1;
const OP_FILTER: u8 = 2;
const OP_PROJECT: u8 = 3;
const OP_JOIN: u8 = 4;
const OP_AGGREGATE: u8 = 5;
const OP_SORT: u8 = 6;
const OP_LIMIT: u8 = 7;
const OP_RETURN: u8 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ScalarType {
    Bool = 1,
    I64 = 2,
    U64 = 3,
    F64 = 4,
    Bytes = 5,
    Utf8 = 6,
    TimestampMicros = 7,
}

impl ScalarType {
    fn decode(value: u8) -> Result<Self, IsaError> {
        match value {
            1 => Ok(Self::Bool),
            2 => Ok(Self::I64),
            3 => Ok(Self::U64),
            4 => Ok(Self::F64),
            5 => Ok(Self::Bytes),
            6 => Ok(Self::Utf8),
            7 => Ok(Self::TimestampMicros),
            _ => Err(IsaError::UnknownScalarType),
        }
    }

    fn fixed_width(self) -> Option<u32> {
        match self {
            Self::Bool => Some(1),
            Self::I64 | Self::U64 | Self::F64 | Self::TimestampMicros => Some(8),
            Self::Bytes | Self::Utf8 => None,
        }
    }

    fn is_ordered(self) -> bool {
        !matches!(self, Self::Bool | Self::Bytes)
    }

    fn is_numeric(self) -> bool {
        matches!(self, Self::I64 | Self::U64 | Self::F64)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParameterDescriptor {
    scalar_type: ScalarType,
    maximum_bytes: u32,
}

impl ParameterDescriptor {
    pub fn new(scalar_type: ScalarType, maximum_bytes: u32) -> Result<Self, IsaError> {
        validate_parameter_width(scalar_type, maximum_bytes)?;
        Ok(Self {
            scalar_type,
            maximum_bytes,
        })
    }

    pub fn scalar_type(self) -> ScalarType {
        self.scalar_type
    }

    pub fn maximum_bytes(self) -> u32 {
        self.maximum_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Field {
    handle: u32,
    scalar_type: ScalarType,
    nullable: bool,
    required_capabilities: u64,
}

impl Field {
    pub fn new(
        handle: u32,
        scalar_type: ScalarType,
        nullable: bool,
        required_capabilities: u64,
    ) -> Result<Self, IsaError> {
        if handle == 0 {
            return Err(IsaError::ZeroHandle);
        }
        Ok(Self {
            handle,
            scalar_type,
            nullable,
            required_capabilities,
        })
    }

    pub fn handle(self) -> u32 {
        self.handle
    }

    pub fn scalar_type(self) -> ScalarType {
        self.scalar_type
    }

    pub fn nullable(self) -> bool {
        self.nullable
    }

    pub fn required_capabilities(self) -> u64 {
        self.required_capabilities
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Relation {
    handle: u32,
    required_capabilities: u64,
    fields: Vec<Field>,
}

impl Relation {
    pub fn new(
        handle: u32,
        required_capabilities: u64,
        mut fields: Vec<Field>,
    ) -> Result<Self, IsaError> {
        if handle == 0 {
            return Err(IsaError::ZeroHandle);
        }
        if fields.is_empty() {
            return Err(IsaError::EmptyRelation);
        }
        if fields.len() > MAX_RELATION_FIELDS {
            return Err(IsaError::SchemaLimitExceeded);
        }
        fields.sort_unstable_by_key(|field| field.handle);
        if fields
            .windows(2)
            .any(|pair| pair[0].handle == pair[1].handle)
        {
            return Err(IsaError::DuplicateHandle);
        }
        Ok(Self {
            handle,
            required_capabilities,
            fields,
        })
    }

    pub fn handle(&self) -> u32 {
        self.handle
    }

    pub fn fields(&self) -> &[Field] {
        &self.fields
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Schema {
    relations: Vec<Relation>,
    digest: [u8; 32],
}

impl Schema {
    pub fn new(mut relations: Vec<Relation>) -> Result<Self, IsaError> {
        if relations.is_empty() {
            return Err(IsaError::EmptySchema);
        }
        if relations.len() > MAX_SCHEMA_RELATIONS {
            return Err(IsaError::SchemaLimitExceeded);
        }
        relations.sort_unstable_by_key(|relation| relation.handle);
        if relations
            .windows(2)
            .any(|pair| pair[0].handle == pair[1].handle)
        {
            return Err(IsaError::DuplicateHandle);
        }
        let mut field_handles = HashSet::new();
        let mut field_count = 0_usize;
        for relation in &relations {
            field_count = field_count
                .checked_add(relation.fields.len())
                .ok_or(IsaError::SchemaLimitExceeded)?;
            if field_count > MAX_SCHEMA_FIELDS {
                return Err(IsaError::SchemaLimitExceeded);
            }
            for field in &relation.fields {
                if !field_handles.insert(field.handle) {
                    return Err(IsaError::DuplicateHandle);
                }
            }
        }
        let digest = schema_digest(&relations);
        Ok(Self { relations, digest })
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn relations(&self) -> &[Relation] {
        &self.relations
    }

    fn relation(&self, handle: u32) -> Option<&Relation> {
        self.relations
            .binary_search_by_key(&handle, |relation| relation.handle)
            .ok()
            .map(|index| &self.relations[index])
    }
}

fn schema_digest(relations: &[Relation]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(SCHEMA_DOMAIN);
    digest.update(&(relations.len() as u32).to_le_bytes());
    for relation in relations {
        digest.update(&relation.handle.to_le_bytes());
        digest.update(&relation.required_capabilities.to_le_bytes());
        digest.update(&(relation.fields.len() as u32).to_le_bytes());
        for field in &relation.fields {
            digest.update(&field.handle.to_le_bytes());
            digest.update(&[field.scalar_type as u8, u8::from(field.nullable)]);
            digest.update(&field.required_capabilities.to_le_bytes());
        }
    }
    *digest.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Comparison {
    Equal = 1,
    NotEqual = 2,
    Less = 3,
    LessOrEqual = 4,
    Greater = 5,
    GreaterOrEqual = 6,
}

impl Comparison {
    fn decode(value: u8) -> Result<Self, IsaError> {
        match value {
            1 => Ok(Self::Equal),
            2 => Ok(Self::NotEqual),
            3 => Ok(Self::Less),
            4 => Ok(Self::LessOrEqual),
            5 => Ok(Self::Greater),
            6 => Ok(Self::GreaterOrEqual),
            _ => Err(IsaError::UnknownInstructionFlag),
        }
    }

    fn is_ordered(self) -> bool {
        !matches!(self, Self::Equal | Self::NotEqual)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum JoinKind {
    Inner = 1,
    Left = 2,
}

impl JoinKind {
    fn decode(value: u8) -> Result<Self, IsaError> {
        match value {
            1 => Ok(Self::Inner),
            2 => Ok(Self::Left),
            _ => Err(IsaError::UnknownInstructionFlag),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AggregateFunction {
    Count = 1,
    Sum = 2,
    Minimum = 3,
    Maximum = 4,
    Average = 5,
}

impl AggregateFunction {
    fn decode(value: u8) -> Result<Self, IsaError> {
        match value {
            1 => Ok(Self::Count),
            2 => Ok(Self::Sum),
            3 => Ok(Self::Minimum),
            4 => Ok(Self::Maximum),
            5 => Ok(Self::Average),
            _ => Err(IsaError::UnknownInstructionFlag),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SortDirection {
    Ascending = 1,
    Descending = 2,
}

impl SortDirection {
    fn decode(value: u32) -> Result<Self, IsaError> {
        match value {
            1 => Ok(Self::Ascending),
            2 => Ok(Self::Descending),
            _ => Err(IsaError::UnknownInstructionFlag),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SortTerm {
    pub field: u32,
    pub direction: SortDirection,
}

pub struct ProgramBuilder {
    schema_digest: [u8; 32],
    declared_work_units: u32,
    parameters: Vec<ParameterDescriptor>,
    instructions: Vec<u8>,
    instruction_count: u16,
}

impl ProgramBuilder {
    pub fn new(schema_digest: [u8; 32], declared_work_units: u32) -> Result<Self, IsaError> {
        if schema_digest == [0; 32] {
            return Err(IsaError::SchemaMismatch);
        }
        if declared_work_units == 0 {
            return Err(IsaError::WorkLimitExceeded);
        }
        Ok(Self {
            schema_digest,
            declared_work_units,
            parameters: Vec::new(),
            instructions: Vec::new(),
            instruction_count: 0,
        })
    }

    pub fn parameter(&mut self, descriptor: ParameterDescriptor) -> Result<u16, IsaError> {
        if self.instruction_count != 0 {
            return Err(IsaError::NonCanonicalProgram);
        }
        if self.parameters.len() >= MAX_PARAMETERS {
            return Err(IsaError::ParameterLimitExceeded);
        }
        let index =
            u16::try_from(self.parameters.len()).map_err(|_| IsaError::ParameterLimitExceeded)?;
        self.parameters.push(descriptor);
        Ok(index)
    }

    pub fn scan(&mut self, relation: u32) -> Result<u16, IsaError> {
        self.push(OP_SCAN, 0, &[relation])
    }

    pub fn filter(
        &mut self,
        input: u16,
        field: u32,
        comparison: Comparison,
        parameter: u16,
    ) -> Result<u16, IsaError> {
        self.push(
            OP_FILTER,
            comparison as u8,
            &[u32::from(input), field, u32::from(parameter)],
        )
    }

    pub fn project(&mut self, input: u16, fields: &[u32]) -> Result<u16, IsaError> {
        let mut payload = Vec::with_capacity(fields.len() + 2);
        payload.push(u32::from(input));
        payload.push(u32::try_from(fields.len()).map_err(|_| IsaError::InstructionLimitExceeded)?);
        payload.extend_from_slice(fields);
        self.push(OP_PROJECT, 0, &payload)
    }

    pub fn join(
        &mut self,
        left: u16,
        right: u16,
        left_field: u32,
        right_field: u32,
        kind: JoinKind,
    ) -> Result<u16, IsaError> {
        self.push(
            OP_JOIN,
            kind as u8,
            &[u32::from(left), u32::from(right), left_field, right_field],
        )
    }

    pub fn aggregate(
        &mut self,
        input: u16,
        field: u32,
        function: AggregateFunction,
    ) -> Result<u16, IsaError> {
        self.push(OP_AGGREGATE, function as u8, &[u32::from(input), field])
    }

    pub fn sort(&mut self, input: u16, terms: &[SortTerm]) -> Result<u16, IsaError> {
        let mut payload = Vec::with_capacity(terms.len() * 2 + 2);
        payload.push(u32::from(input));
        payload.push(u32::try_from(terms.len()).map_err(|_| IsaError::InstructionLimitExceeded)?);
        for term in terms {
            payload.push(term.field);
            payload.push(term.direction as u32);
        }
        self.push(OP_SORT, 0, &payload)
    }

    pub fn limit(&mut self, input: u16, parameter: u16) -> Result<u16, IsaError> {
        self.push(OP_LIMIT, 0, &[u32::from(input), u32::from(parameter)])
    }

    pub fn return_result(&mut self, input: u16) -> Result<u16, IsaError> {
        self.push(OP_RETURN, 0, &[u32::from(input)])
    }

    pub fn finish(self) -> Result<Vec<u8>, IsaError> {
        if self.instruction_count == 0 {
            return Err(IsaError::MissingReturn);
        }
        let parameter_bytes = self
            .parameters
            .len()
            .checked_mul(PARAMETER_BYTES)
            .ok_or(IsaError::ProgramTooLarge)?;
        let complete_bytes = HEADER_BYTES
            .checked_add(parameter_bytes)
            .and_then(|value| value.checked_add(self.instructions.len()))
            .ok_or(IsaError::ProgramTooLarge)?;
        if complete_bytes > MAX_PROGRAM_BYTES {
            return Err(IsaError::ProgramTooLarge);
        }
        let mut program = Vec::with_capacity(complete_bytes);
        program.extend_from_slice(&MAGIC);
        program.push(VERSION_MAJOR);
        program.push(VERSION_MINOR);
        program.extend_from_slice(&0_u16.to_le_bytes());
        program.extend_from_slice(
            &u32::try_from(complete_bytes)
                .map_err(|_| IsaError::ProgramTooLarge)?
                .to_le_bytes(),
        );
        program.extend_from_slice(&self.instruction_count.to_le_bytes());
        program.extend_from_slice(
            &u16::try_from(self.parameters.len())
                .map_err(|_| IsaError::ParameterLimitExceeded)?
                .to_le_bytes(),
        );
        program.extend_from_slice(&self.declared_work_units.to_le_bytes());
        program.extend_from_slice(&[0; 12]);
        program.extend_from_slice(&self.schema_digest);
        for parameter in self.parameters {
            program.push(parameter.scalar_type as u8);
            program.push(0);
            program.extend_from_slice(&0_u16.to_le_bytes());
            program.extend_from_slice(&parameter.maximum_bytes.to_le_bytes());
        }
        program.extend_from_slice(&self.instructions);
        Ok(program)
    }

    fn push(&mut self, opcode: u8, flags: u8, payload: &[u32]) -> Result<u16, IsaError> {
        if usize::from(self.instruction_count) >= MAX_INSTRUCTIONS {
            return Err(IsaError::InstructionLimitExceeded);
        }
        let payload_words =
            u16::try_from(payload.len()).map_err(|_| IsaError::InstructionLimitExceeded)?;
        let added_bytes = INSTRUCTION_HEADER_BYTES
            .checked_add(
                payload
                    .len()
                    .checked_mul(4)
                    .ok_or(IsaError::ProgramTooLarge)?,
            )
            .ok_or(IsaError::ProgramTooLarge)?;
        let complete_bytes = HEADER_BYTES
            .checked_add(self.parameters.len() * PARAMETER_BYTES)
            .and_then(|value| value.checked_add(self.instructions.len()))
            .and_then(|value| value.checked_add(added_bytes))
            .ok_or(IsaError::ProgramTooLarge)?;
        if complete_bytes > MAX_PROGRAM_BYTES {
            return Err(IsaError::ProgramTooLarge);
        }
        self.instructions.push(opcode);
        self.instructions.push(flags);
        self.instructions
            .extend_from_slice(&payload_words.to_le_bytes());
        self.instructions.extend_from_slice(&0_u32.to_le_bytes());
        for value in payload {
            self.instructions.extend_from_slice(&value.to_le_bytes());
        }
        self.instruction_count = self
            .instruction_count
            .checked_add(1)
            .ok_or(IsaError::InstructionLimitExceeded)?;
        Ok(self.instruction_count)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyLimits {
    pub maximum_program_bytes: usize,
    pub maximum_instructions: usize,
    pub maximum_parameters: usize,
    pub maximum_projection_fields: usize,
    pub maximum_sort_terms: usize,
    pub maximum_work_units: u32,
}

impl Default for VerifyLimits {
    fn default() -> Self {
        Self {
            maximum_program_bytes: MAX_PROGRAM_BYTES,
            maximum_instructions: MAX_INSTRUCTIONS,
            maximum_parameters: MAX_PARAMETERS,
            maximum_projection_fields: 4_096,
            maximum_sort_terms: 4_096,
            maximum_work_units: 65_536,
        }
    }
}

#[derive(Clone)]
enum RegisterShape {
    RowSet(Arc<[VisibleField]>),
    Scalar(ScalarType),
    Returned,
}

impl RegisterShape {
    fn is_returnable(&self) -> bool {
        match self {
            Self::RowSet(_) => true,
            Self::Scalar(scalar_type) => matches!(
                scalar_type,
                ScalarType::Bool
                    | ScalarType::I64
                    | ScalarType::U64
                    | ScalarType::F64
                    | ScalarType::Bytes
                    | ScalarType::Utf8
                    | ScalarType::TimestampMicros
            ),
            Self::Returned => false,
        }
    }
}

#[derive(Clone, Copy)]
struct VisibleField {
    handle: u32,
    scalar_type: ScalarType,
}

#[derive(Debug)]
pub struct VerifiedProgram<'a> {
    bytes: &'a [u8],
    digest: [u8; 32],
    instruction_count: u16,
    parameter_count: u16,
    declared_work_units: u32,
    instruction_offset: usize,
}

#[derive(Clone, Debug)]
pub struct OwnedVerifiedProgram {
    bytes: Vec<u8>,
    digest: [u8; 32],
    instruction_count: u16,
    parameter_count: u16,
    declared_work_units: u32,
    instruction_offset: usize,
}

impl OwnedVerifiedProgram {
    pub fn from_verified(program: &VerifiedProgram<'_>) -> Result<Self, IsaError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(program.bytes.len())
            .map_err(|_| IsaError::ProgramTooLarge)?;
        bytes.extend_from_slice(program.bytes);
        Ok(Self {
            bytes,
            digest: program.digest,
            instruction_count: program.instruction_count,
            parameter_count: program.parameter_count,
            declared_work_units: program.declared_work_units,
            instruction_offset: program.instruction_offset,
        })
    }

    pub fn as_verified(&self) -> VerifiedProgram<'_> {
        VerifiedProgram {
            bytes: &self.bytes,
            digest: self.digest,
            instruction_count: self.instruction_count,
            parameter_count: self.parameter_count,
            declared_work_units: self.declared_work_units,
            instruction_offset: self.instruction_offset,
        }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl VerifiedProgram<'_> {
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn schema_digest(&self) -> [u8; 32] {
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&self.bytes[32..64]);
        digest
    }

    pub fn instruction_count(&self) -> u16 {
        self.instruction_count
    }

    pub fn parameter_count(&self) -> u16 {
        self.parameter_count
    }

    pub fn declared_work_units(&self) -> u32 {
        self.declared_work_units
    }

    pub fn parameter(&self, index: u16) -> Result<ParameterDescriptor, IsaError> {
        if index >= self.parameter_count {
            return Err(IsaError::UnknownParameter);
        }
        decode_parameter(self.bytes, usize::from(index))
    }

    pub fn instructions(&self) -> InstructionIter<'_> {
        InstructionIter {
            bytes: self.bytes,
            offset: self.instruction_offset,
            remaining: self.instruction_count,
        }
    }
}

pub fn verify_program<'a>(
    bytes: &'a [u8],
    schema: &Schema,
    granted_capabilities: u64,
    limits: VerifyLimits,
) -> Result<VerifiedProgram<'a>, IsaError> {
    if bytes.len() < HEADER_BYTES
        || bytes.len() > MAX_PROGRAM_BYTES
        || bytes.len() > limits.maximum_program_bytes
    {
        return Err(IsaError::ProgramTooLarge);
    }
    if bytes[0..4] != MAGIC {
        return Err(IsaError::InvalidMagic);
    }
    if bytes[4] != VERSION_MAJOR || bytes[5] != VERSION_MINOR {
        return Err(IsaError::UnsupportedVersion);
    }
    if get_u16(bytes, 6)? != 0 || bytes[20..32] != [0; 12] {
        return Err(IsaError::NonCanonicalProgram);
    }
    let complete_bytes =
        usize::try_from(get_u32(bytes, 8)?).map_err(|_| IsaError::ProgramTooLarge)?;
    if complete_bytes != bytes.len() {
        return Err(IsaError::LengthMismatch);
    }
    let instruction_count = get_u16(bytes, 12)?;
    let parameter_count = get_u16(bytes, 14)?;
    let declared_work_units = get_u32(bytes, 16)?;
    if instruction_count == 0
        || usize::from(instruction_count) > MAX_INSTRUCTIONS
        || usize::from(instruction_count) > limits.maximum_instructions
    {
        return Err(IsaError::InstructionLimitExceeded);
    }
    if usize::from(parameter_count) > MAX_PARAMETERS
        || usize::from(parameter_count) > limits.maximum_parameters
    {
        return Err(IsaError::ParameterLimitExceeded);
    }
    if declared_work_units == 0 || declared_work_units > limits.maximum_work_units {
        return Err(IsaError::WorkLimitExceeded);
    }
    if bytes[32..64] != schema.digest {
        return Err(IsaError::SchemaMismatch);
    }
    let parameter_bytes = usize::from(parameter_count)
        .checked_mul(PARAMETER_BYTES)
        .ok_or(IsaError::ProgramTooLarge)?;
    let instruction_offset = HEADER_BYTES
        .checked_add(parameter_bytes)
        .ok_or(IsaError::ProgramTooLarge)?;
    if instruction_offset > bytes.len() {
        return Err(IsaError::LengthMismatch);
    }
    let mut parameters = Vec::with_capacity(usize::from(parameter_count));
    for index in 0..usize::from(parameter_count) {
        parameters.push(decode_parameter(bytes, index)?);
    }

    let mut registers = Vec::with_capacity(usize::from(instruction_count));
    let mut iterator = InstructionIter {
        bytes,
        offset: instruction_offset,
        remaining: instruction_count,
    };
    let mut computed_work = 0_u32;
    let mut return_count = 0_u16;
    for instruction_index in 0..instruction_count {
        let instruction = iterator.next().ok_or(IsaError::LengthMismatch)??;
        let current_register = instruction_index + 1;
        let shape = match instruction {
            Instruction::Scan { relation } => {
                let relation = schema.relation(relation).ok_or(IsaError::UnknownRelation)?;
                require_capabilities(relation.required_capabilities, granted_capabilities)?;
                let mut fields = Vec::with_capacity(relation.fields.len());
                for field in &relation.fields {
                    require_capabilities(field.required_capabilities, granted_capabilities)?;
                    fields.push(VisibleField {
                        handle: field.handle,
                        scalar_type: field.scalar_type,
                    });
                }
                computed_work = add_work(computed_work, 1)?;
                RegisterShape::RowSet(fields.into())
            }
            Instruction::Filter {
                input,
                field,
                comparison,
                parameter,
            } => {
                let fields = row_set(&registers, input, current_register)?;
                let field_type = visible_field(&fields, field)?.scalar_type;
                let parameter_type = parameters
                    .get(usize::from(parameter))
                    .ok_or(IsaError::UnknownParameter)?
                    .scalar_type;
                if field_type != parameter_type
                    || (comparison.is_ordered() && !field_type.is_ordered())
                {
                    return Err(IsaError::TypeMismatch);
                }
                computed_work = add_work(computed_work, 1)?;
                RegisterShape::RowSet(fields)
            }
            Instruction::Project { input, fields } => {
                let input_fields = row_set(&registers, input, current_register)?;
                if fields.is_empty() || fields.len() > limits.maximum_projection_fields {
                    return Err(IsaError::InstructionLimitExceeded);
                }
                let mut projected = Vec::with_capacity(fields.len());
                let mut previous = None;
                for field in fields.iter() {
                    let field = field?;
                    if previous.is_some_and(|value| value >= field) {
                        return Err(IsaError::NonCanonicalProgram);
                    }
                    previous = Some(field);
                    projected.push(*visible_field(&input_fields, field)?);
                }
                computed_work = add_work(
                    computed_work,
                    u32::try_from(projected.len()).map_err(|_| IsaError::WorkLimitExceeded)?,
                )?;
                RegisterShape::RowSet(projected.into())
            }
            Instruction::Join {
                left,
                right,
                left_field,
                right_field,
                kind: _,
            } => {
                let left_fields = row_set(&registers, left, current_register)?;
                let right_fields = row_set(&registers, right, current_register)?;
                if visible_field(&left_fields, left_field)?.scalar_type
                    != visible_field(&right_fields, right_field)?.scalar_type
                {
                    return Err(IsaError::TypeMismatch);
                }
                let mut joined = Vec::with_capacity(left_fields.len() + right_fields.len());
                joined.extend_from_slice(&left_fields);
                joined.extend_from_slice(&right_fields);
                joined.sort_unstable_by_key(|field| field.handle);
                if joined
                    .windows(2)
                    .any(|pair| pair[0].handle == pair[1].handle)
                {
                    return Err(IsaError::DuplicateHandle);
                }
                computed_work = add_work(computed_work, 2)?;
                RegisterShape::RowSet(joined.into())
            }
            Instruction::Aggregate {
                input,
                field,
                function,
            } => {
                let fields = row_set(&registers, input, current_register)?;
                let scalar_type = visible_field(&fields, field)?.scalar_type;
                let result_type = match function {
                    AggregateFunction::Count => ScalarType::U64,
                    AggregateFunction::Sum if scalar_type.is_numeric() => scalar_type,
                    AggregateFunction::Minimum | AggregateFunction::Maximum
                        if scalar_type.is_ordered() =>
                    {
                        scalar_type
                    }
                    AggregateFunction::Average if scalar_type.is_numeric() => ScalarType::F64,
                    _ => return Err(IsaError::TypeMismatch),
                };
                computed_work = add_work(computed_work, 1)?;
                RegisterShape::Scalar(result_type)
            }
            Instruction::Sort { input, terms } => {
                let fields = row_set(&registers, input, current_register)?;
                if terms.is_empty() || terms.len() > limits.maximum_sort_terms {
                    return Err(IsaError::InstructionLimitExceeded);
                }
                let mut seen = HashSet::with_capacity(terms.len());
                for term in terms.iter() {
                    let term = term?;
                    if !seen.insert(term.field)
                        || !visible_field(&fields, term.field)?.scalar_type.is_ordered()
                    {
                        return Err(IsaError::TypeMismatch);
                    }
                }
                computed_work = add_work(
                    computed_work,
                    u32::try_from(terms.len()).map_err(|_| IsaError::WorkLimitExceeded)?,
                )?;
                RegisterShape::RowSet(fields)
            }
            Instruction::Limit { input, parameter } => {
                let fields = row_set(&registers, input, current_register)?;
                if parameters
                    .get(usize::from(parameter))
                    .ok_or(IsaError::UnknownParameter)?
                    .scalar_type
                    != ScalarType::U64
                {
                    return Err(IsaError::TypeMismatch);
                }
                computed_work = add_work(computed_work, 1)?;
                RegisterShape::RowSet(fields)
            }
            Instruction::Return { input } => {
                let shape = register(&registers, input, current_register)?;
                if !shape.is_returnable() {
                    return Err(IsaError::InvalidRegister);
                }
                return_count = return_count
                    .checked_add(1)
                    .ok_or(IsaError::InstructionLimitExceeded)?;
                if current_register != instruction_count {
                    return Err(IsaError::MissingReturn);
                }
                computed_work = add_work(computed_work, 1)?;
                RegisterShape::Returned
            }
        };
        registers.push(shape);
    }
    if iterator.offset != bytes.len() || return_count != 1 {
        return Err(IsaError::MissingReturn);
    }
    if computed_work > declared_work_units {
        return Err(IsaError::WorkLimitExceeded);
    }
    let mut digest = blake3::Hasher::new();
    digest.update(PROGRAM_DOMAIN);
    digest.update(bytes);
    Ok(VerifiedProgram {
        bytes,
        digest: *digest.finalize().as_bytes(),
        instruction_count,
        parameter_count,
        declared_work_units,
        instruction_offset,
    })
}

fn add_work(current: u32, amount: u32) -> Result<u32, IsaError> {
    current
        .checked_add(amount)
        .ok_or(IsaError::WorkLimitExceeded)
}

fn require_capabilities(required: u64, granted: u64) -> Result<(), IsaError> {
    if required & granted != required {
        return Err(IsaError::CapabilityMismatch);
    }
    Ok(())
}

fn register(
    registers: &[RegisterShape],
    input: u16,
    current_register: u16,
) -> Result<RegisterShape, IsaError> {
    if input == 0 || input >= current_register {
        return Err(IsaError::InvalidRegister);
    }
    registers
        .get(usize::from(input - 1))
        .cloned()
        .ok_or(IsaError::InvalidRegister)
}

fn row_set(
    registers: &[RegisterShape],
    input: u16,
    current_register: u16,
) -> Result<Arc<[VisibleField]>, IsaError> {
    match register(registers, input, current_register)? {
        RegisterShape::RowSet(fields) => Ok(fields),
        RegisterShape::Scalar(_) | RegisterShape::Returned => Err(IsaError::TypeMismatch),
    }
}

fn visible_field(fields: &[VisibleField], handle: u32) -> Result<&VisibleField, IsaError> {
    fields
        .binary_search_by_key(&handle, |field| field.handle)
        .ok()
        .map(|index| &fields[index])
        .ok_or(IsaError::UnknownField)
}

fn validate_parameter_width(scalar_type: ScalarType, maximum_bytes: u32) -> Result<(), IsaError> {
    if let Some(width) = scalar_type.fixed_width() {
        if maximum_bytes != width {
            return Err(IsaError::InvalidParameterWidth);
        }
    } else if maximum_bytes == 0 || maximum_bytes > MAX_VARIABLE_VALUE_BYTES {
        return Err(IsaError::InvalidParameterWidth);
    }
    Ok(())
}

fn decode_parameter(bytes: &[u8], index: usize) -> Result<ParameterDescriptor, IsaError> {
    let offset = HEADER_BYTES
        .checked_add(
            index
                .checked_mul(PARAMETER_BYTES)
                .ok_or(IsaError::ProgramTooLarge)?,
        )
        .ok_or(IsaError::ProgramTooLarge)?;
    let end = offset
        .checked_add(PARAMETER_BYTES)
        .ok_or(IsaError::ProgramTooLarge)?;
    let descriptor = bytes.get(offset..end).ok_or(IsaError::LengthMismatch)?;
    if descriptor[1] != 0 || descriptor[2..4] != [0; 2] {
        return Err(IsaError::NonCanonicalProgram);
    }
    ParameterDescriptor::new(ScalarType::decode(descriptor[0])?, get_u32(descriptor, 4)?)
}

#[derive(Clone, Copy, Debug)]
pub enum Instruction<'a> {
    Scan {
        relation: u32,
    },
    Filter {
        input: u16,
        field: u32,
        comparison: Comparison,
        parameter: u16,
    },
    Project {
        input: u16,
        fields: WordList<'a>,
    },
    Join {
        left: u16,
        right: u16,
        left_field: u32,
        right_field: u32,
        kind: JoinKind,
    },
    Aggregate {
        input: u16,
        field: u32,
        function: AggregateFunction,
    },
    Sort {
        input: u16,
        terms: SortTermList<'a>,
    },
    Limit {
        input: u16,
        parameter: u16,
    },
    Return {
        input: u16,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct WordList<'a> {
    bytes: &'a [u8],
    len: usize,
}

impl<'a> WordList<'a> {
    pub fn len(self) -> usize {
        self.len
    }

    pub fn is_empty(self) -> bool {
        self.len == 0
    }

    pub fn iter(self) -> WordIter<'a> {
        WordIter {
            bytes: self.bytes,
            remaining: self.len,
        }
    }
}

pub struct WordIter<'a> {
    bytes: &'a [u8],
    remaining: usize,
}

impl Iterator for WordIter<'_> {
    type Item = Result<u32, IsaError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let word = get_u32(self.bytes, 0);
        self.bytes = self.bytes.get(4..).unwrap_or_default();
        Some(word)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for WordIter<'_> {}

#[derive(Clone, Copy, Debug)]
pub struct SortTermList<'a> {
    bytes: &'a [u8],
    len: usize,
}

impl<'a> SortTermList<'a> {
    pub fn len(self) -> usize {
        self.len
    }

    pub fn is_empty(self) -> bool {
        self.len == 0
    }

    pub fn iter(self) -> SortTermIter<'a> {
        SortTermIter {
            bytes: self.bytes,
            remaining: self.len,
        }
    }
}

pub struct SortTermIter<'a> {
    bytes: &'a [u8],
    remaining: usize,
}

impl Iterator for SortTermIter<'_> {
    type Item = Result<SortTerm, IsaError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let result = (|| {
            Ok(SortTerm {
                field: get_u32(self.bytes, 0)?,
                direction: SortDirection::decode(get_u32(self.bytes, 4)?)?,
            })
        })();
        self.bytes = self.bytes.get(8..).unwrap_or_default();
        Some(result)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for SortTermIter<'_> {}

pub struct InstructionIter<'a> {
    bytes: &'a [u8],
    offset: usize,
    remaining: u16,
}

impl<'a> Iterator for InstructionIter<'a> {
    type Item = Result<Instruction<'a>, IsaError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(decode_instruction(self.bytes, &mut self.offset))
    }
}

fn decode_instruction<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
) -> Result<Instruction<'a>, IsaError> {
    let header_end = offset
        .checked_add(INSTRUCTION_HEADER_BYTES)
        .ok_or(IsaError::ProgramTooLarge)?;
    let header = bytes
        .get(*offset..header_end)
        .ok_or(IsaError::LengthMismatch)?;
    if header[4..8] != [0; 4] {
        return Err(IsaError::NonCanonicalProgram);
    }
    let opcode = header[0];
    let flags = header[1];
    let word_count = usize::from(get_u16(header, 2)?);
    let payload_bytes = word_count.checked_mul(4).ok_or(IsaError::ProgramTooLarge)?;
    let payload_end = header_end
        .checked_add(payload_bytes)
        .ok_or(IsaError::ProgramTooLarge)?;
    let payload = bytes
        .get(header_end..payload_end)
        .ok_or(IsaError::LengthMismatch)?;
    *offset = payload_end;
    match opcode {
        OP_SCAN if flags == 0 && word_count == 1 => Ok(Instruction::Scan {
            relation: word(payload, 0)?,
        }),
        OP_FILTER if word_count == 3 => Ok(Instruction::Filter {
            input: narrow_u16(word(payload, 0)?)?,
            field: word(payload, 1)?,
            comparison: Comparison::decode(flags)?,
            parameter: narrow_u16(word(payload, 2)?)?,
        }),
        OP_PROJECT if flags == 0 && word_count >= 3 => {
            let count = usize::try_from(word(payload, 1)?)
                .map_err(|_| IsaError::InstructionLimitExceeded)?;
            if count == 0 || word_count != count + 2 {
                return Err(IsaError::NonCanonicalProgram);
            }
            Ok(Instruction::Project {
                input: narrow_u16(word(payload, 0)?)?,
                fields: WordList {
                    bytes: &payload[8..],
                    len: count,
                },
            })
        }
        OP_JOIN if word_count == 4 => Ok(Instruction::Join {
            left: narrow_u16(word(payload, 0)?)?,
            right: narrow_u16(word(payload, 1)?)?,
            left_field: word(payload, 2)?,
            right_field: word(payload, 3)?,
            kind: JoinKind::decode(flags)?,
        }),
        OP_AGGREGATE if word_count == 2 => Ok(Instruction::Aggregate {
            input: narrow_u16(word(payload, 0)?)?,
            field: word(payload, 1)?,
            function: AggregateFunction::decode(flags)?,
        }),
        OP_SORT if flags == 0 && word_count >= 4 => {
            let count = usize::try_from(word(payload, 1)?)
                .map_err(|_| IsaError::InstructionLimitExceeded)?;
            let expected = count
                .checked_mul(2)
                .and_then(|value| value.checked_add(2))
                .ok_or(IsaError::InstructionLimitExceeded)?;
            if count == 0 || word_count != expected {
                return Err(IsaError::NonCanonicalProgram);
            }
            Ok(Instruction::Sort {
                input: narrow_u16(word(payload, 0)?)?,
                terms: SortTermList {
                    bytes: &payload[8..],
                    len: count,
                },
            })
        }
        OP_LIMIT if flags == 0 && word_count == 2 => Ok(Instruction::Limit {
            input: narrow_u16(word(payload, 0)?)?,
            parameter: narrow_u16(word(payload, 1)?)?,
        }),
        OP_RETURN if flags == 0 && word_count == 1 => Ok(Instruction::Return {
            input: narrow_u16(word(payload, 0)?)?,
        }),
        OP_SCAN | OP_FILTER | OP_PROJECT | OP_JOIN | OP_AGGREGATE | OP_SORT | OP_LIMIT
        | OP_RETURN => Err(IsaError::NonCanonicalProgram),
        _ => Err(IsaError::UnknownOpcode),
    }
}

fn narrow_u16(value: u32) -> Result<u16, IsaError> {
    u16::try_from(value).map_err(|_| IsaError::NonCanonicalProgram)
}

fn word(bytes: &[u8], index: usize) -> Result<u32, IsaError> {
    get_u32(
        bytes,
        index.checked_mul(4).ok_or(IsaError::ProgramTooLarge)?,
    )
}

fn get_u16(bytes: &[u8], offset: usize) -> Result<u16, IsaError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(IsaError::LengthMismatch)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn get_u32(bytes: &[u8], offset: usize) -> Result<u32, IsaError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(IsaError::LengthMismatch)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ParameterValue<'a> {
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    Bytes(&'a [u8]),
    Utf8(&'a str),
    TimestampMicros(i64),
}

impl ParameterValue<'_> {
    pub fn scalar_type(self) -> ScalarType {
        match self {
            Self::Bool(_) => ScalarType::Bool,
            Self::I64(_) => ScalarType::I64,
            Self::U64(_) => ScalarType::U64,
            Self::F64(_) => ScalarType::F64,
            Self::Bytes(_) => ScalarType::Bytes,
            Self::Utf8(_) => ScalarType::Utf8,
            Self::TimestampMicros(_) => ScalarType::TimestampMicros,
        }
    }
}

pub struct OperandBuilder<'program, 'bytes> {
    program: &'program VerifiedProgram<'bytes>,
    values: Vec<u8>,
    count: u16,
}

impl<'program, 'bytes> OperandBuilder<'program, 'bytes> {
    pub fn new(program: &'program VerifiedProgram<'bytes>) -> Self {
        Self {
            program,
            values: Vec::new(),
            count: 0,
        }
    }

    pub fn push(&mut self, value: ParameterValue<'_>) -> Result<(), IsaError> {
        let descriptor = self.program.parameter(self.count)?;
        if descriptor.scalar_type != value.scalar_type() {
            return Err(IsaError::TypeMismatch);
        }
        let encoded_len = parameter_value_len(value)?;
        if encoded_len > descriptor.maximum_bytes as usize {
            return Err(IsaError::OperandValueInvalid);
        }
        let next_len = self
            .values
            .len()
            .checked_add(4)
            .and_then(|length| length.checked_add(encoded_len))
            .and_then(|length| length.checked_add(OPERAND_HEADER_BYTES))
            .ok_or(IsaError::ProgramTooLarge)?;
        if next_len > MAX_PROGRAM_BYTES {
            return Err(IsaError::ProgramTooLarge);
        }
        self.values.extend_from_slice(
            &u32::try_from(encoded_len)
                .map_err(|_| IsaError::OperandValueInvalid)?
                .to_le_bytes(),
        );
        match value {
            ParameterValue::Bool(value) => self.values.push(u8::from(value)),
            ParameterValue::I64(value) | ParameterValue::TimestampMicros(value) => {
                self.values.extend_from_slice(&value.to_le_bytes());
            }
            ParameterValue::U64(value) => {
                self.values.extend_from_slice(&value.to_le_bytes());
            }
            ParameterValue::F64(value) => {
                let canonical = if value == 0.0 { 0.0 } else { value };
                self.values
                    .extend_from_slice(&canonical.to_bits().to_le_bytes());
            }
            ParameterValue::Bytes(value) => self.values.extend_from_slice(value),
            ParameterValue::Utf8(value) => self.values.extend_from_slice(value.as_bytes()),
        }
        self.count = self
            .count
            .checked_add(1)
            .ok_or(IsaError::OperandCountMismatch)?;
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<u8>, IsaError> {
        if self.count != self.program.parameter_count {
            return Err(IsaError::OperandCountMismatch);
        }
        let complete_bytes = OPERAND_HEADER_BYTES
            .checked_add(self.values.len())
            .ok_or(IsaError::ProgramTooLarge)?;
        if complete_bytes > MAX_PROGRAM_BYTES {
            return Err(IsaError::ProgramTooLarge);
        }
        let mut operands = Vec::with_capacity(complete_bytes);
        operands.extend_from_slice(&OPERAND_MAGIC);
        operands.push(VERSION_MAJOR);
        operands.push(VERSION_MINOR);
        operands.extend_from_slice(&0_u16.to_le_bytes());
        operands.extend_from_slice(
            &u32::try_from(complete_bytes)
                .map_err(|_| IsaError::ProgramTooLarge)?
                .to_le_bytes(),
        );
        operands.extend_from_slice(&self.count.to_le_bytes());
        operands.extend_from_slice(&[0; 18]);
        operands.extend_from_slice(&self.program.digest);
        operands.extend_from_slice(&self.values);
        Ok(operands)
    }
}

fn parameter_value_len(value: ParameterValue<'_>) -> Result<usize, IsaError> {
    match value {
        ParameterValue::Bool(_) => Ok(1),
        ParameterValue::I64(_) | ParameterValue::U64(_) | ParameterValue::TimestampMicros(_) => {
            Ok(8)
        }
        ParameterValue::F64(value) => {
            if !value.is_finite() {
                return Err(IsaError::OperandValueInvalid);
            }
            Ok(8)
        }
        ParameterValue::Bytes(value) => Ok(value.len()),
        ParameterValue::Utf8(value) => Ok(value.len()),
    }
}

#[derive(Debug)]
pub struct VerifiedOperands<'a> {
    bytes: &'a [u8],
    values_offset: usize,
    digest: [u8; 32],
    program_digest: [u8; 32],
    spans: SmallVec<[(usize, usize); 8]>,
    descriptors: SmallVec<[ParameterDescriptor; 8]>,
}

impl VerifiedOperands<'_> {
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    pub fn complete_block_bytes(&self) -> Option<&[u8]> {
        (self.values_offset == OPERAND_HEADER_BYTES).then_some(self.bytes)
    }

    pub fn compact_bytes(&self) -> &[u8] {
        &self.bytes[self.values_offset..]
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn program_digest(&self) -> [u8; 32] {
        self.program_digest
    }

    pub fn len(&self) -> usize {
        self.spans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    pub fn value(&self, index: u16) -> Result<ParameterValue<'_>, IsaError> {
        let (start, end) = *self
            .spans
            .get(usize::from(index))
            .ok_or(IsaError::UnknownParameter)?;
        let descriptor = *self
            .descriptors
            .get(usize::from(index))
            .ok_or(IsaError::UnknownParameter)?;
        decode_parameter_value(descriptor.scalar_type, &self.bytes[start..end])
    }
}

pub fn verify_operands<'a>(
    bytes: &'a [u8],
    program: &VerifiedProgram<'_>,
) -> Result<VerifiedOperands<'a>, IsaError> {
    if bytes.len() < OPERAND_HEADER_BYTES || bytes.len() > MAX_PROGRAM_BYTES {
        return Err(IsaError::ProgramTooLarge);
    }
    if bytes[0..4] != OPERAND_MAGIC {
        return Err(IsaError::InvalidMagic);
    }
    if bytes[4] != VERSION_MAJOR || bytes[5] != VERSION_MINOR {
        return Err(IsaError::UnsupportedVersion);
    }
    if get_u16(bytes, 6)? != 0 || bytes[14..32] != [0; 18] {
        return Err(IsaError::NonCanonicalProgram);
    }
    if usize::try_from(get_u32(bytes, 8)?).map_err(|_| IsaError::ProgramTooLarge)? != bytes.len() {
        return Err(IsaError::LengthMismatch);
    }
    let count = get_u16(bytes, 12)?;
    if count != program.parameter_count {
        return Err(IsaError::OperandCountMismatch);
    }
    if bytes[32..64] != program.digest {
        return Err(IsaError::OperandDigestMismatch);
    }
    verify_operand_values(bytes, OPERAND_HEADER_BYTES, program, OPERAND_DOMAIN)
}

pub fn verify_compact_operands<'a>(
    bytes: &'a [u8],
    program: &VerifiedProgram<'_>,
) -> Result<VerifiedOperands<'a>, IsaError> {
    if bytes.len() > MAX_PROGRAM_BYTES {
        return Err(IsaError::ProgramTooLarge);
    }
    verify_operand_values(bytes, 0, program, COMPACT_OPERAND_DOMAIN)
}

fn verify_operand_values<'a>(
    bytes: &'a [u8],
    values_offset: usize,
    program: &VerifiedProgram<'_>,
    digest_domain: &[u8],
) -> Result<VerifiedOperands<'a>, IsaError> {
    let mut offset = values_offset;
    let mut spans = SmallVec::with_capacity(usize::from(program.parameter_count()));
    let mut descriptors = SmallVec::with_capacity(usize::from(program.parameter_count()));
    for index in 0..program.parameter_count() {
        let descriptor = program.parameter(index)?;
        let length =
            usize::try_from(get_u32(bytes, offset)?).map_err(|_| IsaError::OperandValueInvalid)?;
        offset = offset.checked_add(4).ok_or(IsaError::ProgramTooLarge)?;
        let end = offset
            .checked_add(length)
            .ok_or(IsaError::ProgramTooLarge)?;
        let value = bytes.get(offset..end).ok_or(IsaError::LengthMismatch)?;
        if length > descriptor.maximum_bytes as usize {
            return Err(IsaError::OperandValueInvalid);
        }
        decode_parameter_value(descriptor.scalar_type, value)?;
        spans.push((offset, end));
        descriptors.push(descriptor);
        offset = end;
    }
    if offset != bytes.len() {
        return Err(IsaError::LengthMismatch);
    }
    let mut digest = blake3::Hasher::new();
    digest.update(digest_domain);
    digest.update(&program.digest);
    digest.update(bytes);
    Ok(VerifiedOperands {
        bytes,
        values_offset,
        digest: *digest.finalize().as_bytes(),
        program_digest: program.digest,
        spans,
        descriptors,
    })
}

fn decode_parameter_value(
    scalar_type: ScalarType,
    bytes: &[u8],
) -> Result<ParameterValue<'_>, IsaError> {
    match scalar_type {
        ScalarType::Bool if bytes.len() == 1 && bytes[0] <= 1 => {
            Ok(ParameterValue::Bool(bytes[0] == 1))
        }
        ScalarType::I64 if bytes.len() == 8 => Ok(ParameterValue::I64(i64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| IsaError::OperandValueInvalid)?,
        ))),
        ScalarType::U64 if bytes.len() == 8 => Ok(ParameterValue::U64(u64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| IsaError::OperandValueInvalid)?,
        ))),
        ScalarType::F64 if bytes.len() == 8 => {
            let bits = u64::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| IsaError::OperandValueInvalid)?,
            );
            let value = f64::from_bits(bits);
            if !value.is_finite() || bits == (-0.0_f64).to_bits() {
                return Err(IsaError::OperandValueInvalid);
            }
            Ok(ParameterValue::F64(value))
        }
        ScalarType::Bytes => Ok(ParameterValue::Bytes(bytes)),
        ScalarType::Utf8 => Ok(ParameterValue::Utf8(
            std::str::from_utf8(bytes).map_err(|_| IsaError::OperandValueInvalid)?,
        )),
        ScalarType::TimestampMicros if bytes.len() == 8 => {
            Ok(ParameterValue::TimestampMicros(i64::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| IsaError::OperandValueInvalid)?,
            )))
        }
        _ => Err(IsaError::OperandValueInvalid),
    }
}

pub struct ProgramCache<T> {
    scope_digest: [u8; 32],
    capacity: usize,
    next_handle: u32,
    by_digest: HashMap<[u8; 32], u32>,
    entries: HashMap<u32, CacheEntry<T>>,
}

struct CacheEntry<T> {
    cache_digest: [u8; 32],
    value: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Promotion {
    pub handle: u32,
    pub inserted: bool,
}

impl<T> ProgramCache<T> {
    pub fn new(scope_digest: [u8; 32], capacity: usize) -> Result<Self, IsaError> {
        if scope_digest == [0; 32] {
            return Err(IsaError::CacheScopeMismatch);
        }
        if capacity == 0 || capacity > MAX_CACHE_ENTRIES {
            return Err(IsaError::CacheLimitExceeded);
        }
        Ok(Self {
            scope_digest,
            capacity,
            next_handle: 1,
            by_digest: HashMap::with_capacity(capacity),
            entries: HashMap::with_capacity(capacity),
        })
    }

    pub fn promote(
        &mut self,
        program: &VerifiedProgram<'_>,
        value: T,
    ) -> Result<Promotion, IsaError> {
        let cache_digest = scoped_cache_digest(self.scope_digest, program.digest);
        if let Some(handle) = self.by_digest.get(&cache_digest) {
            return Ok(Promotion {
                handle: *handle,
                inserted: false,
            });
        }
        if self.entries.len() >= self.capacity {
            return Err(IsaError::CacheLimitExceeded);
        }
        let handle = self.next_handle;
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or(IsaError::CacheLimitExceeded)?;
        if handle == 0 {
            return Err(IsaError::CacheLimitExceeded);
        }
        self.by_digest.insert(cache_digest, handle);
        self.entries.insert(
            handle,
            CacheEntry {
                cache_digest,
                value,
            },
        );
        Ok(Promotion {
            handle,
            inserted: true,
        })
    }

    pub fn resolve(&self, handle: u32, program_digest: [u8; 32]) -> Result<&T, IsaError> {
        let entry = self
            .entries
            .get(&handle)
            .ok_or(IsaError::UnknownCacheHandle)?;
        if entry.cache_digest != scoped_cache_digest(self.scope_digest, program_digest) {
            return Err(IsaError::CacheScopeMismatch);
        }
        Ok(&entry.value)
    }
}

fn scoped_cache_digest(scope_digest: [u8; 32], program_digest: [u8; 32]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(CACHE_DOMAIN);
    digest.update(&scope_digest);
    digest.update(&program_digest);
    *digest.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsaError {
    CacheLimitExceeded,
    CacheScopeMismatch,
    CapabilityMismatch,
    DuplicateHandle,
    EmptyRelation,
    EmptySchema,
    InstructionLimitExceeded,
    InvalidMagic,
    InvalidParameterWidth,
    InvalidRegister,
    LengthMismatch,
    MissingReturn,
    NonCanonicalProgram,
    OperandCountMismatch,
    OperandDigestMismatch,
    OperandValueInvalid,
    ParameterLimitExceeded,
    ProgramTooLarge,
    SchemaLimitExceeded,
    SchemaMismatch,
    TypeMismatch,
    UnknownCacheHandle,
    UnknownField,
    UnknownInstructionFlag,
    UnknownOpcode,
    UnknownParameter,
    UnknownRelation,
    UnknownScalarType,
    UnsupportedVersion,
    WorkLimitExceeded,
    ZeroHandle,
}

impl fmt::Display for IsaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::CacheLimitExceeded => "the program cache limit was exceeded",
            Self::CacheScopeMismatch => "the program cache scope differs",
            Self::CapabilityMismatch => "the program requires an unavailable capability",
            Self::DuplicateHandle => "a numeric handle is duplicated",
            Self::EmptyRelation => "a relation has no field",
            Self::EmptySchema => "the numeric schema has no relation",
            Self::InstructionLimitExceeded => "the instruction limit was exceeded",
            Self::InvalidMagic => "the program magic differs",
            Self::InvalidParameterWidth => "a parameter width is invalid",
            Self::InvalidRegister => "an instruction register is invalid",
            Self::LengthMismatch => "the program length differs",
            Self::MissingReturn => "the program does not have one final return",
            Self::NonCanonicalProgram => "the program encoding is not canonical",
            Self::OperandCountMismatch => "the operand count differs from the program",
            Self::OperandDigestMismatch => "the operands bind a different program",
            Self::OperandValueInvalid => "an operand value is invalid",
            Self::ParameterLimitExceeded => "the parameter limit was exceeded",
            Self::ProgramTooLarge => "the program exceeds its byte limit",
            Self::SchemaLimitExceeded => "the numeric schema exceeds its limit",
            Self::SchemaMismatch => "the program schema differs",
            Self::TypeMismatch => "an instruction type differs",
            Self::UnknownCacheHandle => "the cached program handle is unknown",
            Self::UnknownField => "the field handle is unknown",
            Self::UnknownInstructionFlag => "an instruction flag is unknown",
            Self::UnknownOpcode => "the instruction opcode is unknown",
            Self::UnknownParameter => "the parameter index is unknown",
            Self::UnknownRelation => "the relation handle is unknown",
            Self::UnknownScalarType => "the scalar type is unknown",
            Self::UnsupportedVersion => "the program version is unsupported",
            Self::WorkLimitExceeded => "the program work limit was exceeded",
            Self::ZeroHandle => "a numeric handle is zero",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for IsaError {}

#[cfg(test)]
mod tests {
    use super::*;

    const READ: u64 = 1;

    fn schema() -> Schema {
        Schema::new(vec![
            Relation::new(
                11,
                READ,
                vec![
                    Field::new(101, ScalarType::I64, false, READ).expect("field"),
                    Field::new(102, ScalarType::Utf8, false, READ).expect("field"),
                    Field::new(103, ScalarType::U64, false, READ).expect("field"),
                ],
            )
            .expect("relation"),
            Relation::new(
                12,
                READ,
                vec![
                    Field::new(201, ScalarType::I64, false, READ).expect("field"),
                    Field::new(202, ScalarType::Utf8, false, READ).expect("field"),
                ],
            )
            .expect("relation"),
        ])
        .expect("schema")
    }

    fn dynamic_program(schema: &Schema) -> Vec<u8> {
        let mut builder = ProgramBuilder::new(schema.digest(), 32).expect("builder");
        let filter = builder
            .parameter(ParameterDescriptor::new(ScalarType::I64, 8).expect("parameter"))
            .expect("parameter");
        let limit = builder
            .parameter(ParameterDescriptor::new(ScalarType::U64, 8).expect("parameter"))
            .expect("parameter");
        let scan = builder.scan(11).expect("scan");
        let filtered = builder
            .filter(scan, 101, Comparison::GreaterOrEqual, filter)
            .expect("filter");
        let projected = builder.project(filtered, &[101, 102]).expect("project");
        let sorted = builder
            .sort(
                projected,
                &[SortTerm {
                    field: 101,
                    direction: SortDirection::Descending,
                }],
            )
            .expect("sort");
        let limited = builder.limit(sorted, limit).expect("limit");
        builder.return_result(limited).expect("return");
        builder.finish().expect("program")
    }

    #[test]
    fn dynamic_program_verifies_and_decodes_without_names() {
        let schema = schema();
        let program = dynamic_program(&schema);
        let verified = verify_program(&program, &schema, READ, VerifyLimits::default())
            .expect("verified program");
        assert_eq!(verified.instruction_count(), 6);
        assert_eq!(verified.parameter_count(), 2);
        assert!(!program.windows(6).any(|window| window == b"select"));
        assert!(!program.windows(5).any(|window| window == b"items"));
        assert_eq!(verified.instructions().count(), 6);
    }

    #[test]
    fn every_changed_program_byte_refuses_or_changes_the_program_digest() {
        let schema = schema();
        let program = dynamic_program(&schema);
        let original = verify_program(&program, &schema, READ, VerifyLimits::default())
            .expect("verified program")
            .digest();
        for index in 0..program.len() {
            let mut changed = program.clone();
            changed[index] ^= 1;
            if let Ok(verified) = verify_program(&changed, &schema, READ, VerifyLimits::default()) {
                assert_ne!(verified.digest(), original, "changed byte {index}");
            }
        }
    }

    #[test]
    fn forward_register_and_changed_schema_refuse() {
        let schema = schema();
        let mut program = dynamic_program(&schema);
        let instruction_offset = HEADER_BYTES + 2 * PARAMETER_BYTES;
        let filter_input = instruction_offset + 12 + INSTRUCTION_HEADER_BYTES;
        program[filter_input..filter_input + 4].copy_from_slice(&9_u32.to_le_bytes());
        assert_eq!(
            verify_program(&program, &schema, READ, VerifyLimits::default())
                .expect_err("forward register"),
            IsaError::InvalidRegister
        );

        let other = Schema::new(vec![Relation::new(
            11,
            READ,
            vec![Field::new(999, ScalarType::I64, false, READ).expect("field")],
        )
        .expect("relation")])
        .expect("schema");
        assert_eq!(
            verify_program(
                &dynamic_program(&schema),
                &other,
                READ,
                VerifyLimits::default()
            )
            .expect_err("schema mismatch"),
            IsaError::SchemaMismatch
        );
    }

    #[test]
    fn missing_capability_and_parameter_type_refuse() {
        let schema = schema();
        assert_eq!(
            verify_program(
                &dynamic_program(&schema),
                &schema,
                0,
                VerifyLimits::default()
            )
            .expect_err("capability"),
            IsaError::CapabilityMismatch
        );

        let mut builder = ProgramBuilder::new(schema.digest(), 8).expect("builder");
        let parameter = builder
            .parameter(ParameterDescriptor::new(ScalarType::Utf8, 32).expect("parameter"))
            .expect("parameter");
        let scan = builder.scan(11).expect("scan");
        let filter = builder
            .filter(scan, 101, Comparison::Equal, parameter)
            .expect("filter");
        builder.return_result(filter).expect("return");
        assert_eq!(
            verify_program(
                &builder.finish().expect("program"),
                &schema,
                READ,
                VerifyLimits::default()
            )
            .expect_err("type mismatch"),
            IsaError::TypeMismatch
        );
    }

    #[test]
    fn cache_binds_scope_and_program_digest() {
        let schema = schema();
        let program = dynamic_program(&schema);
        let verified = verify_program(&program, &schema, READ, VerifyLimits::default())
            .expect("verified program");
        let mut cache = ProgramCache::new([7; 32], 2).expect("cache");
        let promotion = cache.promote(&verified, 41_u32).expect("promotion");
        assert!(promotion.inserted);
        assert_eq!(cache.resolve(promotion.handle, verified.digest()), Ok(&41));
        assert_eq!(
            cache
                .resolve(promotion.handle, [8; 32])
                .expect_err("digest"),
            IsaError::CacheScopeMismatch
        );
    }

    #[test]
    fn join_and_aggregate_form_one_bounded_dynamic_program() {
        let schema = schema();
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
        let verified = verify_program(&program, &schema, READ, VerifyLimits::default())
            .expect("verified program");
        assert_eq!(verified.instruction_count(), 5);
    }

    #[test]
    fn compact_operands_bind_the_exact_verified_program() {
        let schema = schema();
        let program = dynamic_program(&schema);
        let verified = verify_program(&program, &schema, READ, VerifyLimits::default())
            .expect("verified program");
        let mut builder = OperandBuilder::new(&verified);
        builder.push(ParameterValue::I64(41)).expect("minimum");
        builder.push(ParameterValue::U64(10)).expect("limit");
        let bytes = builder.finish().expect("operands");
        let operands = verify_operands(&bytes, &verified).expect("verified operands");
        assert_eq!(operands.len(), 2);
        assert_eq!(operands.value(0), Ok(ParameterValue::I64(41)));
        assert_eq!(operands.value(1), Ok(ParameterValue::U64(10)));
        assert_eq!(operands.program_digest(), verified.digest());
        let compact =
            verify_compact_operands(operands.compact_bytes(), &verified).expect("compact operands");
        assert_eq!(compact.complete_block_bytes(), None);
        assert_eq!(compact.value(0), Ok(ParameterValue::I64(41)));
        assert_eq!(compact.value(1), Ok(ParameterValue::U64(10)));
        assert_eq!(compact.program_digest(), verified.digest());
        assert!(!compact.spans.spilled());
        assert!(!compact.descriptors.spilled());
        let owned = OwnedVerifiedProgram::from_verified(&verified).expect("owned program");
        let reopened = owned.as_verified();
        assert_eq!(reopened.bytes(), verified.bytes());
        assert_eq!(reopened.digest(), verified.digest());
        assert_eq!(reopened.instruction_count(), verified.instruction_count());

        let mut changed_program = program.clone();
        let filter_flags = HEADER_BYTES + 2 * PARAMETER_BYTES + 12 + 1;
        changed_program[filter_flags] = Comparison::Less as u8;
        let other = verify_program(&changed_program, &schema, READ, VerifyLimits::default())
            .expect("other program");
        assert_eq!(
            verify_operands(&bytes, &other).expect_err("program digest"),
            IsaError::OperandDigestMismatch
        );
    }

    #[test]
    fn operand_types_and_canonical_floats_fail_closed() {
        let schema = schema();
        let program = dynamic_program(&schema);
        let verified = verify_program(&program, &schema, READ, VerifyLimits::default())
            .expect("verified program");
        let mut wrong = OperandBuilder::new(&verified);
        assert_eq!(
            wrong
                .push(ParameterValue::Utf8("forty-one"))
                .expect_err("wrong type"),
            IsaError::TypeMismatch
        );

        let mut float_builder = ProgramBuilder::new(schema.digest(), 4).expect("builder");
        let float = float_builder
            .parameter(ParameterDescriptor::new(ScalarType::F64, 8).expect("parameter"))
            .expect("parameter");
        let scan = float_builder.scan(11).expect("scan");
        let filter = float_builder
            .filter(scan, 101, Comparison::Equal, float)
            .expect("filter");
        float_builder.return_result(filter).expect("return");
        let float_program = float_builder.finish().expect("program");
        assert_eq!(
            verify_program(&float_program, &schema, READ, VerifyLimits::default())
                .expect_err("field type"),
            IsaError::TypeMismatch
        );
        assert_eq!(
            parameter_value_len(ParameterValue::F64(f64::NAN)).expect_err("not finite"),
            IsaError::OperandValueInvalid
        );
    }
}
