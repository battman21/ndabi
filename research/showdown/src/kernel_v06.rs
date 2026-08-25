//! NDABI v0.6 measures a prepared transition kernel, not only a smaller wire representation.
//!
//! The local profile trusts this kernel and records one canonical transition event. Federated
//! execution still needs an independent proof profile. This module does not equate those profiles.

use std::fmt::Write as _;
use std::io::Write as _;
use std::mem::size_of;

use crc32fast::Hasher as Crc32;
use serde::{Deserialize, Serialize};

pub const TASK_COUNT: usize = 512;
pub const CHANGE_COUNT: usize = 8;
pub const MAX_CHANGES: usize = 16;
pub const EVENT_CAPACITY: usize = 256;
pub const BENCHMARK_NOW: u64 = 1_900_000_000;
pub const CHECKPOINT_KEY: [u8; 32] = [0x5a; 32];

const PROTOCOL_VERSION: u8 = 6;
const KERNEL_ID: u32 = 0x4e44_4b31;
const SCHEMA_VERSION: u16 = 1;
const POLICY_VERSION: u16 = 1;
const RENDERER_VERSION: u16 = 1;
const FULL_WIRE_MAGIC: &[u8; 4] = b"N6WF";
const PREPARED_WIRE_MAGIC: &[u8; 4] = b"N6PF";
const RESULT_MAGIC: &[u8; 4] = b"N6RS";
const EVENT_MAGIC: &[u8; 4] = b"N6EV";
const APPLY_PATCH: u8 = 1;

pub type Hash = [u8; 32];

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Change {
    pub task_ordinal: u16,
    pub status: u8,
    pub priority: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task {
    pub id: u32,
    pub status: u8,
    pub priority: u8,
    pub title: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelState {
    pub revision: u64,
    pub chain_root: Hash,
    pub tasks: Vec<Task>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PreparedCapability {
    pub handle: u64,
    pub generation: u32,
    pub authority_digest: Hash,
    pub kernel_id: u32,
    pub schema_version: u16,
    pub policy_version: u16,
    pub renderer_version: u16,
    pub max_changes: u8,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedCommand {
    pub capability_handle: u64,
    pub capability_generation: u32,
    pub expected_revision: u64,
    pub changes: [Change; MAX_CHANGES],
    pub change_count: u8,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct EventReceipt {
    pub revision: u64,
    pub chain_root: Hash,
    pub result_handle: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventSlot {
    pub bytes: [u8; EVENT_CAPACITY],
    pub len: u16,
    pub receipt: EventReceipt,
}

impl Default for EventSlot {
    fn default() -> Self {
        Self {
            bytes: [0; EVENT_CAPACITY],
            len: 0,
            receipt: EventReceipt::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KernelScratch {
    pub event: EventSlot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub event_count: u64,
    pub revision: u64,
    pub chain_root: Hash,
    pub authenticator: Hash,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StatelessJsonRequest {
    pub capability: PreparedCapability,
    pub expected_revision: u64,
    pub changes: [Change; CHANGE_COUNT],
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub struct JsonResult<'a> {
    pub revision: u64,
    pub chain_root: &'a str,
    pub result_handle: u64,
}

impl KernelState {
    pub fn fixture() -> Self {
        let mut tasks = Vec::with_capacity(TASK_COUNT);
        for index in 0..TASK_COUNT {
            tasks.push(Task {
                id: u32::try_from(index + 1).unwrap_or(u32::MAX),
                status: u8::try_from(index % 4).unwrap_or(0),
                priority: u8::try_from(index % 5).unwrap_or(0),
                title: format!("Task {:04}", index + 1),
            });
        }
        let chain_root = initial_chain_root(&tasks);
        Self {
            revision: 7,
            chain_root,
            tasks,
        }
    }

    pub fn reset_changed_from(&mut self, base: &Self, changes: &[Change]) -> Result<(), String> {
        self.revision = base.revision;
        self.chain_root = base.chain_root;
        for change in changes {
            let index = usize::from(change.task_ordinal);
            let source = base
                .tasks
                .get(index)
                .ok_or_else(|| "the base task is absent".to_string())?;
            let destination = self
                .tasks
                .get_mut(index)
                .ok_or_else(|| "the destination task is absent".to_string())?;
            destination.status = source.status;
            destination.priority = source.priority;
        }
        Ok(())
    }

    pub fn retained_bytes(&self) -> usize {
        size_of::<Self>()
            + self.tasks.capacity() * size_of::<Task>()
            + self
                .tasks
                .iter()
                .map(|task| task.title.capacity())
                .sum::<usize>()
    }
}

impl PreparedCapability {
    pub fn fixture() -> Self {
        let mut authority_digest = [0u8; 32];
        for (index, byte) in authority_digest.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap_or(0).wrapping_mul(17);
        }
        let mut capability = Self {
            handle: 0,
            generation: 11,
            authority_digest,
            kernel_id: KERNEL_ID,
            schema_version: SCHEMA_VERSION,
            policy_version: POLICY_VERSION,
            renderer_version: RENDERER_VERSION,
            max_changes: MAX_CHANGES as u8,
            expires_at: BENCHMARK_NOW + 3_600,
        };
        capability.handle = capability_handle(&capability);
        capability
    }

    pub fn validate_prepared(&self) -> Result<(), String> {
        if self.handle != capability_handle(self) {
            return Err("the prepared capability handle does not match its binding".to_string());
        }
        if self.generation == 0 {
            return Err("the prepared capability generation is zero".to_string());
        }
        if self.kernel_id != KERNEL_ID
            || self.schema_version != SCHEMA_VERSION
            || self.policy_version != POLICY_VERSION
            || self.renderer_version != RENDERER_VERSION
        {
            return Err("the prepared capability version binding does not match".to_string());
        }
        if self.max_changes == 0 || usize::from(self.max_changes) > MAX_CHANGES {
            return Err("the prepared capability change limit is invalid".to_string());
        }
        if self.expires_at <= BENCHMARK_NOW {
            return Err("the prepared capability has expired".to_string());
        }
        Ok(())
    }
}

impl PreparedCommand {
    pub fn fixture(capability: PreparedCapability, changes: [Change; CHANGE_COUNT]) -> Self {
        let mut fixed = [Change::default(); MAX_CHANGES];
        fixed[..CHANGE_COUNT].copy_from_slice(&changes);
        Self {
            capability_handle: capability.handle,
            capability_generation: capability.generation,
            expected_revision: 7,
            changes: fixed,
            change_count: CHANGE_COUNT as u8,
        }
    }

    pub fn active_changes(&self) -> &[Change] {
        &self.changes[..usize::from(self.change_count)]
    }
}

impl Checkpoint {
    pub fn create(receipt: EventReceipt, event_count: u64, key: &[u8; 32]) -> Self {
        let mut bytes = [0u8; 56];
        bytes[..8].copy_from_slice(&event_count.to_le_bytes());
        bytes[8..16].copy_from_slice(&receipt.revision.to_le_bytes());
        bytes[16..48].copy_from_slice(&receipt.chain_root);
        bytes[48..56].copy_from_slice(&receipt.result_handle.to_le_bytes());
        let authenticator = *blake3::keyed_hash(key, &bytes).as_bytes();
        Self {
            event_count,
            revision: receipt.revision,
            chain_root: receipt.chain_root,
            authenticator,
        }
    }

    pub fn verify(&self, receipt: EventReceipt, key: &[u8; 32]) -> bool {
        if self.revision != receipt.revision || self.chain_root != receipt.chain_root {
            return false;
        }
        let expected = Self::create(receipt, self.event_count, key);
        constant_time_equal(&self.authenticator, &expected.authenticator)
    }
}

pub fn fixed_changes() -> [Change; CHANGE_COUNT] {
    [
        Change {
            task_ordinal: 0,
            status: 1,
            priority: 2,
        },
        Change {
            task_ordinal: 64,
            status: 2,
            priority: 0,
        },
        Change {
            task_ordinal: 128,
            status: 3,
            priority: 3,
        },
        Change {
            task_ordinal: 192,
            status: 0,
            priority: 1,
        },
        Change {
            task_ordinal: 256,
            status: 1,
            priority: 4,
        },
        Change {
            task_ordinal: 320,
            status: 2,
            priority: 2,
        },
        Change {
            task_ordinal: 384,
            status: 3,
            priority: 0,
        },
        Change {
            task_ordinal: 448,
            status: 1,
            priority: 2,
        },
    ]
}

pub fn execute_transition_only(
    capability: &PreparedCapability,
    command: &PreparedCommand,
    state: &mut KernelState,
) -> Result<(), String> {
    validate_command(capability, command, state)?;
    apply_validated(state, command.active_changes());
    state.revision += 1;
    Ok(())
}

pub fn execute_prepared(
    capability: &PreparedCapability,
    command: &PreparedCommand,
    state: &mut KernelState,
    scratch: &mut KernelScratch,
) -> Result<EventReceipt, String> {
    validate_command(capability, command, state)?;
    let next_revision = state.revision + 1;
    let result_handle = capability.handle.rotate_left(17) ^ next_revision;
    let length = encode_event(
        &mut scratch.event.bytes,
        capability,
        command,
        state,
        next_revision,
        result_handle,
    )?;
    let chain_root = *blake3::hash(&scratch.event.bytes[..length]).as_bytes();
    let receipt = EventReceipt {
        revision: next_revision,
        chain_root,
        result_handle,
    };
    apply_validated(state, command.active_changes());
    state.revision = next_revision;
    state.chain_root = chain_root;
    scratch.event.len = u16::try_from(length)
        .map_err(|_| "the canonical event length exceeds the slot".to_string())?;
    scratch.event.receipt = receipt;
    Ok(receipt)
}

pub fn verify_and_replay_event(
    capability: &PreparedCapability,
    slot: &EventSlot,
    state: &mut KernelState,
) -> Result<EventReceipt, String> {
    capability.validate_prepared()?;
    let length = usize::from(slot.len);
    if length == 0 || length > EVENT_CAPACITY {
        return Err("the canonical event length is invalid".to_string());
    }
    let actual_root = *blake3::hash(&slot.bytes[..length]).as_bytes();
    if !constant_time_equal(&actual_root, &slot.receipt.chain_root) {
        return Err("the canonical event receipt does not match".to_string());
    }
    let mut reader = Reader::new(&slot.bytes[..length]);
    if reader.take(4)? != EVENT_MAGIC || reader.u8()? != PROTOCOL_VERSION {
        return Err("the canonical event header does not match".to_string());
    }
    if reader.u32()? != capability.kernel_id
        || reader.u16()? != capability.schema_version
        || reader.u16()? != capability.policy_version
        || reader.u16()? != capability.renderer_version
    {
        return Err("the canonical event version binding does not match".to_string());
    }
    if reader.u64()? != capability.handle || reader.u32()? != capability.generation {
        return Err("the canonical event capability binding does not match".to_string());
    }
    if reader.take(32)? != capability.authority_digest {
        return Err("the canonical event authority binding does not match".to_string());
    }
    let previous_revision = reader.u64()?;
    let next_revision = reader.u64()?;
    if previous_revision != state.revision || next_revision != state.revision + 1 {
        return Err("the canonical event revision does not match".to_string());
    }
    if reader.take(32)? != state.chain_root {
        return Err("the canonical event previous root does not match".to_string());
    }
    let result_handle = reader.u64()?;
    if result_handle != capability.handle.rotate_left(17) ^ next_revision {
        return Err("the canonical event result handle does not match".to_string());
    }
    let count = usize::from(reader.u8()?);
    if count == 0 || count > usize::from(capability.max_changes) {
        return Err("the canonical event change count is invalid".to_string());
    }
    let mut changes = [Change::default(); MAX_CHANGES];
    for change in changes.iter_mut().take(count) {
        *change = Change {
            task_ordinal: reader.u16()?,
            status: reader.u8()?,
            priority: reader.u8()?,
        };
    }
    if reader.remaining() != 0 {
        return Err("the canonical event has trailing bytes".to_string());
    }
    validate_changes(&changes[..count], state)?;
    apply_validated(state, &changes[..count]);
    state.revision = next_revision;
    state.chain_root = actual_root;
    Ok(EventReceipt {
        revision: next_revision,
        chain_root: actual_root,
        result_handle,
    })
}

pub fn encode_stateless_json_request(
    capability: PreparedCapability,
    expected_revision: u64,
    changes: [Change; CHANGE_COUNT],
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&StatelessJsonRequest {
        capability,
        expected_revision,
        changes,
    })
    .map_err(|error| error.to_string())
}

pub fn decode_stateless_json_request(
    bytes: &[u8],
) -> Result<(PreparedCapability, PreparedCommand), String> {
    let request: StatelessJsonRequest =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let command = PreparedCommand::fixture(request.capability, request.changes);
    Ok((
        request.capability,
        PreparedCommand {
            expected_revision: request.expected_revision,
            ..command
        },
    ))
}

pub fn encode_json_result_into(output: &mut Vec<u8>, receipt: EventReceipt) -> Result<(), String> {
    output.clear();
    write!(
        output,
        "{{\"revision\":{},\"chain_root\":\"{}\",\"result_handle\":{}}}",
        receipt.revision,
        hex(&receipt.chain_root),
        receipt.result_handle
    )
    .map_err(|error| error.to_string())
}

pub fn decode_json_result(bytes: &[u8]) -> Result<EventReceipt, String> {
    let result: JsonResult<'_> =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    Ok(EventReceipt {
        revision: result.revision,
        chain_root: parse_hash(result.chain_root)?,
        result_handle: result.result_handle,
    })
}

pub fn encode_full_wire_request(
    output: &mut Vec<u8>,
    capability: PreparedCapability,
    command: &PreparedCommand,
) -> Result<(), String> {
    output.clear();
    output.extend_from_slice(FULL_WIRE_MAGIC);
    output.push(PROTOCOL_VERSION);
    output.push(APPLY_PATCH);
    push_capability(output, capability);
    push_command_body(output, command)?;
    append_crc32(output);
    Ok(())
}

pub fn decode_full_wire_request(
    bytes: &[u8],
) -> Result<(PreparedCapability, PreparedCommand), String> {
    let body = verify_crc32(bytes)?;
    let mut reader = Reader::new(body);
    if reader.take(4)? != FULL_WIRE_MAGIC
        || reader.u8()? != PROTOCOL_VERSION
        || reader.u8()? != APPLY_PATCH
    {
        return Err("the full wire request header does not match".to_string());
    }
    let capability = read_capability(&mut reader)?;
    let command = read_command_body(&mut reader, capability.handle, capability.generation)?;
    if reader.remaining() != 0 {
        return Err("the full wire request has trailing bytes".to_string());
    }
    Ok((capability, command))
}

pub fn encode_prepared_wire_request(
    output: &mut Vec<u8>,
    command: &PreparedCommand,
) -> Result<(), String> {
    output.clear();
    output.extend_from_slice(PREPARED_WIRE_MAGIC);
    output.push(PROTOCOL_VERSION);
    output.push(APPLY_PATCH);
    push_u64(output, command.capability_handle);
    push_u32(output, command.capability_generation);
    push_command_body(output, command)?;
    append_crc32(output);
    Ok(())
}

pub fn decode_prepared_wire_request(bytes: &[u8]) -> Result<PreparedCommand, String> {
    let body = verify_crc32(bytes)?;
    let mut reader = Reader::new(body);
    if reader.take(4)? != PREPARED_WIRE_MAGIC
        || reader.u8()? != PROTOCOL_VERSION
        || reader.u8()? != APPLY_PATCH
    {
        return Err("the prepared wire request header does not match".to_string());
    }
    let handle = reader.u64()?;
    let generation = reader.u32()?;
    let command = read_command_body(&mut reader, handle, generation)?;
    if reader.remaining() != 0 {
        return Err("the prepared wire request has trailing bytes".to_string());
    }
    Ok(command)
}

pub fn encode_wire_result_into(output: &mut Vec<u8>, receipt: EventReceipt) -> Result<(), String> {
    output.clear();
    output.extend_from_slice(RESULT_MAGIC);
    output.push(PROTOCOL_VERSION);
    output.push(0);
    push_u64(output, receipt.revision);
    output.extend_from_slice(&receipt.chain_root);
    push_u64(output, receipt.result_handle);
    append_crc32(output);
    Ok(())
}

pub fn decode_wire_result(bytes: &[u8]) -> Result<EventReceipt, String> {
    let body = verify_crc32(bytes)?;
    let mut reader = Reader::new(body);
    if reader.take(4)? != RESULT_MAGIC || reader.u8()? != PROTOCOL_VERSION || reader.u8()? != 0 {
        return Err("the wire result header does not match".to_string());
    }
    let receipt = EventReceipt {
        revision: reader.u64()?,
        chain_root: reader
            .take(32)?
            .try_into()
            .map_err(|_| "the wire result root length does not match".to_string())?,
        result_handle: reader.u64()?,
    };
    if reader.remaining() != 0 {
        return Err("the wire result has trailing bytes".to_string());
    }
    Ok(receipt)
}

pub fn render_patch_into(
    output: &mut String,
    state: &KernelState,
    changes: &[Change],
) -> Result<usize, String> {
    output.clear();
    for change in changes {
        let task = state
            .tasks
            .get(usize::from(change.task_ordinal))
            .ok_or_else(|| "the rendered task is absent".to_string())?;
        writeln!(
            output,
            "  <article data-task=\"{}\"><h2>{}</h2><p>Status {}. Priority {}.</p></article>",
            task.id, task.title, task.status, task.priority
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(output.len())
}

pub fn render_full(state: &KernelState) -> String {
    let mut output = format!("<main data-revision=\"{}\">\n", state.revision);
    for task in &state.tasks {
        let _ = writeln!(
            output,
            "  <article data-task=\"{}\"><h2>{}</h2><p>Status {}. Priority {}.</p></article>",
            task.id, task.title, task.status, task.priority
        );
    }
    output.push_str("</main>");
    output
}

pub fn control_bytes() -> usize {
    size_of::<PreparedCapability>()
        + size_of::<PreparedCommand>()
        + size_of::<KernelScratch>()
        + size_of::<EventReceipt>()
}

pub fn hash_fingerprint(hash: &Hash) -> u64 {
    u64::from_le_bytes(hash[..8].try_into().unwrap_or([0; 8]))
}

fn validate_command(
    capability: &PreparedCapability,
    command: &PreparedCommand,
    state: &KernelState,
) -> Result<(), String> {
    capability.validate_prepared()?;
    if command.capability_handle != capability.handle
        || command.capability_generation != capability.generation
    {
        return Err("the command capability handle does not match".to_string());
    }
    if command.expected_revision != state.revision {
        return Err("the command revision does not match".to_string());
    }
    let count = usize::from(command.change_count);
    if count == 0 || count > usize::from(capability.max_changes) {
        return Err("the command change count is invalid".to_string());
    }
    validate_changes(command.active_changes(), state)
}

fn validate_changes(changes: &[Change], state: &KernelState) -> Result<(), String> {
    let mut seen = [false; TASK_COUNT];
    for change in changes {
        let index = usize::from(change.task_ordinal);
        if index >= state.tasks.len() {
            return Err("the command names an unknown task".to_string());
        }
        if seen[index] {
            return Err("the command changes one task more than once".to_string());
        }
        seen[index] = true;
        if change.status > 3 || change.priority > 4 {
            return Err("the command field value is outside the schema".to_string());
        }
    }
    Ok(())
}

fn apply_validated(state: &mut KernelState, changes: &[Change]) {
    for change in changes {
        let task = &mut state.tasks[usize::from(change.task_ordinal)];
        task.status = change.status;
        task.priority = change.priority;
    }
}

fn encode_event(
    output: &mut [u8; EVENT_CAPACITY],
    capability: &PreparedCapability,
    command: &PreparedCommand,
    state: &KernelState,
    next_revision: u64,
    result_handle: u64,
) -> Result<usize, String> {
    let mut writer = SliceWriter::new(output);
    writer.bytes(EVENT_MAGIC)?;
    writer.u8(PROTOCOL_VERSION)?;
    writer.u32(capability.kernel_id)?;
    writer.u16(capability.schema_version)?;
    writer.u16(capability.policy_version)?;
    writer.u16(capability.renderer_version)?;
    writer.u64(capability.handle)?;
    writer.u32(capability.generation)?;
    writer.bytes(&capability.authority_digest)?;
    writer.u64(state.revision)?;
    writer.u64(next_revision)?;
    writer.bytes(&state.chain_root)?;
    writer.u64(result_handle)?;
    writer.u8(command.change_count)?;
    for change in command.active_changes() {
        writer.u16(change.task_ordinal)?;
        writer.u8(change.status)?;
        writer.u8(change.priority)?;
    }
    Ok(writer.len)
}

fn initial_chain_root(tasks: &[Task]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ndabi-v06-initial-state");
    for task in tasks {
        hasher.update(&task.id.to_le_bytes());
        hasher.update(&[task.status, task.priority]);
        hasher.update(&(task.title.len() as u64).to_le_bytes());
        hasher.update(task.title.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn capability_handle(capability: &PreparedCapability) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ndabi-v06-capability");
    hasher.update(&capability.generation.to_le_bytes());
    hasher.update(&capability.authority_digest);
    hasher.update(&capability.kernel_id.to_le_bytes());
    hasher.update(&capability.schema_version.to_le_bytes());
    hasher.update(&capability.policy_version.to_le_bytes());
    hasher.update(&capability.renderer_version.to_le_bytes());
    hasher.update(&[capability.max_changes]);
    hasher.update(&capability.expires_at.to_le_bytes());
    u64::from_le_bytes(
        hasher.finalize().as_bytes()[..8]
            .try_into()
            .unwrap_or([0; 8]),
    )
}

fn push_capability(output: &mut Vec<u8>, capability: PreparedCapability) {
    push_u64(output, capability.handle);
    push_u32(output, capability.generation);
    output.extend_from_slice(&capability.authority_digest);
    push_u32(output, capability.kernel_id);
    push_u16(output, capability.schema_version);
    push_u16(output, capability.policy_version);
    push_u16(output, capability.renderer_version);
    output.push(capability.max_changes);
    push_u64(output, capability.expires_at);
}

fn read_capability(reader: &mut Reader<'_>) -> Result<PreparedCapability, String> {
    Ok(PreparedCapability {
        handle: reader.u64()?,
        generation: reader.u32()?,
        authority_digest: reader
            .take(32)?
            .try_into()
            .map_err(|_| "the capability authority digest length does not match".to_string())?,
        kernel_id: reader.u32()?,
        schema_version: reader.u16()?,
        policy_version: reader.u16()?,
        renderer_version: reader.u16()?,
        max_changes: reader.u8()?,
        expires_at: reader.u64()?,
    })
}

fn push_command_body(output: &mut Vec<u8>, command: &PreparedCommand) -> Result<(), String> {
    push_u64(output, command.expected_revision);
    output.push(command.change_count);
    if usize::from(command.change_count) > MAX_CHANGES {
        return Err("the encoded command exceeds the change limit".to_string());
    }
    for change in command.active_changes() {
        push_u16(output, change.task_ordinal);
        output.push(change.status);
        output.push(change.priority);
    }
    Ok(())
}

fn read_command_body(
    reader: &mut Reader<'_>,
    handle: u64,
    generation: u32,
) -> Result<PreparedCommand, String> {
    let expected_revision = reader.u64()?;
    let count = usize::from(reader.u8()?);
    if count == 0 || count > MAX_CHANGES {
        return Err("the decoded command change count is invalid".to_string());
    }
    let mut changes = [Change::default(); MAX_CHANGES];
    for change in changes.iter_mut().take(count) {
        *change = Change {
            task_ordinal: reader.u16()?,
            status: reader.u8()?,
            priority: reader.u8()?,
        };
    }
    Ok(PreparedCommand {
        capability_handle: handle,
        capability_generation: generation,
        expected_revision,
        changes,
        change_count: count as u8,
    })
}

fn append_crc32(output: &mut Vec<u8>) {
    let mut hasher = Crc32::new();
    hasher.update(output);
    output.extend_from_slice(&hasher.finalize().to_le_bytes());
}

fn verify_crc32(bytes: &[u8]) -> Result<&[u8], String> {
    let body_length = bytes
        .len()
        .checked_sub(4)
        .ok_or_else(|| "the frame is shorter than its checksum".to_string())?;
    let (body, checksum) = bytes.split_at(body_length);
    let expected = u32::from_le_bytes(
        checksum
            .try_into()
            .map_err(|_| "the frame checksum length does not match".to_string())?,
    );
    let mut hasher = Crc32::new();
    hasher.update(body);
    if hasher.finalize() != expected {
        return Err("the frame checksum does not match".to_string());
    }
    Ok(body)
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn hex(hash: &Hash) -> String {
    let mut output = String::with_capacity(64);
    for byte in hash {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn parse_hash(value: &str) -> Result<Hash, String> {
    if value.len() != 64 {
        return Err("the JSON receipt root length does not match".to_string());
    }
    let mut output = [0u8; 32];
    for (index, destination) in output.iter_mut().enumerate() {
        let start = index * 2;
        *destination =
            u8::from_str_radix(&value[start..start + 2], 16).map_err(|error| error.to_string())?;
    }
    Ok(output)
}

fn constant_time_equal(left: &Hash, right: &Hash) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

struct SliceWriter<'a> {
    bytes: &'a mut [u8],
    len: usize,
}

impl<'a> SliceWriter<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, len: 0 }
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), String> {
        let end = self
            .len
            .checked_add(value.len())
            .ok_or_else(|| "the canonical event length overflowed".to_string())?;
        let destination = self
            .bytes
            .get_mut(self.len..end)
            .ok_or_else(|| "the canonical event exceeds its fixed slot".to_string())?;
        destination.copy_from_slice(value);
        self.len = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), String> {
        self.bytes(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), String> {
        self.bytes(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), String> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), String> {
        self.bytes(&value.to_le_bytes())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| "the frame offset overflowed".to_string())?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| "the frame ended before the required field".to_string())?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().map_err(
            |_| "the u16 field length does not match".to_string(),
        )?))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(
            |_| "the u32 field length does not match".to_string(),
        )?))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(
            |_| "the u64 field length does not match".to_string(),
        )?))
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        KernelState,
        PreparedCapability,
        PreparedCommand,
        [Change; CHANGE_COUNT],
    ) {
        let state = KernelState::fixture();
        let capability = PreparedCapability::fixture();
        let changes = fixed_changes();
        let command = PreparedCommand::fixture(capability, changes);
        (state, capability, command, changes)
    }

    #[test]
    fn canonical_event_replay_is_lossless() {
        let (base, capability, command, _) = fixture();
        let mut executed = base.clone();
        let mut scratch = KernelScratch::default();
        let receipt =
            execute_prepared(&capability, &command, &mut executed, &mut scratch).expect("execute");
        let mut replayed = base;
        let replay_receipt =
            verify_and_replay_event(&capability, &scratch.event, &mut replayed).expect("replay");
        assert_eq!(executed, replayed);
        assert_eq!(receipt, replay_receipt);
        assert_eq!(render_full(&executed), render_full(&replayed));
    }

    #[test]
    fn all_wire_forms_preserve_the_command_and_result() {
        let (_, capability, command, changes) = fixture();
        let mut full = Vec::new();
        encode_full_wire_request(&mut full, capability, &command).expect("full encode");
        let (full_capability, full_command) = decode_full_wire_request(&full).expect("full decode");
        assert_eq!(capability, full_capability);
        assert_eq!(command, full_command);

        let mut prepared = Vec::new();
        encode_prepared_wire_request(&mut prepared, &command).expect("prepared encode");
        assert_eq!(
            command,
            decode_prepared_wire_request(&prepared).expect("prepared decode")
        );

        let json = encode_stateless_json_request(capability, 7, changes).expect("JSON encode");
        let (json_capability, json_command) =
            decode_stateless_json_request(&json).expect("JSON decode");
        assert_eq!(capability, json_capability);
        assert_eq!(command, json_command);

        let receipt = EventReceipt {
            revision: 8,
            chain_root: [0xa5; 32],
            result_handle: 41,
        };
        let mut result = Vec::new();
        encode_wire_result_into(&mut result, receipt).expect("result encode");
        assert_eq!(receipt, decode_wire_result(&result).expect("result decode"));
        encode_json_result_into(&mut result, receipt).expect("JSON result encode");
        assert_eq!(
            receipt,
            decode_json_result(&result).expect("JSON result decode")
        );
    }

    #[test]
    fn a_changed_event_refuses_before_replay_mutation() {
        let (base, capability, command, _) = fixture();
        let mut executed = base.clone();
        let mut scratch = KernelScratch::default();
        execute_prepared(&capability, &command, &mut executed, &mut scratch).expect("execute");
        let changed_byte = usize::from(scratch.event.len) - 1;
        // Change one valid priority value. Only the receipt can detect this semantic mutation.
        scratch.event.bytes[changed_byte] ^= 0x01;
        let mut replayed = base.clone();
        assert!(verify_and_replay_event(&capability, &scratch.event, &mut replayed).is_err());
        assert_eq!(replayed, base);
    }

    #[test]
    fn a_stale_capability_refuses_before_state_mutation() {
        let (base, mut capability, command, _) = fixture();
        capability.generation += 1;
        let mut state = base.clone();
        let mut scratch = KernelScratch::default();
        assert!(execute_prepared(&capability, &command, &mut state, &mut scratch).is_err());
        assert_eq!(state, base);
    }

    #[test]
    fn a_duplicate_change_refuses_before_state_mutation() {
        let (base, capability, mut command, _) = fixture();
        command.changes[1].task_ordinal = command.changes[0].task_ordinal;
        let mut state = base.clone();
        let mut scratch = KernelScratch::default();
        assert!(execute_prepared(&capability, &command, &mut state, &mut scratch).is_err());
        assert_eq!(state, base);
    }

    #[test]
    fn a_changed_checkpoint_refuses() {
        let receipt = EventReceipt {
            revision: 8,
            chain_root: [0x19; 32],
            result_handle: 91,
        };
        let mut checkpoint = Checkpoint::create(receipt, 32, &CHECKPOINT_KEY);
        assert!(checkpoint.verify(receipt, &CHECKPOINT_KEY));
        checkpoint.authenticator[0] ^= 1;
        assert!(!checkpoint.verify(receipt, &CHECKPOINT_KEY));
    }

    #[test]
    fn the_local_control_state_stays_below_two_kibibytes() {
        assert!(
            control_bytes() <= 2_048,
            "control bytes: {}",
            control_bytes()
        );
    }

    #[test]
    fn every_fixture_change_modifies_the_base_state() {
        let state = KernelState::fixture();
        for change in fixed_changes() {
            let task = &state.tasks[usize::from(change.task_ordinal)];
            assert_ne!(
                (task.status, task.priority),
                (change.status, change.priority)
            );
        }
    }

    #[test]
    fn every_single_bit_frame_change_refuses() {
        let (_, capability, command, _) = fixture();
        let mut frames = Vec::new();
        let mut full = Vec::new();
        encode_full_wire_request(&mut full, capability, &command).expect("full frame");
        frames.push((full, true));
        let mut prepared = Vec::new();
        encode_prepared_wire_request(&mut prepared, &command).expect("prepared frame");
        frames.push((prepared, false));
        for (frame, full_frame) in frames {
            for index in 0..frame.len() {
                for bit in 0..8 {
                    let mut changed = frame.clone();
                    changed[index] ^= 1 << bit;
                    let refused = if full_frame {
                        decode_full_wire_request(&changed).is_err()
                    } else {
                        decode_prepared_wire_request(&changed).is_err()
                    };
                    assert!(refused, "changed frame byte {index}, bit {bit} passed");
                }
            }
        }
    }

    #[test]
    fn every_single_bit_event_change_refuses_before_mutation() {
        let (base, capability, command, _) = fixture();
        let mut executed = base.clone();
        let mut scratch = KernelScratch::default();
        execute_prepared(&capability, &command, &mut executed, &mut scratch).expect("execute");
        for index in 0..usize::from(scratch.event.len) {
            for bit in 0..8 {
                let mut changed = scratch.event;
                changed.bytes[index] ^= 1 << bit;
                let mut replay = base.clone();
                assert!(verify_and_replay_event(&capability, &changed, &mut replay).is_err());
                assert_eq!(replay, base);
            }
        }
    }

    #[test]
    fn varied_valid_commands_match_event_replay() {
        let base = KernelState::fixture();
        let capability = PreparedCapability::fixture();
        for iteration in 0..10_000usize {
            let mut changes = [Change::default(); CHANGE_COUNT];
            for (index, change) in changes.iter_mut().enumerate() {
                let ordinal = (iteration.wrapping_mul(13) + index * 61) % TASK_COUNT;
                let task = &base.tasks[ordinal];
                *change = Change {
                    task_ordinal: u16::try_from(ordinal).expect("task ordinal"),
                    status: (task.status + 1 + u8::try_from(iteration % 3).unwrap_or(0)) % 4,
                    priority: (task.priority + 1 + u8::try_from(iteration % 4).unwrap_or(0)) % 5,
                };
            }
            let command = PreparedCommand::fixture(capability, changes);
            let mut direct = base.clone();
            let mut scratch = KernelScratch::default();
            execute_prepared(&capability, &command, &mut direct, &mut scratch).expect("execute");
            let mut replay = base.clone();
            verify_and_replay_event(&capability, &scratch.event, &mut replay).expect("replay");
            assert_eq!(direct, replay);
        }
    }

    #[test]
    fn eight_independent_sessions_complete_under_concurrency() {
        let base = KernelState::fixture();
        let capability = PreparedCapability::fixture();
        let command = PreparedCommand::fixture(capability, fixed_changes());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let worker_base = base.clone();
            let worker_barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                let mut state = worker_base.clone();
                worker_barrier.wait();
                for _ in 0..10_000 {
                    state
                        .reset_changed_from(&worker_base, command.active_changes())
                        .expect("reset state");
                    let mut scratch = KernelScratch::default();
                    execute_prepared(&capability, &command, &mut state, &mut scratch)
                        .expect("execute");
                }
                state
            }));
        }
        for worker in workers {
            let state = worker.join().expect("join worker");
            assert_eq!(state.revision, base.revision + 1);
        }
    }
}
