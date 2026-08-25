//! Persist the last accepted nonce for one NDABI authority binding.
//!
//! The reference store uses an authenticated, canonical snapshot and an atomic rename.
//! A stable lock file permits one writer and prevents concurrent stale snapshots.
//! The store detects corruption, but an external trusted anchor must prevent disk rollback.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const MAGIC: [u8; 4] = *b"NDRP";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = 48;
const RECORD_BYTES: usize = 32;
const TAG_OFFSET: usize = 16;
const TAG_BYTES: usize = 32;
const MAX_RECORDS: usize = 65_536;
const MAC_DOMAIN: &[u8] = b"ndabi-replay-store-v1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReplayIdentity {
    pub profile: u32,
    pub session_handle: u32,
    pub capability_handle: u32,
    pub schema_handle: u32,
    pub generation: u64,
}

impl ReplayIdentity {
    pub fn validate(self) -> Result<Self, ReplayStoreError> {
        if self.profile == 0
            || self.session_handle == 0
            || self.capability_handle == 0
            || self.schema_handle == 0
            || self.generation == 0
        {
            return Err(ReplayStoreError::InvalidIdentity);
        }
        Ok(self)
    }
}

pub trait ReplayStore {
    fn last_nonce(&self, identity: ReplayIdentity) -> Result<u64, ReplayStoreError>;

    /// Persist the nonce before the caller returns accepted work for execution.
    fn advance(&mut self, identity: ReplayIdentity, nonce: u64) -> Result<(), ReplayStoreError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayStoreError {
    AuthenticationFailed,
    Bounds,
    InsecurePermissions,
    InvalidIdentity,
    InvalidPath,
    Io(io::ErrorKind),
    LockUnavailable,
    NonCanonical,
    Replay,
    UnsupportedVersion(u8),
    ZeroNonce,
}

impl fmt::Display for ReplayStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ReplayStoreError {}

impl From<io::Error> for ReplayStoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

#[derive(Default)]
pub struct MemoryReplayStore {
    nonces: BTreeMap<ReplayIdentity, u64>,
}

impl ReplayStore for MemoryReplayStore {
    fn last_nonce(&self, identity: ReplayIdentity) -> Result<u64, ReplayStoreError> {
        let identity = identity.validate()?;
        Ok(self.nonces.get(&identity).copied().unwrap_or(0))
    }

    fn advance(&mut self, identity: ReplayIdentity, nonce: u64) -> Result<(), ReplayStoreError> {
        let identity = identity.validate()?;
        validate_advance(self.last_nonce(identity)?, nonce)?;
        self.nonces.insert(identity, nonce);
        Ok(())
    }
}

pub struct FileReplayStore {
    path: PathBuf,
    _lock: File,
    key: [u8; 32],
    nonces: BTreeMap<ReplayIdentity, u64>,
}

impl fmt::Debug for FileReplayStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileReplayStore")
            .field("path", &self.path)
            .field("key", &"[REDACTED]")
            .field("records", &self.nonces.len())
            .finish_non_exhaustive()
    }
}

impl Drop for FileReplayStore {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl FileReplayStore {
    pub fn open(path: &Path, key: [u8; 32]) -> Result<Self, ReplayStoreError> {
        let path = normalise_path(path)?;
        let lock_path = lock_path(&path)?;
        let lock = open_private(&lock_path, true, true)?;
        acquire_exclusive_lock(&lock)?;
        let nonces = load_snapshot(&path, &key)?;
        Ok(Self {
            path,
            _lock: lock,
            key,
            nonces,
        })
    }

    fn persist(&self, nonces: &BTreeMap<ReplayIdentity, u64>) -> Result<(), ReplayStoreError> {
        let bytes = encode_snapshot(nonces, &self.key)?;
        let parent = self.path.parent().ok_or(ReplayStoreError::InvalidPath)?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".ndabi-replay-")
            .tempfile_in(parent)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&self.path)
            .map_err(|error| ReplayStoreError::from(error.error))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

impl ReplayStore for FileReplayStore {
    fn last_nonce(&self, identity: ReplayIdentity) -> Result<u64, ReplayStoreError> {
        let identity = identity.validate()?;
        Ok(self.nonces.get(&identity).copied().unwrap_or(0))
    }

    fn advance(&mut self, identity: ReplayIdentity, nonce: u64) -> Result<(), ReplayStoreError> {
        let identity = identity.validate()?;
        validate_advance(self.last_nonce(identity)?, nonce)?;
        if self.nonces.len() == MAX_RECORDS && !self.nonces.contains_key(&identity) {
            return Err(ReplayStoreError::Bounds);
        }
        let mut proposed = self.nonces.clone();
        proposed.insert(identity, nonce);
        self.persist(&proposed)?;
        self.nonces = proposed;
        Ok(())
    }
}

fn validate_advance(last_nonce: u64, nonce: u64) -> Result<(), ReplayStoreError> {
    if nonce == 0 {
        return Err(ReplayStoreError::ZeroNonce);
    }
    if nonce <= last_nonce {
        return Err(ReplayStoreError::Replay);
    }
    Ok(())
}

fn normalise_path(path: &Path) -> Result<PathBuf, ReplayStoreError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ReplayStoreError::InvalidPath);
    }
    let parent = path.parent().ok_or(ReplayStoreError::InvalidPath)?;
    let parent = parent.canonicalize()?;
    if !parent.is_dir() {
        return Err(ReplayStoreError::InvalidPath);
    }
    Ok(parent.join(path.file_name().ok_or(ReplayStoreError::InvalidPath)?))
}

fn lock_path(path: &Path) -> Result<PathBuf, ReplayStoreError> {
    let name = path.file_name().ok_or(ReplayStoreError::InvalidPath)?;
    let mut lock_name = name.to_os_string();
    lock_name.push(".lock");
    Ok(path.with_file_name(lock_name))
}

fn open_private(path: &Path, create: bool, write: bool) -> Result<File, ReplayStoreError> {
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    if file.metadata()?.mode() & 0o077 != 0 {
        return Err(ReplayStoreError::InsecurePermissions);
    }
    Ok(file)
}

fn acquire_exclusive_lock(file: &File) -> Result<(), ReplayStoreError> {
    // The lock file remains stable across snapshot renames, so the lock covers the complete store.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Err(ReplayStoreError::LockUnavailable)
    } else {
        Err(error.into())
    }
}

fn load_snapshot(
    path: &Path,
    key: &[u8; 32],
) -> Result<BTreeMap<ReplayIdentity, u64>, ReplayStoreError> {
    let file = match open_private(path, false, false) {
        Ok(file) => file,
        Err(ReplayStoreError::Io(io::ErrorKind::NotFound)) => return Ok(BTreeMap::new()),
        Err(error) => return Err(error),
    };
    let length = usize::try_from(file.metadata()?.len()).map_err(|_| ReplayStoreError::Bounds)?;
    let maximum = HEADER_BYTES
        .checked_add(MAX_RECORDS * RECORD_BYTES)
        .ok_or(ReplayStoreError::Bounds)?;
    if !(HEADER_BYTES..=maximum).contains(&length) {
        return Err(ReplayStoreError::Bounds);
    }
    let read_limit = u64::try_from(maximum + 1).map_err(|_| ReplayStoreError::Bounds)?;
    let mut bytes = Vec::with_capacity(length);
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() != length {
        return Err(ReplayStoreError::Bounds);
    }
    decode_snapshot(&bytes, key)
}

fn encode_snapshot(
    nonces: &BTreeMap<ReplayIdentity, u64>,
    key: &[u8; 32],
) -> Result<Vec<u8>, ReplayStoreError> {
    if nonces.len() > MAX_RECORDS {
        return Err(ReplayStoreError::Bounds);
    }
    let payload_bytes = nonces
        .len()
        .checked_mul(RECORD_BYTES)
        .ok_or(ReplayStoreError::Bounds)?;
    let total_bytes = HEADER_BYTES
        .checked_add(payload_bytes)
        .ok_or(ReplayStoreError::Bounds)?;
    let mut bytes = vec![0u8; total_bytes];
    bytes[0..4].copy_from_slice(&MAGIC);
    bytes[4] = VERSION;
    put_u32(&mut bytes, 8, to_u32(nonces.len())?);
    put_u32(&mut bytes, 12, to_u32(total_bytes)?);
    for (index, (identity, nonce)) in nonces.iter().enumerate() {
        identity.validate()?;
        validate_advance(0, *nonce)?;
        let offset = HEADER_BYTES + index * RECORD_BYTES;
        put_u32(&mut bytes, offset, identity.profile);
        put_u32(&mut bytes, offset + 4, identity.session_handle);
        put_u32(&mut bytes, offset + 8, identity.capability_handle);
        put_u32(&mut bytes, offset + 12, identity.schema_handle);
        put_u64(&mut bytes, offset + 16, identity.generation);
        put_u64(&mut bytes, offset + 24, *nonce);
    }
    let tag = calculate_tag(&bytes, key);
    bytes[TAG_OFFSET..TAG_OFFSET + TAG_BYTES].copy_from_slice(&tag);
    Ok(bytes)
}

fn decode_snapshot(
    bytes: &[u8],
    key: &[u8; 32],
) -> Result<BTreeMap<ReplayIdentity, u64>, ReplayStoreError> {
    if bytes.len() < HEADER_BYTES {
        return Err(ReplayStoreError::Bounds);
    }
    let expected = calculate_tag(bytes, key);
    if !bool::from(bytes[TAG_OFFSET..TAG_OFFSET + TAG_BYTES].ct_eq(&expected)) {
        return Err(ReplayStoreError::AuthenticationFailed);
    }
    if bytes[0..4] != MAGIC || bytes[5..8] != [0; 3] {
        return Err(ReplayStoreError::NonCanonical);
    }
    if bytes[4] != VERSION {
        return Err(ReplayStoreError::UnsupportedVersion(bytes[4]));
    }
    let count = to_usize(get_u32(bytes, 8));
    let declared_length = to_usize(get_u32(bytes, 12));
    if count > MAX_RECORDS
        || declared_length != bytes.len()
        || HEADER_BYTES.checked_add(count * RECORD_BYTES) != Some(bytes.len())
    {
        return Err(ReplayStoreError::Bounds);
    }
    let mut nonces = BTreeMap::new();
    let mut previous = None;
    for index in 0..count {
        let offset = HEADER_BYTES + index * RECORD_BYTES;
        let identity = ReplayIdentity {
            profile: get_u32(bytes, offset),
            session_handle: get_u32(bytes, offset + 4),
            capability_handle: get_u32(bytes, offset + 8),
            schema_handle: get_u32(bytes, offset + 12),
            generation: get_u64(bytes, offset + 16),
        }
        .validate()?;
        let nonce = get_u64(bytes, offset + 24);
        validate_advance(0, nonce)?;
        if previous.is_some_and(|value| value >= identity) {
            return Err(ReplayStoreError::NonCanonical);
        }
        previous = Some(identity);
        nonces.insert(identity, nonce);
    }
    Ok(nonces)
}

fn calculate_tag(bytes: &[u8], key: &[u8; 32]) -> [u8; TAG_BYTES] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(MAC_DOMAIN);
    hasher.update(&bytes[..TAG_OFFSET]);
    hasher.update(&bytes[HEADER_BYTES..]);
    let tag = *hasher.finalize().as_bytes();
    hasher.zeroize();
    tag
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("bounded slice"))
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("bounded slice"))
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn to_u32(value: usize) -> Result<u32, ReplayStoreError> {
    u32::try_from(value).map_err(|_| ReplayStoreError::Bounds)
}

fn to_usize(value: u32) -> usize {
    usize::try_from(value).expect("u32 fits usize on supported targets")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const KEY: [u8; 32] = [0x52; 32];

    fn identity(profile: u32) -> ReplayIdentity {
        ReplayIdentity {
            profile,
            session_handle: 7,
            capability_handle: 11,
            schema_handle: 13,
            generation: 17,
        }
    }

    #[test]
    fn memory_store_advances_each_identity_monotonically() {
        let mut store = MemoryReplayStore::default();
        store.advance(identity(1), 19).expect("first advance");
        store.advance(identity(2), 17).expect("separate profile");
        assert_eq!(store.last_nonce(identity(1)), Ok(19));
        assert_eq!(
            store.advance(identity(1), 19),
            Err(ReplayStoreError::Replay)
        );
        assert_eq!(
            store.advance(identity(1), 18),
            Err(ReplayStoreError::Replay)
        );
    }

    #[test]
    fn file_store_survives_reopen_and_refuses_replay() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("replay.ndr");
        {
            let mut store = FileReplayStore::open(&path, KEY).expect("open replay store");
            store.advance(identity(1), 19).expect("persist nonce");
            assert_eq!(store.last_nonce(identity(1)), Ok(19));
        }
        let mut restored = FileReplayStore::open(&path, KEY).expect("restore replay store");
        assert_eq!(restored.last_nonce(identity(1)), Ok(19));
        assert_eq!(
            restored.advance(identity(1), 19),
            Err(ReplayStoreError::Replay)
        );
        restored
            .advance(identity(1), 20)
            .expect("advance restored store");
    }

    #[test]
    fn file_store_refuses_concurrent_owners() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("replay.ndr");
        let _first = FileReplayStore::open(&path, KEY).expect("first owner");
        assert!(matches!(
            FileReplayStore::open(&path, KEY),
            Err(ReplayStoreError::LockUnavailable)
        ));
    }

    #[test]
    fn file_store_authenticates_every_stored_byte() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("replay.ndr");
        {
            let mut store = FileReplayStore::open(&path, KEY).expect("open replay store");
            store.advance(identity(1), 19).expect("persist nonce");
        }
        let original = fs::read(&path).expect("read replay store");
        for index in 0..original.len() {
            let mut changed = original.clone();
            changed[index] ^= 1;
            fs::write(&path, &changed).expect("write changed replay store");
            assert!(matches!(
                FileReplayStore::open(&path, KEY),
                Err(ReplayStoreError::AuthenticationFailed)
            ));
        }
        fs::write(&path, original).expect("restore replay store");
        assert!(FileReplayStore::open(&path, KEY).is_ok());
    }

    #[test]
    fn file_store_refuses_relative_paths_and_weak_permissions() {
        assert!(matches!(
            FileReplayStore::open(Path::new("relative.ndr"), KEY),
            Err(ReplayStoreError::InvalidPath)
        ));
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("replay.ndr");
        fs::write(&path, []).expect("create replay store");
        let mut permissions = fs::metadata(&path).expect("replay metadata").permissions();
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o644);
        fs::set_permissions(&path, permissions).expect("weaken replay permissions");
        assert!(matches!(
            FileReplayStore::open(&path, KEY),
            Err(ReplayStoreError::InsecurePermissions)
        ));
    }

    #[test]
    fn file_store_refuses_a_symbolic_link_target() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target.ndr");
        let link = directory.path().join("replay.ndr");
        fs::write(&target, []).expect("create target");
        symlink(&target, &link).expect("create symbolic link");
        assert!(matches!(
            FileReplayStore::open(&link, KEY),
            Err(ReplayStoreError::Io(_))
        ));
    }
}
