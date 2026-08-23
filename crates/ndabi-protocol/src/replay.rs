//! Persist canonical read replay state across process restarts.
//!
//! The store authenticates a bounded snapshot and replaces it atomically.
//! A stable lock file prevents concurrent writers from using stale state.
//! An external trusted anchor must still prevent disk rollback.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{ProtocolError, ReplayKey, ReplayStore};

const MAGIC: [u8; 4] = *b"NDR1";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = 48;
const RECORD_BYTES: usize = 56;
const TAG_OFFSET: usize = 16;
const TAG_BYTES: usize = 32;
const MAX_RECORDS: usize = 65_536;
const MAC_DOMAIN: &[u8] = b"ndabi/wire/v1/replay-store";

pub struct FileReplayStore {
    path: PathBuf,
    _lock: File,
    key: Zeroizing<[u8; 32]>,
    nonces: BTreeMap<ReplayKey, u64>,
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

impl FileReplayStore {
    pub fn open(path: &Path, key: [u8; 32]) -> Result<Self, ProtocolError> {
        if key.iter().fold(0_u8, |state, byte| state | byte) == 0 {
            return Err(ProtocolError::ZeroKey);
        }
        let key = Zeroizing::new(key);
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

    fn persist(&self, nonces: &BTreeMap<ReplayKey, u64>) -> Result<(), ProtocolError> {
        let bytes = encode_snapshot(nonces, &self.key)?;
        let parent = self.path.parent().ok_or(ProtocolError::ReplayStoreIo)?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".ndabi-replay-")
            .tempfile_in(parent)
            .map_err(map_io)?;
        temporary.write_all(&bytes).map_err(map_io)?;
        temporary.as_file().sync_all().map_err(map_io)?;
        temporary
            .persist(&self.path)
            .map_err(|error| map_io(error.error))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(map_io)?;
        Ok(())
    }
}

impl ReplayStore for FileReplayStore {
    fn last_nonce(&self, key: ReplayKey) -> Result<u64, ProtocolError> {
        Ok(self.nonces.get(&key).copied().unwrap_or(0))
    }

    fn commit(
        &mut self,
        key: ReplayKey,
        expected_last: u64,
        accepted: u64,
    ) -> Result<(), ProtocolError> {
        if self.last_nonce(key)? != expected_last
            || accepted
                != expected_last
                    .checked_add(1)
                    .ok_or(ProtocolError::NonceEnded)?
        {
            return Err(ProtocolError::ReplayConflict);
        }
        if self.nonces.len() == MAX_RECORDS && !self.nonces.contains_key(&key) {
            return Err(ProtocolError::BudgetExceeded);
        }
        let mut proposed = self.nonces.clone();
        proposed.insert(key, accepted);
        self.persist(&proposed)?;
        self.nonces = proposed;
        Ok(())
    }
}

fn normalise_path(path: &Path) -> Result<PathBuf, ProtocolError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ProtocolError::ReplayStoreIo);
    }
    let parent = path.parent().ok_or(ProtocolError::ReplayStoreIo)?;
    let parent = parent.canonicalize().map_err(map_io)?;
    let metadata = parent.metadata().map_err(map_io)?;
    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
        return Err(ProtocolError::ReplayStoreInsecure);
    }
    Ok(parent.join(path.file_name().ok_or(ProtocolError::ReplayStoreIo)?))
}

fn lock_path(path: &Path) -> Result<PathBuf, ProtocolError> {
    let name = path.file_name().ok_or(ProtocolError::ReplayStoreIo)?;
    let mut lock_name = name.to_os_string();
    lock_name.push(".lock");
    Ok(path.with_file_name(lock_name))
}

fn open_private(path: &Path, create: bool, write: bool) -> Result<File, ProtocolError> {
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(map_io)?;
    if file.metadata().map_err(map_io)?.mode() & 0o077 != 0 {
        return Err(ProtocolError::ReplayStoreInsecure);
    }
    Ok(file)
}

fn acquire_exclusive_lock(file: &File) -> Result<(), ProtocolError> {
    // The stable lock file covers snapshots across each atomic rename.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Err(ProtocolError::ReplayStoreLockUnavailable)
    } else {
        Err(ProtocolError::ReplayStoreIo)
    }
}

fn load_snapshot(path: &Path, key: &[u8; 32]) -> Result<BTreeMap<ReplayKey, u64>, ProtocolError> {
    let file = match open_private(path, false, false) {
        Ok(file) => file,
        Err(ProtocolError::ReplayStoreIo) => match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            _ => return Err(ProtocolError::ReplayStoreIo),
        },
        Err(error) => return Err(error),
    };
    let length = usize::try_from(file.metadata().map_err(map_io)?.len())
        .map_err(|_| ProtocolError::BudgetExceeded)?;
    let maximum = HEADER_BYTES
        .checked_add(MAX_RECORDS * RECORD_BYTES)
        .ok_or(ProtocolError::BudgetExceeded)?;
    if !(HEADER_BYTES..=maximum).contains(&length) {
        return Err(ProtocolError::ReplayStoreAuthenticationFailed);
    }
    let read_limit = u64::try_from(maximum + 1).map_err(|_| ProtocolError::BudgetExceeded)?;
    let mut bytes = Vec::with_capacity(length);
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    if bytes.len() != length {
        return Err(ProtocolError::ReplayStoreAuthenticationFailed);
    }
    decode_snapshot(&bytes, key)
}

fn encode_snapshot(
    nonces: &BTreeMap<ReplayKey, u64>,
    key: &[u8; 32],
) -> Result<Vec<u8>, ProtocolError> {
    if nonces.len() > MAX_RECORDS {
        return Err(ProtocolError::BudgetExceeded);
    }
    let payload_bytes = nonces
        .len()
        .checked_mul(RECORD_BYTES)
        .ok_or(ProtocolError::BudgetExceeded)?;
    let total_bytes = HEADER_BYTES
        .checked_add(payload_bytes)
        .ok_or(ProtocolError::BudgetExceeded)?;
    let mut bytes = vec![0_u8; total_bytes];
    bytes[0..4].copy_from_slice(&MAGIC);
    bytes[4] = VERSION;
    put_u32(&mut bytes, 8, to_u32(nonces.len())?);
    put_u32(&mut bytes, 12, to_u32(total_bytes)?);
    for (index, (replay_key, nonce)) in nonces.iter().enumerate() {
        if *nonce == 0 {
            return Err(ProtocolError::ReplayConflict);
        }
        let offset = HEADER_BYTES + index * RECORD_BYTES;
        bytes[offset..offset + 32].copy_from_slice(&replay_key.context_digest);
        put_u64(&mut bytes, offset + 32, replay_key.session);
        put_u64(&mut bytes, offset + 40, replay_key.generation);
        put_u64(&mut bytes, offset + 48, *nonce);
    }
    let tag = calculate_tag(&bytes, key);
    bytes[TAG_OFFSET..TAG_OFFSET + TAG_BYTES].copy_from_slice(&tag);
    Ok(bytes)
}

fn decode_snapshot(
    bytes: &[u8],
    key: &[u8; 32],
) -> Result<BTreeMap<ReplayKey, u64>, ProtocolError> {
    if bytes.len() < HEADER_BYTES {
        return Err(ProtocolError::ReplayStoreAuthenticationFailed);
    }
    let expected = calculate_tag(bytes, key);
    if bytes[TAG_OFFSET..TAG_OFFSET + TAG_BYTES]
        .ct_eq(&expected)
        .unwrap_u8()
        != 1
    {
        return Err(ProtocolError::ReplayStoreAuthenticationFailed);
    }
    if bytes[0..4] != MAGIC || bytes[5..8] != [0; 3] || bytes[4] != VERSION {
        return Err(ProtocolError::ReplayStoreAuthenticationFailed);
    }
    let count = get_u32(bytes, 8) as usize;
    let declared_length = get_u32(bytes, 12) as usize;
    if count > MAX_RECORDS
        || declared_length != bytes.len()
        || HEADER_BYTES.checked_add(count * RECORD_BYTES) != Some(bytes.len())
    {
        return Err(ProtocolError::ReplayStoreAuthenticationFailed);
    }
    let mut nonces = BTreeMap::new();
    let mut previous = None;
    for index in 0..count {
        let offset = HEADER_BYTES + index * RECORD_BYTES;
        let replay_key = ReplayKey {
            context_digest: bytes[offset..offset + 32]
                .try_into()
                .map_err(|_| ProtocolError::ReplayStoreAuthenticationFailed)?,
            session: get_u64(bytes, offset + 32),
            generation: get_u64(bytes, offset + 40),
        };
        let nonce = get_u64(bytes, offset + 48);
        if replay_key.session == 0
            || replay_key.generation == 0
            || replay_key.context_digest.iter().all(|byte| *byte == 0)
            || nonce == 0
            || previous.is_some_and(|value| value >= replay_key)
        {
            return Err(ProtocolError::ReplayStoreAuthenticationFailed);
        }
        previous = Some(replay_key);
        nonces.insert(replay_key, nonce);
    }
    Ok(nonces)
}

fn calculate_tag(bytes: &[u8], key: &[u8; 32]) -> [u8; TAG_BYTES] {
    let mut digest = blake3::Hasher::new_keyed(key);
    digest.update(MAC_DOMAIN);
    digest.update(&bytes[..TAG_OFFSET]);
    digest.update(&bytes[HEADER_BYTES..]);
    let tag = *digest.finalize().as_bytes();
    digest.zeroize();
    tag
}

fn map_io(_error: io::Error) -> ProtocolError {
    ProtocolError::ReplayStoreIo
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("bounded snapshot"),
    )
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("bounded snapshot"),
    )
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn to_u32(value: usize) -> Result<u32, ProtocolError> {
    u32::try_from(value).map_err(|_| ProtocolError::BudgetExceeded)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    const KEY: [u8; 32] = [0x59; 32];

    fn replay_key(profile: u8) -> ReplayKey {
        ReplayKey {
            context_digest: [profile; 32],
            session: 7,
            generation: 11,
        }
    }

    fn private_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("temporary directory");
        let permissions = fs::Permissions::from_mode(0o700);
        fs::set_permissions(directory.path(), permissions).expect("private directory");
        directory
    }

    #[test]
    fn the_store_survives_reopen_and_refuses_replay() {
        let directory = private_directory();
        let path = directory.path().join("replay.ndr");
        {
            let mut store = FileReplayStore::open(&path, KEY).expect("store");
            store.commit(replay_key(1), 0, 1).expect("first commit");
        }
        let mut restored = FileReplayStore::open(&path, KEY).expect("restored store");
        assert_eq!(restored.last_nonce(replay_key(1)), Ok(1));
        assert_eq!(
            restored.commit(replay_key(1), 0, 1),
            Err(ProtocolError::ReplayConflict)
        );
        restored.commit(replay_key(1), 1, 2).expect("next commit");
    }

    #[test]
    fn every_snapshot_bit_is_authenticated() {
        let directory = private_directory();
        let path = directory.path().join("replay.ndr");
        {
            let mut store = FileReplayStore::open(&path, KEY).expect("store");
            store.commit(replay_key(1), 0, 1).expect("commit");
        }
        let original = fs::read(&path).expect("snapshot");
        for bit in 0..original.len() * 8 {
            let mut changed = original.clone();
            changed[bit / 8] ^= 1 << (bit % 8);
            fs::write(&path, changed).expect("changed snapshot");
            assert_eq!(
                FileReplayStore::open(&path, KEY).unwrap_err(),
                ProtocolError::ReplayStoreAuthenticationFailed,
                "accepted bit {bit}"
            );
        }
        fs::write(&path, original).expect("restored snapshot");
        assert!(FileReplayStore::open(&path, KEY).is_ok());
    }

    #[test]
    fn the_store_refuses_concurrent_owners() {
        let directory = private_directory();
        let path = directory.path().join("replay.ndr");
        let _first = FileReplayStore::open(&path, KEY).expect("first owner");
        assert_eq!(
            FileReplayStore::open(&path, KEY).unwrap_err(),
            ProtocolError::ReplayStoreLockUnavailable
        );
    }

    #[test]
    fn the_store_refuses_weak_permissions_and_symbolic_links() {
        let directory = private_directory();
        let path = directory.path().join("replay.ndr");
        fs::write(&path, []).expect("snapshot");
        let mut permissions = fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&path, permissions).expect("permissions");
        assert_eq!(
            FileReplayStore::open(&path, KEY).unwrap_err(),
            ProtocolError::ReplayStoreInsecure
        );

        let target = directory.path().join("target.ndr");
        let link = directory.path().join("link.ndr");
        fs::write(&target, []).expect("target");
        std::os::unix::fs::symlink(target, &link).expect("link");
        assert_eq!(
            FileReplayStore::open(&link, KEY).unwrap_err(),
            ProtocolError::ReplayStoreIo
        );
    }
}
