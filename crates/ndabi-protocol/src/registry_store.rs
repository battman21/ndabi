//! Persist one active registry digest and its bounded revocation set.
//!
//! The authenticated snapshot refuses tampering and concurrent writers.
//! An external trusted anchor must still refuse valid snapshot rollback.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{DiscoveredRegistry, PlanRegistry, ProtocolError};

const MAGIC: &[u8; 4] = b"NDS1";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = 56;
const RECORD_BYTES: usize = 32;
const TAG_BYTES: usize = 32;
const BASE_BYTES: usize = HEADER_BYTES + TAG_BYTES;
const MAX_REVOKED_REGISTRIES: usize = 4_096;
const MAC_DOMAIN: &[u8] = b"ndabi/wire/v1/registry-store";

/// Supply registry authentication material from an external custody implementation.
pub trait RegistryKeyProvider {
    fn load_registry_key(&self) -> Result<Zeroizing<[u8; 32]>, ProtocolError>;
}

pub struct FileRegistryStore {
    path: PathBuf,
    _lock: File,
    key: Zeroizing<[u8; 32]>,
    generation: u64,
    active_digest: Option<[u8; 32]>,
    revoked: BTreeSet<[u8; 32]>,
}

impl fmt::Debug for FileRegistryStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileRegistryStore")
            .field("path", &self.path)
            .field("key", &"[REDACTED]")
            .field("generation", &self.generation)
            .field("active", &self.active_digest.is_some())
            .field("revoked", &self.revoked.len())
            .finish_non_exhaustive()
    }
}

impl FileRegistryStore {
    pub fn open(path: &Path, key: [u8; 32]) -> Result<Self, ProtocolError> {
        Self::open_with_key(path, Zeroizing::new(key))
    }

    pub fn open_with_provider(
        path: &Path,
        provider: &impl RegistryKeyProvider,
    ) -> Result<Self, ProtocolError> {
        Self::open_with_key(path, provider.load_registry_key()?)
    }

    fn open_with_key(path: &Path, key: Zeroizing<[u8; 32]>) -> Result<Self, ProtocolError> {
        if key.iter().fold(0_u8, |state, byte| state | byte) == 0 {
            return Err(ProtocolError::ZeroKey);
        }
        let path = normalise_path(path)?;
        let lock_path = lock_path(&path)?;
        let lock = open_private(&lock_path, true, true)?;
        acquire_exclusive_lock(&lock)?;
        let snapshot = load_snapshot(&path, &key)?;
        Ok(Self {
            path,
            _lock: lock,
            key,
            generation: snapshot.generation,
            active_digest: snapshot.active_digest,
            revoked: snapshot.revoked,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn active_digest(&self) -> Option<[u8; 32]> {
        self.active_digest
    }

    pub fn is_revoked(&self, digest: [u8; 32]) -> bool {
        self.revoked.contains(&digest)
    }

    pub fn activate(
        &mut self,
        registry: &PlanRegistry,
        generation: u64,
    ) -> Result<(), ProtocolError> {
        let digest = registry.digest();
        if generation <= self.generation {
            return Err(ProtocolError::RegistryGeneration);
        }
        if self.revoked.contains(&digest) {
            return Err(ProtocolError::RegistryRevoked);
        }
        let proposed = Snapshot {
            generation,
            active_digest: Some(digest),
            revoked: self.revoked.clone(),
        };
        self.persist(&proposed)?;
        self.generation = generation;
        self.active_digest = Some(digest);
        Ok(())
    }

    pub fn revoke(&mut self, digest: [u8; 32], generation: u64) -> Result<(), ProtocolError> {
        if digest.iter().fold(0_u8, |state, byte| state | byte) == 0 {
            return Err(ProtocolError::ZeroDigest);
        }
        if generation <= self.generation {
            return Err(ProtocolError::RegistryGeneration);
        }
        if self.revoked.len() == MAX_REVOKED_REGISTRIES && !self.revoked.contains(&digest) {
            return Err(ProtocolError::PlanLimitExceeded);
        }
        let mut revoked = self.revoked.clone();
        revoked.insert(digest);
        let active_digest = self
            .active_digest
            .filter(|active| active.ct_eq(&digest).unwrap_u8() != 1);
        let proposed = Snapshot {
            generation,
            active_digest,
            revoked,
        };
        self.persist(&proposed)?;
        self.generation = generation;
        self.active_digest = active_digest;
        self.revoked = proposed.revoked;
        Ok(())
    }

    pub fn authorise(&self, registry: &PlanRegistry) -> Result<u64, ProtocolError> {
        let digest = registry.digest();
        if self.revoked.contains(&digest) {
            return Err(ProtocolError::RegistryRevoked);
        }
        let Some(active) = self.active_digest else {
            return Err(ProtocolError::RegistryInactive);
        };
        if active.ct_eq(&digest).unwrap_u8() != 1 {
            return Err(ProtocolError::RegistryInactive);
        }
        Ok(self.generation)
    }

    pub fn authorise_discovery(
        &self,
        discovered: &DiscoveredRegistry,
    ) -> Result<(), ProtocolError> {
        if discovered.generation() != self.generation {
            return Err(ProtocolError::RegistryGeneration);
        }
        self.authorise(discovered.registry())?;
        Ok(())
    }

    fn persist(&self, snapshot: &Snapshot) -> Result<(), ProtocolError> {
        let bytes = encode_snapshot(snapshot, &self.key)?;
        let parent = self.path.parent().ok_or(ProtocolError::RegistryStoreIo)?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".ndabi-registry-")
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

struct Snapshot {
    generation: u64,
    active_digest: Option<[u8; 32]>,
    revoked: BTreeSet<[u8; 32]>,
}

fn normalise_path(path: &Path) -> Result<PathBuf, ProtocolError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ProtocolError::RegistryStoreIo);
    }
    let parent = path.parent().ok_or(ProtocolError::RegistryStoreIo)?;
    let parent = parent.canonicalize().map_err(map_io)?;
    let metadata = parent.metadata().map_err(map_io)?;
    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
        return Err(ProtocolError::RegistryStoreInsecure);
    }
    Ok(parent.join(path.file_name().ok_or(ProtocolError::RegistryStoreIo)?))
}

fn lock_path(path: &Path) -> Result<PathBuf, ProtocolError> {
    let name = path.file_name().ok_or(ProtocolError::RegistryStoreIo)?;
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
        return Err(ProtocolError::RegistryStoreInsecure);
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
        Err(ProtocolError::RegistryStoreLockUnavailable)
    } else {
        Err(ProtocolError::RegistryStoreIo)
    }
}

fn load_snapshot(path: &Path, key: &[u8; 32]) -> Result<Snapshot, ProtocolError> {
    let file = match open_private(path, false, false) {
        Ok(file) => file,
        Err(ProtocolError::RegistryStoreIo) => match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Snapshot {
                    generation: 0,
                    active_digest: None,
                    revoked: BTreeSet::new(),
                });
            }
            _ => return Err(ProtocolError::RegistryStoreIo),
        },
        Err(error) => return Err(error),
    };
    let length = usize::try_from(file.metadata().map_err(map_io)?.len())
        .map_err(|_| ProtocolError::PlanLimitExceeded)?;
    let maximum = BASE_BYTES
        .checked_add(MAX_REVOKED_REGISTRIES * RECORD_BYTES)
        .ok_or(ProtocolError::PlanLimitExceeded)?;
    if !(BASE_BYTES..=maximum).contains(&length) {
        return Err(ProtocolError::RegistryStoreAuthenticationFailed);
    }
    let mut bytes = Vec::with_capacity(length);
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    if bytes.len() != length {
        return Err(ProtocolError::RegistryStoreAuthenticationFailed);
    }
    decode_snapshot(&bytes, key)
}

fn encode_snapshot(snapshot: &Snapshot, key: &[u8; 32]) -> Result<Vec<u8>, ProtocolError> {
    if snapshot.generation == 0 || snapshot.revoked.len() > MAX_REVOKED_REGISTRIES {
        return Err(ProtocolError::RegistryGeneration);
    }
    if snapshot
        .active_digest
        .is_some_and(|digest| snapshot.revoked.contains(&digest))
    {
        return Err(ProtocolError::RegistryRevoked);
    }
    let total_bytes = BASE_BYTES
        .checked_add(
            snapshot
                .revoked
                .len()
                .checked_mul(RECORD_BYTES)
                .ok_or(ProtocolError::PlanLimitExceeded)?,
        )
        .ok_or(ProtocolError::PlanLimitExceeded)?;
    let mut bytes = vec![0_u8; total_bytes];
    bytes[0..4].copy_from_slice(MAGIC);
    bytes[4] = VERSION;
    bytes[5] = u8::from(snapshot.active_digest.is_some());
    put_u64(&mut bytes, 8, snapshot.generation);
    put_u32(
        &mut bytes,
        16,
        u32::try_from(snapshot.revoked.len()).map_err(|_| ProtocolError::PlanLimitExceeded)?,
    );
    put_u32(
        &mut bytes,
        20,
        u32::try_from(total_bytes).map_err(|_| ProtocolError::PlanLimitExceeded)?,
    );
    if let Some(active) = snapshot.active_digest {
        bytes[24..56].copy_from_slice(&active);
    }
    for (index, digest) in snapshot.revoked.iter().enumerate() {
        let offset = HEADER_BYTES + index * RECORD_BYTES;
        bytes[offset..offset + RECORD_BYTES].copy_from_slice(digest);
    }
    let tag_offset = total_bytes - TAG_BYTES;
    let tag = snapshot_tag(key, &bytes[..tag_offset]);
    bytes[tag_offset..].copy_from_slice(&tag);
    Ok(bytes)
}

fn decode_snapshot(bytes: &[u8], key: &[u8; 32]) -> Result<Snapshot, ProtocolError> {
    let tag_offset = bytes
        .len()
        .checked_sub(TAG_BYTES)
        .ok_or(ProtocolError::RegistryStoreAuthenticationFailed)?;
    let expected = snapshot_tag(key, &bytes[..tag_offset]);
    if expected.ct_eq(&bytes[tag_offset..]).unwrap_u8() != 1 {
        return Err(ProtocolError::RegistryStoreAuthenticationFailed);
    }
    let revoked_count = get_u32(bytes, 16) as usize;
    let expected_bytes = BASE_BYTES
        .checked_add(
            revoked_count
                .checked_mul(RECORD_BYTES)
                .ok_or(ProtocolError::RegistryStoreAuthenticationFailed)?,
        )
        .ok_or(ProtocolError::RegistryStoreAuthenticationFailed)?;
    if &bytes[0..4] != MAGIC
        || bytes[4] != VERSION
        || bytes[5] > 1
        || bytes[6..8] != [0; 2]
        || get_u32(bytes, 20) as usize != bytes.len()
        || bytes.len() != expected_bytes
        || revoked_count > MAX_REVOKED_REGISTRIES
    {
        return Err(ProtocolError::RegistryStoreAuthenticationFailed);
    }
    let generation = get_u64(bytes, 8);
    if generation == 0 {
        return Err(ProtocolError::RegistryStoreAuthenticationFailed);
    }
    let active_digest = if bytes[5] == 1 {
        let digest = digest_at(bytes, 24)?;
        if digest.iter().fold(0_u8, |state, byte| state | byte) == 0 {
            return Err(ProtocolError::RegistryStoreAuthenticationFailed);
        }
        Some(digest)
    } else {
        if bytes[24..56] != [0; 32] {
            return Err(ProtocolError::RegistryStoreAuthenticationFailed);
        }
        None
    };
    let mut revoked = BTreeSet::new();
    for index in 0..revoked_count {
        let digest = digest_at(bytes, HEADER_BYTES + index * RECORD_BYTES)?;
        if digest.iter().fold(0_u8, |state, byte| state | byte) == 0 || !revoked.insert(digest) {
            return Err(ProtocolError::RegistryStoreAuthenticationFailed);
        }
    }
    if active_digest.is_some_and(|digest| revoked.contains(&digest)) {
        return Err(ProtocolError::RegistryStoreAuthenticationFailed);
    }
    Ok(Snapshot {
        generation,
        active_digest,
        revoked,
    })
}

fn snapshot_tag(key: &[u8; 32], bytes: &[u8]) -> [u8; TAG_BYTES] {
    let mut digest = blake3::Hasher::new_keyed(key);
    digest.update(MAC_DOMAIN);
    digest.update(bytes);
    let tag = *digest.finalize().as_bytes();
    digest.zeroize();
    tag
}

fn digest_at(bytes: &[u8], offset: usize) -> Result<[u8; 32], ProtocolError> {
    bytes
        .get(offset..offset + 32)
        .ok_or(ProtocolError::RegistryStoreAuthenticationFailed)?
        .try_into()
        .map_err(|_| ProtocolError::RegistryStoreAuthenticationFailed)
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked snapshot"),
    )
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("checked snapshot"),
    )
}

fn map_io(_: io::Error) -> ProtocolError {
    ProtocolError::RegistryStoreIo
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::{
        decode_registry_discovery, digest_label, encode_registry_discovery, Authority,
        AuthorityContext, CapabilityManifest, RegisteredPlan, CAPABILITY_QUERY,
    };

    fn private_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        directory
    }

    fn registry(implementation: u8) -> PlanRegistry {
        let plan = RegisteredPlan::new_read(
            1,
            2,
            3,
            1,
            64,
            4,
            CAPABILITY_QUERY,
            digest_label(b"parameters", &[1]),
            digest_label(b"implementation", &[implementation]),
        )
        .expect("plan");
        PlanRegistry::new(
            4,
            5,
            digest_label(b"schema", &[6]),
            digest_label(b"policy", &[7]),
            CapabilityManifest::new(CAPABILITY_QUERY).expect("manifest"),
            [plan],
        )
        .expect("registry")
    }

    fn authority(registry: &PlanRegistry) -> Authority {
        let context = AuthorityContext::new(
            [1; 16],
            [2; 16],
            3,
            digest_label(b"capability", &[4]),
            registry.identity(),
        )
        .expect("context");
        Authority::new_read([5; 32], 6, 7, 10_000, context).expect("authority")
    }

    #[test]
    fn activation_and_revocation_survive_reopen() {
        let directory = private_directory();
        let path = directory.path().join("registry.state");
        let first = registry(1);
        let second = registry(2);
        {
            let mut store = FileRegistryStore::open(&path, [9; 32]).expect("store");
            store.activate(&first, 1).expect("activate first");
            assert_eq!(store.authorise(&first).expect("authorised"), 1);
            store.activate(&second, 2).expect("activate second");
            assert_eq!(
                store.authorise(&first).unwrap_err(),
                ProtocolError::RegistryInactive
            );
            store.revoke(second.digest(), 3).expect("revoke second");
            assert_eq!(
                store.authorise(&second).unwrap_err(),
                ProtocolError::RegistryRevoked
            );
        }
        let store = FileRegistryStore::open(&path, [9; 32]).expect("reopened store");
        assert_eq!(store.generation(), 3);
        assert!(store.is_revoked(second.digest()));
        assert_eq!(store.active_digest(), None);
    }

    #[test]
    fn revoked_and_stale_registry_changes_refuse() {
        let directory = private_directory();
        let path = directory.path().join("registry.state");
        let registry = registry(1);
        let mut store = FileRegistryStore::open(&path, [9; 32]).expect("store");
        store.activate(&registry, 1).expect("activate");
        store.revoke(registry.digest(), 2).expect("revoke");
        assert_eq!(
            store.activate(&registry, 3).unwrap_err(),
            ProtocolError::RegistryRevoked
        );
        assert_eq!(
            store.revoke([8; 32], 2).unwrap_err(),
            ProtocolError::RegistryGeneration
        );
    }

    #[test]
    fn tampering_wrong_keys_and_weak_permissions_refuse() {
        let directory = private_directory();
        let path = directory.path().join("registry.state");
        let registry = registry(1);
        {
            let mut store = FileRegistryStore::open(&path, [9; 32]).expect("store");
            store.activate(&registry, 1).expect("activate");
        }
        assert_eq!(
            FileRegistryStore::open(&path, [8; 32]).unwrap_err(),
            ProtocolError::RegistryStoreAuthenticationFailed
        );

        let mut bytes = fs::read(&path).expect("snapshot");
        bytes[24] ^= 1;
        fs::write(&path, bytes).expect("changed snapshot");
        assert_eq!(
            FileRegistryStore::open(&path, [9; 32]).unwrap_err(),
            ProtocolError::RegistryStoreAuthenticationFailed
        );

        let weak_directory = private_directory();
        fs::set_permissions(weak_directory.path(), fs::Permissions::from_mode(0o755))
            .expect("permissions");
        let weak_path = weak_directory.path().join("registry.state");
        assert_eq!(
            FileRegistryStore::open(&weak_path, [9; 32]).unwrap_err(),
            ProtocolError::RegistryStoreInsecure
        );
    }

    #[test]
    fn every_persisted_snapshot_bit_is_authenticated() {
        let directory = private_directory();
        let path = directory.path().join("registry.state");
        let registry = registry(1);
        {
            let mut store = FileRegistryStore::open(&path, [9; 32]).expect("store");
            store.activate(&registry, 1).expect("activate");
        }
        let original = fs::read(&path).expect("snapshot");
        for bit in 0..original.len() * 8 {
            let mut changed = original.clone();
            changed[bit / 8] ^= 1 << (bit % 8);
            fs::write(&path, changed).expect("changed snapshot");
            assert_eq!(
                FileRegistryStore::open(&path, [9; 32]).unwrap_err(),
                ProtocolError::RegistryStoreAuthenticationFailed,
                "accepted bit {bit}"
            );
        }
        fs::write(&path, original).expect("restored snapshot");
        assert!(FileRegistryStore::open(&path, [9; 32]).is_ok());
    }

    #[test]
    fn discovery_requires_the_current_persisted_generation() {
        let directory = private_directory();
        let path = directory.path().join("registry.state");
        let registry = registry(1);
        let authority = authority(&registry);
        let mut store = FileRegistryStore::open(&path, [9; 32]).expect("store");
        store.activate(&registry, 2).expect("activate");
        let current =
            encode_registry_discovery(&authority, &registry, 2, 9_000).expect("current discovery");
        let current = decode_registry_discovery(&authority, &current, 8_000).expect("discovery");
        store
            .authorise_discovery(&current)
            .expect("current generation");

        let stale =
            encode_registry_discovery(&authority, &registry, 1, 9_000).expect("stale discovery");
        let stale = decode_registry_discovery(&authority, &stale, 8_000).expect("discovery");
        assert_eq!(
            store.authorise_discovery(&stale).unwrap_err(),
            ProtocolError::RegistryGeneration
        );
    }

    #[test]
    fn the_store_refuses_concurrent_owners_and_symbolic_links() {
        let directory = private_directory();
        let path = directory.path().join("registry.state");
        let _first = FileRegistryStore::open(&path, [9; 32]).expect("first owner");
        assert_eq!(
            FileRegistryStore::open(&path, [9; 32]).unwrap_err(),
            ProtocolError::RegistryStoreLockUnavailable
        );

        let target = directory.path().join("target.state");
        let link = directory.path().join("link.state");
        fs::write(&target, []).expect("target");
        std::os::unix::fs::symlink(target, &link).expect("link");
        assert_eq!(
            FileRegistryStore::open(&link, [9; 32]).unwrap_err(),
            ProtocolError::RegistryStoreIo
        );
    }
}
