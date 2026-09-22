use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub ttl: Duration,
    pub max_item_bytes: usize,
    pub max_total_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub id: String,
    pub sha256: String,
    pub bytes: usize,
    pub expires_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRange {
    pub bytes: Vec<u8>,
    pub total_bytes: usize,
    pub sha256: String,
}

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)
            .with_context(|| format!("create artifact root {}", root.display()))?;
        let metadata = fs::symlink_metadata(&root)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("artifact root must be a regular directory");
        }
        Ok(Self { root })
    }

    pub fn put(&self, bytes: &[u8], limits: Limits) -> Result<Stored> {
        if bytes.len() > limits.max_item_bytes {
            bail!("artifact exceeds per-item byte limit");
        }
        self.cleanup(limits.ttl)?;
        let used = self.total_bytes()?;
        let next = used
            .checked_add(bytes.len())
            .ok_or_else(|| anyhow::anyhow!("artifact disk accounting overflow"))?;
        if next > limits.max_total_bytes {
            bail!("artifact store total byte limit reached");
        }

        let id = Uuid::new_v4().to_string();
        let final_path = self.path_for(&id)?;
        let temporary_path = self.root.join(format!(".{id}.partial"));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary_path, &final_path)?;

        Ok(Stored {
            id,
            sha256: sha256(bytes),
            bytes: bytes.len(),
            expires_at_unix_seconds: unix_seconds().saturating_add(limits.ttl.as_secs()),
        })
    }

    pub fn read(&self, id: &str, offset: usize, limit: usize, limits: Limits) -> Result<ReadRange> {
        self.cleanup(limits.ttl)?;
        let path = self.path_for(id)?;
        let metadata = fs::symlink_metadata(&path).context("artifact not found")?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("artifact is not a regular file");
        }
        let total_bytes = usize::try_from(metadata.len()).context("artifact exceeds host size")?;
        if offset > total_bytes {
            bail!("artifact offset exceeds content length");
        }
        let bounded = limit.min(limits.max_item_bytes).min(total_bytes - offset);
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(offset as u64))?;
        let mut bytes = vec![0; bounded];
        file.read_exact(&mut bytes)?;
        Ok(ReadRange {
            sha256: sha256_file(&file)?,
            bytes,
            total_bytes,
        })
    }

    pub fn cleanup(&self, ttl: Duration) -> Result<()> {
        let now = SystemTime::now();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                continue;
            }
            if entry.file_name().to_string_lossy().starts_with('.') {
                fs::remove_file(entry.path())?;
                continue;
            }
            let expired = metadata
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age >= ttl);
            if expired {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    fn total_bytes(&self) -> Result<usize> {
        fs::read_dir(&self.root)?.try_fold(0_usize, |total, entry| {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Ok(total);
            }
            total
                .checked_add(usize::try_from(metadata.len())?)
                .ok_or_else(|| anyhow::anyhow!("artifact disk accounting overflow"))
        })
    }

    fn path_for(&self, id: &str) -> Result<PathBuf> {
        let id = Uuid::parse_str(id).context("invalid artifact id")?;
        Ok(self.root.join(id.to_string()))
    }
}

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn sha256_file(file: &File) -> Result<String> {
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(format!("{:x}", digest.finalize()));
        }
        digest.update(&buffer[..read]);
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("gateway-artifact-test-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn limits() -> Limits {
        Limits {
            ttl: Duration::from_secs(60),
            max_item_bytes: 8,
            max_total_bytes: 12,
        }
    }

    #[test]
    fn stores_sha256_and_reads_a_bounded_range() {
        let temp = TestDir::new();
        let store = Store::new(temp.path().join("artifacts")).unwrap();
        let stored = store.put(b"abcdefgh", limits()).unwrap();
        let read = store.read(&stored.id, 2, 99, limits()).unwrap();
        assert_eq!(read.bytes, b"cdefgh");
        assert_eq!(read.total_bytes, 8);
        assert_eq!(read.sha256, stored.sha256);
    }

    #[test]
    fn rejects_oversize_and_disk_pressure_then_reclaims_expired_items() {
        let temp = TestDir::new();
        let store = Store::new(temp.path().join("artifacts")).unwrap();
        assert!(store.put(b"012345678", limits()).is_err());
        let stored = store.put(b"12345678", limits()).unwrap();
        assert!(store.put(b"12345", limits()).is_err());
        store.cleanup(Duration::ZERO).unwrap();
        assert!(store.put(b"12345", limits()).is_ok());
        assert!(!temp.path().join("artifacts").join(stored.id).exists());
    }

    #[test]
    fn rejects_path_traversal_and_symlink_artifacts() {
        let temp = TestDir::new();
        let store = Store::new(temp.path().join("artifacts")).unwrap();
        assert!(store.read("../secret", 0, 1, limits()).is_err());
        #[cfg(unix)]
        {
            let link = temp
                .path()
                .join("artifacts")
                .join(Uuid::new_v4().to_string());
            std::os::unix::fs::symlink("/etc/passwd", &link).unwrap();
            assert!(
                store
                    .read(link.file_name().unwrap().to_str().unwrap(), 0, 1, limits())
                    .is_err()
            );
            fs::remove_file(link).unwrap();
        }
    }
}
