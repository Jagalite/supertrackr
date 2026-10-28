use super::Result;
use boringtun::x25519::StaticSecret;
use rand::RngCore;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

/// Unix lab identity file: owner-only regular file; never follow a final symlink.
pub fn load_or_create(path: &Path) -> Result<StaticSecret> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            let mut raw = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(raw.as_mut());
            let encoded = Zeroizing::new(hex::encode(raw.as_ref()));
            file.write_all(encoded.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            Ok(StaticSecret::from(*raw))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)?;
            let meta = file.metadata()?;
            // SAFETY: geteuid has no arguments or memory access requirements.
            let uid = unsafe { libc::geteuid() };
            if !meta.is_file()
                || meta.uid() != uid
                || meta.mode() & 0o077 != 0
                || !(64..=65).contains(&meta.len())
            {
                return Err(
                    "identity must be an owner-only regular file containing a 32-byte hex key"
                        .into(),
                );
            }
            let mut encoded = Zeroizing::new(String::new());
            file.take(66).read_to_string(&mut encoded)?;
            let mut raw = Zeroizing::new([0u8; 32]);
            hex::decode_to_slice(encoded.trim_end_matches('\n'), raw.as_mut())
                .map_err(|_| "invalid identity encoding")?;
            Ok(StaticSecret::from(*raw))
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::x25519::PublicKey;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn identity_persists_and_rejects_unsafe_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let a = load_or_create(&path).unwrap();
        let b = load_or_create(&path).unwrap();
        assert_eq!(
            PublicKey::from(&a).as_bytes(),
            PublicKey::from(&b).as_bytes()
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(load_or_create(&link).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_or_create(&path).is_err());
    }
}
