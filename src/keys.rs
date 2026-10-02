use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::{NotaryError, Result};
use crate::record::Record;

pub struct DeviceKey {
    signing: SigningKey,
}

/// First 8 bytes of SHA-256 of the public key, hex. Stable id for rotation.
pub fn key_id(public: &VerifyingKey) -> String {
    hex::encode(&Sha256::digest(public.as_bytes())[..8])
}

impl DeviceKey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    pub fn generate() -> (Self, [u8; 32]) {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        (Self::from_seed(seed), seed)
    }

    /// Write a new key file. Refuses to overwrite: a device key is never regenerated.
    pub fn create_file(path: &Path) -> Result<Self> {
        if path.exists() {
            return Err(NotaryError::config(format!(
                "{} exists; a device key is never overwritten",
                path.display()
            )));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let (key, seed) = Self::generate();
        std::fs::write(path, format!("{}\n", B64.encode(seed)))?;
        restrict_permissions(path)?;
        Ok(key)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|source| NotaryError::Path {
            path: path.to_path_buf(),
            source,
        })?;
        let bytes = B64
            .decode(raw.trim())
            .map_err(|_| NotaryError::config("key file is not valid base64"))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| NotaryError::config("key file must hold a 32 byte seed"))?;
        Ok(Self::from_seed(seed))
    }

    pub fn public(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn key_id(&self) -> String {
        key_id(&self.public())
    }

    pub fn public_b64(&self) -> String {
        B64.encode(self.public().as_bytes())
    }

    pub fn sign(&self, record: &mut Record) -> Result<()> {
        let sig = self.signing.sign(&record.signing_bytes()?);
        record.sig = B64.encode(sig.to_bytes());
        Ok(())
    }
}

pub fn parse_public_b64(b64: &str) -> Result<VerifyingKey> {
    let bytes = B64
        .decode(b64.trim())
        .map_err(|_| NotaryError::fail("public key is not valid base64"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| NotaryError::fail("public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| NotaryError::fail("invalid public key"))
}

pub fn verify_record(record: &Record, public: &VerifyingKey) -> Result<()> {
    let bytes = B64
        .decode(&record.sig)
        .map_err(|_| NotaryError::fail("signature is not valid base64"))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| NotaryError::fail("signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&arr);
    public
        .verify(&record.signing_bytes()?, &sig)
        .map_err(|_| NotaryError::fail("signature does not verify"))
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    // ponytail: Windows ACLs not set; the appliance target is Linux where 0600 applies.
    Ok(())
}
