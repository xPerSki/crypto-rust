use sha2::{Sha256, Digest};
use std::{
    fs::{File, read, write},
    io::{BufReader, Read, Error, ErrorKind}
};
use argon2::Argon2;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
    AeadCore,
};

pub(crate) fn hash(file_path: &str) -> Result<String, Error> {
    let file = File::open(file_path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; 8192];   // 8KB

    let mut hasher = Sha256::new();
    loop {
        let bytes = reader.read(&mut buffer)?;
        if bytes == 0 { break }
        hasher.update(&buffer[..bytes]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn validate_password(password: &str) -> Result<(), Error> {
    if password.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "Password cannot be empty"));
    }
    Ok(())
}

fn validate_decrypt_salt(salt: Option<&str>) -> Result<(), Error> {
    match salt {
        Some(s) if s.len() < 8 => {
            Err(Error::new(ErrorKind::InvalidInput, "Salt must be at least 8 characters"))
        }
        None => {
            eprintln!("Warning: Decrypting without salt.");
            Ok(())
        }
        _ => Ok(()),
    }
}

const FALLBACK_SALT: &[u8] = b"\x00\x00\x00\x00\x00\x00\x00\x00";

fn derive_key(password: &str, salt: Option<&str>) -> Result<[u8; 32], Error> {
    let mut key = [0u8; 32];
    let salt_bytes: &[u8] = match salt {
        Some(s) => s.as_bytes(),
        None => FALLBACK_SALT,
    };
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt_bytes, &mut key)
        .map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?;
    Ok(key)
}

pub(crate) fn encrypt(file_path: &str, password: &str, salt: Option<&str>) -> Result<String, Error> {
    validate_password(password)?;
    if salt.is_none() {
        eprintln!("Warning: no salt provided. Security is reduced. Proceed at your own risk.");
    }

    let plaintext = read(file_path)?;
    let raw_key = derive_key(password, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&raw_key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Encryption failed"))?;

    let mut output = nonce.to_vec();
    output.extend(ciphertext);

    let out_path = format!("{}.s4fe", file_path);
    if std::path::Path::new(&out_path).exists() {
        return Err(Error::new(ErrorKind::AlreadyExists, format!("Output file already exists: {}", out_path)));
    }

    write(&out_path, &output)?;
    Ok(format!("Encrypted -> {}", out_path))
}

pub(crate) fn decrypt(file_path: &str, password: &str, salt: Option<&str>) -> Result<String, Error> {
    validate_password(password)?;
    validate_decrypt_salt(salt)?;

    if !file_path.ends_with(".s4fe") {
        return Err(Error::new(ErrorKind::InvalidInput, "Expected a .s4fe file"));
    }

    let data = read(file_path)?;
    if data.len() < 12 {
        return Err(Error::new(ErrorKind::InvalidData, "File too short"));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);     // 12B nonce
    let nonce = Nonce::from_slice(nonce_bytes);

    let raw_key = derive_key(password, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&raw_key));

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Decryption failed"))?;

    let out_path = file_path.trim_end_matches("[*.s4fe]");
    if std::path::Path::new(out_path).exists() {
        return Err(Error::new(ErrorKind::AlreadyExists, format!("Output file already exists: {}", out_path)));
    }

    write(out_path, &plaintext)?;
    Ok(format!("Decrypted -> {}", out_path))
}
