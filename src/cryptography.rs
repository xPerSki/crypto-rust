use sha2::{Sha256, Digest};
use std::{
    fs::File,
    io::{BufReader, Read, Error}
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
    let result = hasher.finalize();
    Ok(hex::encode(result))
}
