use std::process::exit;

mod cryptography;

#[derive(Debug)]
enum Options {
    Hash,
    Encrypt,
    Decrypt,
}

#[derive(Debug)]
struct Crypto {
    option: Options,
    file_path: String,
    key: Option<String>,
    salt: Option<String>,
}

impl Crypto {
    fn new(option: Options, file_path: String, key: Option<String>, salt: Option<String>) -> Self {
        Self {
            option,
            file_path,
            key,
            salt
        }
    }

    fn hash(&self) -> String {
        match cryptography::hash(&self.file_path) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Hashing Error: {e}");
                exit(1);
            }
        }
    }

    fn encrypt(&self) -> String {
        match &self.key {
            None => {
                eprintln!("Key required for encryption.");
                exit(1);
            }
            Some(k) => match cryptography::encrypt(&self.file_path, k, self.salt.as_deref()) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Encryption Error: {e}");
                    exit(1);
                }
            },
        }
    }

    fn decrypt(&self) -> String {
        match &self.key {
            None => {
                eprintln!("Key required for decryption.");
                exit(1);
            }
            Some(k) => match cryptography::decrypt(&self.file_path, k, self.salt.as_deref()) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Decryption Error: {e}");
                    exit(1);
                }
            },
        }
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();

    if argv.len() < 3 {
        eprintln!("Usage:");
        eprintln!("  {} hash <file>", argv[0]);
        eprintln!("  {} encrypt <file> <key> [salt]", argv[0]);
        eprintln!("  {} decrypt <file> <key> [salt]", argv[0]);
        eprintln!("Note: Omitting salt reduces security.");
        exit(1);
    }

    let option = match argv[1].as_str() {
        "hash" => Options::Hash,
        "encrypt" => Options::Encrypt,
        "decrypt" => Options::Decrypt,
        _ => {
            eprintln!("Unknown option: {}", argv[1]);
            exit(1);
        }
    };

    let file_path = argv[2].clone();
    if !std::path::Path::new(&file_path).exists() {
        eprintln!("File not found: {}", file_path);
        exit(1);
    }

    let key = argv.get(3).cloned();
    let salt = argv.get(4).cloned();

    let crypto = Crypto::new(option, file_path, key, salt);
    let result = match crypto.option {
        Options::Hash => crypto.hash(),
        Options::Encrypt => crypto.encrypt(),
        Options::Decrypt => crypto.decrypt(),
    };

    println!("{}", result);
}
