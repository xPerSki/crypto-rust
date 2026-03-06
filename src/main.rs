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
    file_dir: String,
    key: Option<String>,
}

impl Crypto {
    fn new(option: Options, file_dir: String, key: Option<String>) -> Self {
        Self {
            option,
            file_dir,
            key,
        }
    }

    fn hash(&self) -> String {
        match cryptography::hash(&self.file_dir) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Hashing Error: {e}");
                eprintln!("Exiting...");
                exit(1);
            }
        }
    }

    fn encrypt(&self) -> String {
        todo!()
    }

    fn decrypt(&self) -> String {
        todo!()
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();

    if argv.len() < 3 {
        eprintln!("Usage: {} <hash|encrypt|decrypt> <file> [key]", argv[0]);
        exit(1);
    }

    let option: Options = match argv[1].as_str() {
        "hash" => Options::Hash,
        "encrypt" => Options::Encrypt,
        "decrypt" => Options::Decrypt,
        _ => {
            eprintln!("Unknown option: {}", argv[1]);
            exit(1);
        }
    };
    let file_dir = argv[2].clone();
    let key = argv.get(3).cloned();

    let crypto = Crypto::new(option, file_dir, key);
    let result = match crypto.option {
        Options::Hash => crypto.hash(),
        Options::Encrypt => crypto.encrypt(),
        Options::Decrypt => crypto.decrypt(),
    };

    println!("{}", result);
}
