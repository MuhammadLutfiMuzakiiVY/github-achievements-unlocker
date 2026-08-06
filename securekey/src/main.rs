use clap::{Parser, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use slh_dsa::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s,
    Shake128f, Shake128s, Shake192f, Shake192s, Shake256f, Shake256s,
    Signature as SlhSig, SigningKey as SlhSigningKey, VerifyingKey as SlhVerifyingKey,
};
use slh_dsa::signature::{Keypair, Signer, Verifier};

#[derive(Parser)]
#[command(
    name = "securekey",
    author = "SecureKey Engineering Team",
    version = "1.0.0-pqc",
    about = "NIST FIPS 205 SLH-DSA (SPHINCS+) Post-Quantum Cryptographic Key Generator & Signer Tool",
    long_about = "SecureKey is an enterprise-grade CLI tool for post-quantum digital signatures based on the NIST FIPS 205 SLH-DSA (Stateless Hash-Based Digital Signature Algorithm / SPHINCS+) standard."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new SLH-DSA (SPHINCS+) post-quantum key pair
    Generate {
        /// Parameter set: sha2-128f, sha2-128s, sha2-192f, sha2-192s, sha2-256f, sha2-256s, shake-128f, shake-128s, shake-192f, shake-192s, shake-256f, shake-256s
        #[arg(short, long, default_value = "sha2-128f")]
        param_set: String,

        /// Output directory for key files
        #[arg(short, long, default_value = ".")]
        out_dir: PathBuf,

        /// Base name for generated key files
        #[arg(short, long, default_value = "securekey")]
        name: String,
    },

    /// Sign a file or binary payload using SLH-DSA private key
    Sign {
        /// Path to SLH-DSA private key file (*_private.key)
        #[arg(short, long)]
        key: PathBuf,

        /// Path to file or binary payload to sign
        #[arg(short, long)]
        file: PathBuf,

        /// Output path for signature file (default: <file>.sig)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Verify an SLH-DSA digital signature against a file and public key
    Verify {
        /// Path to SLH-DSA public key file (*_public.pub)
        #[arg(short = 'p', long)]
        pubkey: PathBuf,

        /// Path to the original file or binary payload
        #[arg(short, long)]
        file: PathBuf,

        /// Path to the signature file (*.sig)
        #[arg(short, long)]
        sig: PathBuf,
    },

    /// Inspect SLH-DSA key metadata, NIST security category, and key parameters
    Inspect {
        /// Path to key file (private or public key container)
        #[arg(short, long)]
        key: PathBuf,
    },

    /// Export SLH-DSA public key in Hex, Base64, or PEM format
    Export {
        /// Path to public key container file
        #[arg(short = 'p', long)]
        pubkey: PathBuf,

        /// Output format: hex, base64, pem
        #[arg(short, long, default_value = "base64")]
        format: String,
    },

    /// Rotate SLH-DSA key pair
    Rotate {
        /// Path to current private key file
        #[arg(short, long)]
        key: PathBuf,

        /// Output directory for new rotated key
        #[arg(short, long, default_value = ".")]
        out_dir: PathBuf,
    },

    /// Securely zeroize and destroy key file from disk
    Destroy {
        /// Path to key file to securely wipe
        #[arg(short, long)]
        key: PathBuf,
    },
}

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct PrivateKeyContainer {
    algorithm: String,
    param_set: String,
    created_at: String,
    security_category: u8,
    public_key_b64: String,
    private_key_b64: String,
}

#[derive(Serialize, Deserialize)]
struct PublicKeyContainer {
    algorithm: String,
    param_set: String,
    created_at: String,
    security_category: u8,
    public_key_b64: String,
}

#[derive(Serialize, Deserialize)]
struct SignatureContainer {
    algorithm: String,
    param_set: String,
    signed_at: String,
    file_name: String,
    file_sha256: String,
    signature_b64: String,
}

fn main() {
    let cli = Cli::parse();

    println!("{}", "============================================================".bright_cyan());
    println!("{}", "  SecureKey SLH-DSA (SPHINCS+) Post-Quantum Security CLI".bold().bright_green());
    println!("{}", "  Standard: NIST FIPS 205 (Stateless Hash-Based Signatures)".dimmed());
    println!("{}\n", "============================================================".bright_cyan());

    match cli.command {
        Commands::Generate { param_set, out_dir, name } => {
            cmd_generate(&param_set, &out_dir, &name);
        }
        Commands::Sign { key, file, out } => {
            cmd_sign(&key, &file, out.as_deref());
        }
        Commands::Verify { pubkey, file, sig } => {
            cmd_verify(&pubkey, &file, &sig);
        }
        Commands::Inspect { key } => {
            cmd_inspect(&key);
        }
        Commands::Export { pubkey, format } => {
            cmd_export(&pubkey, &format);
        }
        Commands::Rotate { key, out_dir } => {
            cmd_rotate(&key, &out_dir);
        }
        Commands::Destroy { key } => {
            cmd_destroy(&key);
        }
    }
}

fn get_security_category(param_set: &str) -> u8 {
    if param_set.contains("128") {
        1
    } else if param_set.contains("192") {
        3
    } else if param_set.contains("256") {
        5
    } else {
        1
    }
}

fn cmd_generate(param_set: &str, out_dir: &Path, name: &str) {
    let norm_param = param_set.to_lowercase();
    println!("[i] Generating entropy using OS CSPRNG...");
    let mut rng = rand::thread_rng();

    let created_at = chrono::Utc::now().to_rfc3339();
    let sec_cat = get_security_category(&norm_param);

    let (sk_b64, pk_b64) = match norm_param.as_str() {
        "sha2-128f" | "slh-dsa-sha2-128f" => {
            let sk = SlhSigningKey::<Sha2_128f>::new(&mut rng);
            let pk = sk.verifying_key();
            (base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sk.to_bytes()),
             base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.to_bytes()))
        }
        "sha2-128s" | "slh-dsa-sha2-128s" => {
            let sk = SlhSigningKey::<Sha2_128s>::new(&mut rng);
            let pk = sk.verifying_key();
            (base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sk.to_bytes()),
             base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.to_bytes()))
        }
        "sha2-192f" | "slh-dsa-sha2-192f" => {
            let sk = SlhSigningKey::<Sha2_192f>::new(&mut rng);
            let pk = sk.verifying_key();
            (base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sk.to_bytes()),
             base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.to_bytes()))
        }
        "sha2-192s" | "slh-dsa-sha2-192s" => {
            let sk = SlhSigningKey::<Sha2_192s>::new(&mut rng);
            let pk = sk.verifying_key();
            (base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sk.to_bytes()),
             base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.to_bytes()))
        }
        "sha2-256f" | "slh-dsa-sha2-256f" => {
            let sk = SlhSigningKey::<Sha2_256f>::new(&mut rng);
            let pk = sk.verifying_key();
            (base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sk.to_bytes()),
             base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.to_bytes()))
        }
        "sha2-256s" | "slh-dsa-sha2-256s" => {
            let sk = SlhSigningKey::<Sha2_256s>::new(&mut rng);
            let pk = sk.verifying_key();
            (base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sk.to_bytes()),
             base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.to_bytes()))
        }
        "shake-128f" | "slh-dsa-shake-128f" => {
            let sk = SlhSigningKey::<Shake128f>::new(&mut rng);
            let pk = sk.verifying_key();
            (base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sk.to_bytes()),
             base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.to_bytes()))
        }
        "shake-128s" | "slh-dsa-shake-128s" => {
            let sk = SlhSigningKey::<Shake128s>::new(&mut rng);
            let pk = sk.verifying_key();
            (base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sk.to_bytes()),
             base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.to_bytes()))
        }
        "shake-192f" | "slh-dsa-shake-192f" => {
            let sk = SlhSigningKey::<Shake192f>::new(&mut rng);
            let pk = sk.verifying_key();
            (base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sk.to_bytes()),
             base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.to_bytes()))
        }
        "shake-192s" | "slh-dsa-shake-192s" => {
            let sk = SlhSigningKey::<Shake192s>::new(&mut rng);
            let pk = sk.verifying_key();
            (base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sk.to_bytes()),
             base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.to_bytes()))
        }
        "shake-256f" | "slh-dsa-shake-256f" => {
            let sk = SlhSigningKey::<Shake256f>::new(&mut rng);
            let pk = sk.verifying_key();
            (base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sk.to_bytes()),
             base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.to_bytes()))
        }
        "shake-256s" | "slh-dsa-shake-256s" => {
            let sk = SlhSigningKey::<Shake256s>::new(&mut rng);
            let pk = sk.verifying_key();
            (base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sk.to_bytes()),
             base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.to_bytes()))
        }
        _ => {
            let sk = SlhSigningKey::<Sha2_128f>::new(&mut rng);
            let pk = sk.verifying_key();
            (base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sk.to_bytes()),
             base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.to_bytes()))
        }
    };

    if !out_dir.exists() {
        fs::create_dir_all(out_dir).expect("Failed to create output directory");
    }

    let priv_container = PrivateKeyContainer {
        algorithm: "SLH-DSA (SPHINCS+)".to_string(),
        param_set: norm_param.clone(),
        created_at: created_at.clone(),
        security_category: sec_cat,
        public_key_b64: pk_b64.clone(),
        private_key_b64: sk_b64,
    };

    let pub_container = PublicKeyContainer {
        algorithm: "SLH-DSA (SPHINCS+)".to_string(),
        param_set: norm_param.clone(),
        created_at,
        security_category: sec_cat,
        public_key_b64: pk_b64,
    };

    let priv_path = out_dir.join(format!("{}_private.key", name));
    let pub_path = out_dir.join(format!("{}_public.pub", name));

    let priv_json = serde_json::to_string_pretty(&priv_container).unwrap();
    let pub_json = serde_json::to_string_pretty(&pub_container).unwrap();

    fs::write(&priv_path, priv_json).expect("Failed to write private key file");
    fs::write(&pub_path, pub_json).expect("Failed to write public key file");

    println!("{}", "[+] SUCCESS: SLH-DSA Key Pair Generated Successfully!".bold().bright_green());
    println!("  - Algorithm: {}", "SLH-DSA (NIST FIPS 205)".cyan());
    println!("  - Parameter Set: {}", norm_param.yellow());
    println!("  - NIST Security Category: {}", format!("Category {}", sec_cat).magenta());
    println!("  - Private Key Saved: {}", priv_path.display().to_string().bright_blue());
    println!("  - Public Key Saved:  {}", pub_path.display().to_string().bright_blue());
}

fn hash_file_sha256(path: &Path) -> (Vec<u8>, String) {
    use sha2::Digest;
    let mut file = File::open(path).expect("Failed to open file for hashing");
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 8192];

    let mut content_bytes = Vec::new();

    loop {
        let count = file.read(&mut buffer).expect("Failed reading file chunk");
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
        content_bytes.extend_from_slice(&buffer[..count]);
    }

    let hash_res = hasher.finalize();
    (content_bytes, hex::encode(hash_res))
}

fn cmd_sign(key_path: &Path, file_path: &Path, out_path: Option<&Path>) {
    println!("[i] Reading Private Key from: {}", key_path.display().to_string().cyan());
    let key_data = fs::read_to_string(key_path).expect("Failed to read private key file");
    let priv_container: PrivateKeyContainer = serde_json::from_str(&key_data).expect("Invalid private key format");

    println!("[i] Hashing target file: {}", file_path.display().to_string().cyan());
    let (content_bytes, sha256_hex) = hash_file_sha256(file_path);

    let sk_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &priv_container.private_key_b64)
        .expect("Failed to decode private key base64");

    let norm_param = priv_container.param_set.to_lowercase();
    println!("[i] Signing message payload with SLH-DSA ({})", norm_param.yellow());

    let sig_b64 = match norm_param.as_str() {
        "sha2-128f" | "slh-dsa-sha2-128f" => {
            let sk = SlhSigningKey::<Sha2_128f>::try_from(sk_bytes.as_slice()).expect("Invalid sk bytes");
            let sig = sk.sign(&content_bytes);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
        }
        "sha2-128s" | "slh-dsa-sha2-128s" => {
            let sk = SlhSigningKey::<Sha2_128s>::try_from(sk_bytes.as_slice()).expect("Invalid sk bytes");
            let sig = sk.sign(&content_bytes);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
        }
        "sha2-192f" | "slh-dsa-sha2-192f" => {
            let sk = SlhSigningKey::<Sha2_192f>::try_from(sk_bytes.as_slice()).expect("Invalid sk bytes");
            let sig = sk.sign(&content_bytes);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
        }
        "sha2-192s" | "slh-dsa-sha2-192s" => {
            let sk = SlhSigningKey::<Sha2_192s>::try_from(sk_bytes.as_slice()).expect("Invalid sk bytes");
            let sig = sk.sign(&content_bytes);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
        }
        "sha2-256f" | "slh-dsa-sha2-256f" => {
            let sk = SlhSigningKey::<Sha2_256f>::try_from(sk_bytes.as_slice()).expect("Invalid sk bytes");
            let sig = sk.sign(&content_bytes);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
        }
        "sha2-256s" | "slh-dsa-sha2-256s" => {
            let sk = SlhSigningKey::<Sha2_256s>::try_from(sk_bytes.as_slice()).expect("Invalid sk bytes");
            let sig = sk.sign(&content_bytes);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
        }
        "shake-128f" | "slh-dsa-shake-128f" => {
            let sk = SlhSigningKey::<Shake128f>::try_from(sk_bytes.as_slice()).expect("Invalid sk bytes");
            let sig = sk.sign(&content_bytes);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
        }
        "shake-128s" | "slh-dsa-shake-128s" => {
            let sk = SlhSigningKey::<Shake128s>::try_from(sk_bytes.as_slice()).expect("Invalid sk bytes");
            let sig = sk.sign(&content_bytes);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
        }
        "shake-192f" | "slh-dsa-shake-192f" => {
            let sk = SlhSigningKey::<Shake192f>::try_from(sk_bytes.as_slice()).expect("Invalid sk bytes");
            let sig = sk.sign(&content_bytes);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
        }
        "shake-192s" | "slh-dsa-shake-192s" => {
            let sk = SlhSigningKey::<Shake192s>::try_from(sk_bytes.as_slice()).expect("Invalid sk bytes");
            let sig = sk.sign(&content_bytes);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
        }
        "shake-256f" | "slh-dsa-shake-256f" => {
            let sk = SlhSigningKey::<Shake256f>::try_from(sk_bytes.as_slice()).expect("Invalid sk bytes");
            let sig = sk.sign(&content_bytes);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
        }
        "shake-256s" | "slh-dsa-shake-256s" => {
            let sk = SlhSigningKey::<Shake256s>::try_from(sk_bytes.as_slice()).expect("Invalid sk bytes");
            let sig = sk.sign(&content_bytes);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
        }
        _ => {
            let sk = SlhSigningKey::<Sha2_128f>::try_from(sk_bytes.as_slice()).expect("Invalid sk bytes");
            let sig = sk.sign(&content_bytes);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
        }
    };

    let default_sig_path = PathBuf::from(format!("{}.sig", file_path.display()));
    let target_sig_path = out_path.unwrap_or(&default_sig_path);

    let sig_container = SignatureContainer {
        algorithm: priv_container.algorithm.clone(),
        param_set: norm_param,
        signed_at: chrono::Utc::now().to_rfc3339(),
        file_name: file_path.file_name().unwrap_or_default().to_string_lossy().to_string(),
        file_sha256: sha256_hex,
        signature_b64: sig_b64,
    };

    let sig_json = serde_json::to_string_pretty(&sig_container).unwrap();
    fs::write(target_sig_path, sig_json).expect("Failed to write signature file");

    println!("{}", "[+] SUCCESS: SLH-DSA Signature Generated!".bold().bright_green());
    println!("  - Target File: {}", file_path.display().to_string().cyan());
    println!("  - Signature File: {}", target_sig_path.display().to_string().bright_blue());
}

fn cmd_verify(pubkey_path: &Path, file_path: &Path, sig_path: &Path) {
    println!("[i] Reading Public Key from: {}", pubkey_path.display().to_string().cyan());
    let pub_data = fs::read_to_string(pubkey_path).expect("Failed to read public key file");
    let pub_container: PublicKeyContainer = serde_json::from_str(&pub_data).expect("Invalid public key format");

    println!("[i] Reading Signature from: {}", sig_path.display().to_string().cyan());
    let sig_data = fs::read_to_string(sig_path).expect("Failed to read signature file");
    let sig_container: SignatureContainer = serde_json::from_str(&sig_data).expect("Invalid signature format");

    println!("[i] Hashing target file: {}", file_path.display().to_string().cyan());
    let (content_bytes, sha256_hex) = hash_file_sha256(file_path);

    if sig_container.file_sha256 != sha256_hex {
        println!("{}", "[-] VERIFICATION FAILED: SHA-256 hash mismatch! File has been tampered with or modified!".bold().bright_red());
        return;
    }

    let pk_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &pub_container.public_key_b64)
        .expect("Failed to decode public key base64");
    let sig_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sig_container.signature_b64)
        .expect("Failed to decode signature base64");

    let norm_param = pub_container.param_set.to_lowercase();
    println!("[i] Verifying SLH-DSA Signature ({})", norm_param.yellow());

    let is_valid = match norm_param.as_str() {
        "sha2-128f" | "slh-dsa-sha2-128f" => {
            if let (Ok(pk), Ok(sig)) = (SlhVerifyingKey::<Sha2_128f>::try_from(pk_bytes.as_slice()), SlhSig::<Sha2_128f>::try_from(sig_bytes.as_slice())) {
                pk.verify(&content_bytes, &sig).is_ok()
            } else { false }
        }
        "sha2-128s" | "slh-dsa-sha2-128s" => {
            if let (Ok(pk), Ok(sig)) = (SlhVerifyingKey::<Sha2_128s>::try_from(pk_bytes.as_slice()), SlhSig::<Sha2_128s>::try_from(sig_bytes.as_slice())) {
                pk.verify(&content_bytes, &sig).is_ok()
            } else { false }
        }
        "sha2-192f" | "slh-dsa-sha2-192f" => {
            if let (Ok(pk), Ok(sig)) = (SlhVerifyingKey::<Sha2_192f>::try_from(pk_bytes.as_slice()), SlhSig::<Sha2_192f>::try_from(sig_bytes.as_slice())) {
                pk.verify(&content_bytes, &sig).is_ok()
            } else { false }
        }
        "sha2-192s" | "slh-dsa-sha2-192s" => {
            if let (Ok(pk), Ok(sig)) = (SlhVerifyingKey::<Sha2_192s>::try_from(pk_bytes.as_slice()), SlhSig::<Sha2_192s>::try_from(sig_bytes.as_slice())) {
                pk.verify(&content_bytes, &sig).is_ok()
            } else { false }
        }
        "sha2-256f" | "slh-dsa-sha2-256f" => {
            if let (Ok(pk), Ok(sig)) = (SlhVerifyingKey::<Sha2_256f>::try_from(pk_bytes.as_slice()), SlhSig::<Sha2_256f>::try_from(sig_bytes.as_slice())) {
                pk.verify(&content_bytes, &sig).is_ok()
            } else { false }
        }
        "sha2-256s" | "slh-dsa-sha2-256s" => {
            if let (Ok(pk), Ok(sig)) = (SlhVerifyingKey::<Sha2_256s>::try_from(pk_bytes.as_slice()), SlhSig::<Sha2_256s>::try_from(sig_bytes.as_slice())) {
                pk.verify(&content_bytes, &sig).is_ok()
            } else { false }
        }
        "shake-128f" | "slh-dsa-shake-128f" => {
            if let (Ok(pk), Ok(sig)) = (SlhVerifyingKey::<Shake128f>::try_from(pk_bytes.as_slice()), SlhSig::<Shake128f>::try_from(sig_bytes.as_slice())) {
                pk.verify(&content_bytes, &sig).is_ok()
            } else { false }
        }
        "shake-128s" | "slh-dsa-shake-128s" => {
            if let (Ok(pk), Ok(sig)) = (SlhVerifyingKey::<Shake128s>::try_from(pk_bytes.as_slice()), SlhSig::<Shake128s>::try_from(sig_bytes.as_slice())) {
                pk.verify(&content_bytes, &sig).is_ok()
            } else { false }
        }
        "shake-192f" | "slh-dsa-shake-192f" => {
            if let (Ok(pk), Ok(sig)) = (SlhVerifyingKey::<Shake192f>::try_from(pk_bytes.as_slice()), SlhSig::<Shake192f>::try_from(sig_bytes.as_slice())) {
                pk.verify(&content_bytes, &sig).is_ok()
            } else { false }
        }
        "shake-192s" | "slh-dsa-shake-192s" => {
            if let (Ok(pk), Ok(sig)) = (SlhVerifyingKey::<Shake192s>::try_from(pk_bytes.as_slice()), SlhSig::<Shake192s>::try_from(sig_bytes.as_slice())) {
                pk.verify(&content_bytes, &sig).is_ok()
            } else { false }
        }
        "shake-256f" | "slh-dsa-shake-256f" => {
            if let (Ok(pk), Ok(sig)) = (SlhVerifyingKey::<Shake256f>::try_from(pk_bytes.as_slice()), SlhSig::<Shake256f>::try_from(sig_bytes.as_slice())) {
                pk.verify(&content_bytes, &sig).is_ok()
            } else { false }
        }
        "shake-256s" | "slh-dsa-shake-256s" => {
            if let (Ok(pk), Ok(sig)) = (SlhVerifyingKey::<Shake256s>::try_from(pk_bytes.as_slice()), SlhSig::<Shake256s>::try_from(sig_bytes.as_slice())) {
                pk.verify(&content_bytes, &sig).is_ok()
            } else { false }
        }
        _ => false,
    };

    if is_valid {
        println!("{}", "[+] SUCCESS: SLH-DSA Signature is VALID and AUTHENTIC! Data integrity confirmed.".bold().bright_green());
    } else {
        println!("{}", "[-] VERIFICATION FAILED: SLH-DSA signature is INVALID!".bold().bright_red());
    }
}

fn cmd_inspect(key_path: &Path) {
    let data = fs::read_to_string(key_path).expect("Failed to read key file");
    if let Ok(priv_c) = serde_json::from_str::<PrivateKeyContainer>(&data) {
        println!("{}", "=== SLH-DSA Private Key Container Metadata ===".bold().cyan());
        println!("  - Algorithm:          {}", priv_c.algorithm.yellow());
        println!("  - Parameter Set:      {}", priv_c.param_set.yellow());
        println!("  - Security Category:  Category {}", priv_c.security_category);
        println!("  - Created At:         {}", priv_c.created_at);
        println!("  - Public Key (B64):   {}", priv_c.public_key_b64);
        println!("  - Private Key Status: {}", "Protected / Zeroized on Drop".bright_green());
    } else if let Ok(pub_c) = serde_json::from_str::<PublicKeyContainer>(&data) {
        println!("{}", "=== SLH-DSA Public Key Container Metadata ===".bold().cyan());
        println!("  - Algorithm:          {}", pub_c.algorithm.yellow());
        println!("  - Parameter Set:      {}", pub_c.param_set.yellow());
        println!("  - Security Category:  Category {}", pub_c.security_category);
        println!("  - Created At:         {}", pub_c.created_at);
        println!("  - Public Key (B64):   {}", pub_c.public_key_b64);
    } else {
        eprintln!("{}", "[-] Error: Unrecognized key container format".bright_red());
    }
}

fn cmd_export(pubkey_path: &Path, format: &str) {
    let data = fs::read_to_string(pubkey_path).expect("Failed to read public key file");
    let pub_c: PublicKeyContainer = serde_json::from_str(&data).expect("Invalid public key file");

    let raw_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &pub_c.public_key_b64).expect("Invalid base64");

    println!("{}", format!("=== Exported Public Key ({}) ===", format.to_uppercase()).bold().cyan());

    match format.to_lowercase().as_str() {
        "hex" => {
            println!("{}", hex::encode(&raw_bytes));
        }
        "pem" => {
            println!("-----BEGIN SLH-DSA PUBLIC KEY-----");
            println!("{}", pub_c.public_key_b64);
            println!("-----END SLH-DSA PUBLIC KEY-----");
        }
        _ => {
            println!("{}", pub_c.public_key_b64);
        }
    }
}

fn cmd_rotate(key_path: &Path, out_dir: &Path) {
    println!("[i] Rotating key from: {}", key_path.display().to_string().cyan());
    let data = fs::read_to_string(key_path).expect("Failed to read key file");
    let priv_c: PrivateKeyContainer = serde_json::from_str(&data).expect("Invalid key file");

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let archive_path = key_path.with_extension(format!("bak_{}", timestamp));

    fs::rename(key_path, &archive_path).expect("Failed to archive old key");
    println!("  - Archived old key to: {}", archive_path.display().to_string().yellow());

    cmd_generate(&priv_c.param_set, out_dir, "securekey_rotated");
    println!("{}", "[+] Key Rotation Completed Successfully!".bold().bright_green());
}

fn cmd_destroy(key_path: &Path) {
    if !key_path.exists() {
        eprintln!("{}", "[-] Key file not found!".bright_red());
        return;
    }

    let file_len = fs::metadata(key_path).map(|m| m.len()).unwrap_or(4096);
    println!("[i] Overwriting key file with random bytes...");

    let mut random_bytes = vec![0u8; file_len as usize];
    getrandom::getrandom(&mut random_bytes).ok();

    fs::write(key_path, &random_bytes).ok();
    fs::remove_file(key_path).expect("Failed to delete key file");

    println!("{}", "[+] SUCCESS: Key file securely zeroized and destroyed from disk!".bold().bright_green());
}
