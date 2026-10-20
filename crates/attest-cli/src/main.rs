use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use verifier_core::SignedCredential;

#[derive(Parser)]
#[command(
    name = "attest-cli",
    version,
    about = "Offline verifier for Attest credentials"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a signed credential without contacting the Attest API.
    Verify(VerifyArgs),
    /// Verify that one transparency-log root is consistent with another.
    Consistency(ConsistencyArgs),
    /// Print the version.
    Version,
}

#[derive(Parser)]
struct VerifyArgs {
    /// Path to a file containing the SignedCredential JSON ("-" for stdin).
    #[arg(long)]
    credential: String,
    /// Issuer Ed25519 public key, hex encoded.
    #[arg(long, conflicts_with = "keyring", required_unless_present = "keyring")]
    public_key: Option<String>,
    /// Issuer keyring JSON from `/api/issuers/{id}/keys`.
    #[arg(long, conflicts_with = "public_key")]
    keyring: Option<PathBuf>,
    /// Optional status list JSON used to detect revocation.
    #[arg(long)]
    status_list: Option<PathBuf>,
    /// Optional Merkle proof JSON verified against its embedded root.
    #[arg(long)]
    proof: Option<PathBuf>,
}

#[derive(Parser)]
struct ConsistencyArgs {
    /// Path to a consistency proof JSON from `/api/log/consistency`.
    #[arg(long)]
    proof: PathBuf,
    /// Optional root to pin before verifying the proof.
    #[arg(long)]
    expected_first_root: Option<String>,
    /// Optional root to pin after verifying the proof.
    #[arg(long)]
    expected_second_root: Option<String>,
}

#[derive(Serialize)]
struct VerifyOutcome {
    credential_id: String,
    issuer: String,
    subject: String,
    credential_type: String,
    key_id: Option<String>,
    key_status: Option<String>,
    signature_valid: bool,
    revoked: bool,
    status: &'static str,
    inclusion_proved: Option<bool>,
}

#[derive(Deserialize)]
struct Keyring {
    keys: Vec<KeyEntry>,
}

#[derive(Deserialize)]
struct KeyEntry {
    key_id: String,
    public_key_hex: String,
    #[serde(default = "default_key_status")]
    status: String,
}

fn default_key_status() -> String {
    "active".into()
}

#[derive(Deserialize)]
struct ConsistencyProof {
    first_size: usize,
    second_size: usize,
    first_root: String,
    second_root: String,
    proof: Vec<String>,
}

#[derive(Serialize)]
struct ConsistencyOutcome {
    consistent: bool,
    first_size: usize,
    second_size: usize,
    first_root: String,
    second_root: String,
}

#[derive(Deserialize)]
struct StatusList {
    #[serde(default)]
    revoked: Vec<StatusEntry>,
}

#[derive(Deserialize)]
struct StatusEntry {
    credential_id: String,
    reason: String,
}

#[derive(Deserialize)]
struct Proof {
    credential_id: String,
    leaf_hash: String,
    leaf_index: usize,
    tree_size: usize,
    root_hash: String,
    audit_path: Vec<String>,
}

fn main() {
    let cli = Cli::parse();
    let exit_code = match cli.command {
        Command::Version => {
            println!("attest-cli {}", verifier_core::VERSION);
            0
        }
        Command::Verify(args) => match run_verify(args) {
            Ok((outcome, valid)) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&outcome).expect("serialize outcome")
                );
                if valid { 0 } else { 1 }
            }
            Err(message) => {
                eprintln!("error: {message}");
                2
            }
        },
        Command::Consistency(args) => match run_consistency(args) {
            Ok((outcome, consistent)) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&outcome).expect("serialize outcome")
                );
                if consistent { 0 } else { 1 }
            }
            Err(message) => {
                eprintln!("error: {message}");
                2
            }
        },
    };
    std::process::exit(exit_code);
}

fn run_verify(args: VerifyArgs) -> Result<(VerifyOutcome, bool), String> {
    let credential_raw = read_to_string(&args.credential)?;
    let signed: SignedCredential = serde_json::from_str(&credential_raw)
        .map_err(|error| format!("parse credential: {error}"))?;

    let (public_key_hex, key_id, key_status) =
        resolve_public_key(&signed, args.public_key.as_deref(), args.keyring.as_ref())?;
    let verifying_key = verifier_core::verifying_key_from_hex(&public_key_hex)
        .map_err(|error| format!("parse public key: {error}"))?;
    let signature_valid = verifier_core::verify_signed_credential(&verifying_key, &signed).is_ok();
    let key_revoked = key_status.as_deref() == Some("revoked");

    let revoked = match &args.status_list {
        Some(path) => {
            let raw =
                fs::read_to_string(path).map_err(|error| format!("read status list: {error}"))?;
            let status_list: StatusList = serde_json::from_str(&raw)
                .map_err(|error| format!("parse status list: {error}"))?;
            status_list
                .revoked
                .iter()
                .find(|entry| entry.credential_id == signed.claims.credential_id)
                .map(|entry| entry.reason.clone())
        }
        None => None,
    };

    let inclusion_proved = match &args.proof {
        Some(path) => Some(verify_proof(path, &signed.claims.credential_id)?),
        None => None,
    };

    let status = if !signature_valid {
        "invalid_signature"
    } else if key_revoked {
        "issuer_key_revoked"
    } else if revoked.is_some() {
        "revoked"
    } else {
        "valid"
    };

    let outcome = VerifyOutcome {
        credential_id: signed.claims.credential_id.clone(),
        issuer: signed.claims.issuer.clone(),
        subject: signed.claims.subject.clone(),
        credential_type: signed.claims.credential_type.clone(),
        key_id,
        key_status,
        signature_valid,
        revoked: revoked.is_some(),
        status,
        inclusion_proved,
    };

    let valid =
        signature_valid && !key_revoked && revoked.is_none() && inclusion_proved != Some(false);
    Ok((outcome, valid))
}

fn resolve_public_key(
    signed: &SignedCredential,
    public_key: Option<&str>,
    keyring_path: Option<&PathBuf>,
) -> Result<(String, Option<String>, Option<String>), String> {
    if let Some(public_key) = public_key {
        return Ok((public_key.to_string(), signed.claims.key_id.clone(), None));
    }

    let path = keyring_path.ok_or("either --public-key or --keyring is required")?;
    let raw = fs::read_to_string(path).map_err(|error| format!("read keyring: {error}"))?;
    let keyring: Keyring =
        serde_json::from_str(&raw).map_err(|error| format!("parse keyring: {error}"))?;

    let entry = match signed.claims.key_id.as_deref() {
        Some(key_id) => keyring
            .keys
            .iter()
            .find(|entry| entry.key_id == key_id)
            .ok_or_else(|| format!("keyring does not contain key {key_id}"))?,
        None if keyring.keys.len() == 1 => &keyring.keys[0],
        None => {
            return Err(
                "credential has no key_id; pass --public-key or a single-key keyring".into(),
            );
        }
    };

    Ok((
        entry.public_key_hex.clone(),
        Some(entry.key_id.clone()),
        Some(entry.status.clone()),
    ))
}

fn run_consistency(args: ConsistencyArgs) -> Result<(ConsistencyOutcome, bool), String> {
    let raw = fs::read_to_string(&args.proof)
        .map_err(|error| format!("read consistency proof: {error}"))?;
    let proof: ConsistencyProof =
        serde_json::from_str(&raw).map_err(|error| format!("parse consistency proof: {error}"))?;

    let first_root = decode_32(&proof.first_root, "first_root")?;
    let second_root = decode_32(&proof.second_root, "second_root")?;
    let audit_path = proof
        .proof
        .iter()
        .map(|node| decode_32(node, "proof node"))
        .collect::<Result<Vec<_>, _>>()?;

    let mut consistent = verifier_core::verify_consistency(
        proof.first_size,
        proof.second_size,
        &first_root,
        &second_root,
        &audit_path,
    );
    if let Some(expected) = args.expected_first_root {
        consistent &= expected.eq_ignore_ascii_case(&proof.first_root);
    }
    if let Some(expected) = args.expected_second_root {
        consistent &= expected.eq_ignore_ascii_case(&proof.second_root);
    }

    Ok((
        ConsistencyOutcome {
            consistent,
            first_size: proof.first_size,
            second_size: proof.second_size,
            first_root: proof.first_root,
            second_root: proof.second_root,
        },
        consistent,
    ))
}

fn verify_proof(path: &PathBuf, credential_id: &str) -> Result<bool, String> {
    let raw = fs::read_to_string(path).map_err(|error| format!("read proof: {error}"))?;
    let proof: Proof =
        serde_json::from_str(&raw).map_err(|error| format!("parse proof: {error}"))?;

    if proof.credential_id != credential_id {
        return Err(format!(
            "proof is for credential {}, expected {}",
            proof.credential_id, credential_id
        ));
    }

    let leaf = decode_32(&proof.leaf_hash, "leaf_hash")?;
    let root = decode_32(&proof.root_hash, "root_hash")?;
    let audit_path = proof
        .audit_path
        .iter()
        .map(|node| decode_32(node, "audit_path node"))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(verifier_core::verify_inclusion(
        &leaf,
        proof.leaf_index,
        proof.tree_size,
        &root,
        &audit_path,
    ))
}

fn decode_32(value: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|error| format!("decode {label}: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} must be 32 bytes"))
}

fn read_to_string(path: &str) -> Result<String, String> {
    if path == "-" {
        use std::io::Read;
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|error| format!("read stdin: {error}"))?;
        Ok(buffer)
    } else {
        fs::read_to_string(path).map_err(|error| format!("read {path}: {error}"))
    }
}
