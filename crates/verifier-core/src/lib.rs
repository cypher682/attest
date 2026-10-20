use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialClaims {
    pub credential_id: String,
    pub issuer: String,
    pub subject: String,
    pub credential_type: String,
    pub claims: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedCredential {
    pub claims: CredentialClaims,
    pub signature_hex: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("serialize claims: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("decode signature: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid signing seed")]
    InvalidSeed,
    #[error("invalid public key")]
    InvalidPublicKey,
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn new_credential_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn generate_seed_hex() -> String {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    hex::encode(seed)
}

pub fn signing_key_from_seed_hex(seed_hex: &str) -> Result<SigningKey> {
    let bytes = hex::decode(seed_hex)?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidSeed)?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn verifying_key_hex(verifying_key: &VerifyingKey) -> String {
    hex::encode(verifying_key.to_bytes())
}

pub fn verifying_key_from_hex(public_key_hex: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(public_key_hex)?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidPublicKey)?;
    VerifyingKey::from_bytes(&key).map_err(|_| Error::InvalidPublicKey)
}

pub fn sign_claims(
    signing_key: &SigningKey,
    claims: &CredentialClaims,
) -> Result<SignedCredential> {
    let payload = serde_json::to_vec(claims)?;
    let signature = signing_key.sign(&payload);

    Ok(SignedCredential {
        claims: claims.clone(),
        signature_hex: hex::encode(signature.to_bytes()),
    })
}

pub fn verify_signed_credential(
    verifying_key: &VerifyingKey,
    credential: &SignedCredential,
) -> Result<()> {
    let payload = serde_json::to_vec(&credential.claims)?;
    let signature_bytes = hex::decode(&credential.signature_hex)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| Error::InvalidSignature)?;

    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| Error::InvalidSignature)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn leaf_hash(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0u8]);
    hasher.update(payload);
    hasher.finalize().into()
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => [0u8; 32],
        1 => leaves[0],
        tree_size => {
            let split = largest_power_of_two_less_than(tree_size);
            node_hash(
                &merkle_root(&leaves[..split]),
                &merkle_root(&leaves[split..]),
            )
        }
    }
}

pub fn inclusion_proof(leaves: &[[u8; 32]], index: usize) -> Option<Vec<[u8; 32]>> {
    if index >= leaves.len() {
        return None;
    }
    if leaves.len() == 1 {
        return Some(Vec::new());
    }

    let split = largest_power_of_two_less_than(leaves.len());
    let mut proof = if index < split {
        inclusion_proof(&leaves[..split], index)?
    } else {
        inclusion_proof(&leaves[split..], index - split)?
    };
    proof.push(if index < split {
        merkle_root(&leaves[split..])
    } else {
        merkle_root(&leaves[..split])
    });
    Some(proof)
}

pub fn verify_inclusion(
    leaf: &[u8; 32],
    index: usize,
    tree_size: usize,
    root: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if index >= tree_size || tree_size == 0 {
        return false;
    }

    let Some((hash, remaining)) = reconstruct_inclusion(leaf, index, tree_size, proof) else {
        return false;
    };
    remaining.is_empty() && hash == *root
}

fn reconstruct_inclusion<'a>(
    leaf: &[u8; 32],
    index: usize,
    tree_size: usize,
    proof: &'a [[u8; 32]],
) -> Option<([u8; 32], &'a [[u8; 32]])> {
    if tree_size == 1 {
        return Some((*leaf, proof));
    }

    let split = largest_power_of_two_less_than(tree_size);
    if index < split {
        let (left, proof) = reconstruct_inclusion(leaf, index, split, proof)?;
        let (right, proof) = proof.split_first()?;
        Some((node_hash(&left, right), proof))
    } else {
        let (right, proof) = reconstruct_inclusion(leaf, index - split, tree_size - split, proof)?;
        let (left, proof) = proof.split_first()?;
        Some((node_hash(left, &right), proof))
    }
}

pub fn consistency_proof(leaves: &[[u8; 32]], first_size: usize) -> Option<Vec<[u8; 32]>> {
    if first_size == 0 || first_size > leaves.len() {
        return None;
    }
    if first_size == leaves.len() {
        return Some(Vec::new());
    }

    Some(subproof(first_size, leaves, true))
}

fn subproof(first_size: usize, leaves: &[[u8; 32]], complete: bool) -> Vec<[u8; 32]> {
    let tree_size = leaves.len();
    if first_size == tree_size {
        return if complete {
            Vec::new()
        } else {
            vec![merkle_root(leaves)]
        };
    }

    let split = largest_power_of_two_less_than(tree_size);
    if first_size <= split {
        let mut proof = subproof(first_size, &leaves[..split], complete);
        proof.push(merkle_root(&leaves[split..]));
        proof
    } else {
        let mut proof = subproof(first_size - split, &leaves[split..], false);
        proof.push(merkle_root(&leaves[..split]));
        proof
    }
}

fn largest_power_of_two_less_than(value: usize) -> usize {
    debug_assert!(value > 1);
    let mut power = 1;
    while power * 2 < value {
        power *= 2;
    }
    power
}

pub fn verify_consistency(
    first_size: usize,
    second_size: usize,
    first_root: &[u8; 32],
    second_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if first_size == 0 || first_size > second_size {
        return false;
    }
    if first_size == second_size {
        return proof.is_empty() && first_root == second_root;
    }

    let mut first_node = first_size - 1;
    let mut second_node = second_size - 1;
    while first_node & 1 == 1 {
        first_node >>= 1;
        second_node >>= 1;
    }

    let mut proof = proof;
    let mut first_hash;
    let mut second_hash;
    if first_node == 0 {
        first_hash = *first_root;
        second_hash = *first_root;
    } else {
        let Some((head, tail)) = proof.split_first() else {
            return false;
        };
        first_hash = *head;
        second_hash = *head;
        proof = tail;
    }

    for node in proof {
        if second_node == 0 {
            return false;
        }
        if first_node & 1 == 1 || first_node == second_node {
            first_hash = node_hash(node, &first_hash);
            second_hash = node_hash(node, &second_hash);
            while first_node != 0 && first_node & 1 == 0 {
                first_node >>= 1;
                second_node >>= 1;
            }
        } else {
            second_hash = node_hash(&second_hash, node);
        }
        first_node >>= 1;
        second_node >>= 1;
    }

    first_hash == *first_root && second_hash == *second_root && second_node == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims() -> CredentialClaims {
        CredentialClaims {
            credential_id: "00000000-0000-0000-0000-000000000001".into(),
            issuer: "demo-university".into(),
            subject: "holder-001".into(),
            credential_type: "Degree".into(),
            claims: json!({"degree": "BSc Computer Science", "year": 2026}),
            key_id: None,
        }
    }

    #[test]
    fn signs_and_verifies() {
        let (signing_key, verifying_key) = generate_keypair();
        let signed = sign_claims(&signing_key, &claims()).expect("sign");

        verify_signed_credential(&verifying_key, &signed).expect("verify");
    }

    #[test]
    fn rejects_tampered_claims() {
        let (signing_key, verifying_key) = generate_keypair();
        let mut signed = sign_claims(&signing_key, &claims()).expect("sign");
        signed.claims.claims["year"] = json!(2025);

        let result = verify_signed_credential(&verifying_key, &signed);

        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn rejects_a_different_key() {
        let (signing_key, _) = generate_keypair();
        let (_, other_verifying_key) = generate_keypair();
        let signed = sign_claims(&signing_key, &claims()).expect("sign");

        let result = verify_signed_credential(&other_verifying_key, &signed);

        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn seed_round_trips_to_a_public_key() {
        let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let signing_key = signing_key_from_seed_hex(seed).expect("seed");
        let public_key = verifying_key_hex(&signing_key.verifying_key());

        assert_eq!(
            public_key,
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        verifying_key_from_hex(&public_key).expect("public key");
    }

    #[test]
    fn merkle_proof_verifies_for_odd_and_even_trees() {
        for size in 1..=9 {
            let leaves: Vec<[u8; 32]> = (0..size)
                .map(|i| leaf_hash(format!("leaf-{i}").as_bytes()))
                .collect();
            let root = merkle_root(&leaves);

            for index in 0..size {
                let proof = inclusion_proof(&leaves, index).expect("proof");
                assert!(
                    verify_inclusion(&leaves[index], index, size, &root, &proof),
                    "proof failed for size {size} index {index}"
                );
            }
        }
    }

    #[test]
    fn merkle_proof_rejects_a_tampered_leaf() {
        let leaves: Vec<[u8; 32]> = (0..5)
            .map(|i| leaf_hash(format!("leaf-{i}").as_bytes()))
            .collect();
        let root = merkle_root(&leaves);
        let proof = inclusion_proof(&leaves, 2).expect("proof");
        let tampered = leaf_hash(b"tampered");

        assert!(!verify_inclusion(&tampered, 2, leaves.len(), &root, &proof));
    }

    #[test]
    fn key_id_is_optional_and_changes_signed_bytes() {
        let (signing_key, verifying_key) = generate_keypair();
        let legacy = claims();
        let legacy_bytes = serde_json::to_vec(&legacy).expect("legacy json");
        assert!(!String::from_utf8_lossy(&legacy_bytes).contains("key_id"));

        let mut bound = legacy.clone();
        bound.key_id = Some("00000000-0000-0000-0000-000000000002".into());
        let bound_bytes = serde_json::to_vec(&bound).expect("bound json");
        assert!(String::from_utf8_lossy(&bound_bytes).contains("key_id"));

        let signed = sign_claims(&signing_key, &bound).expect("sign");
        verify_signed_credential(&verifying_key, &signed).expect("verify");

        let mut tampered = signed;
        tampered.claims.key_id = Some("different-key".into());
        assert!(matches!(
            verify_signed_credential(&verifying_key, &tampered),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn consistency_proofs_verify_for_all_tree_sizes() {
        for second_size in 1..=16 {
            let leaves: Vec<[u8; 32]> = (0..second_size)
                .map(|i| leaf_hash(format!("leaf-{i}").as_bytes()))
                .collect();
            let second_root = merkle_root(&leaves);

            for first_size in 1..=second_size {
                let first_root = merkle_root(&leaves[..first_size]);
                let proof = consistency_proof(&leaves, first_size).expect("consistency proof");

                assert!(
                    verify_consistency(first_size, second_size, &first_root, &second_root, &proof,),
                    "consistency failed for first {first_size} second {second_size}"
                );
            }
        }
    }

    #[test]
    fn consistency_proof_rejects_tampered_inputs() {
        let leaves: Vec<[u8; 32]> = (0..7)
            .map(|i| leaf_hash(format!("leaf-{i}").as_bytes()))
            .collect();
        let first_root = merkle_root(&leaves[..3]);
        let second_root = merkle_root(&leaves);
        let proof = consistency_proof(&leaves, 3).expect("consistency proof");

        let mut tampered_root = second_root;
        tampered_root[0] ^= 1;
        assert!(!verify_consistency(
            3,
            7,
            &first_root,
            &tampered_root,
            &proof
        ));

        let mut tampered_proof = proof.clone();
        tampered_proof[0][0] ^= 1;
        assert!(!verify_consistency(
            3,
            7,
            &first_root,
            &second_root,
            &tampered_proof
        ));

        assert!(!verify_consistency(8, 7, &first_root, &second_root, &proof));
    }

    #[test]
    fn consistency_proof_is_empty_for_equal_sizes() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| leaf_hash(format!("leaf-{i}").as_bytes()))
            .collect();
        let root = merkle_root(&leaves);

        assert_eq!(consistency_proof(&leaves, 4), Some(Vec::new()));
        assert!(verify_consistency(4, 4, &root, &root, &[]));
        assert!(!verify_consistency(4, 4, &root, &root, &[root]));
    }
}
