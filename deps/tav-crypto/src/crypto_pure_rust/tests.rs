// Copyright (c) 2026 Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use ring::{rand::SystemRandom, signature::KeyPair};
use x509_cert::der::{
    asn1::{AnyRef, BitStringRef, UintRef},
    Decode, Encode,
};
use x509_cert::spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

const MESSAGE: &[u8] = b"MigTD TAV ring RSA verification";
const TEST_KEY: &[u8] =
    include_bytes!("../../../td-shim/library/ring/tests/rsa_test_private_key_2048.p8");

fn key_pair() -> signature::RsaKeyPair {
    signature::RsaKeyPair::from_pkcs8(TEST_KEY).expect("public ring test fixture")
}

fn spki(encoded_key: &[u8]) -> Vec<u8> {
    SubjectPublicKeyInfoRef {
        algorithm: AlgorithmIdentifierRef {
            oid: pkcs1::ALGORITHM_OID,
            parameters: Some(AnyRef::NULL),
        },
        subject_public_key: BitStringRef::from_bytes(encoded_key).unwrap(),
    }
    .to_der()
    .unwrap()
}

fn spki_with_components(n: &[u8], e: &[u8]) -> Vec<u8> {
    spki(
        &pkcs1::RsaPublicKey {
            modulus: UintRef::new(n).unwrap(),
            public_exponent: UintRef::new(e).unwrap(),
        }
        .to_der()
        .unwrap(),
    )
}

fn algorithms() -> [(SignatureKeyAlgorithm, &'static dyn signature::RsaEncoding); 6] {
    use RsaPkcs1v15SignatureKeyAlgorithm::*;
    use RsaPssSignatureKeyAlgorithm::*;
    [
        (
            SignatureKeyAlgorithm::RsaPkcs1v15(Rs256),
            &signature::RSA_PKCS1_SHA256,
        ),
        (
            SignatureKeyAlgorithm::RsaPkcs1v15(Rs384),
            &signature::RSA_PKCS1_SHA384,
        ),
        (
            SignatureKeyAlgorithm::RsaPkcs1v15(Rs512),
            &signature::RSA_PKCS1_SHA512,
        ),
        (
            SignatureKeyAlgorithm::RsaPss(Ps256),
            &signature::RSA_PSS_SHA256,
        ),
        (
            SignatureKeyAlgorithm::RsaPss(Ps384),
            &signature::RSA_PSS_SHA384,
        ),
        (
            SignatureKeyAlgorithm::RsaPss(Ps512),
            &signature::RSA_PSS_SHA512,
        ),
    ]
}

#[test]
fn all_six_algorithms_verify_and_reject_message_key_signature_or_algorithm_substitution() {
    let signer = key_pair();
    let encoded = spki(signer.public_key().as_ref());
    let rng = SystemRandom::new();
    let components = rsa_public_key_from_spki(&encoded).unwrap();
    let mut other_modulus = components.n.clone();
    other_modulus[10] ^= 2;
    let other_key = spki_with_components(&other_modulus, &components.e);

    for (algorithm, padding) in algorithms() {
        let key = Key::from_spki_der(&encoded, algorithm).unwrap();
        let mut bytes = vec![0; signer.public().modulus_len()];
        signer.sign(padding, &rng, MESSAGE, &mut bytes).unwrap();
        let signed = Signature::from_bytes(&bytes, algorithm).unwrap();
        Crypto::verify_signature(&key, &signed, MESSAGE).unwrap();
        assert!(Crypto::verify_signature(&key, &signed, b"different message").is_err());
        let other_key = Key::from_spki_der(&other_key, algorithm).unwrap();
        assert!(Crypto::verify_signature(&other_key, &signed, MESSAGE).is_err());

        for (different, _) in algorithms() {
            if different != algorithm {
                let wrong = Signature::from_bytes(&bytes, different).unwrap();
                assert!(Crypto::verify_signature(&key, &wrong, MESSAGE).is_err());
            }
        }
        bytes[7] ^= 1;
        let tampered = Signature::from_bytes(&bytes, algorithm).unwrap();
        assert!(Crypto::verify_signature(&key, &tampered, MESSAGE).is_err());
        let shortened = Signature::from_bytes(&bytes[..bytes.len() - 1], algorithm);
        assert!(shortened.is_err());
    }
}

#[test]
fn malformed_spki_parameters_bitstrings_and_trailing_data_are_rejected() {
    let signer = key_pair();
    let encoded = spki(signer.public_key().as_ref());
    let algorithm = algorithms()[0].0;
    let mut parsed = SubjectPublicKeyInfoRef::from_der(&encoded).unwrap();

    parsed.algorithm.parameters = None;
    assert!(Key::from_spki_der(&parsed.to_der().unwrap(), algorithm).is_err());
    parsed.algorithm.parameters = Some(AnyRef::from_der(&[4, 0]).unwrap());
    assert!(Key::from_spki_der(&parsed.to_der().unwrap(), algorithm).is_err());
    parsed.algorithm.parameters = Some(AnyRef::NULL);
    parsed.algorithm.oid = x509_cert::der::oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    assert!(Key::from_spki_der(&parsed.to_der().unwrap(), algorithm).is_err());

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(Key::from_spki_der(&trailing, algorithm).is_err());
    let mut inner_trailing = signer.public_key().as_ref().to_vec();
    inner_trailing.push(0);
    assert!(Key::from_spki_der(&spki(&inner_trailing), algorithm).is_err());

    let mut unused = signer.public_key().as_ref().to_vec();
    *unused.last_mut().unwrap() &= 0xfe;
    let mut parsed = SubjectPublicKeyInfoRef::from_der(&encoded).unwrap();
    parsed.subject_public_key = BitStringRef::new(1, &unused).unwrap();
    let error = rsa_public_key_from_spki(&parsed.to_der().unwrap()).unwrap_err();
    assert!(error.to_string().contains("unused bits"));
    assert!(Key::from_spki_der(signer.public_key().as_ref(), algorithm).is_err());
}

#[test]
fn modulus_and_exponent_bounds_are_checked_before_verification() {
    let signer = key_pair();
    let components = rsa_public_key_from_spki(&spki(signer.public_key().as_ref())).unwrap();
    for modulus in [vec![0], vec![0xff; 128], vec![0xff; 513]] {
        assert!(rsa_public_key_from_spki(&spki_with_components(&modulus, &components.e)).is_err());
    }
    let mut not_2048_bits = components.n.clone();
    not_2048_bits[0] = 0x7f;
    assert!(
        rsa_public_key_from_spki(&spki_with_components(&not_2048_bits, &components.e)).is_err()
    );
    let mut even = components.n.clone();
    *even.last_mut().unwrap() &= 0xfe;
    assert!(rsa_public_key_from_spki(&spki_with_components(&even, &components.e)).is_err());

    for exponent in [0u64, 1, 2, 4, 1 << 33, (1 << 33) + 1, 1 << 48] {
        assert!(rsa_public_key_from_spki(&spki_with_components(
            &components.n,
            &exponent.to_be_bytes(),
        ))
        .is_err());
    }
    for exponent in [3u64, 65537, (1 << 33) - 1] {
        rsa_public_key_from_spki(&spki_with_components(
            &components.n,
            &exponent.to_be_bytes(),
        ))
        .unwrap();
    }
}

#[test]
fn malformed_signature_lengths_are_rejected() {
    for (algorithm, _) in algorithms() {
        for length in [0, 1, 128, 255, 513, 1024] {
            assert!(Signature::from_bytes(&vec![0; length], algorithm).is_err());
        }
    }
}

#[test]
fn pss_rejects_nonstandard_salt_and_mgf1_hash() {
    let signer = key_pair();
    let algorithm = SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps256);
    let key = Key::from_spki_der(&spki(signer.public_key().as_ref()), algorithm).unwrap();
    for bytes in [
        include_bytes!("../test_data/rsa_pss_sha256_wrong_salt.bin"),
        include_bytes!("../test_data/rsa_pss_sha256_wrong_mgf1.bin"),
    ] {
        let signed = Signature::from_bytes(bytes, algorithm).unwrap();
        assert!(Crypto::verify_signature(&key, &signed, MESSAGE).is_err());
    }
}
