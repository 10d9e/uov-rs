use uov_rs::{KeyPair, Scheme, Signature, SigningKey, VerifyingKey};

#[test]
fn sign_and_verify() {
    let kp = KeyPair::generate(Scheme::IpPkcSkc);
    let sig = kp.signing_key.sign(b"hello world");
    assert!(kp.verifying_key.verify(b"hello world", &sig));
    assert!(!kp.verifying_key.verify(b"wrong message", &sig));
}

#[test]
fn roundtrip_key_bytes() {
    let scheme = Scheme::IpPkcSkc;
    let kp = KeyPair::generate(scheme);

    let sk2 = SigningKey::from_bytes(scheme, kp.signing_key.as_bytes());
    let vk2 = VerifyingKey::from_bytes(scheme, kp.verifying_key.as_bytes());

    let sig = sk2.sign(b"roundtrip");
    assert!(vk2.verify(b"roundtrip", &sig));
}

#[test]
fn roundtrip_signature_bytes() {
    let kp = KeyPair::generate(Scheme::IpPkcSkc);
    let sig = kp.signing_key.sign(b"test");
    let sig2 = Signature::from_bytes(sig.as_bytes());
    assert!(kp.verifying_key.verify(b"test", &sig2));
}

#[test]
fn all_schemes_sign_verify() {
    let schemes = [
        Scheme::Ip,
        Scheme::IpPkc,
        Scheme::IpPkcSkc,
        Scheme::Is,
        Scheme::IsPkc,
        Scheme::IsPkcSkc,
        Scheme::III,
        Scheme::IIIPkc,
        Scheme::IIIPkcSkc,
        Scheme::V,
        Scheme::VPkc,
        Scheme::VPkcSkc,
    ];
    for scheme in schemes {
        let kp = KeyPair::generate(scheme);
        let sig = kp.signing_key.sign(b"test all schemes");
        assert!(
            kp.verifying_key.verify(b"test all schemes", &sig),
            "failed for {:?}",
            scheme
        );
    }
}
