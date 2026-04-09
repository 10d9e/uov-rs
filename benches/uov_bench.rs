use criterion::{criterion_group, criterion_main, Criterion};
use uov_rs::{KeyPair, Scheme};

fn bench_scheme(c: &mut Criterion, scheme: Scheme, name: &str) {
    c.bench_function(&format!("{}/keygen", name), |b| {
        b.iter(|| KeyPair::generate(scheme))
    });

    let kp = KeyPair::generate(scheme);
    let msg = b"benchmark message for UOV signature scheme";

    c.bench_function(&format!("{}/sign", name), |b| {
        b.iter(|| kp.signing_key.sign(msg))
    });

    let sig = kp.signing_key.sign(msg);

    c.bench_function(&format!("{}/verify", name), |b| {
        b.iter(|| kp.verifying_key.verify(msg, &sig))
    });
}

fn bench_all(c: &mut Criterion) {
    let schemes: &[(Scheme, &str)] = &[
        (Scheme::Ip, "Ip"),
        (Scheme::IpPkc, "Ip-pkc"),
        (Scheme::IpPkcSkc, "Ip-pkc-skc"),
        (Scheme::Is, "Is"),
        (Scheme::IsPkc, "Is-pkc"),
        (Scheme::IsPkcSkc, "Is-pkc-skc"),
        (Scheme::III, "III"),
        (Scheme::IIIPkc, "III-pkc"),
        (Scheme::IIIPkcSkc, "III-pkc-skc"),
        (Scheme::V, "V"),
        (Scheme::VPkc, "V-pkc"),
        (Scheme::VPkcSkc, "V-pkc-skc"),
    ];

    for &(scheme, name) in schemes {
        bench_scheme(c, scheme, name);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_all
}
criterion_main!(benches);
