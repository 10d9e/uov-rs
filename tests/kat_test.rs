use aes::Aes256;
use cipher::{BlockEncrypt, KeyInit};
use sha2::{Digest, Sha256};
use uov_rs::uov_all;

/// NIST KAT DRBG (AES-256 CTR mode) - matches the Python NIST_KAT_DRBG class.
struct NistKatDrbg {
    key: [u8; 32],
    ctr: [u8; 16],
}

impl NistKatDrbg {
    fn new(seed: &[u8]) -> Self {
        assert_eq!(seed.len(), 48);
        let mut drbg = NistKatDrbg {
            key: [0u8; 32],
            ctr: [0u8; 16],
        };
        let update = drbg.get_bytes(48);
        let update: Vec<u8> = update
            .iter()
            .zip(seed.iter())
            .map(|(&a, &b)| a ^ b)
            .collect();
        drbg.key.copy_from_slice(&update[..32]);
        drbg.ctr.copy_from_slice(&update[32..]);
        drbg
    }

    fn increment_ctr(&mut self) {
        // Big-endian increment
        for i in (0..16).rev() {
            self.ctr[i] = self.ctr[i].wrapping_add(1);
            if self.ctr[i] != 0 {
                break;
            }
        }
    }

    fn get_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut tmp = Vec::new();
        let cipher = Aes256::new((&self.key).into());
        while tmp.len() < num_bytes {
            self.increment_ctr();
            let mut block = self.ctr.into();
            cipher.encrypt_block(&mut block);
            tmp.extend_from_slice(&block);
        }
        tmp.truncate(num_bytes);
        tmp
    }

    fn random_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        let output = self.get_bytes(num_bytes);
        let update = self.get_bytes(48);
        self.key.copy_from_slice(&update[..32]);
        self.ctr.copy_from_slice(&update[32..]);
        output
    }
}

fn test_rsp(iut: &uov_rs::Uov, katnum: usize) -> String {
    let seed: Vec<u8> = (0..48).map(|i| i as u8).collect();
    let mut drbg = NistKatDrbg::new(&seed);
    let mut kat = format!("# {}\n\n", iut.params.katname);

    for count in 0..katnum {
        eprintln!("# {}/{} {}", count, katnum, iut.params.katname);
        kat += &format!("count = {}\n", count);

        let seed = drbg.random_bytes(48);
        let mut kat_drbg = NistKatDrbg::new(&seed);

        kat += &format!("seed = {}\n", hex::encode_upper(&seed));

        let mlen = 33 * (count + 1);
        kat += &format!("mlen = {}\n", mlen);

        let msg = drbg.random_bytes(mlen);
        kat += &format!("msg = {}\n", hex::encode_upper(&msg));

        let mut keygen_rbg = |n: usize| kat_drbg.random_bytes(n);
        let (pk, sk) = iut.keygen(&mut keygen_rbg);
        kat += &format!("pk = {}\n", hex::encode_upper(&pk));
        kat += &format!("sk = {}\n", hex::encode_upper(&sk));

        let mut sign_rbg = |n: usize| kat_drbg.random_bytes(n);
        let sig = iut.sign(&msg, &sk, &mut sign_rbg);

        let mut sm = msg.clone();
        sm.extend_from_slice(&sig);
        kat += &format!("smlen = {}\n", sm.len());
        kat += &format!("sm = {}\n", hex::encode_upper(&sm));

        let m2 = iut.open(&sm, &pk);
        match m2 {
            Some(ref m) if m == &msg => {}
            _ => {
                kat += "(verify error)\n";
                eprintln!("test_rsp() verify error");
            }
        }
        kat += "\n";
    }
    kat
}

#[test]
fn kat_1() {
    let expected: Vec<(&str, &str)> = vec![
        (
            "OV(256,112,44)-classic",
            "5e055716f1c5627a463821032754588788ea0936af6999e981fdd4c9687ecf3e",
        ),
        (
            "OV(256,112,44)-pkc",
            "4faaa60017839dbefd70b772019200e064aafe67abf65f821926afa66f5013d7",
        ),
        (
            "OV(256,112,44)-pkc-skc",
            "287235330008a590278a106423e3596bbf1035eb1d0276c4b44c370e6eb0044a",
        ),
        (
            "OV(16,160,64)-classic",
            "8a75ba48fd6f250e0e6e2eb68e77a54620f11b2c3fce9aae4601c491157e6862",
        ),
        (
            "OV(16,160,64)-pkc",
            "10d81a0d23a102aa98b4ade3ec895d2d0efb11bf6a5e19bc1637496bff6aa7e6",
        ),
        (
            "OV(16,160,64)-pkc-skc",
            "aacf0751c2d25c3404595d56a5ce60281f1e1002d42770c37008cb517dbd4976",
        ),
        (
            "OV(256,184,72)-classic",
            "794427d6cc5b49779f9d4428bdb68702d61a77d76bc5c040082c3f53838661e4",
        ),
        (
            "OV(256,184,72)-pkc",
            "c292f77f564551ac93959d77c644f7c4d989c2e38e5a0d5d3034b13f2eb791b5",
        ),
        (
            "OV(256,184,72)-pkc-skc",
            "6f94dd3e385ce97cb06b1eb6994bfe925538df3eb954ee0576cabd7babddeba5",
        ),
        (
            "OV(256,244,96)-classic",
            "1655a654ff4b751a527403d3ea05abbfc3740913a3adf87075782f8076646146",
        ),
        (
            "OV(256,244,96)-pkc",
            "253d2bd64189440ed8f8f71ab3ac637b20d9409be897fd816ac52f376d1e2ab3",
        ),
        (
            "OV(256,244,96)-pkc-skc",
            "759ea9c46d0b89c7d707ab9b58394541bc0df65d6b3291722a1a6a7171a9dd89",
        ),
    ];

    let all = uov_all();
    for (i, iut) in all.iter().enumerate() {
        let kat = test_rsp(iut, 1);
        let hash = Sha256::digest(kat.as_bytes());
        let hash_hex = hex::encode(hash);
        eprintln!("{} {} (1)", hash_hex, iut.params.katname);
        assert_eq!(
            hash_hex, expected[i].1,
            "KAT mismatch for {}",
            expected[i].0
        );
    }
}
