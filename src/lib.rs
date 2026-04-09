use aes::Aes128;
use cipher::{KeyIvInit, StreamCipher};
use rand::{rngs::OsRng, RngCore};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

type Ctr128 = ctr::Ctr128BE<Aes128>;

// Finite field operations

fn gf16_mul(a: u8, b: u8) -> u8 {
    let mut a = a as u16;
    let mut r = a & ((b & 1) as u16).wrapping_neg();
    for i in 1..4u8 {
        let t = a & 8;
        a = ((a ^ t) << 1) ^ (t >> 2) ^ (t >> 3);
        r ^= a & (((b >> i) & 1) as u16).wrapping_neg();
    }
    r as u8
}

fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut a = a as u16;
    let mut r = a & ((b & 1) as u16).wrapping_neg();
    for i in 1..8u8 {
        a = (a << 1) ^ ((a >> 7).wrapping_neg() & 0x11B);
        r ^= a & (((b >> i) & 1) as u16).wrapping_neg();
    }
    r as u8
}

fn gf_mulm(v: &[u8], a: u8, gf: usize, m: usize) -> Vec<u8> {
    if gf == 256 {
        gf256_mulm(v, a, m)
    } else {
        gf16_mulm(v, a, m)
    }
}

fn gf256_mulm(v: &[u8], a: u8, _m: usize) -> Vec<u8> {
    let m_sz = v.len();
    let mut val = v.to_vec();
    let mask_bit0: u8 = if a & 1 != 0 { 0xFF } else { 0x00 };
    let mut r: Vec<u8> = val.iter().map(|&x| x & mask_bit0).collect();

    for i in 1..8u8 {
        let mut new_val = vec![0u8; m_sz];
        for j in 0..m_sz {
            let tj = val[j] & 0x80;
            let vj = val[j] ^ tj;
            new_val[j] = (vj << 1) ^ (tj >> 7) ^ (tj >> 6) ^ (tj >> 4) ^ (tj >> 3);
        }
        val = new_val;
        if (a >> i) & 1 != 0 {
            for j in 0..m_sz {
                r[j] ^= val[j];
            }
        }
    }
    r
}

fn gf16_mulm(v: &[u8], a: u8, _m: usize) -> Vec<u8> {
    let m_sz = v.len();
    let mut val = v.to_vec();
    let mask_bit0: u8 = if a & 1 != 0 { 0xFF } else { 0x00 };
    let mut r: Vec<u8> = val.iter().map(|&x| x & mask_bit0).collect();

    for i in 1..4u8 {
        let mut new_val = vec![0u8; m_sz];
        for j in 0..m_sz {
            let tj = val[j] & 0x88;
            let vj = val[j] ^ tj;
            new_val[j] = (vj << 1) ^ (tj >> 3) ^ (tj >> 2);
        }
        val = new_val;
        if (a >> i) & 1 != 0 {
            for j in 0..m_sz {
                r[j] ^= val[j];
            }
        }
    }
    r
}

fn gf_mul(a: u8, b: u8, gf: usize) -> u8 {
    if gf == 256 {
        gf256_mul(a, b)
    } else {
        gf16_mul(a, b)
    }
}

fn gf_inv(a: u8, gf: usize) -> u8 {
    let gf_bits: u8 = if gf == 256 { 8 } else { 4 };
    let mut r = a;
    let mut a = a;
    for _ in 2..gf_bits {
        a = gf_mul(a, a, gf);
        r = gf_mul(r, a, gf);
    }
    r = gf_mul(r, r, gf);
    r
}

fn gf_pack(v: &[u8], gf: usize) -> Vec<u8> {
    if gf == 256 {
        v.to_vec()
    } else {
        let mut out = Vec::with_capacity(v.len() / 2);
        for i in (0..v.len()).step_by(2) {
            out.push(v[i] | (v[i + 1] << 4));
        }
        out
    }
}

fn gf_unpack(b: &[u8], gf: usize) -> Vec<u8> {
    if gf == 256 {
        b.to_vec()
    } else {
        let mut v = Vec::with_capacity(b.len() * 2);
        for &x in b {
            v.push(x & 0x0F);
            v.push(x >> 4);
        }
        v
    }
}

type MVector = Vec<u8>;

fn mvec_zero(m_sz: usize) -> MVector {
    vec![0u8; m_sz]
}

fn mvec_xor(a: &MVector, b: &MVector) -> MVector {
    a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect()
}

fn mvec_from_bytes(b: &[u8], m_sz: usize) -> MVector {
    b[..m_sz].to_vec()
}

type TriMatrix = Vec<Vec<MVector>>;
type RectMatrix = Vec<Vec<MVector>>;

#[allow(clippy::needless_range_loop)]
fn unpack_mtri(b: &[u8], d: usize, m_sz: usize) -> TriMatrix {
    let mut m = vec![vec![mvec_zero(m_sz); d]; d];
    let mut p = 0;
    for i in 0..d {
        for j in i..d {
            m[i][j] = mvec_from_bytes(&b[p..], m_sz);
            p += m_sz;
        }
    }
    m
}

#[allow(clippy::needless_range_loop)]
fn pack_mtri(m: &TriMatrix, d: usize) -> Vec<u8> {
    let mut b = Vec::new();
    for i in 0..d {
        for j in i..d {
            b.extend_from_slice(&m[i][j]);
        }
    }
    b
}

#[allow(clippy::needless_range_loop)]
fn unpack_mrect(b: &[u8], h: usize, w: usize, m_sz: usize) -> RectMatrix {
    let mut m = vec![vec![mvec_zero(m_sz); w]; h];
    let mut p = 0;
    for i in 0..h {
        for j in 0..w {
            m[i][j] = mvec_from_bytes(&b[p..], m_sz);
            p += m_sz;
        }
    }
    m
}

#[allow(clippy::needless_range_loop)]
fn pack_mrect(m: &RectMatrix, h: usize, w: usize) -> Vec<u8> {
    let mut b = Vec::new();
    for i in 0..h {
        for j in 0..w {
            b.extend_from_slice(&m[i][j]);
        }
    }
    b
}

fn unpack_rect(b: &[u8], h: usize, w: usize, gf: usize) -> Vec<Vec<u8>> {
    if gf == 256 {
        (0..h).map(|i| b[i * w..(i + 1) * w].to_vec()).collect()
    } else {
        let w_sz = w / 2;
        (0..h)
            .map(|i| gf_unpack(&b[i * w_sz..(i + 1) * w_sz], gf))
            .collect()
    }
}

fn shake256_hash(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut buf = vec![0u8; output_len];
    reader.read(&mut buf);
    buf
}

fn aes128ctr(key: &[u8], len: usize) -> Vec<u8> {
    let iv = [0u8; 16];
    let mut cipher = Ctr128::new(key.into(), &iv.into());
    let mut buf = vec![0u8; len];
    cipher.apply_keystream(&mut buf);
    buf
}

#[derive(Clone)]
pub struct UovParams {
    pub gf: usize,
    pub n: usize,
    pub m: usize,
    pub v: usize,
    pub pkc: bool,
    pub skc: bool,
    pub name: &'static str,
    pub katname: String,
    pub gf_bits: usize,
    pub v_sz: usize,
    pub n_sz: usize,
    pub m_sz: usize,
    pub seed_sk_sz: usize,
    pub seed_pk_sz: usize,
    pub salt_sz: usize,
    pub sig_sz: usize,
    pub so_sz: usize,
    pub p1_sz: usize,
    pub p2_sz: usize,
    pub p3_sz: usize,
    pub pk_sz: usize,
    pub sk_sz: usize,
}

impl UovParams {
    pub fn new(gf: usize, n: usize, m: usize, pkc: bool, skc: bool, name: &'static str) -> Self {
        let v = n - m;
        let gf_bits = if gf == 256 { 8 } else { 4 };
        let v_sz = gf_bits * v / 8;
        let n_sz = gf_bits * n / 8;
        let m_sz = gf_bits * m / 8;
        let seed_sk_sz = 32;
        let seed_pk_sz = 16;
        let salt_sz = 16;

        let triangle = |n: usize| n * (n + 1) / 2;
        let sig_sz = n_sz + salt_sz;
        let so_sz = m * v_sz;
        let p1_sz = m_sz * triangle(v);
        let p2_sz = m_sz * v * m;
        let p3_sz = m_sz * triangle(m);

        let pk_sz = if pkc {
            seed_pk_sz + p3_sz
        } else {
            p1_sz + p2_sz + p3_sz
        };

        let sk_sz = if skc {
            seed_sk_sz
        } else {
            seed_sk_sz + so_sz + p1_sz + p2_sz
        };

        let kc = if pkc {
            if skc {
                "pkc-skc"
            } else {
                "pkc"
            }
        } else {
            "classic"
        };
        let katname = format!("OV({},{},{})-{}", gf, n, m, kc);

        UovParams {
            gf,
            n,
            m,
            v,
            pkc,
            skc,
            name,
            katname,
            gf_bits,
            v_sz,
            n_sz,
            m_sz,
            seed_sk_sz,
            seed_pk_sz,
            salt_sz,
            sig_sz,
            so_sz,
            p1_sz,
            p2_sz,
            p3_sz,
            pk_sz,
            sk_sz,
        }
    }
}

pub struct Uov {
    pub params: UovParams,
}

impl Uov {
    pub fn new(params: UovParams) -> Self {
        Uov { params }
    }

    #[allow(clippy::needless_range_loop)]
    fn calc_f2_p3(&self, p1: &[u8], p2: &[u8], so: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let p = &self.params;
        let m_sz = p.m_sz;
        let v = p.v;
        let m = p.m;
        let gf = p.gf;

        let m1 = unpack_mtri(p1, v, m_sz);
        let mut m2 = unpack_mrect(p2, v, m, m_sz);
        let mo = unpack_rect(so, m, v, gf);

        let mut m3 = vec![vec![mvec_zero(m_sz); m]; m];
        for j in 0..m {
            for i in 0..v {
                let mut t = m2[i][j].clone();
                for k in i..v {
                    t = mvec_xor(&t, &gf_mulm(&m1[i][k], mo[j][k], gf, m));
                }
                for k in 0..m {
                    let u = gf_mulm(&t, mo[k][i], gf, m);
                    if j < k {
                        m3[j][k] = mvec_xor(&m3[j][k], &u);
                    } else {
                        m3[k][j] = mvec_xor(&m3[k][j], &u);
                    }
                }
            }
        }

        for i in 0..v {
            for j in 0..m {
                let mut t = m2[i][j].clone();
                for k in 0..=i {
                    t = mvec_xor(&t, &gf_mulm(&m1[k][i], mo[j][k], gf, m));
                }
                for k in i..v {
                    t = mvec_xor(&t, &gf_mulm(&m1[i][k], mo[j][k], gf, m));
                }
                m2[i][j] = t;
            }
        }

        let p3 = pack_mtri(&m3, m);
        let sks = pack_mrect(&m2, v, m);
        (sks, p3)
    }

    #[allow(clippy::needless_range_loop)]
    fn gauss_solve(&self, ll: &[MVector], c: &[u8]) -> Option<Vec<u8>> {
        let p = &self.params;
        let h = p.m;
        let w = p.m + 1;
        let gf = p.gf;

        let ll_elems: Vec<Vec<u8>> = ll.iter().map(|x| gf_unpack(x, gf)).collect();

        let mut mat: Vec<Vec<u8>> = (0..h)
            .map(|j| {
                let mut row = Vec::with_capacity(w);
                for i in 0..h {
                    row.push(ll_elems[i][j]);
                }
                row.push(c[j]);
                row
            })
            .collect();

        for i in 0..h {
            let mut j = i;
            while j < h && mat[j][i] == 0 {
                j += 1;
            }
            if j == h {
                return None;
            }
            if i != j {
                for k in 0..w {
                    mat[i][k] ^= mat[j][k];
                }
            }
            let inv = gf_inv(mat[i][i], gf);
            for k in 0..w {
                mat[i][k] = gf_mul(mat[i][k], inv, gf);
            }
            for j2 in 0..h {
                let x = mat[j2][i];
                if j2 != i {
                    for k in 0..w {
                        mat[j2][k] ^= gf_mul(mat[i][k], x, gf);
                    }
                }
            }
        }

        Some((0..h).map(|i| mat[i][w - 1]).collect())
    }

    fn pubmap(&self, z: &[u8], tm: &[u8]) -> Vec<u8> {
        let p = &self.params;
        let v = p.v;
        let m = p.m;
        let m_sz = p.m_sz;
        let gf = p.gf;

        let m1 = unpack_mtri(tm, v, m_sz);
        let m2 = unpack_mrect(&tm[p.p1_sz..], v, m, m_sz);
        let m3 = unpack_mtri(&tm[p.p1_sz + p.p2_sz..], m, m_sz);
        let x = gf_unpack(z, gf);

        let mut y = mvec_zero(m_sz);

        for i in 0..v {
            for j in i..v {
                y = mvec_xor(&y, &gf_mulm(&m1[i][j], gf_mul(x[i], x[j], gf), gf, m));
            }
        }
        for i in 0..v {
            for j in 0..m {
                y = mvec_xor(&y, &gf_mulm(&m2[i][j], gf_mul(x[i], x[v + j], gf), gf, m));
            }
        }
        for i in 0..m {
            for j in i..m {
                y = mvec_xor(
                    &y,
                    &gf_mulm(&m3[i][j], gf_mul(x[v + i], x[v + j], gf), gf, m),
                );
            }
        }

        y
    }

    fn expand_p(&self, seed_pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let p = &self.params;
        let pk = aes128ctr(seed_pk, p.p1_sz + p.p2_sz);
        (pk[..p.p1_sz].to_vec(), pk[p.p1_sz..].to_vec())
    }

    fn expand_pk(&self, cpk: &[u8]) -> Vec<u8> {
        let p = &self.params;
        let seed_pk = &cpk[..p.seed_pk_sz];
        let p3 = &cpk[p.seed_pk_sz..];
        let (p1, p2) = self.expand_p(seed_pk);
        let mut epk = p1;
        epk.extend_from_slice(&p2);
        epk.extend_from_slice(p3);
        epk
    }

    fn expand_sk(&self, csk: &[u8]) -> Vec<u8> {
        let p = &self.params;
        let seed_sk = &csk[..p.seed_sk_sz];
        let seed_pk_so = shake256_hash(seed_sk, p.seed_pk_sz + p.so_sz);
        let seed_pk = &seed_pk_so[..p.seed_pk_sz];
        let so = &seed_pk_so[p.seed_pk_sz..];
        let (p1, p2) = self.expand_p(seed_pk);
        let (sks, _p3) = self.calc_f2_p3(&p1, &p2, so);
        let mut esk = seed_sk.to_vec();
        esk.extend_from_slice(so);
        esk.extend_from_slice(&p1);
        esk.extend_from_slice(&sks);
        esk
    }

    pub fn keygen(&self, rbg: &mut dyn FnMut(usize) -> Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let p = &self.params;
        let seed_sk = rbg(p.seed_sk_sz);
        let seed_pk_so = shake256_hash(&seed_sk, p.seed_pk_sz + p.so_sz);
        let seed_pk = &seed_pk_so[..p.seed_pk_sz];
        let so = &seed_pk_so[p.seed_pk_sz..];
        let (p1, p2) = self.expand_p(seed_pk);
        let (sks, p3) = self.calc_f2_p3(&p1, &p2, so);

        let pk = if p.pkc {
            let mut pk = seed_pk.to_vec();
            pk.extend_from_slice(&p3);
            pk
        } else {
            let mut pk = p1.clone();
            pk.extend_from_slice(&p2);
            pk.extend_from_slice(&p3);
            pk
        };

        let sk = if p.skc {
            seed_sk
        } else {
            let mut sk = seed_sk;
            sk.extend_from_slice(so);
            sk.extend_from_slice(&p1);
            sk.extend_from_slice(&sks);
            sk
        };

        (pk, sk)
    }

    #[allow(clippy::needless_range_loop)]
    pub fn sign(&self, msg: &[u8], sk: &[u8], rbg: &mut dyn FnMut(usize) -> Vec<u8>) -> Vec<u8> {
        let p = &self.params;
        let gf = p.gf;

        let sk = if p.skc {
            self.expand_sk(sk)
        } else {
            sk.to_vec()
        };

        let seed_sk = &sk[..p.seed_sk_sz];
        let so = &sk[p.seed_sk_sz..p.seed_sk_sz + p.so_sz];
        let p1_data = &sk[p.seed_sk_sz + p.so_sz..p.seed_sk_sz + p.so_sz + p.p1_sz];
        let sks_data =
            &sk[p.seed_sk_sz + p.so_sz + p.p1_sz..p.seed_sk_sz + p.so_sz + p.p1_sz + p.p2_sz];

        let mo = unpack_rect(so, p.m, p.v, gf);
        let m1 = unpack_mtri(p1_data, p.v, p.m_sz);
        let ms = unpack_mrect(sks_data, p.v, p.m, p.m_sz);

        let salt = rbg(p.salt_sz);

        let mut hash_input = msg.to_vec();
        hash_input.extend_from_slice(&salt);
        let t = shake256_hash(&hash_input, p.m_sz);

        let mut ctr = 0u16;
        let mut x_sol: Option<Vec<u8>> = None;
        let mut vinegar = Vec::new();

        while x_sol.is_none() && ctr < 0x100 {
            let mut expand_input = msg.to_vec();
            expand_input.extend_from_slice(&salt);
            expand_input.extend_from_slice(seed_sk);
            expand_input.push(ctr as u8);
            vinegar = gf_unpack(&shake256_hash(&expand_input, p.v_sz), gf);
            ctr += 1;

            let mut ll = vec![mvec_zero(p.m_sz); p.m];
            for i in 0..p.m {
                for j in 0..p.v {
                    ll[i] = mvec_xor(&ll[i], &gf_mulm(&ms[j][i], vinegar[j], gf, p.m));
                }
            }

            let mut r = t.clone();
            for i in 0..p.v {
                let mut u = mvec_zero(p.m_sz);
                for j in i..p.v {
                    u = mvec_xor(&u, &gf_mulm(&m1[i][j], vinegar[j], gf, p.m));
                }
                let u2 = gf_mulm(&u, vinegar[i], gf, p.m);
                r = mvec_xor(&r, &u2);
            }
            let r_elems = gf_unpack(&r, gf);

            x_sol = self.gauss_solve(&ll, &r_elems);
        }

        let x = x_sol.expect("signing failed after 256 attempts");

        let mut y = vinegar;
        for i in 0..p.m {
            for j in 0..p.v {
                y[j] ^= gf_mul(mo[i][j], x[i], gf);
            }
        }

        let mut sig = gf_pack(&y, gf);
        sig.extend_from_slice(&gf_pack(&x, gf));
        sig.extend_from_slice(&salt);
        sig
    }

    pub fn verify(&self, sig: &[u8], msg: &[u8], pk: &[u8]) -> bool {
        let p = &self.params;

        let pk = if p.pkc {
            self.expand_pk(pk)
        } else {
            pk.to_vec()
        };

        let x = &sig[..p.n_sz];
        let salt = &sig[p.n_sz..p.n_sz + p.salt_sz];

        let mut hash_input = msg.to_vec();
        hash_input.extend_from_slice(salt);
        let t = shake256_hash(&hash_input, p.m_sz);

        t == self.pubmap(x, &pk)
    }

    pub fn open(&self, sm: &[u8], pk: &[u8]) -> Option<Vec<u8>> {
        let msg_sz = sm.len() - self.params.sig_sz;
        let msg = &sm[..msg_sz];
        let sig = &sm[msg_sz..];
        if self.verify(sig, msg, pk) {
            Some(msg.to_vec())
        } else {
            None
        }
    }
}

pub fn uov_1p() -> Uov {
    Uov::new(UovParams::new(256, 112, 44, false, false, "uov-Ip-classic"))
}
pub fn uov_1p_pkc() -> Uov {
    Uov::new(UovParams::new(256, 112, 44, true, false, "uov-Ip-pkc"))
}
pub fn uov_1p_pkc_skc() -> Uov {
    Uov::new(UovParams::new(256, 112, 44, true, true, "uov-Ip-pkc+skc"))
}
pub fn uov_1s() -> Uov {
    Uov::new(UovParams::new(16, 160, 64, false, false, "uov-Is-classic"))
}
pub fn uov_1s_pkc() -> Uov {
    Uov::new(UovParams::new(16, 160, 64, true, false, "uov-Is-pkc"))
}
pub fn uov_1s_pkc_skc() -> Uov {
    Uov::new(UovParams::new(16, 160, 64, true, true, "uov-Is-pkc+skc"))
}
pub fn uov_3() -> Uov {
    Uov::new(UovParams::new(
        256,
        184,
        72,
        false,
        false,
        "uov-III-classic",
    ))
}
pub fn uov_3_pkc() -> Uov {
    Uov::new(UovParams::new(256, 184, 72, true, false, "uov-III-pkc"))
}
pub fn uov_3_pkc_skc() -> Uov {
    Uov::new(UovParams::new(256, 184, 72, true, true, "uov-III-pkc+skc"))
}
pub fn uov_5() -> Uov {
    Uov::new(UovParams::new(256, 244, 96, false, false, "uov-V-classic"))
}
pub fn uov_5_pkc() -> Uov {
    Uov::new(UovParams::new(256, 244, 96, true, false, "uov-V-pkc"))
}
pub fn uov_5_pkc_skc() -> Uov {
    Uov::new(UovParams::new(256, 244, 96, true, true, "uov-V-pkc+skc"))
}

pub fn uov_all() -> Vec<Uov> {
    vec![
        uov_1p(),
        uov_1p_pkc(),
        uov_1p_pkc_skc(),
        uov_1s(),
        uov_1s_pkc(),
        uov_1s_pkc_skc(),
        uov_3(),
        uov_3_pkc(),
        uov_3_pkc_skc(),
        uov_5(),
        uov_5_pkc(),
        uov_5_pkc_skc(),
    ]
}

// === Public SDK ===

/// UOV parameter set selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// NIST Level I, GF(256), n=112, m=44
    Ip,
    /// NIST Level I, GF(256), n=112, m=44, compressed public key
    IpPkc,
    /// NIST Level I, GF(256), n=112, m=44, compressed public + secret key
    IpPkcSkc,
    /// NIST Level I, GF(16), n=160, m=64
    Is,
    /// NIST Level I, GF(16), n=160, m=64, compressed public key
    IsPkc,
    /// NIST Level I, GF(16), n=160, m=64, compressed public + secret key
    IsPkcSkc,
    /// NIST Level III, GF(256), n=184, m=72
    III,
    /// NIST Level III, GF(256), n=184, m=72, compressed public key
    IIIPkc,
    /// NIST Level III, GF(256), n=184, m=72, compressed public + secret key
    IIIPkcSkc,
    /// NIST Level V, GF(256), n=244, m=96
    V,
    /// NIST Level V, GF(256), n=244, m=96, compressed public key
    VPkc,
    /// NIST Level V, GF(256), n=244, m=96, compressed public + secret key
    VPkcSkc,
}

impl Scheme {
    fn to_uov(self) -> Uov {
        match self {
            Scheme::Ip => uov_1p(),
            Scheme::IpPkc => uov_1p_pkc(),
            Scheme::IpPkcSkc => uov_1p_pkc_skc(),
            Scheme::Is => uov_1s(),
            Scheme::IsPkc => uov_1s_pkc(),
            Scheme::IsPkcSkc => uov_1s_pkc_skc(),
            Scheme::III => uov_3(),
            Scheme::IIIPkc => uov_3_pkc(),
            Scheme::IIIPkcSkc => uov_3_pkc_skc(),
            Scheme::V => uov_5(),
            Scheme::VPkc => uov_5_pkc(),
            Scheme::VPkcSkc => uov_5_pkc_skc(),
        }
    }
}

/// A UOV signing key (secret key).
pub struct SigningKey {
    scheme: Scheme,
    uov: Uov,
    sk: Vec<u8>,
}

/// A UOV verification key (public key).
pub struct VerifyingKey {
    scheme: Scheme,
    uov: Uov,
    pk: Vec<u8>,
}

/// A UOV signature.
pub struct Signature {
    bytes: Vec<u8>,
}

/// A UOV key pair (signing key + verifying key).
pub struct KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl KeyPair {
    /// Generate a new key pair using OS randomness.
    pub fn generate(scheme: Scheme) -> Self {
        let uov = scheme.to_uov();
        let mut rbg = |n: usize| {
            let mut buf = vec![0u8; n];
            getrandom(&mut buf);
            buf
        };
        let (pk, sk) = uov.keygen(&mut rbg);
        let uov2 = scheme.to_uov();
        KeyPair {
            signing_key: SigningKey { scheme, uov, sk },
            verifying_key: VerifyingKey {
                scheme,
                uov: uov2,
                pk,
            },
        }
    }
}

impl SigningKey {
    /// Reconstruct a signing key from raw bytes.
    pub fn from_bytes(scheme: Scheme, bytes: &[u8]) -> Self {
        let uov = scheme.to_uov();
        assert_eq!(bytes.len(), uov.params.sk_sz, "invalid secret key length");
        SigningKey {
            scheme,
            uov,
            sk: bytes.to_vec(),
        }
    }

    /// Return the raw secret key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.sk
    }

    /// Sign a message, returning a detached signature.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let mut rbg = |n: usize| {
            let mut buf = vec![0u8; n];
            getrandom(&mut buf);
            buf
        };
        let sig = self.uov.sign(msg, &self.sk, &mut rbg);
        Signature { bytes: sig }
    }

    /// Return the scheme this key was generated for.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }
}

impl VerifyingKey {
    /// Reconstruct a verifying key from raw bytes.
    pub fn from_bytes(scheme: Scheme, bytes: &[u8]) -> Self {
        let uov = scheme.to_uov();
        assert_eq!(bytes.len(), uov.params.pk_sz, "invalid public key length");
        VerifyingKey {
            scheme,
            uov,
            pk: bytes.to_vec(),
        }
    }

    /// Return the raw public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.pk
    }

    /// Verify a signature against a message. Returns `true` if valid.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        self.uov.verify(&sig.bytes, msg, &self.pk)
    }

    /// Return the scheme this key was generated for.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }
}

impl Signature {
    /// Construct a signature from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Signature {
            bytes: bytes.to_vec(),
        }
    }

    /// Return the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn getrandom(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}
