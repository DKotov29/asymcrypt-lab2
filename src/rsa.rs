use malachite::Natural;
use malachite::num::arithmetic::traits::{ModInverse, ModPow};
use malachite::num::basic::traits::One;

pub fn generate(p: &Natural, q: &Natural) -> (Natural){
    let n = p*q;
    let oiler = (p - Natural::ONE) * (q - Natural::ONE);
    let e = Natural::from(0b10000000000000001u64);
    let d = e.mod_inverse(oiler).unwrap();
    (d)
}

pub fn encrypt(m: &Natural, n: &Natural) -> Option<Natural>{
    let e = Natural::from(0b10000000000000001u64);
    if m > &(n - Natural::ONE) {
        return None;
    }
    let c = m.mod_pow(e, n);
    Some(c)
}

pub fn decrypt(c: &Natural, d: &Natural, n: &Natural) -> Option<Natural>{
    if c > &(n - Natural::ONE) {
        return None;
    }
    let m = c.mod_pow(d, n);
    Some(m)
}

pub fn sign(m: &Natural, d: &Natural, n: &Natural) -> Natural{
    m.mod_pow(d, n)
}

pub fn verify_sign(m: &Natural, s: &Natural, n: &Natural) -> bool {
    let e = Natural::from(0b10000000000000001u64);
    m == &s.mod_pow(e, n)
}
