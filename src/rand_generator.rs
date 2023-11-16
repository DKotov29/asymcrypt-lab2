use bitvec::prelude::*;
use rand::Rng;

pub fn generate(amount: usize) -> Vec<u64> {
    let mut vec = Vec::with_capacity(amount);
    let mut rng = rand::thread_rng();
    for _ in 0..amount {
        let num: u64 = rng.gen();
        vec.push(num);
    }
    vec
}
