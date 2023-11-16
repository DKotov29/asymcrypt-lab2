extern crate core;

use std::sync::Mutex;
use std::time::Instant;
use rayon::prelude::*;
use malachite::Natural;
use malachite::num::basic::traits::One;
use malachite::num::logic::traits::BitIterable;

mod prime_test;
mod rand_generator;
mod rsa;

fn main() {
    let now = Instant::now();
    let vec = par_generate(4, 2);
    let (p, q) = (
        vec.get(0).unwrap().clone(),
        vec.get(1).unwrap().clone());
    let d = rsa::generate(&p, &q);
    let n = &p * &q;
    println!("p: {p}\nq: {q}\nn: {n}\nd: {d}");
    let k = Natural::from_owned_limbs_asc(rand_generator::generate(2));
    println!("\nk: {k}");

    let vec = par_generate(4, 2);
    let (mut p1, mut q1) = (
        vec.get(0).unwrap().clone(),
        vec.get(1).unwrap().clone());
    let mut n1 = &p1 * &q1;
    println!("{:?}", now.elapsed());
    while &n > &n1 {
        let vec = par_generate(4, 2);
        p1 = vec.get(0).unwrap().clone();
        q1 = vec.get(1).unwrap().clone();
        n1 = &p1 * &q1;
    }
    let d1 = rsa::generate(&p1, &q1);
    println!("p1: {p1}\nq1: {q1}\nn1: {n1}\nd1: {d1}");
    println!("{:?}", now.elapsed());
    //A
    let (k1, s1) = send_key(&k, &d, &n, &n1); //  get what to send
    println!("encrypted k: {k1}\nencrypted sign: {s1}");
    //B
    let (dk, ds) = receive_key(&k1, &s1, &d1, &n1);
    println!("decrypted k: {dk}\ndecrypted s: {ds}");
    println!("verify sign: {}", rsa::verify_sign(&dk, &ds, &n));
    //
}

pub fn send_key(k: &Natural, d: &Natural, n: &Natural, n1: &Natural) -> (Natural, Natural) {
    let k1 = rsa::encrypt(k, n1).unwrap();
    let s = rsa::sign(k, d, n);
    let s1 = rsa::encrypt(&s, n1).unwrap();
    (k1, s1)
}

pub fn receive_key(encrypted /*k1*/: &Natural, s1/*sign_ciphed*/: &Natural, d1: &Natural, n1: &Natural) -> (Natural/*k*/, Natural/*sign*/) {
    let k = rsa::decrypt(encrypted, d1, n1).unwrap();
    let s = rsa::decrypt(s1, d1, n1).unwrap();
    (k, s)
}


fn par_generate(at_once: usize, amount: usize) -> Vec<Natural> {
    let mut vec = Vec::with_capacity(amount);
    let mut gen = Mutex::new(Vec::with_capacity(amount));
    while gen.lock().unwrap().len() < amount {
        (0..at_once).par_bridge().for_each(|_| {
            let mut found = false;
            let mut number = Natural::ONE;
            while !found {
                let gen_len: usize = 256 / 64; // in u64
                let vec = rand_generator::generate(gen_len);
                let num = Natural::from_owned_limbs_asc(vec);
                let mn = num.bits().count();
                if mn < 256 {
                    continue;
                }
                found = prime_test::test(&num);
                number = num;
            }
            gen.lock().unwrap().push(number);
            if gen.lock().unwrap().len() >= amount {
                rayon::yield_now();
            }
        });
    }
    for i in &gen.lock().unwrap()[0..amount] {
        vec.push(i.clone());
    }
    vec
}
