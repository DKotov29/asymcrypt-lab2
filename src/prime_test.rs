
use std::ops::{Div, Mul, Rem};
use malachite::Natural;
use malachite::num::arithmetic::traits::{Gcd, Mod, ModInverse, ModPow};
use malachite::num::basic::traits::{One, Two, Zero};
use malachite::num::logic::traits::BitIterable;
use crate::rand_generator;

pub fn test(number: &Natural) -> bool {
    match trial_div(&number) {
        true => {
            return miller_rabin(&number);
        }
        false => { return false; }
    }
}

pub fn trial_div(num: &Natural) -> bool {
    let mut div = Natural::TWO;
    while div != 24 {
        if num.rem(&div) == Natural::ZERO {
            return false;
        }
        div += Natural::ONE;
    }
    return true;
}

pub fn miller_rabin(number: &Natural) -> bool { //number = p
    let mut d = number - Natural::ONE;
    let mut s = 0usize;

    while (&d).mod_op(Natural::TWO) == Natural::ZERO {
        s += 1;
        d = d.div(Natural::TWO);
    }
    let len = number.bits().count();
    'label: for _k in 0..len {
        let x = {
            let mut x = Natural::from_owned_limbs_asc(rand_generator::generate(2));
            while &x < &Natural::ONE || &x > number {
                x = Natural::from_owned_limbs_asc(rand_generator::generate(2))
            }
            x
        };
        let gc = (&x).gcd(number);
        if gc > Natural::ONE {
            return false;
        }
        if gc == Natural::ONE {
            let mut x_d = (&x).mod_pow(&d, number);
            if x_d == 1 || x_d == number - Natural::ONE {
                continue;
            }
            let mut r = 0usize;

            let mut x_r = x.mod_pow((&d).mul(Natural::TWO), number);
            while r != s {
                if x_r == Natural::ONE {
                    return false;
                }
                if x_r == number - Natural::ONE {
                    continue 'label;
                }
                x_r = x_r.mod_pow(Natural::TWO, number);
                r += 1;
            }
            return false;
        }
    }
    return true;
}