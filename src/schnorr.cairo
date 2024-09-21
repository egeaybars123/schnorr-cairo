use core::ec::stark_curve::GEN_X;
use core::ec::stark_curve::GEN_Y;
use core::ec::stark_curve::ORDER;
use core::fmt::{Display, Formatter, Error};

use core::ec::{EcPoint, EcPointTrait, ec_point_unwrap, NonZeroEcPoint};
use core::poseidon::PoseidonTrait;
use core::hash::{HashStateTrait, HashStateExTrait};
use core::math::u256_mul_mod_n;

impl EcPointDisplay of Display<EcPoint> {
    fn fmt(self: @EcPoint, ref f: Formatter) -> Result<(), Error> {
        let non_zero: NonZeroEcPoint = (*self).try_into().unwrap();
        let (x, y): (felt252, felt252) = ec_point_unwrap(non_zero);
        writeln!(f, "Point ({x}, {y})")
    }
}

fn main() {
    let generator: EcPoint = EcPointTrait::new(GEN_X, GEN_Y).unwrap();
    let k: felt252 = 859825214214312162317391210310; //private key
    let P: EcPoint = generator.mul(k); //public key
    let (P_x, P_y): (felt252, felt252) = ec_point_unwrap(P.try_into().unwrap());

    let r: felt252 = 46952909012476409278523962123414653; //secret nonce
    let R: EcPoint = generator.mul(r);
    let (R_x, R_y): (felt252, felt252) = ec_point_unwrap(R.try_into().unwrap());


    let message: felt252 = 'I love Cairo';
    //let e = 1;
    let e = PoseidonTrait::new().update(R_x).update(R_y).update(P_x).update(P_y).update(message).finalize();

    println!("msg_hash: {}", e);

    //TODO: Do these operations in finite field with modular arithmetic
    let s: felt252 = add_mod_p(r, mul_mod_p(k, e, ORDER), ORDER); //Signature given to Bob, our recipient.
    println!("signature: {}", s);

    //Bob's operations - already knowing P, R and message (can compute e as well)
    let s_G: EcPoint = generator.mul(s);
    let P_e: EcPoint = P.mul(e);
    let rhs: EcPoint = P_e + R;

    println!("s_G: {}", s_G);
    println!("R + P.e: {}", rhs);
    let (s_Gx, s_Gy): (felt252, felt252) = ec_point_unwrap(s_G.try_into().unwrap());
    let (rhs_x, rhs_y): (felt252, felt252) = ec_point_unwrap(s_G.try_into().unwrap());

    if ((rhs_x == s_Gx) && (s_Gy == rhs_y)) {
        println!("Signature verification: true");
    } else {
        println!("Signature verification: false");
    }
}

fn add_mod_p(x: felt252, y: felt252, p: felt252) -> felt252 {
    let x_u256: u256 = x.into();
    let y_u256: u256 = y.into();
    let p_u256: u256 = p.into();

    let result: u256 = (x_u256 + y_u256) % p_u256;

    return result.try_into().unwrap();
}

fn mul_mod_p(x: felt252, y: felt252, p: felt252) -> felt252 {
    let x_u256: u256 = x.into();
    let y_u256: u256 = y.into();
    let p_u256: u256 = p.into();

    let result: u256 = u256_mul_mod_n(x_u256, y_u256, p_u256.try_into().unwrap());

    return result.try_into().unwrap();
}