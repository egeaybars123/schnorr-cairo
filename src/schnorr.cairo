use core::ec::stark_curve::GEN_X;
use core::ec::stark_curve::GEN_Y;
use core::ec::stark_curve::ORDER;
use core::fmt::{Display, Formatter, Error};

use core::ec::{EcPoint, EcPointTrait, ec_point_unwrap, NonZeroEcPoint, EcState, EcStateTrait};
use core::poseidon::PoseidonTrait;
use core::hash::{HashStateTrait, HashStateExTrait};
use core::math::u256_mul_mod_n;

pub impl EcPointDisplay of Display<EcPoint> {
    fn fmt(self: @EcPoint, ref f: Formatter) -> Result<(), Error> {
        let non_zero: NonZeroEcPoint = (*self).try_into().unwrap();
        let (x, y): (felt252, felt252) = ec_point_unwrap(non_zero);
        writeln!(f, "Point ({x}, {y})")
    }
}

impl PartialEqImpl of PartialEq<EcPoint> {
    fn eq(lhs: @EcPoint, rhs: @EcPoint) -> bool {
        let (lhs_x, lhs_y): (felt252, felt252) = ec_point_unwrap((*lhs).try_into().unwrap());
        let (rhs_x, rhs_y): (felt252, felt252) = ec_point_unwrap((*rhs).try_into().unwrap());

        if ((rhs_x == lhs_x) && (rhs_y == lhs_y)) {
            true
        } else {
            false
        }
    }
}

fn main() {
    let generator: EcPoint = EcPointTrait::new(GEN_X, GEN_Y).unwrap();
    let private_key_array: Array<felt252> = array![8598252142143121623173912103109023791, 4549714982273490124415453232325793];
    let secret_nonce_array: Array<felt252> = array![9187104788595651319060602581700, 5302284069823954953322726808654];
    let mut public_key_array: Array<EcPoint> = array![];
    for k in private_key_array.clone() {
        let pub_key = generator.mul(k);
        public_key_array.append(pub_key);
    };
    let message: felt252 = 'I love Cairo';
    let l = PoseidonTrait::new();
    //Hash of all public keys
    for p in public_key_array.clone() {
        let (P_x, _): (felt252, felt252) = ec_point_unwrap(p.try_into().unwrap());
        let _ = l.update_with(P_x);
    };
    let hash_l = l.finalize();
    let mut a_i: Array<felt252> = array![];

    for p in public_key_array.clone() {
        let (P_x, _): (felt252, felt252) = ec_point_unwrap(p.try_into().unwrap());
        let hash = PoseidonTrait::new().update(hash_l).update(P_x).finalize();
        a_i.append(hash);
    };

    //******************** SHARED PUBLIC KEY CALCULATION ********************
    let mut initial_shared_pub_key: EcState = EcStateTrait::init();
    let mut index = 0;
    for a in a_i.clone() {
        let pub_key = *public_key_array.at(index);
        let result = pub_key.mul(a); //scalar multiplication
        let non_zero_result: NonZeroEcPoint = result.try_into().unwrap();
        initial_shared_pub_key.add(non_zero_result);
        index += 1;
    };
    let shared_public_key: EcPoint = initial_shared_pub_key.finalize();

    println!("Shared Public Key: {}", shared_public_key);

    //******************** SHARED NONCE CALCULATION ********************
    let mut initial_shared_nonce: EcState = EcStateTrait::init();
    for i in secret_nonce_array.clone() {
        let R_i = generator.mul(i);
        let non_zero_R_i: NonZeroEcPoint = R_i.try_into().unwrap();
        initial_shared_nonce.add(non_zero_R_i);
    };
    let shared_nonce = initial_shared_nonce.finalize();

    println!("Shared Nonce Key: {}", shared_nonce);

    let (R_x, _): (felt252, felt252) = ec_point_unwrap(shared_nonce.try_into().unwrap());
    let (X_x, _): (felt252, felt252) = ec_point_unwrap(shared_public_key.try_into().unwrap());
    let e = PoseidonTrait::new().update(R_x).update(X_x).update(message).finalize(); //Challenge

    let mut sig_index = 0;
    let mut signature = 0;
    for k_i in private_key_array {
        let r_i = *secret_nonce_array.at(sig_index);
        let a_i_value = *a_i.at(sig_index);
        let rhs = mul_mod_p(e, mul_mod_p(k_i, a_i_value, ORDER), ORDER);
        signature = felt252_add_mod_p(signature, felt252_add_mod_p(rhs, r_i, ORDER), ORDER);
        sig_index += 1;
    };

    println!("Aggregated Signature: {}", signature);

    //******************** SIGNATURE VERIFICATION ********************
    let s_G = generator.mul(signature);
    let rhs = shared_nonce + shared_public_key.mul(e);
    println!("Aggregated Signature Verification: {}", s_G == rhs);
}

fn schnorr() {
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
    let s: felt252 = r + mul_mod_p(k, e, ORDER); //Signature given to Bob, our recipient.
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

pub fn mul_mod_p(x: felt252, y: felt252, p: felt252) -> felt252 {
    let x_u256: u256 = x.into();
    let y_u256: u256 = y.into();
    let p_u256: u256 = p.into();

    let result: u256 = u256_mul_mod_n(x_u256, y_u256, p_u256.try_into().unwrap());

    return result.try_into().unwrap();
}

fn felt252_add_mod_p(x: felt252, y: felt252, p: felt252) -> felt252 {
    let x_u256: u256 = x.into();
    
    let sum = x + y;

    //Checks for overflow - behaving as checked_add
    if sum.into() < x_u256 {
        let felt252_max = 0x800000000000011000000000000000000000000000000000000000000000000;
        let mod_difference = felt252_max - p;

        return sum + mod_difference + 1;
    }

    return sum;
}