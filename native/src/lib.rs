extern crate argon2;
extern crate rustler;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rustler::{Encoder, Env, NifResult, Term};

mod atoms {
    rustler::atoms! {
        ok,error
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn hash<'a>(env: Env<'a>, password: &str) -> NifResult<Term<'a>> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    return match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(hash) => Ok((atoms::ok(), hash.to_string()).encode(env)),
        Err(error) => Ok((atoms::error(), error.to_string()).encode(env)),
    };
}

#[rustler::nif(schedule = "DirtyCpu")]
fn verify<'a>(env: Env<'a>, password: &str, password_hash: &str) -> NifResult<Term<'a>> {
    match PasswordHash::new(password_hash) {
        Ok(parsed_hash) => {
            let argon2 = Argon2::default();
            Ok((
                atoms::ok(),
                argon2
                    .verify_password(password.as_bytes(), &parsed_hash)
                    .is_ok(),
            )
                .encode(env))
        }
        Err(error) => Ok((atoms::error(), error.to_string()).encode(env)),
    }
}

rustler::init!("argon2", [hash, verify]);
