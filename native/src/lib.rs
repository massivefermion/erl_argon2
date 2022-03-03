extern crate argon2;
extern crate rustler;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rustler::{Encoder, Env, NifResult, NifUnitEnum, Term};

mod atoms {
    rustler::atoms! {
        ok,error
    }
}

#[derive(NifUnitEnum)]
enum AlgorithmAtom {
    Argon2d,
    Argon2i,
    Argon2id,
}

#[rustler::nif(schedule = "DirtyCpu")]
fn hash<'a>(env: Env<'a>, password: &str, algorithm: AlgorithmAtom) -> NifResult<Term<'a>> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = match algorithm {
        AlgorithmAtom::Argon2d => {
            Argon2::new(Algorithm::Argon2d, Version::V0x13, Params::default())
        }
        AlgorithmAtom::Argon2i => {
            Argon2::new(Algorithm::Argon2i, Version::V0x13, Params::default())
        }
        AlgorithmAtom::Argon2id => {
            Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default())
        }
    };

    match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(hashed) => Ok((atoms::ok(), hashed.to_string()).encode(env)),
        Err(error) => Ok((atoms::error(), error.to_string()).encode(env)),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn hash_with_secret<'a>(
    env: Env<'a>,
    password: &str,
    algorithm: AlgorithmAtom,
    secret: &str,
) -> NifResult<Term<'a>> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = match algorithm {
        AlgorithmAtom::Argon2d => Argon2::new_with_secret(
            secret.as_bytes(),
            Algorithm::Argon2d,
            Version::V0x13,
            Params::default(),
        ),
        AlgorithmAtom::Argon2i => Argon2::new_with_secret(
            secret.as_bytes(),
            Algorithm::Argon2i,
            Version::V0x13,
            Params::default(),
        ),
        AlgorithmAtom::Argon2id => Argon2::new_with_secret(
            secret.as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            Params::default(),
        ),
    };

    match argon2 {
        Ok(argon2) => match argon2.hash_password(password.as_bytes(), &salt) {
            Ok(hashed) => Ok((atoms::ok(), hashed.to_string()).encode(env)),
            Err(error) => Ok((atoms::error(), error.to_string()).encode(env)),
        },
        Err(error) => Ok((atoms::error(), error.to_string()).encode(env)),
    }
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

#[rustler::nif(schedule = "DirtyCpu")]
fn verify_with_secret<'a>(
    env: Env<'a>,
    password: &str,
    password_hash: &str,
    secret: &str,
) -> NifResult<Term<'a>> {
    match PasswordHash::new(password_hash) {
        Ok(parsed_hash) => {
            let argon2 = Argon2::new_with_secret(
                secret.as_bytes(),
                Algorithm::Argon2id,
                Version::V0x13,
                Params::default(),
            );

            match argon2 {
                Ok(argon2) => Ok((
                    atoms::ok(),
                    argon2
                        .verify_password(password.as_bytes(), &parsed_hash)
                        .is_ok(),
                )
                    .encode(env)),

                Err(error) => Ok((atoms::error(), error.to_string()).encode(env)),
            }
        }
        Err(error) => Ok((atoms::error(), error.to_string()).encode(env)),
    }
}

rustler::init!(
    "argon2",
    [hash, hash_with_secret, verify, verify_with_secret]
);
