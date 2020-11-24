// SPDX-License-Identifier: MIT

use std::fmt;

use aes::Aes256;
use block_modes::{Cbc, BlockMode, block_padding::Pkcs7};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Visitor;
use sha2::Sha256;

#[derive(Debug, Default)]
pub struct CipherSuite {
        master_key: Vec<u8>,
        pub master_key_hash: String,
        mac_key: Vec<u8>,

        decrypt_key: Option<Vec<u8>>,
}

#[derive(Debug, failure::Fail)]
pub enum CipherError {
        #[fail(display = "failed to verify key")]
        InvalidMac,

        #[fail(display = "only type 2 ciphers are supported")]
        InvalidKeyType,

        #[fail(display = "key length must  be exactly 32 bytes")]
        InvalidKeyLength,

        #[fail(display = "block mode error")]
        BlockModeError,

        #[fail(display = "failed to set decrypt key: {:?}", 0)]
        DecryptionKeyError(String),
}

impl CipherSuite {
        pub fn from(email: &str, password: &str, kdf_iterations: usize) -> Self {
                let (master_key, master_key_hash, mac_key) =
                        derive_master_key(email, password, kdf_iterations);

                Self {
                        master_key,
                        master_key_hash,
                        mac_key,
                        decrypt_key: None,
                }
        }

        pub fn set_decrypt_key(&mut self, key: &CipherString) -> Result<(), CipherError> {
                let key = key.decrypt_raw(&self.master_key, &self.mac_key)
                        .map_err(|e| CipherError::DecryptionKeyError(e.to_string()))?;

                self.decrypt_key = Some(Vec::from(&key[0..32]));
                self.mac_key = Vec::from(&key[32..64]);

                Ok(())
        }
}

fn derive_master_key(email: &str, password: &str, iter_count: usize) -> (Vec<u8>, String, Vec<u8>) {
        let mut master_key = vec![0u8; 32];
        pbkdf2::<Hmac<Sha256>>(
                password.as_bytes(), email.as_bytes(), iter_count, &mut master_key
        );

        let mut master_key_hash = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(
                &master_key, password.as_bytes(), 1, &mut master_key_hash
        );

        // Expand master key
        let hkdf = Hkdf::<Sha256>::from_prk(&master_key).unwrap();
        hkdf.expand("enc".as_bytes(), &mut master_key).unwrap();

        let mut mac_key = vec![0u8; 32];
        hkdf.expand("mac".as_bytes(), &mut mac_key).unwrap();

        (master_key, base64::encode(&master_key_hash), mac_key)
}

#[derive(Clone, Debug)]
pub struct CipherString {
        type_: usize,

        iv: Vec<u8>,
        ct: Vec<u8>,
        mac: Vec<u8>,
}

impl CipherString {
        fn from_str(text: &str) -> Option<CipherString> {
                let type_end = text.find('.')?;
                let type_ = text[0..type_end].parse::<usize>().ok()?;

                let mut parts = text[type_end+1..].split('|');

                let iv = base64::decode(parts.next()?).ok()?;
                let ct = base64::decode(parts.next()?).ok()?;
                let mac = base64::decode(parts.next()?).ok()?;

                Some(CipherString { type_, iv, ct, mac })
        }

        fn as_str(&self) -> String {
                format!("{}.{}|{}|{}",
                        self.type_,
                        base64::encode(&self.iv),
                        base64::encode(&self.ct),
                        base64::encode(&self.mac),
                )
        }

        fn is_valid_mac(&self, mac_key: &[u8]) -> bool {
                if mac_key.len() != 32 {
                        return false;
                }

                let mut message = Vec::<u8>::new();
                message.extend(&self.iv);
                message.extend(&self.ct);

                let mut mac = Hmac::<Sha256>::new_varkey(mac_key).unwrap();
                mac.input(&message);

                mac.verify(&self.mac).is_ok()
        }

        pub fn decrypt_raw(&self, key: &[u8], mac: &[u8]) -> Result<Vec<u8>, CipherError> {
                if self.type_ != 2 {
                        return Err(CipherError::InvalidKeyType);
                }

                if !self.is_valid_mac(mac) {
                        return Err(CipherError::InvalidMac);
                }

                // Currently only one cipher (type 2) is supported/used by bitwarden:
                //   pbkdf2/aes-cbc-256/hmac-sha256

                Cbc::<Aes256, Pkcs7>::new_var(key, &self.iv)
                        .map_err(|_| CipherError::InvalidKeyLength)?
                        .decrypt_vec(&self.ct)
                        .map_err(|_| CipherError::BlockModeError)
        }

        pub fn decrypt(&self, cipher: &CipherSuite) -> Option<String> {
                self.decrypt_raw(cipher.decrypt_key.as_ref()?, &cipher.mac_key)
                        .ok()
                        .and_then(|s| String::from_utf8(s).ok())
        }
}

struct CipherStringVisitor;

impl<'de> Visitor<'de> for CipherStringVisitor {
        type Value = CipherString;

        fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                fmt.write_str("valid cipher string")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<CipherString, E> {
                CipherString::from_str(value)
                        .ok_or(E::custom("invalid cipher string"))
        }
}

impl<'de> Deserialize<'de> for CipherString {
        fn deserialize<D>(deserializer: D) -> Result<CipherString, D::Error>
                where D: Deserializer<'de>
        {
                deserializer.deserialize_str(CipherStringVisitor)
        }
}

impl Serialize for CipherString {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where S: Serializer
        {

                serializer.serialize_str(&self.as_str())
        }
}
