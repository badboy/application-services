/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Handles cryptographic functions.
 * Depending on platform, this may call various libraries or have other dependencies.
 *
 * This uses prime256v1 EC encryption that should come from internal crypto calls. The "application-services"
 * module compiles openssl, however, so might be enough to tie into that.
 */
use base64;
use std::clone;
use std::cmp;
use std::fmt;

use ece::{
    Aes128GcmEceWebPushImpl, AesGcmEceWebPushImpl, AesGcmEncryptedBlock, LocalKeyPair,
    LocalKeyPairImpl,
};
use openssl::rand::rand_bytes;
mod error;

const SER_AUTH_LENGTH: usize = 16;

/* build the key off of the OpenSSL key implementation.
 * Much of this is taken from rust_ece/crypto/openssl/lib.rs
 */

pub struct Key {
    /// A "Key" contains the cryptographic Web Push Key data.
    private: LocalKeyPairImpl,
    pub public: Vec<u8>,
    pub auth: Vec<u8>,
}

impl clone::Clone for Key {
    fn clone(&self) -> Key {
        Key {
            private: LocalKeyPairImpl::new(&self.private.to_raw()).unwrap(),
            public: self.public.clone(),
            auth: self.auth.clone(),
        }
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{private: {:?}, public: {:?}, auth: {:?}}}",
            base64::encode_config(&self.private.to_raw(), base64::URL_SAFE_NO_PAD),
            base64::encode_config(&self.public, base64::URL_SAFE_NO_PAD),
            base64::encode_config(&self.auth, base64::URL_SAFE_NO_PAD)
        )
    }
}

impl cmp::PartialEq for Key {
    fn eq(&self, other: &Key) -> bool {
        self.private.to_raw() == other.private.to_raw()
            && self.public == other.public
            && self.auth == other.auth
    }
}

impl Key {
    /*
    re-instantiating the private key from a vector looks to be overly complex.
    */

    //TODO: Make these real serde functions
    /// Serialize a Key's private and auth information into a recoverable byte array.
    pub fn serialize(&self) -> error::Result<Vec<u8>> {
        // Unfortunately, EcKey::private_key_from_der(original.private_key_to_der())
        // produces a Key, but reading the public_key().to_bytes() fails with an
        // openssl "incompatible objects" error.
        // This does not bode well for doing actual functions with it.
        // So for now, hand serializing the Key.
        let mut result: Vec<u8> = Vec::new();
        let mut keypv = self.private.to_raw();
        let pvlen = keypv.len();
        //let mut key_bytes = self.public;
        //let pblen = key_bytes.len();
        // specify the version
        result.push(1);
        result.push(self.auth.len() as u8);
        result.append(&mut self.auth.clone());
        result.push(pvlen as u8);
        result.append(&mut keypv);
        //result.push(pblen as u8);
        //result.append(&mut key_bytes);
        Ok(result)
    }

    /// Recover a byte array into a Key structure.
    pub fn deserialize(raw: Vec<u8>) -> error::Result<Key> {
        if raw[0] != 1 {
            return Err(error::ErrorKind::GeneralError(
                "Unknown Key Serialization version".to_owned(),
            )
            .into());
        }
        let mut start = 1;
        // TODO: Make the following a macro call.
        // fetch out the auth
        let mut l = raw[start] as usize;
        start += 1;
        let mut end = start + l;
        let auth = &raw[start..end];
        // get the private key
        l = raw[end] as usize;
        start = end + 1;
        end = start + l;
        // generate the private key from the components
        let private = match LocalKeyPairImpl::new(&raw[start..end]) {
            Ok(p) => p,
            Err(e) => {
                return Err(error::ErrorKind::GeneralError(format!(
                    "Could not reinstate key {:?}",
                    e
                ))
                .into());
            }
        };
        let pubkey = match private.pub_as_raw() {
            Ok(v) => v,
            Err(e) => {
                return Err(error::ErrorKind::GeneralError(format!(
                    "Could not dump public key: {:?}",
                    e
                ))
                .into());
            }
        };
        Ok(Key {
            private: private,
            public: pubkey,
            auth: auth.to_vec(),
        })
    }
}

pub trait Cryptography {
    /// generate a new local EC p256 key
    fn generate_key() -> error::Result<Key>;

    /// General decrypt function. Calls to decrypt_aesgcm or decrypt_aes128gcm as needed.
    // (sigh, can't use notifier::Notification because of circular dependencies.)
    fn decrypt(
        key: &Key,
        body: Vec<u8>,
        encoding: &str,
        salt: Option<Vec<u8>>,
        dh: Option<Vec<u8>>,
    ) -> error::Result<Vec<u8>>;
    // IIUC: objects created on one side of FFI can't be freed on the other side, so we have to use references (or clone)

    /// Decrypt the obsolete "aesgcm" format (which is still used by a number of providers)
    fn decrypt_aesgcm(
        key: &Key,
        content: &[u8],
        salt: Option<Vec<u8>>,
        crypto_key: Option<Vec<u8>>,
    ) -> error::Result<Vec<u8>>;

    /// Decrypt the RFC 8188 format.
    fn decrypt_aes128gcm(key: &Key, content: &[u8]) -> error::Result<Vec<u8>>;
}

pub struct Crypto;

pub fn get_bytes(size: usize) -> error::Result<Vec<u8>> {
    let mut bytes = vec![0u8; size];
    rand_bytes(bytes.as_mut_slice())?;
    Ok(bytes)
}

impl Cryptography for Crypto {
    /// Generate a new cryptographic Key
    fn generate_key() -> error::Result<Key> {
        let key = match LocalKeyPairImpl::generate_random() {
            Ok(k) => k,
            Err(e) => {
                return Err(error::ErrorKind::GeneralError(format!(
                    "Could not generate key: {:?}",
                    e
                ))
                .into());
            }
        };
        let auth = get_bytes(SER_AUTH_LENGTH)?;
        let pubkey = match key.pub_as_raw() {
            Ok(v) => v,
            Err(e) => {
                return Err(error::ErrorKind::GeneralError(format!(
                    "Could not dump public key: {:?}",
                    e
                ))
                .into());
            }
        };
        Ok(Key {
            private: key,
            public: pubkey,
            auth,
        })
    }

    /// Decrypt the incoming webpush message based on the content-encoding
    fn decrypt(
        key: &Key,
        body: Vec<u8>,
        encoding: &str,
        salt: Option<Vec<u8>>,
        dh: Option<Vec<u8>>,
    ) -> error::Result<Vec<u8>> {
        // convert the private key into something useful.
        match encoding.to_lowercase().as_str() {
            "aesgcm" => Self::decrypt_aesgcm(&key, &body, salt, dh),
            "aes128gcm" => Self::decrypt_aes128gcm(&key, &body),
            _ => Err(error::ErrorKind::GeneralError("Unknown Content Encoding".to_string()).into()),
        }
    }

    // IIUC: objects created on one side of FFI can't be freed on the other side, so we have to use references (or clone)
    fn decrypt_aesgcm(
        key: &Key,
        content: &[u8],
        salt: Option<Vec<u8>>,
        crypto_key: Option<Vec<u8>>,
    ) -> error::Result<Vec<u8>> {
        let dh = match crypto_key {
            Some(v) => v,
            None => {
                return Err(error::ErrorKind::GeneralError("Missing public key".to_string()).into());
            }
        };
        let salt = match salt {
            Some(v) => v,
            None => return Err(error::ErrorKind::GeneralError("Missing salt".to_string()).into()),
        };
        let block = match AesGcmEncryptedBlock::new(&dh, &salt, 4096, content.to_vec()) {
            Ok(b) => b,
            Err(e) => {
                return Err(error::ErrorKind::GeneralError(format!(
                    "Could not create block: {}",
                    e
                ))
                .into());
            }
        };
        match AesGcmEceWebPushImpl::decrypt(&key.private, &key.auth, &block) {
            Ok(result) => Ok(result),
            Err(e) => Err(error::ErrorKind::OpenSSLError(format!("{:?}", e)).into()),
        }
    }

    fn decrypt_aes128gcm(key: &Key, content: &[u8]) -> error::Result<Vec<u8>> {
        match Aes128GcmEceWebPushImpl::decrypt(&key.private, &key.auth, &content) {
            Ok(result) => Ok(result),
            Err(e) => Err(error::ErrorKind::OpenSSLError(format!("{:?}", e)).into()),
        }
    }
}

#[cfg(test)]
mod crypto_tests {
    use super::*;
    use openssl::ec::EcKey;

    use base64;

    use error;

    const PLAINTEXT:&str = "Amidst the mists and coldest frosts I thrust my fists against the\nposts and still demand to see the ghosts.\n\n";

    fn decrypter(
        ciphertext: Vec<u8>,
        encoding: &str,
        salt: Option<Vec<u8>>,
        dh: Option<Vec<u8>>,
    ) -> error::Result<Vec<u8>> {
        // The following come from internal storage;
        // More than likely, this will be stored either as an encoded or raw DER.
        let priv_key_der_raw = "MHcCAQEEIKiZMcVhlVccuwSr62jWN4YPBrPmPKotJUWl1id0d2ifoAoGCCqGSM49AwEHoUQDQgAEFwl1-zUa0zLKYVO23LqUgZZEVesS0k_jQN_SA69ENHgPwIpWCoTq-VhHu0JiSwhF0oPUzEM-FBWYoufO6J97nQ";
        // The auth token
        let auth_raw = "LsuUOBKVQRY6-l7_Ajo-Ag";
        // This would be the public key sent to the subscription service.
        let pub_key_raw = "BBcJdfs1GtMyymFTtty6lIGWRFXrEtJP40Df0gOvRDR4D8CKVgqE6vlYR7tCYksIRdKD1MxDPhQVmKLnzuife50";

        // create the private key we need.
        let private = EcKey::private_key_from_der(
            &base64::decode_config(priv_key_der_raw, base64::URL_SAFE_NO_PAD).unwrap(),
        )
        .unwrap();
        let auth = base64::decode_config(auth_raw, base64::URL_SAFE_NO_PAD).unwrap();
        /*
        // The externally generated data was created using pywebpush.
        // To generate a private key:
        let group = EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1).unwrap();
        let private_key = EcKey::generate(&group).unwrap();
        let mut context = BigNumContext::new().unwrap();

        // Dump the DER for "storage"
        println!("DER: {:?}", base64::encode_config(&private_key.private_key_to_der().unwrap(), base64::URL_SAFE_NO_PAD));
        let public_key = private_key.public_key().to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut context).unwrap();
        println!("PUB: {:?}", base64::encode_config(&public_key, base64::URL_SAFE_NO_PAD));
        */
        let key = Key {
            private: private.into(),
            public: base64::decode_config(pub_key_raw, base64::URL_SAFE_NO_PAD).unwrap(),
            auth,
        };

        Crypto::decrypt(&key, ciphertext, encoding, salt, dh)
    }

    #[test]
    fn test_decrypt_aesgcm() {
        // The following comes from the delivered message body
        let ciphertext = base64::decode_config(
            "BNKu5uTFhjyS-06eECU9-6O61int3Rr7ARbm-xPhFuyDO5sfxVs-HywGaVonvzkarvfvXE9IRT_YNA81Og2uSqDasdMuwqm1zd0O3f7049IkQep3RJ2pEZTy5DqvI7kwMLDLzea9nroq3EMH5hYhvQtQgtKXeWieEL_3yVDQVg",
            base64::URL_SAFE_NO_PAD).unwrap();
        // and now from the header values
        let dh = base64::decode_config(
            "BMOebOMWSRisAhWpRK9ZPszJC8BL9MiWvLZBoBU6pG6Kh6vUFSW4BHFMh0b83xCg3_7IgfQZXwmVuyu27vwiv5c",
            base64::URL_SAFE_NO_PAD).unwrap();
        let salt =
            base64::decode_config("tSf2qu43C9BD0zkvRW5eUg", base64::URL_SAFE_NO_PAD).unwrap();

        // and this is what it should be.

        let decrypted = decrypter(ciphertext, "aesgcm", Some(salt), Some(dh)).unwrap();

        // println!("decrypted: {:?}\n plaintext:{:?} ", String::from_utf8(decrypted).unwrap(), plaintext);
        assert!(String::from_utf8(decrypted).unwrap() == PLAINTEXT.to_string());
    }

    #[test]
    fn test_fail_decrypt_aesgcm() {
        let ciphertext = base64::decode_config(
            "BNKu5uTFhjyS-06eECU9-6O61int3Rr7ARbm-xPhFuyDO5sfxVs-HywGaVonvzkarvfvXE9IRT_YNA81Og2uSqDasdMuwqm1zd0O3f7049IkQep3RJ2pEZTy5DqvI7kwMLDLzea9nroq3EMH5hYhvQtQgtKXeWieEL_3yVDQVg",
            base64::URL_SAFE_NO_PAD).unwrap();
        let dh = base64::decode_config(
            "BMOebOMWSRisAhWpRK9ZPszJC8BL9MiWvLZBoBU6pG6Kh6vUFSW4BHFMh0b83xCg3_7IgfQZXwmVuyu27vwiv5c",
            base64::URL_SAFE_NO_PAD).unwrap();
        let salt = base64::decode_config("SomeInvalidSaltValue", base64::URL_SAFE_NO_PAD).unwrap();

        decrypter(ciphertext, "aesgcm", Some(salt), Some(dh))
            .expect_err("Failed to abort, bad salt");
    }

    #[test]
    fn test_decrypt_aes128gcm() {
        let ciphertext = base64::decode_config(
            "Ek7iQgliMqS9kjFoiVOqRgAAEABBBFirfBtF6XTeHVPABFDveb1iu7uO1XVA_MYJeAo-4ih8WYUsXSTIYmkKMv5_UB3tZuQI7BQ2EVpYYQfvOCrWZVMRL8fJCuB5wVXcoRoTaFJwTlJ5hnw6IMSiaMqGVlc8drX7Hzy-ugzzAKRhGPV2x-gdsp58DZh9Ww5vHpHyT1xwVkXzx3KTyeBZu4gl_zR0Q00li17g0xGsE6Dg3xlkKEmaalgyUyObl6_a8RA6Ko1Rc6RhAy2jdyY1LQbBUnA",
            base64::URL_SAFE_NO_PAD).unwrap();

        let decrypted = decrypter(ciphertext, "aes128gcm", None, None).unwrap();

        assert!(String::from_utf8(decrypted).unwrap() == PLAINTEXT.to_string());
    }

    #[test]
    fn test_key_serde() {
        let key = Crypto::generate_key().unwrap();
        let key_dump = key.serialize().unwrap();
        let key2 = Key::deserialize(key_dump).unwrap();
        assert!(key.private.to_raw() == key2.private.to_raw());
        assert!(key.public == key2.public);
        assert!(key.auth == key2.auth);
        assert!(key == key2);
    }

    #[test]
    fn test_key_debug() {
        let key = Crypto::generate_key().unwrap();

        println!("Key: {:?}", key);
    }
}
