/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::errors::*;
use crate::DeviceResponse;
use ece::{
    Aes128GcmEceWebPushImpl, LocalKeyPair, LocalKeyPairImpl, RemoteKeyPairImpl, WebPushParams,
};
use hex;
use ring::rand::SecureRandom;
use serde_derive::*;
use sync15::KeyBundle;

pub const COMMAND_NAME: &'static str = "https://identity.mozilla.com/cmd/open-uri";

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedSendTabPayload {
    /// URL Safe Base 64 encrypted send-tab payload.
    encrypted: String,
}

impl EncryptedSendTabPayload {
    pub fn decrypt(self, keys: &PrivateSendTabKeys) -> Result<SendTabPayload> {
        let encrypted = base64::decode_config(&self.encrypted, base64::URL_SAFE_NO_PAD)?;
        let private_key = LocalKeyPairImpl::new(&keys.private_key)?;
        let decrypted =
            Aes128GcmEceWebPushImpl::decrypt(&private_key, &keys.auth_secret, &encrypted)?;
        Ok(serde_json::from_slice(&decrypted)?)
    }
}

#[derive(Serialize, Deserialize)]
pub struct SendTabPayload {
    entries: Vec<TabData>,
}

impl SendTabPayload {
    pub fn single_tab(title: &str, url: &str) -> Self {
        SendTabPayload {
            entries: vec![TabData {
                title: title.to_string(),
                url: url.to_string(),
            }],
        }
    }
    fn encrypt(&self, keys: PublicSendTabKeys) -> Result<EncryptedSendTabPayload> {
        let bytes = serde_json::to_vec(&self)?;
        let public_key = base64::decode_config(&keys.public_key, base64::URL_SAFE_NO_PAD)?;
        let public_key = RemoteKeyPairImpl::from_raw(&public_key);
        let auth_secret = base64::decode_config(&keys.auth_secret, base64::URL_SAFE_NO_PAD)?;
        let encrypted = Aes128GcmEceWebPushImpl::encrypt(
            &public_key,
            &auth_secret,
            &bytes,
            WebPushParams::default(),
        )?;
        let encrypted = base64::encode_config(&encrypted, base64::URL_SAFE_NO_PAD);
        Ok(EncryptedSendTabPayload { encrypted })
    }
}

#[derive(Serialize, Deserialize)]
pub struct TabData {
    title: String,
    url: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PrivateSendTabKeys {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    auth_secret: Vec<u8>,
}

impl PrivateSendTabKeys {
    pub fn from_random(rng: &SecureRandom) -> Result<Self> {
        let key_pair = LocalKeyPairImpl::generate_random()?;
        let private_key = key_pair.to_raw();
        let public_key = key_pair.pub_as_raw()?;
        let mut auth_secret = vec![0u8; 16];
        rng.fill(&mut auth_secret)
            .map_err(|_| ErrorKind::RngFailure)?;
        Ok(Self {
            public_key,
            private_key,
            auth_secret,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct SendTabKeysPayload {
    /// Hex encoded kid (kXCS).
    kid: String,
    /// Base 64 encoded IV.
    #[serde(rename = "IV")]
    iv: String,
    /// Hex encoded hmac.
    hmac: String,
    /// Base 64 encoded ciphertext.
    ciphertext: String,
}

impl SendTabKeysPayload {
    fn decrypt(self, ksync: &[u8], kxcs: &[u8]) -> Result<PublicSendTabKeys> {
        // Most of the code here is copied from `EncryptedBso::decrypt`:
        // we can't use that method as-it because `EncryptedBso` forces
        // a payload id to be specified, which in turns make the Firefox
        // Desktop commands implementation angry.
        if hex::decode(self.kid)? != kxcs {
            return Err(ErrorKind::MismatchedKeys.into());
        }
        let key = KeyBundle::from_ksync_bytes(ksync)?;
        if !key.verify_hmac_string(&self.hmac, &self.ciphertext)? {
            return Err(ErrorKind::HmacMismatch.into());
        }
        let iv = base64::decode(&self.iv)?;
        let ciphertext = base64::decode(&self.ciphertext)?;
        let cleartext = key.decrypt(&ciphertext, &iv)?;
        Ok(serde_json::from_str(&cleartext)?)
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicSendTabKeys {
    /// URL Safe Base 64 encoded push public key.
    #[serde(rename = "publicKey")]
    public_key: String,
    /// URL Safe Base 64 encoded auth secret.
    #[serde(rename = "authSecret")]
    auth_secret: String,
}

impl PublicSendTabKeys {
    fn encrypt(&self, ksync: &[u8], kxcs: &[u8]) -> Result<SendTabKeysPayload> {
        // Most of the code here is copied from `CleartextBso::encrypt`:
        // we can't use that method as-it because `CleartextBso` forces
        // a payload id to be specified, which in turns make the Firefox
        // Desktop commands implementation angry.
        let key = KeyBundle::from_ksync_bytes(ksync)?;
        let cleartext = serde_json::to_vec(&self)?;
        let (enc_bytes, iv) = key.encrypt_bytes_rand_iv(&cleartext)?;
        let iv_base64 = base64::encode(&iv);
        let enc_base64 = base64::encode(&enc_bytes);
        let hmac = key.hmac_string(enc_base64.as_bytes())?;
        Ok(SendTabKeysPayload {
            kid: hex::encode(kxcs),
            iv: iv_base64,
            hmac,
            ciphertext: enc_base64,
        })
    }
    pub fn as_command_data(&self, kek: &KeyEncryptingKey) -> Result<String> {
        let (ksync, kxcs) = match kek {
            KeyEncryptingKey::SyncKeys(ksync, kxcs) => (ksync, kxcs),
        };
        let encrypted_public_keys = self.encrypt(&ksync, &kxcs)?;
        Ok(serde_json::to_string(&encrypted_public_keys)?)
    }
}

impl From<PrivateSendTabKeys> for PublicSendTabKeys {
    fn from(internal: PrivateSendTabKeys) -> Self {
        Self {
            public_key: base64::encode_config(&internal.public_key, base64::URL_SAFE_NO_PAD),
            auth_secret: base64::encode_config(&internal.auth_secret, base64::URL_SAFE_NO_PAD),
        }
    }
}

pub enum KeyEncryptingKey {
    /// <ksync, kxcs>
    SyncKeys(Vec<u8>, Vec<u8>),
}

pub fn build_send_command(
    kek: &KeyEncryptingKey,
    target: &DeviceResponse,
    send_tab_payload: &SendTabPayload,
) -> Result<serde_json::Value> {
    let (ksync, kxcs) = match kek {
        KeyEncryptingKey::SyncKeys(ksync, kxcs) => (ksync, kxcs),
    };
    let command = target
        .available_commands
        .get(COMMAND_NAME)
        .ok_or_else(|| ErrorKind::UnsupportedCommand("Send Tab"))?;
    let bundle: SendTabKeysPayload = serde_json::from_str(command)?;
    let public_keys = bundle.decrypt(&ksync, &kxcs)?;
    let encrypted_payload = send_tab_payload.encrypt(public_keys)?;
    Ok(serde_json::to_value(&encrypted_payload)?)
}
