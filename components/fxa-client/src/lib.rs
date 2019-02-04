/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::{
    commands::send_tab::{
        self, EncryptedSendTabPayload, PrivateSendTabKeys, PublicSendTabKeys, SendTabPayload,
    },
    errors::*,
    http_client::{
        Client, CommandData, DeviceUpdateRequest, DeviceUpdateRequestBuilder, PendingCommand,
        PushSubscription,
    },
    scoped_keys::ScopedKeysFlow,
    util::{now, random_base64_url_string},
};
pub use crate::{
    config::Config,
    http_client::{DeviceResponse, DeviceType, ProfileResponse as Profile},
};
use lazy_static::lazy_static;
use ring::{digest, rand::SystemRandom};
use serde_derive::*;
use std::{
    collections::{HashMap, HashSet},
    iter::FromIterator,
    panic::RefUnwindSafe,
    time::{SystemTime, UNIX_EPOCH},
};
use url::Url;
#[cfg(feature = "browserid")]
use {
    crate::{
        http_client::browser_id::jwt_utils,
        login_sm::{LoginState::*, *},
    },
    std::mem,
};

mod commands;
mod config;
pub mod errors;
#[cfg(feature = "ffi")]
pub mod ffi;
mod http_client;
#[cfg(feature = "browserid")]
mod login_sm;
mod scoped_keys;
pub mod scopes;
mod state_persistence;
mod util;

// If a cached token has less than `OAUTH_MIN_TIME_LEFT` seconds left to live,
// it will be considered already expired.
const OAUTH_MIN_TIME_LEFT: u64 = 60;
// A cached profile response is considered fresh for `PROFILE_FRESHNESS_THRESHOLD` ms.
const PROFILE_FRESHNESS_THRESHOLD: u64 = 120000; // 2 minutes

lazy_static! {
    static ref RNG: SystemRandom = SystemRandom::new();
}

// If this structure is modified, please
// check whether or not a migration needs to be done
// as these fields are persisted as a JSON string
// (see `state_persistence.rs`).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StateV2 {
    config: Config,
    #[cfg(feature = "browserid")]
    login_state: LoginState,
    refresh_token: Option<RefreshToken>,
    scoped_keys: HashMap<String, ScopedKey>,
    last_handled_command: Option<u64>,
    // Remove serde(default) once we are V3.
    #[serde(default)]
    commands_data: HashMap<String, String>,
}

#[cfg(feature = "browserid")]
#[derive(Deserialize)]
pub struct WebChannelResponse {
    uid: String,
    email: String,
    verified: bool,
    #[serde(rename = "sessionToken")]
    session_token: String,
    #[serde(rename = "keyFetchToken")]
    key_fetch_token: String,
    #[serde(rename = "unwrapBKey")]
    unwrap_kb: String,
}

#[cfg(feature = "browserid")]
impl WebChannelResponse {
    pub fn from_json(json: &str) -> Result<WebChannelResponse> {
        serde_json::from_str(json).map_err(|e| e.into())
    }
}

struct CachedResponse<T> {
    response: T,
    cached_at: u64,
    etag: String,
}

pub struct FirefoxAccount {
    state: StateV2,
    access_token_cache: HashMap<String, AccessTokenInfo>,
    flow_store: HashMap<String, OAuthFlow>,
    persist_callback: Option<PersistCallback>,
    profile_cache: Option<CachedResponse<Profile>>,
}

pub struct SyncKeys(pub String, pub String);

pub struct PersistCallback {
    callback_fn: Box<Fn(&str) + Send + RefUnwindSafe>,
}

impl PersistCallback {
    pub fn new<F>(callback_fn: F) -> PersistCallback
    where
        F: Fn(&str) + 'static + Send + RefUnwindSafe,
    {
        PersistCallback {
            callback_fn: Box::new(callback_fn),
        }
    }

    pub fn call(&self, json: &str) {
        (*self.callback_fn)(json);
    }
}

impl FirefoxAccount {
    fn from_state(state: StateV2) -> Self {
        Self {
            state,
            access_token_cache: HashMap::new(),
            flow_store: HashMap::new(),
            persist_callback: None,
            profile_cache: None,
        }
    }

    pub fn with_config(config: Config) -> Self {
        Self::from_state(StateV2 {
            config,
            #[cfg(feature = "browserid")]
            login_state: Unknown,
            refresh_token: None,
            scoped_keys: HashMap::new(),
            last_handled_command: None,
            commands_data: HashMap::new(),
        })
    }

    pub fn new(content_url: &str, client_id: &str, redirect_uri: &str) -> Self {
        let config = Config::new(content_url, client_id, redirect_uri);
        Self::with_config(config)
    }

    // Initialize state from Firefox Accounts credentials obtained using the
    // web flow.
    #[cfg(feature = "browserid")]
    pub fn from_credentials(
        content_url: &str,
        client_id: &str,
        redirect_uri: &str,
        credentials: WebChannelResponse,
    ) -> Result<Self> {
        let config = Config::new(content_url, client_id, redirect_uri);
        let session_token = hex::decode(credentials.session_token)?;
        let key_fetch_token = hex::decode(credentials.key_fetch_token)?;
        let unwrap_kb = hex::decode(credentials.unwrap_kb)?;
        let login_state_data = ReadyForKeysState::new(
            credentials.uid,
            credentials.email,
            session_token,
            key_fetch_token,
            unwrap_kb,
        );
        let login_state = if credentials.verified {
            EngagedAfterVerified(login_state_data)
        } else {
            EngagedBeforeVerified(login_state_data)
        };

        Ok(Self::from_state(StateV2 {
            config,
            login_state,
            refresh_token: None,
            scoped_keys: HashMap::new(),
            last_handled_command: None,
            commands_data: HashMap::new(),
        }))
    }

    pub fn from_json(data: &str) -> Result<Self> {
        let state = state_persistence::state_from_json(data)?;
        Ok(Self::from_state(state))
    }

    pub fn to_json(&self) -> Result<String> {
        state_persistence::state_to_json(&self.state)
    }

    #[cfg(feature = "browserid")]
    fn to_married(&mut self) -> Option<&MarriedState> {
        self.advance();
        match self.state.login_state {
            Married(ref married) => Some(married),
            _ => None,
        }
    }

    #[cfg(feature = "browserid")]
    pub fn advance(&mut self) {
        let client = Client::new(&self.state.config);
        let state_machine = LoginStateMachine::new(client);
        let state = mem::replace(&mut self.state.login_state, Unknown);
        self.state.login_state = state_machine.advance(state);
    }

    pub fn get_access_token(&mut self, scope: &str) -> Result<AccessTokenInfo> {
        if scope.contains(" ") {
            return Err(ErrorKind::MultipleScopesRequested.into());
        }
        if let Some(oauth_info) = self.access_token_cache.get(scope) {
            if oauth_info.expires_at > util::now_secs() + OAUTH_MIN_TIME_LEFT {
                return Ok(oauth_info.clone());
            }
        }
        let client = Client::new(&self.state.config);
        let resp = match self.state.refresh_token {
            Some(ref refresh_token) => match refresh_token.scopes.contains(scope) {
                true => client.oauth_token_with_refresh_token(&refresh_token.token, &[scope])?,
                false => return Err(ErrorKind::NoCachedToken(scope.to_string()).into()),
            },
            None => {
                #[cfg(feature = "browserid")]
                {
                    match Self::session_token_from_state(&self.state.login_state) {
                        Some(session_token) => {
                            client.oauth_token_with_session_token(session_token, &[scope])?
                        }
                        None => return Err(ErrorKind::NoCachedToken(scope.to_string()).into()),
                    }
                }
                #[cfg(not(feature = "browserid"))]
                {
                    return Err(ErrorKind::NoCachedToken(scope.to_string()).into());
                }
            }
        };
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ErrorKind::IllegalState("Current date before Unix Epoch.".to_string()))?;
        let expires_at = since_epoch.as_secs() + resp.expires_in;
        let token_info = AccessTokenInfo {
            scope: resp.scope,
            token: resp.access_token,
            key: self.state.scoped_keys.get(scope).cloned(),
            expires_at,
        };
        self.access_token_cache
            .insert(scope.to_string(), token_info.clone());
        Ok(token_info)
    }

    pub fn begin_pairing_flow(&mut self, pairing_url: &str, scopes: &[&str]) -> Result<String> {
        let mut url = self.state.config.content_url_path("/pair/supp")?;
        let pairing_url = Url::parse(pairing_url)?;
        if url.host_str() != pairing_url.host_str() {
            return Err(ErrorKind::OriginMismatch.into());
        }
        url.set_fragment(pairing_url.fragment());
        self.oauth_flow(url, scopes, true)
    }

    pub fn begin_oauth_flow(&mut self, scopes: &[&str], wants_keys: bool) -> Result<String> {
        let mut url = self.state.config.authorization_endpoint()?;
        url.query_pairs_mut()
            .append_pair("action", "email")
            .append_pair("response_type", "code");
        let scopes: Vec<String> = match self.state.refresh_token {
            Some(ref refresh_token) => {
                // Union of the already held scopes and the one requested.
                let mut all_scopes: Vec<String> = vec![];
                all_scopes.extend(scopes.iter().map(|s| s.to_string()));
                let existing_scopes = refresh_token.scopes.clone();
                all_scopes.extend(existing_scopes);
                HashSet::<String>::from_iter(all_scopes)
                    .into_iter()
                    .collect()
            }
            None => scopes.iter().map(|s| s.to_string()).collect(),
        };
        let scopes: Vec<&str> = scopes.iter().map(<_>::as_ref).collect();
        self.oauth_flow(url, &scopes, wants_keys)
    }

    fn oauth_flow(&mut self, mut url: Url, scopes: &[&str], wants_keys: bool) -> Result<String> {
        let state = random_base64_url_string(&*RNG, 16)?;
        let code_verifier = random_base64_url_string(&*RNG, 43)?;
        let code_challenge = digest::digest(&digest::SHA256, &code_verifier.as_bytes());
        let code_challenge = base64::encode_config(&code_challenge, base64::URL_SAFE_NO_PAD);
        url.query_pairs_mut()
            .append_pair("client_id", &self.state.config.client_id)
            .append_pair("redirect_uri", &self.state.config.redirect_uri)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("code_challenge_method", "S256")
            .append_pair("code_challenge", &code_challenge)
            .append_pair("access_type", "offline");
        let scoped_keys_flow = match wants_keys {
            true => {
                let flow = ScopedKeysFlow::with_random_key(&*RNG)?;
                let jwk_json = flow.generate_keys_jwk()?;
                let keys_jwk = base64::encode_config(&jwk_json, base64::URL_SAFE_NO_PAD);
                url.query_pairs_mut().append_pair("keys_jwk", &keys_jwk);
                Some(flow)
            }
            false => None,
        };
        self.flow_store.insert(
            state.clone(), // Since state is supposed to be unique, we use it to key our flows.
            OAuthFlow {
                scoped_keys_flow,
                code_verifier,
            },
        );
        Ok(url.to_string())
    }

    pub fn complete_oauth_flow(&mut self, code: &str, state: &str) -> Result<()> {
        let oauth_flow = match self.flow_store.remove(state) {
            Some(oauth_flow) => oauth_flow,
            None => return Err(ErrorKind::UnknownOAuthState.into()),
        };
        let client = Client::new(&self.state.config);
        let resp = client.oauth_token_with_code(&code, &oauth_flow.code_verifier)?;
        // This assumes that if the server returns keys_jwe, the jwk argument is Some.
        match resp.keys_jwe {
            Some(ref jwe) => {
                let scoped_keys_flow = match oauth_flow.scoped_keys_flow {
                    Some(flow) => flow,
                    None => {
                        return Err(ErrorKind::UnrecoverableServerError(
                            "Got a JWE without sending a JWK.",
                        )
                        .into());
                    }
                };
                let decrypted_keys = scoped_keys_flow.decrypt_keys_jwe(jwe)?;
                let scoped_keys: serde_json::Map<String, serde_json::Value> =
                    serde_json::from_str(&decrypted_keys)?;
                for (scope, key) in scoped_keys {
                    let scoped_key: ScopedKey = serde_json::from_value(key)?;
                    self.state.scoped_keys.insert(scope, scoped_key);
                }
            }
            None => {
                if oauth_flow.scoped_keys_flow.is_some() {
                    log::error!("Expected to get keys back alongside the token but the server didn't send them.");
                    return Err(ErrorKind::TokenWithoutKeys.into());
                }
            }
        };
        let client = Client::new(&self.state.config);
        // We are only interested in the refresh token at this time because we
        // don't want to return an over-scoped access token.
        // Let's be good citizens and destroy this access token.
        if let Err(err) = client.destroy_oauth_token(&resp.access_token) {
            log::warn!("Access token destruction failure: {:?}", err);
        }
        let refresh_token = match resp.refresh_token {
            Some(ref refresh_token) => refresh_token.clone(),
            None => return Err(ErrorKind::RefreshTokenNotPresent.into()),
        };
        // In order to keep 1 and only 1 refresh token alive per client instance,
        // we also destroy the existing refresh token.
        if let Some(ref old_refresh_token) = self.state.refresh_token {
            if let Err(err) = client.destroy_oauth_token(&old_refresh_token.token) {
                log::warn!("Refresh token destruction failure: {:?}", err);
            }
        }
        self.state.refresh_token = Some(RefreshToken {
            token: refresh_token,
            scopes: HashSet::from_iter(resp.scope.split(' ').map(|s| s.to_string())),
        });
        self.maybe_call_persist_callback();
        Ok(())
    }

    #[cfg(feature = "browserid")]
    fn session_token_from_state(state: &LoginState) -> Option<&[u8]> {
        match state {
            &Separated(_) | Unknown => None,
            // Despite all these states implementing the same trait we can't treat
            // them in a single arm, so this will do for now :/
            &EngagedBeforeVerified(ref state) | &EngagedAfterVerified(ref state) => {
                Some(state.session_token())
            }
            &CohabitingBeforeKeyPair(ref state) => Some(state.session_token()),
            &CohabitingAfterKeyPair(ref state) => Some(state.session_token()),
            &Married(ref state) => Some(state.session_token()),
        }
    }

    #[cfg(feature = "browserid")]
    pub fn generate_assertion(&mut self, audience: &str) -> Result<String> {
        let married = match self.to_married() {
            Some(married) => married,
            None => return Err(ErrorKind::NotMarried.into()),
        };
        let key_pair = married.key_pair();
        let certificate = married.certificate();
        Ok(jwt_utils::create_assertion(
            key_pair,
            &certificate,
            audience,
        )?)
    }

    pub fn get_profile(&mut self, ignore_cache: bool) -> Result<Profile> {
        let profile_access_token = self.get_access_token(scopes::PROFILE)?.token;
        let mut etag = None;
        if let Some(ref cached_profile) = self.profile_cache {
            if !ignore_cache && now() < cached_profile.cached_at + PROFILE_FRESHNESS_THRESHOLD {
                return Ok(cached_profile.response.clone());
            }
            etag = Some(cached_profile.etag.clone());
        }
        let client = Client::new(&self.state.config);
        match client.profile(&profile_access_token, etag)? {
            Some(response_and_etag) => {
                if let Some(etag) = response_and_etag.etag {
                    self.profile_cache = Some(CachedResponse {
                        response: response_and_etag.response.clone(),
                        cached_at: now(),
                        etag,
                    });
                }
                Ok(response_and_etag.response)
            }
            None => match self.profile_cache {
                Some(ref cached_profile) => Ok(cached_profile.response.clone()),
                None => Err(ErrorKind::UnrecoverableServerError(
                    "Got a 304 without having sent an eTag.",
                )
                .into()),
            },
        }
    }

    #[cfg(feature = "browserid")]
    pub fn get_sync_keys(&mut self) -> Result<SyncKeys> {
        let married = match self.to_married() {
            Some(married) => married,
            None => return Err(ErrorKind::NotMarried.into()),
        };
        let sync_key = hex::encode(married.sync_key());
        Ok(SyncKeys(sync_key, married.xcs().to_string()))
    }

    pub fn get_token_server_endpoint_url(&self) -> Result<Url> {
        self.state.config.token_server_endpoint_url()
    }

    pub fn get_connection_success_url(&self) -> Result<Url> {
        let mut url = self
            .state
            .config
            .content_url_path("connect_another_device")?;
        url.query_pairs_mut()
            .append_pair("showSuccessMessage", "true");
        Ok(url)
    }

    pub fn get_devices(&mut self) -> Result<Vec<DeviceResponse>> {
        let access_token = self.get_refresh_token()?;
        // let access_token = self.get_access_token(scopes::DEVICES_READ)?.token;
        let client = Client::new(&self.state.config);
        client.devices(&access_token)
    }

    pub fn invoke_command(
        &mut self,
        command: &str,
        target: &DeviceResponse,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let access_token = self.get_refresh_token()?;
        // let access_token = self.get_access_token(scopes::DEVICES_WRITE)?.token;
        let client = Client::new(&self.state.config);
        client.invoke_command(&access_token, command, &target.id, payload)
    }

    pub fn handle_push_message(&mut self, payload: PushPayload) -> Result<Vec<AccountEvent>> {
        match payload {
            PushPayload::CommandReceived(_) => self.poll_remote_commands(),
        }
    }

    pub fn poll_remote_commands(&mut self) -> Result<Vec<AccountEvent>> {
        let last_command_index = self.state.last_handled_command.unwrap_or(0);
        let refresh_token = self.get_refresh_token()?;
        let client = Client::new(&self.state.config);
        // We increment last_command_index by 1 because the server response includes the current index.
        let pending_commands =
            client.pending_commands(refresh_token, last_command_index + 1, None)?;
        if pending_commands.messages.len() == 0 {
            return Ok(Vec::new());
        }
        log::info!("Handling {} messages", pending_commands.messages.len());
        let account_events = self.handle_commands(pending_commands.messages)?;
        self.state.last_handled_command = Some(pending_commands.index);
        self.maybe_call_persist_callback();
        Ok(account_events)
    }

    // TODO: tests for that
    fn handle_commands(&mut self, messages: Vec<PendingCommand>) -> Result<Vec<AccountEvent>> {
        let mut account_events: Vec<AccountEvent> = Vec::with_capacity(messages.len());
        let commands: Vec<_> = messages.into_iter().map(|m| m.data).collect();
        let devices = self.get_devices()?;
        for data in commands {
            match self.handle_command(data, &devices) {
                Ok((sender, tab)) => account_events.push(AccountEvent::TabReceived((sender, tab))),
                Err(e) => log::error!("Error while processing command: {}", e),
            };
        }
        Ok(account_events)
    }

    // Returns EncryptedSendTabPayload for now because we only receive send-tab commands and
    // it's way easier, but should probably return AccountEvent or similar in the future.
    fn handle_command(
        &mut self,
        command_data: CommandData,
        devices: &[DeviceResponse],
    ) -> Result<(Option<DeviceResponse>, SendTabPayload)> {
        let sender = command_data
            .sender
            .and_then(|s| devices.iter().find(|i| i.id == s).map(|x| x.clone()));
        match command_data.command.as_str() {
            send_tab::COMMAND_NAME => {
                let send_tab_key: PrivateSendTabKeys =
                    match self.state.commands_data.get(send_tab::COMMAND_NAME) {
                        Some(s) => serde_json::from_str(s)?,
                        None => return Err(ErrorKind::IllegalState(
                            "Cannot find send-tab keys. Has ensure_send_tab been called before?"
                                .to_string(),
                        )
                        .into()),
                    };
                let encrypted_payload: EncryptedSendTabPayload =
                    serde_json::from_value(command_data.payload)?;
                Ok((sender, encrypted_payload.decrypt(&send_tab_key)?))
            }
            _ => Err(ErrorKind::UnknownCommand(command_data.command).into()),
        }
    }

    pub fn set_push_subscription(&self, push_subscription: PushSubscription) -> Result<()> {
        let update = DeviceUpdateRequestBuilder::new()
            .push_subscription(push_subscription)
            .build();
        self.update_device(update)
    }

    pub fn set_display_name(&self, name: &str) -> Result<()> {
        let update = DeviceUpdateRequestBuilder::new().display_name(name).build();
        self.update_device(update)
    }

    pub fn clear_display_name(&self) -> Result<()> {
        let update = DeviceUpdateRequestBuilder::new()
            .clear_display_name()
            .build();
        self.update_device(update)
    }

    // TODO: use the PATCH endpoint instead of overwritting everything.
    pub fn register_command(&self, command: &str, value: &str) -> Result<()> {
        let mut commands = HashMap::new();
        commands.insert(command.to_owned(), value.to_owned());
        let update = DeviceUpdateRequestBuilder::new()
            .available_commands(commands)
            .build();
        self.update_device(update)
    }

    // TODO: this currently deletes every command registered.
    pub fn unregister_command(&self, _: &str) -> Result<()> {
        let commands = HashMap::new();
        let update = DeviceUpdateRequestBuilder::new()
            .available_commands(commands)
            .build();
        self.update_device(update)
    }

    pub fn clear_commands(&self) -> Result<()> {
        let update = DeviceUpdateRequestBuilder::new()
            .clear_available_commands()
            .build();
        self.update_device(update)
    }

    fn update_device(&self, update: DeviceUpdateRequest) -> Result<()> {
        let refresh_token = self.get_refresh_token()?;
        let client = Client::new(&self.state.config);
        client.update_device(refresh_token, update)
    }

    fn get_refresh_token(&self) -> Result<&str> {
        match self.state.refresh_token {
            Some(ref token_info) => Ok(&token_info.token),
            None => Err(ErrorKind::NoRefreshToken.into()),
        }
    }

    fn get_scoped_key(&self, scope: &str) -> Result<&ScopedKey> {
        match self.state.scoped_keys.get(scope) {
            Some(ref scoped_key) => Ok(scoped_key),
            None => Err(ErrorKind::NoCachedKey(scope.to_string()).into()),
        }
    }

    pub fn register_persist_callback(&mut self, persist_callback: PersistCallback) {
        self.persist_callback = Some(persist_callback);
    }

    pub fn unregister_persist_callback(&mut self) {
        self.persist_callback = None;
    }

    fn maybe_call_persist_callback(&self) {
        if let Some(ref cb) = self.persist_callback {
            match self.to_json() {
                Ok(ref json) => cb.call(json),
                Err(_) => log::error!("Error with to_json in persist_callback"),
            };
        }
    }

    #[cfg(feature = "browserid")]
    pub fn sign_out(mut self) {
        let client = Client::new(&self.state.config);
        client.sign_out();
        self.state.login_state = self.state.login_state.to_separated();
    }

    pub fn send_tab(&mut self, target: &DeviceResponse, title: &str, url: &str) -> Result<()> {
        let payload = SendTabPayload::single_tab(title, url);
        let kek = self.sync_keys_as_send_tab_kek()?;
        let command_payload = send_tab::build_send_command(&kek, target, &payload)?;
        self.invoke_command(send_tab::COMMAND_NAME, target, &command_payload)
    }

    pub fn ensure_send_tab_registered(&mut self) -> Result<()> {
        let own_keys: PrivateSendTabKeys =
            match self.state.commands_data.get(send_tab::COMMAND_NAME) {
                Some(s) => serde_json::from_str(s)?,
                None => {
                    let keys = PrivateSendTabKeys::from_random(&*RNG)?;
                    self.state.commands_data.insert(
                        send_tab::COMMAND_NAME.to_owned(),
                        serde_json::to_string(&keys)?,
                    );
                    self.maybe_call_persist_callback();
                    keys
                }
            };
        let public_keys: PublicSendTabKeys = own_keys.into();
        let kek = self.sync_keys_as_send_tab_kek()?;
        let command_data: String = public_keys.as_command_data(&kek)?;
        self.register_command(send_tab::COMMAND_NAME, &command_data)?;
        Ok(())
    }

    fn sync_keys_as_send_tab_kek(&self) -> Result<send_tab::KeyEncryptingKey> {
        let oldsync_key = self.get_scoped_key(scopes::OLD_SYNC)?;
        let ksync = base64::decode_config(&oldsync_key.k, base64::URL_SAFE_NO_PAD)?;
        let kxcs: &str = oldsync_key.kid.splitn(2, '-').collect::<Vec<_>>()[1];
        let kxcs = base64::decode_config(&kxcs, base64::URL_SAFE_NO_PAD)?;
        Ok(send_tab::KeyEncryptingKey::SyncKeys(ksync, kxcs))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum AccountEvent {
    // In the future: ProfileUpdated etc.
    TabReceived((Option<DeviceResponse>, SendTabPayload)),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopedKey {
    pub kty: String,
    pub scope: String,
    /// URL Safe Base 64 encoded key.
    pub k: String,
    pub kid: String,
}

impl ScopedKey {
    pub fn key_bytes(&self) -> Result<Vec<u8>> {
        Ok(base64::decode_config(&self.k, base64::URL_SAFE_NO_PAD)?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefreshToken {
    pub token: String,
    pub scopes: HashSet<String>,
}

pub struct OAuthFlow {
    pub scoped_keys_flow: Option<ScopedKeysFlow>,
    pub code_verifier: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessTokenInfo {
    pub scope: String,
    pub token: String,
    pub key: Option<ScopedKey>,
    pub expires_at: u64, // seconds since epoch
}

#[derive(Debug, Deserialize)]
#[serde(tag = "command", content = "data")]
pub enum PushPayload {
    #[serde(rename = "fxaccounts:command_received")]
    CommandReceived(CommandReceivedPushPayload),
}

#[derive(Debug, Deserialize)]
pub struct CommandReceivedPushPayload {
    command: String,
    index: u64,
    sender: String,
    url: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn test_fxa_is_send() {
        fn is_send<T: Send>() {}
        is_send::<FirefoxAccount>();
    }

    #[test]
    fn test_serialize_deserialize() {
        let fxa1 =
            FirefoxAccount::new("https://stable.dev.lcip.org", "12345678", "https://foo.bar");
        let fxa1_json = fxa1.to_json().unwrap();
        drop(fxa1);
        let fxa2 = FirefoxAccount::from_json(&fxa1_json).unwrap();
        let fxa2_json = fxa2.to_json().unwrap();
        assert_eq!(fxa1_json, fxa2_json);
    }

    #[test]
    fn test_oauth_flow_url() {
        let mut fxa = FirefoxAccount::new(
            "https://accounts.firefox.com",
            "12345678",
            "https://foo.bar",
        );
        let url = fxa.begin_oauth_flow(&[scopes::PROFILE], false).unwrap();
        let flow_url = Url::parse(&url).unwrap();

        assert_eq!(flow_url.host_str(), Some("accounts.firefox.com"));
        assert_eq!(flow_url.path(), "/authorization");

        let mut pairs = flow_url.query_pairs();
        assert_eq!(pairs.count(), 9);
        assert_eq!(
            pairs.next(),
            Some((Cow::Borrowed("action"), Cow::Borrowed("email")))
        );
        assert_eq!(
            pairs.next(),
            Some((Cow::Borrowed("response_type"), Cow::Borrowed("code")))
        );
        assert_eq!(
            pairs.next(),
            Some((Cow::Borrowed("client_id"), Cow::Borrowed("12345678")))
        );
        assert_eq!(
            pairs.next(),
            Some((
                Cow::Borrowed("redirect_uri"),
                Cow::Borrowed("https://foo.bar")
            ))
        );
        assert_eq!(
            pairs.next(),
            Some((Cow::Borrowed("scope"), Cow::Borrowed(scopes::PROFILE)))
        );
        let state_param = pairs.next().unwrap();
        assert_eq!(state_param.0, Cow::Borrowed("state"));
        assert_eq!(state_param.1.len(), 22);
        assert_eq!(
            pairs.next(),
            Some((
                Cow::Borrowed("code_challenge_method"),
                Cow::Borrowed("S256")
            ))
        );
        let code_challenge_param = pairs.next().unwrap();
        assert_eq!(code_challenge_param.0, Cow::Borrowed("code_challenge"));
        assert_eq!(code_challenge_param.1.len(), 43);
        assert_eq!(
            pairs.next(),
            Some((Cow::Borrowed("access_type"), Cow::Borrowed("offline")))
        );
    }

    #[test]
    fn test_oauth_flow_url_with_keys() {
        let mut fxa = FirefoxAccount::new(
            "https://accounts.firefox.com",
            "12345678",
            "https://foo.bar",
        );
        let url = fxa.begin_oauth_flow(&[scopes::PROFILE], true).unwrap();
        let flow_url = Url::parse(&url).unwrap();

        assert_eq!(flow_url.host_str(), Some("accounts.firefox.com"));
        assert_eq!(flow_url.path(), "/authorization");

        let mut pairs = flow_url.query_pairs();
        assert_eq!(pairs.count(), 10);
        assert_eq!(
            pairs.next(),
            Some((Cow::Borrowed("action"), Cow::Borrowed("email")))
        );
        assert_eq!(
            pairs.next(),
            Some((Cow::Borrowed("response_type"), Cow::Borrowed("code")))
        );
        assert_eq!(
            pairs.next(),
            Some((Cow::Borrowed("client_id"), Cow::Borrowed("12345678")))
        );
        assert_eq!(
            pairs.next(),
            Some((
                Cow::Borrowed("redirect_uri"),
                Cow::Borrowed("https://foo.bar")
            ))
        );
        assert_eq!(
            pairs.next(),
            Some((Cow::Borrowed("scope"), Cow::Borrowed(scopes::PROFILE)))
        );
        let state_param = pairs.next().unwrap();
        assert_eq!(state_param.0, Cow::Borrowed("state"));
        assert_eq!(state_param.1.len(), 22);
        assert_eq!(
            pairs.next(),
            Some((
                Cow::Borrowed("code_challenge_method"),
                Cow::Borrowed("S256")
            ))
        );
        let code_challenge_param = pairs.next().unwrap();
        assert_eq!(code_challenge_param.0, Cow::Borrowed("code_challenge"));
        assert_eq!(code_challenge_param.1.len(), 43);
        assert_eq!(
            pairs.next(),
            Some((Cow::Borrowed("access_type"), Cow::Borrowed("offline")))
        );
        let keys_jwk = pairs.next().unwrap();
        assert_eq!(keys_jwk.0, Cow::Borrowed("keys_jwk"));
        assert_eq!(keys_jwk.1.len(), 168);
    }

    #[test]
    fn test_pairing_flow_url() {
        static SCOPES: &'static [&'static str] = &["https://identity.mozilla.com/apps/oldsync"];
        static PAIRING_URL: &'static str = "https://accounts.firefox.com/pair#channel_id=658db7fe98b249a5897b884f98fb31b7&channel_key=1hIDzTj5oY2HDeSg_jA2DhcOcAn5Uqq0cAYlZRNUIo4";
        static EXPECTED_URL: &'static str = "https://accounts.firefox.com/pair/supp?client_id=12345678&redirect_uri=https%3A%2F%2Ffoo.bar&scope=https%3A%2F%2Fidentity.mozilla.com%2Fapps%2Foldsync&state=SmbAA_9EA5v1R2bgIPeWWw&code_challenge_method=S256&code_challenge=ZgHLPPJ8XYbXpo7VIb7wFw0yXlTa6MUOVfGiADt0JSM&access_type=offline&keys_jwk=eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6Ing5LUltQjJveDM0LTV6c1VmbW5sNEp0Ti14elV2eFZlZXJHTFRXRV9BT0kiLCJ5IjoiNXBKbTB3WGQ4YXdHcm0zREl4T1pWMl9qdl9tZEx1TWlMb1RkZ1RucWJDZyJ9#channel_id=658db7fe98b249a5897b884f98fb31b7&channel_key=1hIDzTj5oY2HDeSg_jA2DhcOcAn5Uqq0cAYlZRNUIo4";

        let mut fxa = FirefoxAccount::new(
            "https://accounts.firefox.com",
            "12345678",
            "https://foo.bar",
        );
        let url = fxa.begin_pairing_flow(&PAIRING_URL, &SCOPES).unwrap();
        let flow_url = Url::parse(&url).unwrap();
        let expected_parsed_url = Url::parse(EXPECTED_URL).unwrap();

        assert_eq!(flow_url.host_str(), Some("accounts.firefox.com"));
        assert_eq!(flow_url.path(), "/pair/supp");
        assert_eq!(flow_url.fragment(), expected_parsed_url.fragment());

        let mut pairs = flow_url.query_pairs();
        assert_eq!(pairs.count(), 8);
        assert_eq!(
            pairs.next(),
            Some((Cow::Borrowed("client_id"), Cow::Borrowed("12345678")))
        );
        assert_eq!(
            pairs.next(),
            Some((
                Cow::Borrowed("redirect_uri"),
                Cow::Borrowed("https://foo.bar")
            ))
        );
        assert_eq!(
            pairs.next(),
            Some((
                Cow::Borrowed("scope"),
                Cow::Borrowed("https://identity.mozilla.com/apps/oldsync")
            ))
        );
        let state_param = pairs.next().unwrap();
        assert_eq!(state_param.0, Cow::Borrowed("state"));
        assert_eq!(state_param.1.len(), 22);
        assert_eq!(
            pairs.next(),
            Some((
                Cow::Borrowed("code_challenge_method"),
                Cow::Borrowed("S256")
            ))
        );
        let code_challenge_param = pairs.next().unwrap();
        assert_eq!(code_challenge_param.0, Cow::Borrowed("code_challenge"));
        assert_eq!(code_challenge_param.1.len(), 43);
        assert_eq!(
            pairs.next(),
            Some((Cow::Borrowed("access_type"), Cow::Borrowed("offline")))
        );
        let keys_jwk = pairs.next().unwrap();
        assert_eq!(keys_jwk.0, Cow::Borrowed("keys_jwk"));
        assert_eq!(keys_jwk.1.len(), 168);
    }

    #[test]
    fn test_pairing_flow_origin_mismatch() {
        static PAIRING_URL: &'static str =
            "https://bad.origin.com/pair#channel_id=foo&channel_key=bar";
        let mut fxa = FirefoxAccount::new(
            "https://accounts.firefox.com",
            "12345678",
            "https://foo.bar",
        );
        let url =
            fxa.begin_pairing_flow(&PAIRING_URL, &["https://identity.mozilla.com/apps/oldsync"]);

        assert!(url.is_err());

        match url {
            Ok(_) => {
                panic!("should have error");
            }
            Err(err) => match err.kind() {
                ErrorKind::OriginMismatch { .. } => {}
                _ => panic!("error not OriginMismatch"),
            },
        }
    }

    #[test]
    fn test_get_connection_success_url() {
        let fxa = FirefoxAccount::new("https://stable.dev.lcip.org", "12345678", "https://foo.bar");
        let url = fxa.get_connection_success_url().unwrap().to_string();
        assert_eq!(
            url,
            "https://stable.dev.lcip.org/connect_another_device?showSuccessMessage=true"
                .to_string()
        );
    }

    #[test]
    fn test_deserialize_push_message() {
        let json = "{\"version\":1,\"command\":\"fxaccounts:command_received\",\"data\":{\"command\":\"send-tab-recv\",\"index\":1,\"sender\":\"bobo\",\"url\":\"https://mozilla.org\"}}";
        let _: PushPayload = serde_json::from_str(&json).unwrap();
    }
}
