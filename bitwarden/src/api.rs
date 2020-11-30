// SPDX-License-Identifier: MIT

use reqwest::header::{self, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api_definition::{
    PreloginRequest, PreloginResponse, LoginRequest, LoginResponse, SyncResponse
};
use crate::cipher::CipherSuite;

const AUTH_URL: &str = "https://identity.bitwarden.com/connect/token";
const BASE_URL: &str = "https://api.bitwarden.com";

#[derive(Clone, Debug, failure::Fail)]
pub enum ApiError {
    #[fail(display = "network error: failed to retrieve {}", 0)]
    NetworkError(String),

    #[fail(display = "authentication failed: wrong username or password")]
    LoginFailed,

    #[fail(display = "failed to sync vault: {}", 0)]
    SyncFailed(String),
}

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthData {
    access_token: String,
    expires_in: usize,
    token_type: String,

    kdf: u32,
    pub kdf_iterations: u32,

    #[serde(skip)]
    pub cipher: CipherSuite,
}

fn perform_prelogin(
    client: &reqwest::blocking::Client,
    email: &str,
) -> ApiResult<PreloginResponse> {
    let url = format!("{}/accounts/prelogin", BASE_URL);

    let data = PreloginRequest { email };
    let response = client
        .post(&url)
        .json(&data)
        .send()
        .map_err(|err| ApiError::NetworkError(err.to_string()))?;

    if response.status().is_success() {
        response.json::<PreloginResponse>().map_err(|_| ApiError::LoginFailed)
    } else {
        Err(ApiError::LoginFailed)
    }
}

fn perform_token_auth(
    client: &reqwest::blocking::Client,
    email: &str,
    cipher: &CipherSuite,
) -> ApiResult<LoginResponse> {
    let device_id = Uuid::new_v4().to_hyphenated().to_string();

    let data = LoginRequest {
        grant_type: "password",
        username: email,
        scope: "api offline_access",
        client_id: "connector",
        device_type: 3,
        device_id: &device_id,
        device_name: "bwtui",
        password: &cipher.master_key_hash,
    };

    let response = client
        .post(AUTH_URL)
        .form(&data)
        .send()
        .map_err(|err| ApiError::NetworkError(err.to_string()))?;

    if response.status().is_success() {
        response.json::<LoginResponse>().map_err(|_| ApiError::LoginFailed)
    } else {
        Err(ApiError::LoginFailed)
    }
}

pub fn authenticate(email: &str, password: &str) -> ApiResult<AuthData> {
    let client = reqwest::blocking::Client::new();

    let PreloginResponse {
        kdf,
        kdf_iterations,
    } = perform_prelogin(&client, email)?;

    let cipher = CipherSuite::from(email, password, kdf_iterations);

    let LoginResponse {
        access_token,
        expires_in,
        token_type,
    } = perform_token_auth(&client, email, &cipher)?;

    Ok(AuthData {
        access_token,
        expires_in,
        token_type,
        kdf,
        kdf_iterations,
        cipher,
    })
}

pub fn sync(auth_data: &AuthData) -> ApiResult<SyncResponse> {
    let url = format!("{}/sync", BASE_URL);

    let mut headers = HeaderMap::new();
    let auth_header = format!("{} {}", auth_data.token_type, auth_data.access_token);
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&auth_header).unwrap(),
    );

    let response = reqwest::blocking::Client::new()
        .get(&url)
        .headers(headers)
        .send()
        .map_err(|_| ApiError::NetworkError(url))?;

    if response.status().is_success() {
        response.json::<SyncResponse>()
            .map_err(|_| ApiError::SyncFailed("received invalid response".to_string()))
    } else {
        Err(ApiError::SyncFailed("server reject the request".to_string()))
    }
}
