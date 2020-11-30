// SPDX-License-Identifier: MIT

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cipher::CipherString;

#[derive(Debug, Serialize)]
pub(crate) struct PreloginRequest<'a> {
    pub email: &'a str,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PreloginResponse {
    #[serde(alias = "Kdf")]
    pub kdf: u32,
    #[serde(alias = "KdfIterations")]
    pub kdf_iterations: u32,
}

#[derive(Debug, Serialize)]
pub(crate) struct LoginRequest<'a> {
    pub grant_type: &'a str,
    pub username: &'a str,
    pub scope: &'a str,
    pub client_id: &'a str,
    #[serde(alias = "deviceType")]
    pub device_type: usize,
    #[serde(alias = "deviceIdentifier")]
    pub device_id: &'a str,
    #[serde(alias = "deviceName")]
    pub device_name: &'a str,
    pub password: &'a str,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginResponse {
    pub access_token: String,
    pub expires_in: usize,
    pub token_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Profile {
    #[serde(alias = "Object")]
    object: String,
    #[serde(alias = "Id")]
    pub uuid: Uuid,
    #[serde(alias = "Name")]
    pub name: String,
    #[serde(alias = "Email")]
    pub email: String,
    #[serde(alias = "EmailVerified")]
    pub email_verified: bool,
    #[serde(alias = "Premium")]
    pub premium: bool,
    #[serde(alias = "MasterPasswordHint")]
    pub master_password_hint: Option<String>,
    #[serde(alias = "Culture")]
    pub language: String,
    #[serde(alias = "TwoFactorEnabled")]
    pub tfa_enabled: bool,
    #[serde(alias = "Key")]
    pub key: CipherString,
    #[serde(alias = "PrivateKey")]
    pub private_key: CipherString,
    #[serde(alias = "SecurityStamp")]
    pub security_stamp: String,
    #[serde(alias = "Organizations")]
    pub organizations: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Folder {
    #[serde(alias = "Object")]
    object: String,
    #[serde(alias = "Id")]
    pub uuid: Uuid,
    #[serde(alias = "Name")]
    pub name: CipherString,
    #[serde(alias = "RevisionDate")]
    pub last_changed: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CipherEntryFields {
    #[serde(alias = "Type")]
    pub type_: usize,
    #[serde(alias = "Name")]
    pub name: CipherString,
    #[serde(alias = "Value")]
    pub value: CipherString,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CipherEntryHistory {
    #[serde(alias = "Password")]
    pub password: String,
    #[serde(alias = "LastUsedDate")]
    pub last_used_date: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CipherEntryUriMatch {
    #[serde(alias = "Uri")]
    pub uri: CipherString,
    #[serde(alias = "Match")]
    pub match_: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CipherEntryData {
    #[serde(alias = "Uri")]
    pub uri: Option<CipherString>,
    #[serde(alias = "Uris")]
    pub uris: Option<Vec<CipherEntryUriMatch>>,
    #[serde(alias = "Username")]
    pub username: CipherString,
    #[serde(alias = "Password")]
    pub password: CipherString,
    #[serde(alias = "PasswordRevisionDate")]
    pub assword_last_changed: Option<DateTime<Utc>>,
    #[serde(alias = "Totp")]
    pub totp: Option<String>,
    #[serde(alias = "Name")]
    pub name: CipherString,
    #[serde(alias = "Notes")]
    pub notes: Option<String>,
    #[serde(alias = "Fields")]
    pub fields: Option<Vec<CipherEntryFields>>,
    #[serde(alias = "PasswordHistory")]
    pub password_history: Option<Vec<CipherEntryHistory>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CipherEntry {
    #[serde(alias = "Object")]
    object: String,
    #[serde(alias = "CollectionIds")]
    pub collection_ids: Vec<Uuid>,
    #[serde(alias = "FolderId")]
    pub folder_id: Option<Uuid>,
    #[serde(alias = "Favorite")]
    pub favorite: bool,
    #[serde(alias = "Edit")]
    pub edit: bool,
    #[serde(alias = "Id")]
    pub uuid: Uuid,
    #[serde(alias = "OrganizationId")]
    pub organization_id: Option<Uuid>,
    #[serde(alias = "Type")]
    pub type_: usize,
    #[serde(alias = "Data")]
    pub data: CipherEntryData,
    #[serde(alias = "Name")]
    pub name: CipherString,
    #[serde(alias = "Notes")]
    pub notes: Option<String>,
    #[serde(alias = "Login", skip)]
    pub login: Option<CipherEntryData>,
    #[serde(alias = "Card")]
    pub card: Option<String>,
    #[serde(alias = "Identity")]
    pub identity: Option<String>,
    #[serde(alias = "SecureNote")]
    pub secure_note: Option<String>,
    #[serde(alias = "Fields")]
    pub fields: Option<Vec<CipherEntryFields>>,
    #[serde(alias = "PasswordHistory")]
    pub password_history: Option<Vec<CipherEntryHistory>>,
    #[serde(alias = "Attachments")]
    pub attachments: Option<String>,
    #[serde(alias = "OrganizationUseTotp")]
    pub organization_tfa: bool,
    #[serde(alias = "RevisionDate")]
    pub last_changed: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Domains {
    // TODO
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SyncResponse {
    #[serde(alias = "Object")]
    object: String,
    #[serde(alias = "Profile")]
    pub profile: Profile,
    #[serde(alias = "Folders")]
    pub folders: Vec<Folder>,
    #[serde(alias = "Collections")]
    pub collections: Vec<String>,
    #[serde(alias = "Ciphers")]
    pub ciphers: Vec<CipherEntry>,
    #[serde(alias = "Domains", skip)]
    domains: Option<Domains>,
}
