use std::env;
use std::fs::File;
use std::io::BufReader;
use std::process::exit;

use anyhow::{Context, Result};
use chrono::{Duration, Local};
use getopts::Options;
use jsonwebtoken::{Algorithm, encode, EncodingKey, Header};
use reqwest::Url;
use serde;
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    aud: String,
    exp: usize,
    iat: usize,
    iss: String,
    sub: String,
    uid: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Credential {
    private_key: String,
    client_email: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct FirebaseTokenRequest {
    token: String,
    #[serde(rename = "returnSecureToken")]
    return_secure_token: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct FirebaseTokenResponse {
    #[serde(rename = "idToken")]
    id_token: String,
    #[serde(rename = "refreshToken")]
    refresh_token: String,
    #[serde(rename = "expiresIn")]
    expires_in: String,
}

fn main() {
    let apikey = match load_apikey() {
        Ok(apikey) => apikey,
        Err(err) => {
            eprintln!("{}", err);
            exit(1)
        }
    };
    let credential = match load_credential() {
        Ok(credential) => credential,
        Err(err) => {
            eprintln!("{}", err);
            exit(1)
        }
    };

    let claims = create_claims(&credential);
    match encode_claims(&credential, &claims) {
        Ok(token) => {
            match get_token(&apikey, &token) {
                Ok(token) => println!("{}", token.id_token),
                Err(err) => {
                    eprintln!("{}", err);
                    exit(1)
                }
            }
        }
        Err(err) => {
            eprintln!("{}", err);
            exit(1)
        }
    }
}

/// apikey を読み込む
fn load_apikey() -> Result<String> {
    let args: Vec<String> = env::args().collect();

    let mut opts = Options::new();
    opts.optopt("a", "apikey", "apikey for firebase project", "NAME");
    opts.optflag("h", "help", "print this help menu");
    let matches = opts.parse(&args[1..])?;
    match matches.opt_str("apikey") {
        Some(key) => Ok(key),
        None => {
            env::var("FTC_APIKEY")
                .context("apikey not found")
        }
    }
}

/// credential を読み込む
fn load_credential() -> Result<Credential> {
    let path = env::var("GOOGLE_APPLICATION_CREDENTIALS")
        .context("GOOGLE_APPLICATION_CREDENTIALS not found")?;
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let credential: Credential = serde_json::from_reader(reader)
        .context("json parse error")?;
    Ok(credential)
}

/// firebase のクレームを作成
fn create_claims(credential: &Credential) -> Claims {
    let now = Local::now();
    Claims {
        aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit".to_string(),
        iat: now.timestamp() as usize,
        exp: (now + Duration::seconds(3600)).timestamp() as usize,
        iss: credential.client_email.to_string(),
        sub: credential.client_email.to_string(),
        uid: "uid".to_string(),
    }
}

/// クレームをエンコードして jwt にする
fn encode_claims<'a>(credential: &'a Credential, claims: &'a Claims) -> Result<String> {
    let key = &EncodingKey::from_rsa_pem(&credential.private_key.as_bytes())?;
    let encoded = encode(&Header::new(Algorithm::RS256), claims, key)?;
    Ok(encoded)
}

/// firebase からアクセストークンを取得
fn get_token(apikey: &String, token: &String) -> Result<FirebaseTokenResponse> {
    let url = Url::parse_with_params(
        "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken",
        &[("key", apikey)],
    )?;
    let request_params = FirebaseTokenRequest {
        token: token.to_string(),
        return_secure_token: true,
    };
    reqwest::blocking::Client::new()
        .post(url)
        .json(&request_params)
        .send()?
        .json()
        .context("sign in with custom token failure")
}