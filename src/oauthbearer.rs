use crate::sasl;

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

/// The OAUTHBEARER mechanism name.
pub const OAUTHBEARER: &str = "OAUTHBEARER";

#[derive(Deserialize, Serialize)]
pub struct OAuthBearerError {
    pub status: String,
    pub schemes: String,
    pub scope: String,
}

impl std::fmt::Display for OAuthBearerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OAUTHBEARER authentication error {}", self.status)
    }
}

#[derive(Default)]
pub struct OAuthBearerOptions {
    pub username: String,
    pub token: String,
    pub host: String,
    pub port: u16,
}

/// An implementation of the OAUTHBEARER authentication mechanism, as
/// described in RFC 7628.
#[derive(Default)]
pub struct OAuthBearerClinet {
    options: OAuthBearerOptions,
}

impl OAuthBearerClinet {
    pub fn new(options: OAuthBearerOptions) -> Self {
        Self {
            options,
        }
    }
}

impl sasl::Client for OAuthBearerClinet {
    fn start(&mut self) -> Result<(String, Vec<u8>)> {
        let mut authzid = String::new();
        if !self.options.username.is_empty() {
            authzid = format!("a={}", self.options.username);
        }
        let mut str = format!("n,{},", authzid);

        if !self.options.host.is_empty() {
            str = format!("{str}\x01host={}", self.options.host);
        }

        if self.options.port != 0 {
            str = format!("{str}\x01port={}", self.options.port);
        }
        str = format!("{str}\x01auth=Bearer {}\x01\x01", self.options.token);
        Ok((OAUTHBEARER.to_string(), str.into_bytes()))
    }

    fn next(&mut self, challenge: &[u8]) -> Result<Vec<u8>> {
        let auth_bearer_error: OAuthBearerError = serde_json::from_slice(challenge)?;
        Err(anyhow!(auth_bearer_error.to_string()))
    }
}

pub type OAuthBearerAuthenticator = Box<dyn Fn(OAuthBearerOptions) -> Result<(), OAuthBearerError>>;

pub struct OAuthBearerServer {
    done: bool,
    fail_error: Option<anyhow::Error>,
    authenticator: OAuthBearerAuthenticator,
}

impl OAuthBearerServer {
    pub fn new<F>(authenticator: F) -> Self
    where F: Fn(OAuthBearerOptions) -> Result<(), OAuthBearerError> + 'static {
        Self {
            done: false,
            fail_error: None,
            authenticator: Box::new(authenticator),
        }
    }

    fn fail(&mut self, descr: &str) -> Result<(Vec<u8>, bool)> {
        let oauth_bearer_error = OAuthBearerError{
            status: "invalid_request".to_string(),
            schemes: "bearer".to_string(),
            scope: "".to_string(),
        };
        self.fail_error = Some(anyhow!(descr.to_string()));
        Ok((serde_json::to_vec(&oauth_bearer_error)?, false))
    }
}

impl sasl::Server for OAuthBearerServer {
    fn next(&mut self, response: Option<&[u8]>) -> Result<(Vec<u8>, bool)> {
        // Per RFC, we cannot just send an error, we need to return JSON-structured
        // value as a challenge and then after getting dummy response from the
        // client stop the exchange.
        if self.fail_error.is_some() {
            // Server libraries (rs-smtp, rs-imap) will not call next on
            // protocol-specific SASL cancel response ('*'). However, GS2 (and
            // indirectly OAUTHBEARER) defines a protocol-independent way to do so
            // using 0x01.
            let response = response.unwrap_or(&[]);
            if response.len() != 1 && response.get(0) != Some(&0x01) {
                bail!("unexpected response");
            }
            return Err(self.fail_error.take().unwrap());
        }

        if self.done {
            bail!(sasl::ERR_UNEXPECTED_CLIENT_RESPONSE);
        }

        // Generate empty challenge.
        if response.is_none() {
            return Ok((Vec::new(), false));
        }
        let response = response.unwrap();

        self.done = true;

        // Cut n,a=username,\x01host=...\x01auth=...
        // into
        //   n
        //   a=username
        //   \x01host=...\x01auth=...\x01\x01
        let parts = response.splitn(3, |&c| c == b',').collect::<Vec<_>>();
        if parts.len() != 3 {
            return self.fail("Invalid response");
        }
        let flag = parts[0];
        let authzid = parts[1];
        if !flag.starts_with(b"n") {
            return self.fail("Invalid response, missing 'n' in gs2-cb-flag");
        }
        let mut opts = OAuthBearerOptions::default();
        if authzid.len() > 0 {
            if !authzid.starts_with(b"a=") {
                return self.fail("Invalid response, missing 'a=' in gs2-authzid");
            }
            opts.username = String::from_utf8(authzid[2..].to_vec())?;
        }

        // Cut \x01host=...\x01auth=...\x01\x01
        // into
        //   *empty*
        //   host=...
        //   auth=...
        //   *empty*
        //
        // Note that this code does not do a lot of checks to make sure the input
        // follows the exact format specified by RFC.
        let params = parts[2].split(|&c| c == b'\x01');
        for p in params {
            // Skip empty fields (one at start and end).
            if p.is_empty() {
                continue;
            }

            let p_parts = p.splitn(2, |&c| c == b'=').collect::<Vec<_>>();
            if p_parts.len() != 2 {
                return self.fail("Invalid response, missing '='");
            }

            match p_parts[0] {
                b"host" => {
                    opts.host = String::from_utf8(p_parts[1].to_vec())?;
                }
                b"port" => {
                    let port = String::from_utf8(p_parts[1].to_vec());
                    if let Ok(port) = port {
                        opts.port = port.parse()?;
                    } else {
                        return self.fail("Invalid response, malformed 'port' value");
                    }
                }
                b"auth" => {
                    const PREFIX: &str = "bearer ";
                    let auth = String::from_utf8(p_parts[1].to_vec())?.to_lowercase();
                    if !auth.starts_with(PREFIX) {
                        return self.fail("Unsupported token type");
                    }
                    
                    opts.token = auth[PREFIX.len()..].to_string();
                }
                _ => {
                    return self.fail(&format!("Invalid response, unknown parameter: {}", String::from_utf8(p_parts[0].to_vec())?));
                }
            }
        }

        if let Err(err) = (self.authenticator)(opts) {
            self.fail_error = Some(anyhow!(err.to_string()));
            return Ok((serde_json::to_vec(&err)?, false));
        }

        Ok((Vec::new(), true))
    }
}

