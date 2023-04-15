use crate::sasl;

use anyhow::{anyhow, Result};

/// The LOGIN mechanism name.
pub const LOGIN: &str = "LOGIN";

/// A client implementation of the LOGIN authentication mechanism for SMTP,
/// as described in http://www.iana.org/go/draft-murchison-sasl-login
///
/// It is considered obsolete, and should not be used when other mechanisms are
/// available. For plaintext password authentication use PLAIN mechanism.
pub struct LoginClient {
    username: String,
    password: String,
}

impl LoginClient {
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password,
        }
    }
}

impl sasl::Client for LoginClient {
    fn start(&mut self) -> Result<(String, Vec<u8>)> {
        Ok((
            LOGIN.to_string(),
            self.username.clone().into_bytes(),
        ))
    }

    fn next(&mut self, challenge: &[u8]) -> Result<Vec<u8>> {
        if challenge == b"Password:" {
            Ok(self.password.clone().into_bytes())
        } else {
            Err(anyhow!(sasl::ERR_UNEXPECTED_SERVER_CHALLENGE))
        }
    }
}

/// Authenticates users with an username and a password.
pub type LoginAuthenticator = Box<dyn Fn(&str, &str) -> Result<()> + Send>;

enum LoginState {
    LoginNotStarted,
    LoginWaitingUsername,
    LoginWaitingPassword,
}

/// A server implementation of the LOGIN authentication mechanism, as described
/// in https://tools.ietf.org/html/draft-murchison-sasl-login-00.
///
/// LOGIN is obsolete and should only be enabled for legacy clients that cannot
/// be updated to use PLAIN.
pub struct LoginServer {
    state: LoginState,
    username: String,
    password: String,
    authenticator: LoginAuthenticator,
}

impl LoginServer {
    pub fn new<F>(authenticator: LoginAuthenticator) -> Self {
        Self {
            state: LoginState::LoginNotStarted,
            username: String::new(),
            password: String::new(),
            authenticator,
        }
    }
}

impl sasl::Server for LoginServer {
    fn next(&mut self, response: Option<&[u8]>) -> Result<(Vec<u8>, bool)> {
        match self.state {
            LoginState::LoginNotStarted => {
                // Check for initial response field, as per RFC4422 section 3
                if response.is_none() {
                    return Ok((b"Username:".to_vec(), false));
                }
                self.state = LoginState::LoginWaitingUsername;
                self.username = String::from_utf8(response.unwrap_or(&[]).to_vec())?;
                self.state = LoginState::LoginWaitingPassword;
                return Ok((b"Password:".to_vec(), false));
            }
            LoginState::LoginWaitingUsername => {
                self.username = String::from_utf8(response.unwrap_or(&[]).to_vec())?;
                self.state = LoginState::LoginWaitingPassword;
                return Ok((b"Password:".to_vec(), false));
            }
            LoginState::LoginWaitingPassword => {
                self.password = String::from_utf8(response.unwrap_or(&[]).to_vec())?;
                (self.authenticator)(&self.username, &self.password)?;
                self.state = LoginState::LoginNotStarted;
                return Ok((Vec::new(), true));
            }
        }
    }
}
