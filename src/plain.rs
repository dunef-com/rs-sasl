use crate::sasl;

use anyhow::{anyhow, bail, Result};

/// The PLAIN mechanism name.
pub const PLAIN: &str = "PLAIN";

/// A client implementation of the PLAIN authentication mechanism, as described
/// in RFC 4616. Authorization identity may be left blank to indicate that it is
/// the same as the username.
pub struct PlainClient {
    identity: String,
    username: String,
    password: String,
}

impl PlainClient {
    pub fn new(identity: String, username: String, password: String) -> Self {
        Self {
            identity,
            username,
            password,
        }
    }
}

impl sasl::Client for PlainClient {
    fn start(&mut self) -> Result<(String, Vec<u8>)> {
        Ok((
            PLAIN.to_string(),
            format!("{}\x00{}\x00{}", self.identity, self.username, self.password).into_bytes()
        ))
    }

    fn next(&mut self, _challenge: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!(sasl::ERR_UNEXPECTED_SERVER_CHALLENGE))
    }
}

/// authenticates users with an identity, a username and a password. If the
/// identity is left blank, it indicates that it is the same as the username.
/// If identity is not empty and the server doesn't support it, an error must be
/// returned.
pub type PlainAuthenticator = Box<dyn Fn(&str, &str, &str) -> Result<()> + Send>;

/// A server implementation of the PLAIN authentication mechanism, as described
/// in RFC 4616.
pub struct PlainServer {
    done: bool,
    authenticator: PlainAuthenticator,
}

impl PlainServer {
    pub fn new(authenticator: PlainAuthenticator) -> Self {
        Self {
            done: false,
            authenticator,
        }
    }
}

impl sasl::Server for PlainServer {
    fn next(&mut self, response: Option<&[u8]>) -> Result<(Vec<u8>, bool)> {
        if self.done {
            bail!(sasl::ERR_UNEXPECTED_CLIENT_RESPONSE);
        }

        // No initial response, send an empty challenge
        if response.is_none() {
            return Ok((Vec::new(), false));
        }
        let response = response.unwrap();

        let mut parts = response.split(|&b| b == b'\x00');
        let identity = parts.next().ok_or_else(|| anyhow!("sasl: missing identity"))?;
        let username = parts.next().ok_or_else(|| anyhow!("sasl: missing username"))?;
        let password = parts.next().ok_or_else(|| anyhow!("sasl: missing password"))?;

        (self.authenticator)(
            std::str::from_utf8(identity)?,
            std::str::from_utf8(username)?,
            std::str::from_utf8(password)?,
        )?;

        self.done = true;

        Ok((Vec::new(), true))
    }
}

#[test]
fn test_new_plain_client() -> Result<()> {
    use crate::sasl::Client;

    let mut c = PlainClient::new("identity".to_string(), "username".to_string(), "password".to_string());

    let (mech, ir) = c.start().map_err(|e| anyhow!("Error while starting client: {}", e))?;
    if mech != PLAIN {
        bail!("Invalid mechanism name: {}", mech);
    }

    let expected = vec!(105, 100, 101, 110, 116, 105, 116, 121, 0, 117, 115, 101, 114, 110, 97, 109, 101, 0, 112, 97, 115, 115, 119, 111, 114, 100);
    if ir != expected {
        bail!("Invalid initial response: {:?}", ir);
    }

    Ok(())
}