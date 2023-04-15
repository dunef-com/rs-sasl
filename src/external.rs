use crate::sasl;

use anyhow::{anyhow, Result};

/// The EXTERNAL mechanism name.
pub const EXTERNAL: &str = "EXTERNAL";

/// An implementation of the EXTERNAL authentication mechanism, as described in
/// RFC 4422. Authorization identity may be left blank to indicate that the
/// client is requesting to act as the identity associated with the
//. authentication credentials.
pub struct ExternalClient {
    identity: String,
}

impl ExternalClient {
    pub fn new(identity: String) -> Self {
        Self {
            identity,
        }
    }
}

impl sasl::Client for ExternalClient {
    fn start(&mut self) -> Result<(String, Vec<u8>)> {
        Ok((
            EXTERNAL.to_string(),
            self.identity.clone().into_bytes(),
        ))
    }

    fn next(&mut self, _challenge: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!(sasl::ERR_UNEXPECTED_SERVER_CHALLENGE))
    }
}

/// ExternalAuthenticator authenticates users with the EXTERNAL mechanism. If
/// the identity is left blank, it indicates that it is the same as the one used
/// in the external credentials. If identity is not empty and the server doesn't
/// support it, an error must be returned.
pub type ExternalAuthenticator = Box<dyn Fn(&str) -> Result<()> + Send>;

/// NewExternalServer creates a server implementation of the EXTERNAL
/// authentication mechanism, as described in RFC 4422.
pub struct ExternalServer {
    done: bool,
    authenticator: ExternalAuthenticator,
}

impl ExternalServer {
    pub fn new<F>(authenticator: ExternalAuthenticator) -> Self {
        Self {
            done: false,
            authenticator,
        }
    }
}

impl sasl::Server for ExternalServer {
    fn next(&mut self, response: Option<&[u8]>) -> Result<(Vec<u8>, bool)> {
        if self.done {
            return Err(anyhow!(sasl::ERR_UNEXPECTED_CLIENT_RESPONSE));
        }

        if response.is_none() {
            return Ok((Vec::new(), false));
        }
        let response = response.unwrap();

        self.done = true;

        if response.contains(&b'\x00') {
            return Err(anyhow!("identity contains a NUL character"));
        }

        (self.authenticator)(std::str::from_utf8(response)?)?;
        Ok((Vec::new(), true))
    }
}