use crate::sasl;

use anyhow::{anyhow, bail, Result};

/// The ANONYMOUS mechanism name.
pub const ANONYMOUS: &str = "ANONYMOUS";

/// A client implementation of the ANONYMOUS authentication mechanism, as
/// described in RFC 4505.
pub struct AnonymousClient {
    trace: String,
}

impl AnonymousClient {
    pub fn new(trace: String) -> Self {
        Self {
            trace,
        }
    }
}

impl sasl::Client for AnonymousClient {
    fn start(&mut self) -> Result<(String, Vec<u8>)> {
        Ok((
            ANONYMOUS.to_string(),
            self.trace.clone().into_bytes(),
        ))
    }

    fn next(&mut self, _challenge: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!(sasl::ERR_UNEXPECTED_SERVER_CHALLENGE))
    }
}

/// Get trace information from clients logging in anonymously.
pub type AnonymousAuthenticator = Box<dyn Fn(&str) -> Result<()>>;

/// A server implementation of the ANONYMOUS authentication mechanism, as
/// described in RFC 4505.
pub struct AnonymousServer {
    done: bool,
    authenticator: AnonymousAuthenticator,
}

impl AnonymousServer {
    pub fn new<F>(authenticator: F) -> Self
    where F: Fn(&str) -> Result<()> + 'static {
        Self {
            done: false,
            authenticator: Box::new(authenticator),
        }
    }
}

impl sasl::Server for AnonymousServer {
    fn next(&mut self, response: Option<&[u8]>) -> Result<(Vec<u8>, bool)> {
        if self.done {
            bail!(sasl::ERR_UNEXPECTED_CLIENT_RESPONSE);
        }

        // No initial response, send an empty challenge
        if response.is_none() {
            return Ok((Vec::new(), false));
        }
        let response = response.unwrap();

        self.done = true;

        (self.authenticator)(std::str::from_utf8(response)?)?;
        Ok((Vec::new(), true))
    }
}