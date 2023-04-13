use anyhow::{Result};

pub const ERR_UNEXPECTED_CLIENT_RESPONSE: &str = "sasl: unexpected client response";
pub const ERR_UNEXPECTED_SERVER_CHALLENGE: &str = "sasl: unexpected server challenge";

/// Client interface to perform challenge-response authentication.
pub trait Client {
    /// Begins SASL authentication with the server. It returns the
    /// authentication mechanism name and "initial response" data (if required
    /// by the selected mechanism). A non-nil error causes the client to abort
    /// the authentication attempt.
    /// 
    /// A nil ir value is different from a zero-length value. The nil value
    /// indicates that the selected mechanism does not use an initial response,
    /// while a zero-length value indicates an empty initial respons
    /// e, which must
    /// be sent to the server.
    fn start(&mut self) -> Result<(String, Vec<u8>)>;
	
    /// Continues challenge-response authentication. A non-nil error causes
    /// the client to abort the authentication attempt.
    fn next(&mut self, challenge: &[u8]) -> Result<Vec<u8>>;
}

/// Server interface to perform challenge-response authentication.
pub trait Server {
    /// Begins or continues challenge-response authentication. If the client
    /// supplies an initial response, response is non-nil.
    /// 
    /// If the authentication is finished, done is set to true. If the
    /// authentication has failed, an error is returned.
    fn next(&mut self, response: Option<&[u8]>) -> Result<(Vec<u8>, bool)>;
}