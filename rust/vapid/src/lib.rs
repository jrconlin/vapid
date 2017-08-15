use std::collections::HashMap;
use openssl::ec::EcKey;
use openssl::nid;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}

static SCHEMA:String = "WebPush";

struct Key {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    key_id : Nid,
}

impl Key {
    fn init() {
        public_key = vec![];
        private_key = vec![];
        key_id = nid::SECP256R1
    }

    fn to_private_raw(&self) -> String {
        "Return the private key as a raw bit array"
    }

    fn from_private_raw(bits:String) {
        "Read a private key from a raw bit array"
    }

    fn to_public_raw(&self) -> String {
        "Return the public key as a raw bit array"
    }

    fn from_public_raw(bits:String) {
        "Read a public key from a raw bit array"
    }

}

mod Vapid {

    pub fn generate_keys() -> Key {
        "Generate the VAPID private key"
    }

    pub fn sign(key: Key, claims: HashMap) -> String {
        "Sign the claims"
    }

    pub fn verify(key: Key, validation_token: String, verification_token:String) -> bool {
        "Verify that the validation token string matches for the verification token string"
    }
}



