extern crate base64;
extern crate openssl;
extern crate serde_json;

use openssl::bn::BigNum;
use openssl::bn::BigNumContext;
use openssl::hash::MessageDigest;
use openssl::ec;
use openssl::nid;
use openssl::sign::{Signer, Verifier};
use openssl::pkey;

use std::collections::HashMap;
use openssl::error::ErrorStack;
use std::error::Error;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}


static SCHEMA: &str = "WebPush";

// Can this be killed/removed? Do I need it?
#[allow(dead_code)]
pub struct Key {
    pub key: ec::EcKey ,
}

#[allow(dead_code)]
impl Key {
    fn new() -> Key {
        Key {
            key: ec::EcKey::from_curve_name(Key::name()).unwrap(),
        }
    }

    fn name() -> nid::Nid {
        nid::X9_62_PRIME256V1
    }

    fn group() -> ec::EcGroup {
        ec::EcGroup::from_curve_name(Key::name()).expect("EC Prime256v1 curve not supported")
    }

    fn generate() -> Key {
        Key {
            key: ec::EcKey::generate(&Key::group()).unwrap(),
        }
    }

    fn to_private_raw(&self) -> String {
        // Return the private key as a raw bit array
        let key = self.key.private_key().unwrap();
        String::from_utf8(key.to_vec()).unwrap()
    }

    // TODO: This may be wrong. Therea pears to be a set of derive funcs for PKeyCtx
    fn derive_ec_public_point(bits:String) -> Key {
        //Read a private key from a raw bit array
        let group = Key::group();
        let mut ctx = BigNumContext::new().unwrap();
        let mut new_key = ec::EcKeyBuilder::new().unwrap();

        let bytes:Vec<u8>  = bits.into_bytes();
        let secret = BigNum::from_slice(&bytes).unwrap();
        let mut point = ec::EcPoint::new(&group).unwrap();
        point.mul_generator(&group, &secret, &mut ctx).unwrap();
        new_key.set_group(&group);
        new_key.set_public_key(&point);
        new_key.set_private_key(&secret);
        Key {
            key: new_key.build(),
        }
    }

    fn to_public_raw(&self) -> String {
        //Return the public key as a raw bit array
        let mut ctx = BigNumContext::new().unwrap();
        let group = Key::group();

        let key = self.key.public_key().unwrap();
        String::from_utf8(key.to_bytes(&group,
                                       ec::POINT_CONVERSION_COMPRESSED,
                                       &mut ctx).unwrap()).unwrap()
    }

    fn from_public_raw(bits:String) -> Key {
        //Read a public key from a raw bit array
        let bytes:Vec<u8> = bits.into_bytes();
        let group = Key::group();
        let mut ctx = BigNumContext::new().unwrap();
        let point = ec::EcPoint::from_bytes(&group, &bytes, &mut ctx).unwrap();
        let new_key = ec::EcKey::from_public_key(&group, &point).unwrap();
        Key {
            key: new_key,
        }
    }

}

pub fn generate_keys() -> Key {
    //Generate the VAPID private key
    Key::generate()
}

pub fn sign(key: Key, claims: HashMap<String, String>) -> String {
    // convert the hash to a normalized JSON string
    // TODO: check and auto-fill claims
    let mut ctx = BigNumContext::new().unwrap();
    let prefix:String = String::from("{\"typ\":\"JWT\",\"alg\":\"ES256\"}");
    let json:String = serde_json::to_string(&claims).unwrap();
    let content = format!("{}.{}",
        base64::encode_config(&prefix, base64::URL_SAFE_NO_PAD),
        base64::encode_config(&json, base64::URL_SAFE_NO_PAD)
    );
    // TODO: Fix ownership issues with key.key
    let pub_key = &pkey::PKey::from_ec_key(key.key).unwrap();

    let mut signer = Signer::new(
        MessageDigest::sha256(),
        pub_key,
    ).unwrap();
    signer.update(&content.clone().into_bytes()).unwrap();
    let signature = signer.finish().unwrap();

    let auth_t = format!("{}.{}",
                         content.clone(),
                         base64::encode_config(
                             unsafe{ &String::from_utf8_unchecked(signature) },
                             base64::URL_SAFE_NO_PAD
                         ));
    let auth_k = base64::encode_config(
        unsafe {
            &String::from_utf8_unchecked(key.key.public_key().unwrap().to_bytes(
                &Key::group(),
                ec::POINT_CONVERSION_COMPRESSED,
                &mut ctx).unwrap())
         },
        base64::URL_SAFE_NO_PAD,
    );

    format!("Authorization: {} t={},k={}", SCHEMA, auth_t, auth_k)
}

pub fn verify(key: Key, validation_token: String, verification_token:String) -> bool {
    //Verify that the validation token string matches for the verification token string
    return false
}
