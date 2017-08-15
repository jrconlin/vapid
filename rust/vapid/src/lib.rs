extern crate base64;
extern crate openssl;
extern crate serde_json;
extern crate time;

use openssl::bn::BigNum;
use openssl::bn::BigNumContext;
use openssl::hash::MessageDigest;
use openssl::ec;
use openssl::nid;
use openssl::sign::{Signer, Verifier};
use openssl::pkey;

use std::collections::HashMap;

// Preferred schema (in decending order)
static SCHEMA: &str = "vapid";

// Can this be killed/removed? Do I need it?
pub struct Key {
    pub key: ec::EcKey
}

//TODO: Toss in a module?

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

    // TODO: This may be wrong. There appears to be a set of derive funcs for PKeyCtx
    fn derive_ec_public_point(bits: String) -> Key {
        //Read a private key from a raw bit array
        let group = Key::group();
        let mut ctx = BigNumContext::new().unwrap();
        let mut new_key = ec::EcKeyBuilder::new().unwrap();

        let bytes: Vec<u8> = bits.into_bytes();
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

    fn from_public_raw(bits: String) -> Key {
        //Read a public key from a raw bit array
        let bytes: Vec<u8> = bits.into_bytes();
        let group = Key::group();
        let mut ctx = BigNumContext::new().unwrap();
        let point = ec::EcPoint::from_bytes(&group, &bytes, &mut ctx).unwrap();
        let new_key = ec::EcKey::from_public_key(&group, &point).unwrap();
        Key {
            key: new_key,
        }
    }
}


pub fn sign(key: Key, claims: &mut HashMap<String, serde_json::Value>) -> String {
    // convert the hash to a normalized JSON string
    // TODO: check and auto-fill claims
    let mut ctx = BigNumContext::new().unwrap();
    let prefix = String::from("{\"typ\":\"JWT\",\"alg\":\"ES256\"}");
    if !claims.contains_key(&String::from("sub")) {
        panic!("No \"sub\" found in claims");
    }
    if claims.get("sub").unwrap().as_str().unwrap().starts_with("mailto") == false {
        panic!("\"sub\" not a valid html reference.")
    }
    let today = time::now_utc();
    claims.entry(String::from("exp"))
        .or_insert(serde_json::Value::from(
            (today + time::Duration::hours(23)).to_timespec().sec));
    if claims.get("exp").unwrap().as_i64().unwrap() < today.to_timespec().sec {
        panic!("\"exp\" already expired.")
    }
    let json: String = serde_json::to_string(&claims).unwrap();
    let content = format!("{}.{}",
                          base64::encode_config(&prefix, base64::URL_SAFE_NO_PAD),
                          base64::encode_config(&json, base64::URL_SAFE_NO_PAD)
    );
    let auth_k = base64::encode_config(
        unsafe {
            &String::from_utf8_unchecked(key.key.public_key().unwrap().to_bytes(
                &Key::group(),
                ec::POINT_CONVERSION_COMPRESSED,
                &mut ctx).unwrap())
        },
        base64::URL_SAFE_NO_PAD,
    );
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
                             unsafe { &String::from_utf8_unchecked(signature) },
                             base64::URL_SAFE_NO_PAD
                         ));

    format!("Authorization: {} t={},k={}", SCHEMA, auth_t, auth_k)
}

struct AuthElements {
    t: Vec<String>,
    k: String,
}

fn parse_auth_token(auth_token: &mut String) -> AuthElements {
    let mut parts: Vec<&str> = auth_token.splitn(2, " ").collect();
    let mut schema = parts.remove(0).to_lowercase();
    // Ignore the first token if it's the header line.
    if schema == "authorization:" {
        schema = parts.remove(0).to_lowercase();
    }
    let mut reply: AuthElements = AuthElements { t: Vec::new(), k: String::from("") };
    match parts[0].to_lowercase().as_ref() {
        "vapid" => {
            let sub_parts: Vec<&str> = parts[1].splitn(2, ",").collect();
            for kvi in &sub_parts {
                let kv:Vec<String> = kvi.splitn(2, "=").map(|x| String::from(x)).collect();
                match kv[0].to_lowercase().as_ref() {
                    "t" => {
                        reply.t = kv[1].rsplit(".").map(|x| String::from(x)).collect();
                    },
                    "k" => { reply.k = String::from(kv[1].clone()) },
                    _ => {}
                }
            }
        },
        "webpush" => {
            reply.t = parts[1].split(".").map(|x| String::from(x)).collect();
        }
        _ => { panic!("Unknown schema type: {}", parts[0]) }
    };
    return reply
}

pub fn verify(auth_token: String, verification_token: String) -> bool {
    //Verify that the auth token string matches for the verification token string
    let auth_token = parse_auth_token(&mut String::from(auth_token.clone()));
    let pub_ec_key = Key::from_public_raw(auth_token.k);
    let pub_key = &pkey::PKey::from_ec_key(pub_ec_key.key).unwrap();
    let mut verifier = Verifier::new(
        MessageDigest::sha256(),
        pub_key,
    ).unwrap();

    verifier.update(&auth_token.t[0].clone().into_bytes());

    return verifier.finish(&auth_token.t[1].clone().into_bytes()).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign() {
        let key = Key::generate();

        let mut claims:HashMap<String, serde_json::Value> = HashMap::new();
        claims.insert(String::from("sub"),
                      serde_json::Value::from(String::from("mailto:mail@example.com")));
        let result = sign(key, &mut claims);
        assert!(result.starts_with("Authorization: "));
        assert!(result.contains(" vapid "));

        // tear apart the auth token for the happy bits
        let token = result.split(" ").nth(2).unwrap();
        let sub_parts: Vec<&str> = token.split(",").collect();
        let mut auth_parts:HashMap<String, String> = HashMap::new();
        for kvi in &sub_parts {
            let kv: Vec<String> = kvi.splitn(2, "=").map(|x| String::from(x)).collect();
            auth_parts.insert(kv[0].clone(), kv[1].clone());
         }
        assert!(auth_parts.contains_key("t"));
        assert!(auth_parts.contains_key("k"));

        // now tear apart the token
        let token:Vec<&str> = auth_parts.get("t").unwrap().split(".").collect();
        assert_eq!(token.len(), 3);

        let content = String::from_utf8(
            base64::decode_config(token[0], base64::URL_SAFE_NO_PAD).unwrap()
        ).unwrap();
        let items:HashMap<String, String> = serde_json::from_str(&content).unwrap();
        assert!(items.contains_key("typ"));
        assert!(items.contains_key("alg"));

        let content:String = String::from_utf8(
            base64::decode_config(token[1], base64::URL_SAFE_NO_PAD).unwrap()
        ).unwrap();
        let items:HashMap<String, serde_json::Value> = serde_json::from_str(&content).unwrap();

        assert!(items.contains_key("exp"));
        assert!(items.contains_key( "sub"));
    }

    // TODO: Test fail cases, verification, values, integration

    #[test]
    fn test_verify() {

    }
}

