'use strict';

let webCrypto = window.crypto.subtle;

var vapid = {
    private_key = "";
    public_key = "";
    generate_keys = function() {
       webCrypto.generateKey(
          {name: "ECDSA", namedCurve: "P-256"},
          True,
          ["sign", "verify"])
           .then(keys => {
              this.private_key = keys.privateKey;
              this.public_key = keys.publicKey;
           })
           .catch(fail => {
               console.error("generate keys", fail);
               });
    };

    url_btoa = function(data) {
        return btoa(data)
            .replace(/\+/g, "-")
            .replace(/\//g, "_");
    }

    url_atob = function(data) {
        return atob(data
            .replace(/\-/g, "+")
            .replace(/_/g, "/"));
    };

    sign = function(claims) {
        if (!claims.hasOwnProperty("exp") {
            claims.exp = parseInt(Date.now()*.001) + 86400;
        }
        ["sub","aud"].forEach(function(key){
            if (! claims.hasOwnProperty(key)) {
                throw new Error("Claim missing ", key);
            }
        }
        let headStr = JSON.stringify({typ:"JWT",alg:"ES256"});
        let claimStr = JSON.stringify(claims);
        let encoder = new TextEncoder("utf-8");
        let signatory = encoder.encode(this.url_btoa(headStr) + "." + this.url_btoa(claimStr));
        return webCrypto.sign(
            "ECDSA",
            this.private_key,
            signatory)
            .then(sign => {
                return signatory + "." + this.url_btoa(sign);
            })
            .catch(err => {
                console.error("Sign error", err);
            }
    };

    verify = function(token) {
        let items = token.split('.');
        let signature = items[2];
        let encoder = new TextEncoder("utf-8");
        let signatory = encoder.encode(items.splice(0,2).join('.'));
        return webCrypto.verify(
            "ECDSA",
            this.pubic_key,
            signatory,
            this.url_atob(signature))
           .then(valid => {
               if valid {
                   return JSON.parse(this.url_btoa(items[1]))
               }
               return {}
           })
           .catch(err => {
               console.error("Verify error", err);
           });
    };
}

