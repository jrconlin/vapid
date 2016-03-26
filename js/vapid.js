/*
 * This is a JavaScript Scratchpad.
 *
 * Enter some JavaScript, then Right Click or choose from the Execute Menu:
 * 1. Run to evaluate the selected text (Ctrl+R),
 * 2. Inspect to bring up an Object Inspector on the result (Ctrl+I), or,
 * 3. Display to insert the result in a comment after the selection. (Ctrl+L)
 */

'use strict';

var webCrypto = window.crypto.subtle;

function ord(c){
    return c.charCodeAt(0);
}

function chr(c){
    return String.fromCharCode(c);
}

var vapid = {
    _private_key:  "",
    _public_key: "",
    generate_keys: function() {
       webCrypto.generateKey(
          {name: "ECDSA", namedCurve: "P-256"},
          true,
          ["sign", "verify"])
           .then(keys => {
              this._private_key = keys.privateKey;
              this._public_key = keys.publicKey;
              console.info("Keys defined.");
           })
           .catch(fail => {
               console.error("generate keys", fail);
               });
    },

    url_btoa: function(data) {
        return btoa(data)
            .replace(/\+/g, "-")
            .replace(/\//g, "_");
    },

    url_atob: function(data) {
        return atob(data
            .replace(/\-/g, "+")
            .replace(/_/g, "/"));
    },

    export_private_der: function() {
        return webCrypto.exportKey("jwk", this._private_key)
            .then(k => {
                // verifying key
                let xv = this.url_atob(k.x);
                let yv = this.url_atob(k.y);
                // private key
                let dv = this.url_atob(k.d);

                // verifying key (public)
                let vk = '\x00\x04' + xv + yv;
                // \x02 is integer
                let int1 = '\x02\x01\x01'; // integer 1
                // \x04 is octet string
                let dvstr = '\x04' + chr(dv.length) + dv;
                let curve_oid = "\x06\x08" +
                    "\x2a\x86\x48\xce\x3d\x03\x01\x07";
                // \xaX is a construct, low byte is order.
                let curve_oid_const = '\xa0' + chr(curve_oid.length) +
                    curve_oid;
                // \x03 is a bitstring
                let vk_enc = '\x03' + chr(vk.length) + vk;
                let vk_const = '\xa1' + chr(vk_enc.length) + vk_enc;
                // \x30 is a sequence start.
                let seq = int1 + dvstr + curve_oid + vk_const;
                console.debug("Sequence:", seq.length, seq);
                let rder = "\x30" + chr(seq.length) + seq;
                return btoa(rder);
            })
        .catch(err => console.error(err))
    },

    export_public_der: function () {
        return webCrypto.exportKey("raw", this._public_key)
            .then(k => {
                // raw keys always begin with a 4
                let xv = new Uint8Array(k.slice(1, 33));
                let yv = new Uint8Array(k.slice(33));

                let xs = "";
                for (let i of xv) {xs += String.fromCharCode(i)};

                let ys = "";
                for (let i of yv) {ys += String.fromCharCode(i)};
                let point = "\x00\x04" + xs + ys;
                // a combination of the oid_ecPublicKey + p256 encoded oid
                let prefix = "\x30\x13" +  // sequence + length
                    "\x06\x07" + "\x2a\x86\x48\xce\x3d\x02\x01" +
                    "\x06\x08" + "\x2a\x86\x48\xce\x3d\x03\x01\x07"
                let encPoint = "\x03" + chr(point.length) + point
                let rder = "\x30" + chr(prefix.length + encPoint.length) +
                    prefix + encPoint;
                let der = btoa(rder);
                return der;
            });
    },

    sign: function(claims) {
        if (this._public_key == "") {
            throw new Error("No keys defined. Please use generate_keys() or load a public key.");
        }
        if (!claims.hasOwnProperty("exp")) {
            claims.exp = parseInt(Date.now()*.001) + 86400;
        }
        ["sub","aud"].forEach(function(key){
            if (! claims.hasOwnProperty(key)) {
                throw new Error("Claim missing ", key);
            }
        })
        let headStr = JSON.stringify({typ:"JWT",alg:"ES256"});
        let claimStr = JSON.stringify(claims);
        let encoder = new TextEncoder("utf-8");
        let content = this.url_btoa(headStr) + "." + this.url_btoa(claimStr);
        let signatory = encoder.encode(content);
        return webCrypto.sign(
            {name:"ECDSA", hash:{name:"SHA-256"}},
            this._private_key,
            signatory)
            .then(sign => {
                return this.public_der()
                    .then( der => {
                        return {
                            authorization: "Bearer " + content + "." + this.url_btoa(sign),
                            "crypto-key": "p256ecdsa=" + der,
                        }
                    })
            })
            .catch(err => {
                console.error("Sign error", err);
            })
    },

    verify: function(token) {
        if (this._private_key == "") {
            throw new Error("No keys defined. Please use generate_keys() or load a private key.");
        }
        let items = token.split('.');
        let signature = items[2];
        let encoder = new TextEncoder("utf-8");
        let signatory = encoder.encode(items.splice(0,2).join('.'));
        return webCrypto.verify(
            {name:"ECDSA", hash:{name:"SHA-256"}},
            this.pubic_key,
            signatory,
            this.url_atob(signature))
           .then(valid => {
               if (valid) {
                   return JSON.parse(this.url_btoa(items[1]))
               }
               return {}
           })
           .catch(err => {
               console.error("Verify error", err);
           });
    }
}
