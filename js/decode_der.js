function decode_der(str) {
    /* Decode a Public Key DER string into a Uint8Array
     */
    arr = new Uint8Array(cstr.length)
    for (i=0; i<cstr.length;i++) {
        arr[i] = cstr.charCodeAt(i);
    }
    return arr;
}

function decode_pem(str) {
    /* Take a URL Safe base64 string and convert to a Uint8 Byte Array.
     *
     * See https://en.wikipedia.org/wiki/Base64 for characters exchanges
     */
    // Strip the header and footer, remove new lines.
    str.replace(/-{5}[^-]+-{5}/gm, '').replace("\n","");
    // convert to array
    return decode_der(str)
}

