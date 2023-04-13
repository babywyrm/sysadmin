
const CryptoJS = require('crypto-js');
const fs = require('fs');
const readline = require('readline');

var wordlist = '/usr/share/wordlists/rockyou.txt';

var rl = readline.createInterface({
    input : fs.createReadStream(wordlist)
});

var enc2 = "THINGSTHO"

rl.on('line', function (word) {
    var dec = CryptoJS.AES.decrypt(enc2, word).toString();
    try {
        var secret = CryptoJS.AES.decrypt(secret2, dec).toString(CryptoJS.enc.Utf8);
        if (
            (/^[0-9a-f]+$/i.test(secret) || /^[2-7a-z]+=*$/i.test(secret)) && secret.length > 5
          ) {
            console.log("Secret: " + secret);
            console.log("Passphrase: " + word);
            process.exit(0);
          }      
    }
    catch {}
});

////////////////
////////////////

const crypto = require("crypto-js");
const readline = require('readline');
const fs = require('fs');

const fileStream = fs.createReadStream('/root/HTB/Derailed/rockyou.txt');
const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity
});

const kpas_secret = "XU2FsXXXXXXXXXXXXXXXXXN2";
const kpas_enc_key = "XXXXU2FsdGVkX19dXXXXXXXX1";

rl.on('line', (line) => {
  const encrypt = crypto.AES.decrypt(kpas_enc_key, line.toString('ascii')).toString();
    try {
        const secret = crypto.AES.decrypt(kpas_secret, encrypt).toString(crypto.enc.Utf8);
        if(secret.length >= 1)
        console.log(secret);
    } catch {}
});

////////////////
////////////////
