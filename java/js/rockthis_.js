
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
