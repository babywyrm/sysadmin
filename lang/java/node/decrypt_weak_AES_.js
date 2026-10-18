//
//
var CryptoJS = require("crypto-js");

const convert = (from, to) => str => Buffer.from(str, from).toString(to);
const hexToUtf8 = convert('hex', 'utf8');

var secret1 = "SLNFKSDFNSDFNKSDFSDFSDFSLDKFNSDFLK";

//
//

var lineReader = require('readline').createInterface({
    input: require('fs').createReadStream('/root/HTB/Derailed/rockyou.txt')
});

//
//

lineReader.on('line', function (line) {
    var cipher1 = CryptoJS.AES.decrypt(secret1, line);
    var originalText1 = cipher1.toString();
    var secret2 = "DNFKSDFNSDKFSNDFKLSDKFNSLDKFNSDFNSDFN";
    var cipher2 = CryptoJS.AES.decrypt(secret2, originalText1);
    var originalText2 = cipher2.toString();
    if (
        /^[A-Za-z0-9]*$/.test(hexToUtf8(originalText2)) &&
        hexToUtf8(originalText2) != "" &&
        hexToUtf8(originalText2).length == 16
        ) {
            console.log(originalText1);
            console.log(hexToUtf8(originalText2));
            console.log(line);
        }
    });

//
//
