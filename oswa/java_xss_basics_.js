

// https://blog.sessionstack.com/how-javascript-works-5-types-of-xss-attacks-tips-on-preventing-them-e6e28327748a
//
++++++++++++++++

let inputs = document.getElementsByTagName("input") 

for (let input of inputs){
    console.log(input.value)}

++++++++++++++++

function logKey(event){
  console.log(event.key)
}

document.addEventListener('keydown', logKey);

++++++++++++++++
