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
