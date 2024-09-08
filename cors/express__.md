##
#
https://gist.github.com/adjeim/a2ddb5214c92ce5d708fb0a3d6f073f6
#
##

# CORS Middleware for Node.js and Express

```
var allowedHost = {
    'http://localhost:3001': true,
    'http://localhost:7357': true
};

var allowCrossDomain = function(req, res, next) {
  if(allowedHost[req.headers.origin]) {
    res.header('Access-Control-Allow-Credentials', true);
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');
    // intercept OPTIONS method
    if ('OPTIONS' == req.method) {
      res.send(200);
    }
    else {
      next();
    }
  } else {
    res.send(403, {auth: false});
  }
};
```


```
/*
 * CORS Support in my Node.js web app written with Express
 */

// http://stackoverflow.com/questions/7067966/how-to-allow-cors-in-express-nodejs
app.all('/*', function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", 'Content-Type, X-Requested-With');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    next();
});
// handle OPTIONS requests from the browser
app.options("*", function(req,res,next){res.send(200);});

// routes follow below
```

CORS Cheat Sheet for Express + TypeScript
CORS Cheat Sheet for Express + TypeScript.md
Install cors package and its TypeScript types:

```
npm install cors
npm install --save-dev @types/cors
Update the entry point of your Express app to allow your server to use cors middleware. Configure your CORS options with the origins you would like to allow.
import express from 'express';
import cors from 'cors';

const app = express();

// Add a list of allowed origins.
// If you have more origins you would like to add, you can add them to the array below.
const allowedOrigins = ['http://localhost:3000'];

const options: cors.CorsOptions = {
  origin: allowedOrigins
};

// Then pass these options to cors:
app.use(cors(options));

app.use(express.json());


app.listen(5000, () => {
  console.log('Express server listening on port 5000');
});
@SchoolyB
SchoolyB commented on May 6, 2023
THANK YOU 👍

@hasael-web
hasael-web commented on Oct 25, 2023
thank you

@Demnu
Demnu commented on Nov 4, 2023
perfect! thankyou
```
@DhruvSavaj
DhruvSavaj commented on Feb 24
Thanks, I resolved the error but CORS is not preventing it properly, do you have any idea?

I have allowed only one origin "http://localhost:3000", and I am testing with the "http://localhost:450" URL from Postman, by changing "Origin".

Here is my sample cURL, localhost:8936 is my API endpoint
```
curl --location 'localhost:8936' \ --header 'Origin: localhost:450'
```
It is still getting a 200 OK response.

@socx
socx commented on Mar 20
Very useful! Thanks.
