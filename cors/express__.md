##
#
https://gist.github.com/adjeim/a2ddb5214c92ce5d708fb0a3d6f073f6
#
##

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
