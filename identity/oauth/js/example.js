OAuthClient.js
import fetch from 'node-fetch'

// some provider data is copied from github.com/simov/grant
const providers = {
  bogus: {
    authorize_url: "http://localhost:8282/auth/request/path",
    access_url: "http://localhost:8282/access/token/request",
  },

  google: {
    authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
    access_url: "https://oauth2.googleapis.com/token"
  },

  github: {
    authorize_url: "https://github.com/login/oauth/authorize",
    access_url: "https://github.com/login/oauth/access_token",
  },
}

export default class OAuthClient {
  constructor(config) {
    this.config = config
    this.provider = providers[config.provider]

    if (!this.provider) throw new Error(`Unknown OAuth provider ${config.provider}`)
  }

  authorizeUrl() {
    const { client_id, redirect_uri } = this.config
    const url = new URL(this.provider.authorize_url)
    const params = url.searchParams

    params.set('response_type', 'code')
    params.set('client_id', client_id)
    params.set('redirect_uri', redirect_uri)

    return url.toString()
  }

  async fetchAccessToken(code) {
    const { client_id, client_secret } = this.config

    const response = await fetch(this.provider.access_url, {
      method: 'POST',
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id,
        client_secret
      })
    })

    return {
      success: response.ok,
      payload: await response.json()
    }
  }
}
usage.js
import OAuthClient from './OAuthClient.js'

// instantiate the client
const client = new OAuthClient({
  provider: 'google',
  client_id: '...',
  client_secret: '...',
  redirect_uri: '...'
})

// Step 1: Generate the authorization url, and redirect the user there
const url = client.authorizationUrl()
redirectTo(url)

// Step 2: When the user returns to the callback url, the url will contain a `code` query param.
// Use that `code` to get the access token
const code = params.get('code')
const response = await client.fetchAccessToken(code)

if (response.success) {
  // log the access token
  console.log(response.payload)
}

//
//

mkdir oauth2-server
cd oauth2-server
npm init -y
npm install express oauth2-server body-parser
Create the Server Code:
Create a file named server.js with the following content:

javascript
Copy code
// server.js
const express = require('express');
const bodyParser = require('body-parser');
const OAuth2Server = require('oauth2-server');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const Request = OAuth2Server.Request;
const Response = OAuth2Server.Response;

const oauth = new OAuth2Server({
    model: require('./model.js'),
    accessTokenLifetime: 60 * 60, // 1 hour
    allowBearerTokensInQueryString: true
});

// Endpoint to obtain an access token
app.post('/oauth/token', (req, res) => {
    const request = new Request(req);
    const response = new Response(res);

    oauth.token(request, response)
        .then((token) => {
            res.json(token);
        })
        .catch((err) => {
            res.status(err.code || 500).json(err);
        });
});

// Protected resource endpoint
app.get('/secure', (req, res, next) => {
    const request = new Request(req);
    const response = new Response(res);

    oauth.authenticate(request, response)
        .then((token) => {
            res.json({ message: 'Secure data', user: token });
        })
        .catch((err) => {
            res.status(err.code || 500).json(err);
        });
});

app.listen(3000, () => {
    console.log('OAuth2 server listening on port 3000');
});
Create the Model:
Create a file named model.js to handle OAuth2 data and validation logic. This is a basic example and does not include database integration.

javascript
Copy code
// model.js
const uuid = require('uuid');

let tokens = [];
let clients = [{
    clientId: 'client123',
    clientSecret: 'secret123',
    grants: ['password']
}];
let users = [{
    id: 'user1',
    username: 'john',
    password: 'doe'
}];

module.exports = {
    getAccessToken: function(token) {
        const accessToken = tokens.find(t => t.accessToken === token);
        return accessToken ? {
            accessToken: accessToken.accessToken,
            accessTokenExpiresAt: accessToken.accessTokenExpiresAt,
            client: { id: accessToken.clientId },
            user: { id: accessToken.userId }
        } : false;
    },

    getClient: function(clientId, clientSecret) {
        return clients.find(client => client.clientId === clientId && client.clientSecret === clientSecret);
    },

    saveToken: function(token, client, user) {
        const accessToken = {
            accessToken: token.accessToken,
            accessTokenExpiresAt: token.accessTokenExpiresAt,
            clientId: client.id,
            userId: user.id
        };
        tokens.push(accessToken);
        return accessToken;
    },

    getUser: function(username, password) {
        return users.find(user => user.username === username && user.password === password);
    },

    verifyScope: function(token, scope) {
        return true;
    },

    revokeToken: function(token) {
        tokens = tokens.filter(t => t.accessToken !== token.accessToken);
        return true;
    }
};
OAuth2 Client
Create a simple HTML file named client.html:

html
Copy code
<!DOCTYPE html>
<html>
<head>
    <title>OAuth2 Client</title>
</head>
<body>
    <h1>OAuth2 Client</h1>
    <div>
        <h2>Login</h2>
        <input type="text" id="username" placeholder="Username"><br>
        <input type="password" id="password" placeholder="Password"><br>
        <button onclick="login()">Login</button>
    </div>
    <div>
        <h2>Secure Data</h2>
        <button onclick="getSecureData()">Get Secure Data</button>
        <pre id="secureData"></pre>
    </div>

    <script>
        let accessToken = '';

        function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            fetch('http://localhost:3000/oauth/token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `grant_type=password&username=${username}&password=${password}&client_id=client123&client_secret=secret123`
            })
            .then(response => response.json())
            .then(data => {
                accessToken = data.access_token;
                alert('Login successful!');
            })
            .catch(error => console.error('Error:', error));
        }

        function getSecureData() {
            fetch('http://localhost:3000/secure', {
                headers: {
                    'Authorization': 'Bearer ' + accessToken
                }
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('secureData').textContent = JSON.stringify(data, null, 2);
            })
            .catch(error => console.error('Error:', error));
        }
    </script>
</body>
</html>

node server.js
