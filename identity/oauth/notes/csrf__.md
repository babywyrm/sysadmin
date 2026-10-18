CSRF Tokens in OAuth2 Scenarios
Preventing CSRF in Authorization Requests:

##
#
https://github.com/curveball/oauth2
#
##

When initiating the OAuth2 authorization flow (e.g., the authorization code flow), CSRF tokens can be used to protect against CSRF attacks during the authorization request.
The client generates a state parameter (which acts as a CSRF token) and includes it in the authorization request to the OAuth2 provider.
Upon redirection back to the client with the authorization code, the client verifies that the state parameter matches the one it initially sent.
Protecting API Endpoints:

For API requests that modify user data (e.g., POST, PUT, DELETE), CSRF tokens can still be used alongside OAuth2 tokens to ensure that the request is intentionally made by the user.
The client includes the CSRF token in the request headers or body, and the server validates the token before processing the request.
Implementing CSRF Protection in OAuth2 Authorization Flow
Step-by-Step:
Generate State Token:

When redirecting the user to the OAuth2 provider’s authorization endpoint, generate a unique state token and store it in the user’s session.
javascript
Copy code
// Pseudocode example
const stateToken = generateRandomToken();
sessionStorage.setItem('oauth2_state', stateToken);
const authUrl = `https://oauthprovider.com/auth?response_type=code&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI&state=${stateToken}`;
window.location.href = authUrl;
Include State Token in the Authorization Request:

The state token is sent as part of the authorization request to the OAuth2 provider.
Validate State Token:

When the OAuth2 provider redirects back to your application with the authorization code and state token, validate the state token against the one stored in the user’s session.
javascript
Copy code
// Pseudocode example
const returnedState = getQueryParameter('state');
const storedState = sessionStorage.getItem('oauth2_state');

if (returnedState !== storedState) {
    throw new Error('Invalid state token');
}

// Proceed with exchanging the authorization code for an access token
Benefits and Limitations
Benefits:
Mitigates CSRF Attacks: Prevents CSRF attacks during the OAuth2 authorization flow, ensuring that the authorization request is legitimate.
Adds an Extra Layer of Security: Even if an attacker obtains the OAuth2 tokens, CSRF tokens add an additional barrier for certain types of attacks, requiring the attacker to also obtain the CSRF token.
Limitations:
Not a Complete Solution: CSRF tokens do not protect against session hijacking or token theft where an attacker already has access to the OAuth2 tokens.
Requires Secure Storage: Both OAuth2 tokens and CSRF tokens must be stored securely to prevent access by malicious scripts.
Comprehensive Security Strategy
To provide robust security in an OAuth2 scenario, consider the following comprehensive strategy:

Use CSRF Tokens:

Implement CSRF protection for the OAuth2 authorization flow and API endpoints that modify data.
Secure Storage of Tokens:

Store OAuth2 tokens in HttpOnly cookies to prevent access by client-side scripts.
Short-Lived Tokens:

Use short-lived OAuth2 access tokens and implement refresh tokens to limit the impact of a compromised token.
Monitor and Detect Anomalies:

Implement monitoring to detect unusual login activity, such as logins from new devices or unexpected IP addresses.
Implement Multi-Factor Authentication (MFA):

Require MFA for sensitive operations to add an extra layer of security.
Scope Limitation:

Limit the permissions granted by OAuth2 tokens to the minimum necessary.
By integrating CSRF tokens with other security measures, you can enhance the overall security of your OAuth2 implementation and protect against a wider range of attacks.






To use this middleware, have a working OAuth2 authorization server. The Curveball project has one, but you can supply your own as long as it supports token introspection.

After you obtained your OAuth2 clientId, you can add this middleware:

import { Application } from '@curveball/core';
import oauth2 from '@curveball/oauth2';
import { OAuth2Client } from '@badgateway/oauth2-client';

const client = new OAuth2Client({
  clientId: 'My-app',
  introspectionEndpoint: 'https://my-oauth2-server.example.org/introspect',
});

const app = new Application();
app.use(oauth2({
  publicPrefixes: [
    '/health-check',
    '/login',
    '/register'
  ],
  client,
}));
It might be needed for your Curveball resource server to also authenticate itself to the OAuth2 server with its own credentials.

If this is the case, you must at least also pass the clientSecret property to OAuth2Client.

Modern servers allow clients to 'discover' the introspection endpoint, via a document hosted on /.well-known/oauth-authorization-server. If your server supports this, it's highly recommended to use this instead as other features and authentication schemes can automatically be discovered.

For these cases, all you need to do is specify the server and the client will do the rest:

const client = OAuth2Client({
  clientId: 'My-app',
  server: 'https://my-oauth2-server.example.org/',
});
That's it! Now your endpoints are secured.

Getting information about the logged in user
If you are writing an endpoint, and you want to know who is logged in, you can now use the auth helper:

function myController(ctx: Context) {

  /**
   * Returns true if the user is logged in
   */
  ctx.auth.isLoggedIn();

  /**
   * Returns information about the user.
   *
   * Return properties:
   *   id - Unique machine-readable id. Taken from the 'sub' from introspection.
   *        a12nserver will return a User url here.
   *   displayName - A human-readable username
   */
  console.log(
    ctx.auth.principal
  );

}
Privilege system
This package also provides an API for managing user privileges (Access Control Rules). If the OAuth2 introspection endpoint returned a list of privileges, this will be automatically used. a12n-server supports this.

The general structure of privileges is like this:

const privileges = {
  'https://my-api/article/1': ['read', 'write']
  'https://my-api/article/2': ['read', 'write']
}
At the top level is a list of resources a user has acccess to, and at the second level a list of privileges. For example:

The resource (like https://my-api/article/1) can be any URI and doesn't have to exist, as long as it's a good identifier for the resource.

Both the resource and the privilege names may be *, which means 'all'.

Given that the resources are URIs, it's possible to omit part of the URI.

So given if a user is accessing https://my-api/article/1 the following 3 calls are equivalent:

ctx.privileges.has('read', 'http://my-api/article/1');
ctx.privileges.has('read', '/article/1');
ctx.privileges.has('read');
Other examples:
function myController(ctx: Context) {

  /**
   * Returns true if a user had a privilege
   */
  ctx.privileges.has('read');

  /**
   * Throws a 403 Forbidden if a user did not have a privilege.
   */
  ctx.privileges.require('write');

  /**
   * Return the full privilege list for the current resource.
   */
  console.log(ctx.privileges.get());

}
Similar examples, but now with a resource specified:

function myController(ctx: Context) {

  /**
   * Returns true if a user had a privilege
   */
  ctx.privileges.has('read', 'http://my-other-api.example/foo');

  /**
   * Throws a 403 Forbidden if a user did not have a privilege.
   */
  ctx.privileges.require('write', 'http://articles.example/article/1');

  /**
   * Return the full privilege list for a resource.
   */
  console.log(ctx.privileges.get('http://api-example/groups/123'));

}
Providing your own privileges
If you are not using a12n-server, or a server that is compatible with its privilege system, you can also write your own middleware for providing privilege information.

The easiest is to add your middleware after the oauth2 middleware and set it up as such:

const app = new Application();

// OAuth2 middleware
app.use( oauth2({
  /* ... */
});



/**
 * Real applications probably store this in a database.
 */
const privilegeTable = {
  // A regular user
  'https://my-auth/user/1': {
    'https://my-api/article/1': ['read', 'write']
    'https://my-api/article/2': ['write']
  }
  // An admin user
  'https://my-auth/user/2': {
    '*': ['*']
  }
};


// Providing your own privileges
app.use((ctx, next) => {

  if (ctx.auth.isLoggedIn()) {
    if (ctx.auth.principal.id in privilegesTable) {
      ctx.privileges.setData(privilegesTable[ctx.auth.principal.id]);
    }
  }
  return next();

});
