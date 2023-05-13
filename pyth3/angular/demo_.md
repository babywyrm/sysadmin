
##
#
https://developer.okta.com/blog/2019/03/25/build-crud-app-with-python-flask-angular
#
##






Getting error Error: No such command “root)/shims/python”.

Aug '19
oktadev-​blog
Randall Degges

Sounds like you don’t have the Python interpreter working properly. You may want to re-install Python.

Sep '19
oktadev-​blog
Jeremy Savoy

When starting up ng I get the following, I have checked and rechecked my code against the instructions – something is missing as I believe I have followed to the letter …

** Angular Live Development Server is listening on localhost:8080, open your browser on http://localhost:8080/ **

Date: 2019-09-23T16:46:52.004Z
Hash: 08ef2b6ffd5bdd5068d2
Time: 5883ms

chunk {es2015-polyfills} es2015-polyfills.js, es2015-polyfills.js.map (es2015-polyfills) 285 kB [initial] [rendered]
chunk {main} main.js, main.js.map (main) 1.99 kB [initial] [rendered]
chunk {polyfills} polyfills.js, polyfills.js.map (polyfills) 93.3 kB [initial] [rendered]
chunk {runtime} runtime.js, runtime.js.map (runtime) 6.08 kB [entry] [rendered]
chunk {styles} styles.js, styles.js.map (styles) 181 kB [initial] [rendered]
chunk {vendor} vendor.js, vendor.js.map (vendor) 327 kB [initial] [rendered]

ERROR in src/app/app-routing.module.ts(22,6): error TS2322: Type ‘{ yourOktaDomain: any; }’ is not assignable to type ‘string’.
src/app/app-routing.module.ts(22,15): error TS2304: Cannot find name ‘yourOktaDomain’.
src/app/app-routing.module.ts(23,6): error TS2322: Type ‘{ yourClientId: any; }’ is not assignable to type ‘string’.
src/app/app-routing.module.ts(23,17): error TS2304: Cannot find name ‘yourClientId’.

:information_source: ｢wdm｣: Failed to compile.

Sep '19
oktadev-​blog
Jeremy Savoy

Ok, so I figured this out – for someone new to Okta (like myself), in app-routing.module.ts you need to replace the values “yourOktaDomain” and “yourClientID” with the following:


issuer: ‘https://<your_dev_domain_from_okta>.okta.com/oauth2/default’,
clientId: ‘<your_client_id_from_okta>’,

Also, the files home.component.scss and login.component.scss don’t exist - you will have to manually touch them as only the extensions “sass” for those files exist when created with the commands above. After that, things worked as expected.

Aug '20
oktadev-​blog
Varun Suraj

It seems like since this post was published, changes have been made to @okta/okta-angular. Specifically, OktaAuthModule doesn’t have the function initAuth() anymore. When I write this in Visual Studio Code, I get the following error message: “Property ‘initAuth’ does not exist on type ‘typeof OktaAuthModule’”. How can I fix this error? P.S. this is from this section: https://developer.okta.com/…

Aug '20
oktadev-​blog
Matt Raible

Hello Varun,

Please see our Configure the Angular SDK docs to see how to configure Angular with the latest version of our SDK. In short, change this:


@NgModule({
 imports: [
   RouterModule.forRoot(routes),
   OktaAuthModule.initAuth({
     issuer: {yourOktaDomain},
     clientId: {yourClientId},
     redirectUri: ‘http://localhost:8080/implicit/callback’,
     scope: ‘openid profile email’
   })
 ],
 exports: [RouterModule]
})
To this:


import {
  OKTA_CONFIG,
  OktaAuthModule,
} from ‘@okta/okta-angular’;

const config = {
  issuer: {yourOktaDomain},
  clientId: {yourClientId},
  redirectUri: ‘http://localhost:8080/implicit/callback’,
  scope: ‘openid profile email’
};

@NgModule({
  imports: [
    OktaAuthModule,
  ],
  providers: [
    { provide: OKTA_CONFIG, useValue: config },
  ],
})
I’ll update this blog post soon to use the latest version.

Jan '21
oktadev-​blog
Claudio

Hello can you help me please.
I have 2 errors in home.component.ts
https://uploads.disquscdn.c…

1.- import GithubClientService
El módulo ‘"…/gb-client.service"’ no tiene ningún miembro ‘GithubClientService’ exportado.ts(2305)

2.- (component) HomeComponent: class
class HomeComponent
Can’t resolve all parameters for HomeComponent in /home/claudio/Datos/www/Python/mapy/app/http/web-app/src/app/home/home.component.ts: ([object Object], ?, ?).ng

Jan '21
oktadev-​blog
Matt Raible

I’m not sure, it looks similar to this example’s home.component.ts. I’d try comparing your code to this post’s repo on GitHub.

Jan '21
oktadev-​blog
Claudio

Ya lo hice, compare todo el código y no encuentro la diferencia

Feb '21
oktadev-​blog
Matt Raible

If I clone the repo:


git clone GitHub - oktadev/okta-python-angular-crud-example: Flask + Angular CRUD Example
And open it in IntelliJ IDEA, you’re right, there are red lines under a lot of the imports. However, if I do the following, the lines disappear.


cd app/http/web-app
npm i
Proof:

https://uploads.disquscdn.c…

Feb '21
oktadev-​blog
Derek Wohlfahrt

It appears this is not actually verifying the access token, just decoding the payload

token = authorization.split(’ ')[1]
resp = decode(token, None, verify=False, algorithms=[‘HS256’])

Or am I missing something?

Mar '21
oktadev-​blog
Sirius Black

i faced same issue, it is due to pyjwt version mismatch. Try installing same version mentioned above, it worked for me. Thanks.

Sep '22
Andy​Lu
The process you describe

Create a new OIDC app by navigating to Applications > Add Application > select Single-Page > App , and click Next . Fill in the following values: …

does not reflect the current reality on the Okta-homepage.
I clicked on “Applications” → “Applications” and then did not manage to resemble your instructions based on what is actually there.

Please provide updated instructions, thanks in advance.
Andy

Continue Discussion
