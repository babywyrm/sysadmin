Security Assertion Markup Language (SAML) is an open standard for exchanging authentication and authorization data between parties, in particular, between an identity provider and a service provider. The relationship between both providers sets up a trust relationship. The [SAML 2.0 Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-saml2-bearer), allow an OAuth/OIDC client to use this existing trust. By providing a valid SAML Assertion to the authorization servers `/token` endpoint, the client can exchange an assertion for access/id tokens without requiring the client approval authorization step. This tutorial will demonstrate how to set up the grant type, then manually exchange a SAML Assertion for tokens. Afterward, an optional application can be configured to demonstrate the flow.

##
#
https://raw.githubusercontent.com/emanor-okta/saml-assertion-flow-samples/main/Manual_SAML_Assertion_Flow.md
#
##

# What You’ll Need

-   Okta tenant

    -   don’t have an Okta tenant, [create a new one here](https://www.okta.com/free-trial/)

-   [Golang](https://golang.org/dl/) (1.16+) **if running the sample application**.

# Reference Okta Org

A preconfigured Okta Org exists so settings can be verified. To view the configurations, login to <https://dev-96797994-admin.okta.com>  
Credentials  
Username: `read.only`  
Password: `Th1sPassword`  

# Configure the SAML Service Provider Application

The same Okta Org will both generate and consume a SAML Assertion. So the OIDC application will consume a SAML Assertion from the same Org it is defined in. To accomplish this a SAML Service Provider application using `https://httpbin.org/post` will be created.  

1.  In the Admin Console, navigate to **Applications** > **Applications**, click `Create App Integration`.

2.  Select **SAML 2.0**.

3.  Enter a **name** for your app and click `next`.

4.  For **Single sign on URL** enter `https://httpbin.org/post`

5.  Uncheck **Use this for Recipient URL and Destination URL**

6.  Enter `http://changeMeLater` for the **Recipient URL**, **Destination URL**, and **Audience URI**. These values will be updated later from the SAML Identity Provider.

7.  Click `Show advanced settings`.

8.  For **Response dropdown** select **Unsigned**

9.  Click `next`.

10. Select **I’m an Okta customer adding an internal app**, followed by selecting **This is an internal app that we have created**.

11. Click `finish`.

12. Open the newly created application and click the `Sign On` tab.

13. Click `View Setup Instructions`.

14. Click `Download certificate`.

    > **_NOTE:_**  this will save the certificate with a `.cert` extension. Change this extension to `.pem`.

15. Make note of the **Identity Provider Single Sign-On URL** and **Identity Provider Issuer**. These values will be used later.

16. Assign a test user to the application.

The SAML Service Provider Application is defined at **Applications** &gt; **Applications** &gt; **Manual SAML Assertion Flow** in the refrence Org.

# Configure the SAML Identity Provider

In Okta, configuring a SAML Identity Provider (IdP) means that Okta becomes the Service Provider (SP) and is capable of consuming a SAML Assertion sent from an external SAML IdP. In this sample, the same Okta Org serves as both IdP and SP.

1.  In the Admin Console, navigate to **Security** &gt; **Identity Providers**.

2.  Click `Add Identity Provider` and select **Add SAML 2.0 IdP**.

3.  Enter a **Name** for your IdP.

4.  For **IdP Username** select **idpuser.subjectNameId**.

5.  Under **SAML Protocol Settings** for **Idp Issuer URI**, enter the **Identity Provider Issuer** value copied from the SP application in step 15. For **Idp Single Sign-On URL**, enter the **Identity Provider Single Sign-On URL** value copied from the SP application in step 15.

6.  For **IdP Signature Certificate** browse to the certificate downloaded from the SAML application and upload it.

7.  Click `Add Identity Provider`.

8.  Once the IdP is created click the `drop down arrow` on the left hand side of the IdP.

9.  Copy down the values of **Assertion Consumer Service URL** and **Audience URI**.

The SAML IdP is defined at **Security** &gt; **Identity Providers** &gt; **Manual SAML Assertion Flow IdP** in the reference Org.

## Finish Setting up the SAML Service Provider Application

Use the values from the SAML IdP to complete the SP configuration.

1.  In the Admin Console, navigate to **Applications** &gt; **Applications**.

2.  Edit the SAML SP Application and navigate to the **General tab**.

3.  Under the **SAML Settings** click `Edit`.

4.  In the **General Settings** section click `Next`.

5.  For **Recipient URL** and **Destination URL** enter the value copied down for the **Assertion Consumer Service URL** from the SAML IdP.

6.  For **Audience URI** use the value copied down for **Audience URI** from the SAML IdP.

7.  Click `Next` followed by `Finish` without making any changes.

    > The Single Sign On URL should still be `https://httpbin.org/post`, which is where the SAML Response will be sent. The **Recipient** and **Audience** values will be set to a registered SAML IdP. In order for Okta to accept a SAML Assertion in the SAML Assertion Flow, the **Recipient** and **Audience** values in the Assertion *need* to match the values of a SAML IdP registered in the Okta Org.

1.  From the **General tab** scroll down to the **App Embed Link** and copy the URL for later.

# Configure the OIDC Application

An OIDC application needs to be configured for the SAML Assertion Flow. A Native Application will be created for this.

1.  In the Admin Console, navigate to **Applications** &gt; **Applications**.

2.  Click **Create App Integration**.

3.  Select **ODIC - OpenID Connect** as the **Sign-in method**, and **Native Application** as the **Application type**.

4.  Click `Next`

5.  Enter a name for your app integration.

6.  In the **Grant type** section specify **SAML 2.0 Assertion**.

7.  In the **Assignments** section, select **Skip group assignment for now**.

8.  The rest of the default settings can be left, click `Save`.

9.  From the **General** tab click `Edit`, in the **Client Credentials** section select **Use Client Authentication**.

10. Click `Save`.

11. Assign the same test user to the application that was assigned to the SAML Service Provider Application.

The OIDC Application is defined at **Applications** &gt; **Applications** &gt; **SAML Assertion OIDC Flow** in the reference Org.

# Configure the Authorization Server for the SAML Grant

An authorization server needs to be configured for the SAML Assertion Flow. For this example the **default** authorization server will be used.

1.  In the Admin Console, navigate to **Security** &gt; **API**.

2.  On the Authorization Servers tab, select **default** from the Name column in the table.

3.  Select the **Access Policies** tab.

4.  For **Default Policy** in the **Assigned to clients** section, verify that either **All Clients** is set, or the OIDC application configured prior is set.

5.  Click the `pencil` for **Default Policy Rule** to edit.

6.  In the Edit Rule window, select **SAML 2.0 Assertion** in the **IF Grant type is** section if not currently enabled.

7.  Click `Update Rule`.

The Authorization Server is defined at **Security** &gt; **API** &gt; **Authorization Servers** &gt; **default** in the reference Org.

# Execute the SAML Assertion Flow

At this point everything should be setup and ready to run the SAML Assertion Flow.

-   A SAML Service Provider Application has been configured to send a SAML Assertion too `https://httpbin.org/post`.

-   A SAML Identity Provider has been configured that is able to validate the SAML Assertion sent to the SAML SP.

-   An OIDC Application has been configured capable of of the SAML Assertion Flow.

-   An Authorization Server has been configured that allows the SAML Assertion Grant type.

    > An OIDC App that is configured for the SAML Assertion Flow relies on a registered SAML Identity provider(s). There is no direct mapping between the app and the registered provider however, so a single app could accept assertions from multiple SAML IdPs.

The flow starts with Okta sending a SAML Response to the SAML Service Provider Application.

1.  Open a browser and enter the **App Embed Link** copied earlier from the SAML Service Provider Application in the address location.

2.  After login, if a valid Okta session doesn’t exist your browser will redirect to `https://httpbin.org/post` with a SAML Response.

3.  As part of the form data sent to `https://httpbin.org/post` should be a **SAMLResponse**. Copy the contents of the SAMLResponse not including the opening/closing quotes.

![SAML Response sent to httpbin.org](saml-assertion-flow-with-okta/.img/httpbin.png)

1.  Navigate to `https://www.base64decode.org`.

2.  Keep the default settings and paste the **SAMLResponse** value in the top window.

3.  Click `DECODE`.

4.  In the **decoded content** search for the text **saml2:assertion**. There should be an opening and closing XML element.

5.  Copy the contents of the assertion including both opening and closing **saml2:assertion** tags.

![SAML Response Decoded](saml-assertion-flow-with-okta/.img/resp\_decoded.png)

1.  Navigate to `https://www.base64encode.org`

2.  Keep the default settings and paste the **assertion** in the top window.

3.  Click `ENCODE`.

This produces the needed SAML assertion to make the `/token` call for your OIDC application.

![SAML Assertion Enecoded](saml-assertion-flow-with-okta/.img/assertion\_encoded.png)

1.  With the encoded SAML Assertion, use [cURL](https://curl.se/) or [Postman](https://www.postman.com/) to make a call to the `/token` endpoint of the configured authorization server.

<!-- -->

    curl --location --request POST 'https://{DOMAIN}.okta.com/oauth2/default/v1/token' \
    --header 'Accept: application/json' \
    --header 'Authorization: Basic MG9hMWJvOTcwMGpHb0J0UnU1ZDc6aXRtQTFtN1VsVjEwMFZmQW9EUjVWRWc5MFU0OHdEUTZpNEM2QmRGbg==' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer' \
    --data-urlencode 'scope=openid profile email offline_access' \
    --data-urlencode 'assertion=PHNhbWwyOkFzc2VydGlvbi...FtbDI6QXNzZXJ0aW9uPg=='

The Authorization header is the base64 encoded value of the OIDC applications **client\_id** and **client\_secret** separated by a **colon**, Base64(client\_id:client\_secret)

1.  The call to `/token` should return the OAuth tokens.

<!-- -->

    {
        "access_token": "eyJraWQiOiJZSEdyS3VGY3JyM1h0...oIwH2tjRQ",
        "expires_in": 300,
        "id_token": "eyJraWQiOiJZSEdyS3VGY3JyM1h0TERZ...BekDjInNg",
        "scope": "profile email openid",
        "token_type": "Bearer"
    }

# Common Problems

Configuring this flow often takes a bit of troubleshooting to get it dialed in correctly. Often the following error will be received during configuration,

    {
        "error": "invalid_grant",
        "error_description": "'assertion' is not a valid SAML 2.0 Assertion."
    }

-   The audience/recipient in the SAML Assertion does not match what is configured in a registered SAML IdP in Okta.

-   The SAML Assertion is not signed, or there is an algorithm mismatch.

-   If using an Okta Org with a custom domain URL, the wrong issuer (URL) is useed.

-   The full SAML Response was used instead of the Assertion.

# Sample Application

![Sample App](saml-assertion-flow-with-okta/.img/sample.gif)

If the above was configured successfully, you may want to try the sample application. It requires [Golang](https://golang.org/dl/) (1.16+).

    git clone https://github.com/emanor-okta/saml-assertion-flow-samples.git
    cd saml-assertion-flow-samples/saml-assertion-flow-with-okta
    go mod tidy
    go run main.go

The app is already configured for an existing Okta Org and can be tested as is.

-   With the app running navigate to `http://localhost:8080`

-   Click `Get Tokens`

-   This will invoke the embedded URL link for the SAML SP Application.

-   When prompted for credentials use `read.only` / `Th1sPassword`

-   The application will run through the flow displaying the various requests/responses of the flow.

## Configure the app for Your Org

-   With the app running navigate to `http://localhost:8080` and click `Config`

-   For **Okta SAML Embed Link** enter the **App Embed Link** from the SAML Service Application created.

-   Click `Save SAML Settings`

-   For **Client ID** enter the ID from the OIDC Application.

-   For **Client Secret** enter the Secret from the OIDC Application.

-   For **Token URL** enter `https://{OKTA_ORG}/oauth2/default/v1/token`

-   Click `Save OIDC Settings`

The final step is to edit the SAML SP Application to send the SAML Response to `http://localhost:8080/samlresponse` instead of `https://httpbin.org/post`.

-   

-   Click `Edit`

-   Click `Next` without any changes

-   Under **SAML Settings** &gt; **General** &gt; **Single sign on URL**, enter `http://localhost:8080/samlresponse`

-   Click `Next` without any other changes

-   Click `Finish` without any changes

Click `Get Tokens` again, this time enter your own credentials 😎

# Wrap Up

Hopefully this provided valuable knowledge on how the SAML Assertion Grant type is setup in Okta. The next step is to integrate your own external SAML IdP.

-   To learn about this and other Grant Types please visit [here](https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/)

-   Interested in other potential use-cases for the SAML Assertion Grant flow

    -   SAML Assertion flow with [Keycloak](https://www.keycloak.org/) and Okta [sample application](https://github.com/emanor-okta/saml-assertion-flow-samples/tree/main/saml-assertion-flow-keycloak)

    -   SAML Assertion flow with an application generated assertion [sample application](https://github.com/emanor-okta/saml-assertion-flow-samples/tree/main/self-generated/saml-assertion-flow-self-generated)
