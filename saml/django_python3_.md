
That's it! With this configuration, when a user accesses the /saml2_auth/login/ URL, 
they will be redirected to the SAML IdP to authenticate. Once authenticated, 
they will be redirected back to the /saml2_auth/acs/ URL,
where their SAML attributes will be extracted and a Django user will be created or updated as specified in the user_created_callback_function.


```
def user_created_callback_function(user, attributes, user_info):
    # Extract relevant SAML attributes to create a new Django user
    email = attributes.get('email', [''])[0]
    first_name = attributes.get('firstName', [''])[0]
    last_name = attributes.get('lastName', [''])[0]
    
    # Update Django user object with the extracted attributes
    user.email = email
    user.first_name = first_name
    user.last_name = last_name
    user.save()

```

####
####

```

from django.urls import path
from django_auth_saml2.views import acs, metadata, login, logout

urlpatterns = [
    path('saml2_auth/login/', login, name='saml2_login'),
    path('saml2_auth/logout/', logout, name='saml2_logout'),
    path('saml2_auth/metadata/', metadata, name='saml2_metadata'),
    path('saml2_auth/acs/', acs, name='saml2_acs'),
    # ... your other URL patterns ...
]

```

####
####

```
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'django_auth_saml2.backends.Saml2Backend',
]

SAML2_AUTH = {
    # Metadata configuration
    'METADATA_AUTO_CONF_URL': 'https://your-saml-idp.com/metadata',
    'ENTITY_ID': 'https://your-django-app.com/saml2_auth/acs/',
    'ASSERTION_URL': 'https://your-django-app.com/saml2_auth/acs/',
    
    # User attributes configuration
    'NAMEID_FORMAT': 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    'USE_JWT': True,
    'CREATE_USER': True,
    'USER_CREATED_CALLBACK': 'path.to.your.user_created_callback_function',
    
    # Optional: Security settings
    'SIGNATURE_ALGORITHM': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'DIGEST_ALGORITHM': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'IDP_CERT': 'path/to/idp/cert.pem',
    'SP_PRIVATE_KEY': 'path/to/sp/key.pem',
    'SP_CERT': 'path/to/sp/cert.pem',
}

```

########
########

Code Your Python App to Provide SSO via OneLogin
You can use OneLogin’s open-source SAML toolkit for Python to enable single sign-on (SSO) for your app via any identity provider that offers SAML authentication.

Use this document to learn how to set up the SSO connection between your app and OneLogin, specifically.

We’ll use the demo-django or demo-flask apps (python-saml-master/demo-django or python-saml-master/demo-flask) delivered in the toolkit to demonstrate how to perform the necessary tasks. These are simple apps that demonstrate the SSO and single logout (SLO) flow enabled by the SAML toolkit.

For important information about prerequisites and installing and developing an app with the SAML Toolkit for Python, see OneLogin’s SAML Python Toolkit. 

The download also includes documentation of the OneLogin SAML Toolkit Python library. See /python-saml-master/docs/saml2/index.html.

Task 1: Prepare the demo files
Download the SAML Toolkit for Python.

Deploy Python and your Django or Flask framework in an appropriate location relative to your python-saml-master folder.

Note the presence of the settings.json file in both demos (python-saml-master/demo-django/saml or python-saml-master/demo-flask/saml). You’ll be doing most of your configurations in this file.

Task 2: Create an app connector in OneLogin
Use the SAML Test Connector (Advanced) connector to build an application connector for your app. For demo purposes, we’ll build one for the demo-django or demo-flask apps.

This app connector provides you with the SAML values your app needs to communicate with OneLogin as an identity provider. It also provides a place for you to provide SAML values that OneLogin needs to communicate with your app as a service provider.

Access OneLogin.

Go to Applications > Add App.

Search for SAML Test Connector.

Select the SAML Test Connector (Advanced) app.

Edit the Display Name, if required. In the case of working with the demo-django app, enter demo-django, for example.

Accept other default values for now and click Save.

Task 3: Define identity provider values in settings.json
In this step, provide your app with the identity provider values it needs to communicate with OneLogin. For demo purposes, we’ll provide the values for the demo-django and demo-flask apps.

Open settings.json in python-saml-master/demo-django/saml or python-saml-master/demo-flask/saml.

In the OneLogin app connector UI you kept open from the previous task, select the SSO tab.

Copy values from the SSO tab and paste them into the idp section of settings.json as shown below.

Copy SSO Tab Field Value	to	settings.json Location
Issuer URL

➞	
entityId

SAML 2.0 Endpoint (HTTP)

➞	
singleSignOnService

SLO Endpoint (HTTP)

➞	
singleLogoutService

X.509 Certificate > View Details

➞	
x509cert

After copying values from the SSO tab into the idp section of your settings.json file, it should look something like this:


"idp": {
        "entityId": "https://app.onelogin.com/saml/metadata/123456",
        "singleSignOnService": {
            "url": "https://domain.onelogin.com/trust/saml2/http-post/sso/123456",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "singleLogoutService": {
            "url": "https://domain.onelogin.com/trust/saml2/http-redirect/slo/123456",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": "XXXXxXXX1xXxXXXxXXXXXXxXXxxXx..."
    }
x509cert must be a one-line string: Ensure that your x509cert value is a one-line string, with no line breaks. Use the FORMAT A X509 CERTIFICATE tool to format your value, if necessary.

Save settings.json.

Keep the OneLogin app connector UI open for the next task.

Task 4: Define service provider values in settings.json
In this step, we define the service provider values that OneLogin requires to identify your app. For demo purposes, we provide the values for the demo-django and demo-flask apps.

Open settings.json in python-saml-master/demo-django/saml or python-saml-master/demo-flask/saml.

In the sp section, replace the variable in each of the URLs with your actual domain value. When completed, the URLs should look something like the following.

Important: Ensure that the protocol used on the URLs http/https matches the way the app is served.

entityID: http://myapp.com/metadata/

assertionConsumerService: http://myapp.com/?acs

singleLogoutService: http://myapp.com/?sls

For the NameIDFormat value, change unspecified to emailAddress. This is the value used by OneLogin.

Save settings.json.

In the OneLogin app connector UI you kept open from the previous task, select the Configuration tab.

Copy values from settings.json into the Configuration tab fields as shown below.

Copy settings.json Value	to	Configuration Tab Field
assertionConsumerService

➞	
ACS (Consumer) URL

Recipient

singleLogoutService

➞	
Single Logout URL

entityId

➞	
Audience

For a detailed description of each of the fields on the Configuration tab, see How to Use the OneLogin SAML Test Connector for more details.

You can leave RelayState blank. It will respect the value sent by the Service Provider.

For now, set ACS (Consumer) URL Validator to .*.

Once you have verified that the connection between your app and OneLogin is working, you’ll want to set this value to perform an actual validation. See How to Use the OneLogin SAML Test Connector for more details.

Your Configuration tab should now look something like this:



Click Save.

If you need advanced security for production, be sure to also configure the advanced_settings.json file.

For more information about how configure the settings.json and advanced_settings.json file, see the Toolkit documentation.

Task 5: Add users to your app connector
In this task, you’ll give users access to the app connector you just created and configured. For example, you’ll need to ensure that you have access to the app connector to be able to access the demo-django or demo-flask app.

With your app connector open, select the Access tab.

Ensure that the settings give you access to the app connector. For example, enable a role that will give you access. In this case, let’s say that the Default role grants access to relevant users, as shown below.


Click Save.

Task 6: Log in to your app
At this point, the setup is complete and you should be able to single sign-on to and single logout of your app. For demo purposes, we’ll show the login and logout behavior using the demo-django or demo-flask app.

Log in using service provider-initiated SAML
The following login flow illustrates service provider-initiated SAML, in which the request for authentication and authorization is initiated from the app, or service provider.

Access the demo-django or demo-flask app. For example, access: http://localhost:8000. The selected app displays. For example, the demo-django app displays as shown below.



Select Login. The OneLogin login UI displays. Selecting the Login link demonstrates the user experience when logging into your app via SSO.

Enter your OneLogin credentials.

A page listing the values from the app connector’s Parameters tab displays. For your app, this would display your app in a logged in state.

Select Logout. Selecting the Logout link demonstrates the user experience when logging out of your app via SLO. For example, the demo-django app logout state displays as shown below.



Troubleshooting
If you see this UI instead of the OneLogin login UI, please ensure that you have completed Task 5: Add users to your app connector.



Log in using identity provider-initiated SAML
The following login flow illustrates identity provider-Initiated SAML, in which the login request is initiated from the identity provider. In this case, that user experience would be as follows:

On your OneLogin App Home page, select the app connector your created. For example, select the demo-django app as shown below.



The page listing the values from the app connector’s Parameters tab displays. For your app, this would display your app in a logged in state.

Select Logout. Selecting the Logout link demonstrates the user experience when logging out of your app via SLO. For example, the demo-django app logout state displays as shown below.



?tags=onelogin+saml+python” target=”_blank”>StackOverflow.
