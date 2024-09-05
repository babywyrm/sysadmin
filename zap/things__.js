//
// https://github.com/zaproxy/community-scripts
//

// This script will log a browser into Juice Shop when forced user mode is enabled.
// The 'Juice Shop Session Management.js' script must have been set to authenticate correctly.
// Make sure to use the version of that script in this repo rather than the one included with ZAP 2.9.0 as
// it has been enhanced to support this script.

var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
//Change the jsUrl var if the instance of Juice Shop you are using is not listening on http://localhost:3000
var jsUrl = "http://localhost:3000";

function browserLaunched(ssutils) {
  var token = ScriptVars.getGlobalVar("juiceshop.token");
  if (token != null) {
    logger("browserLaunched " + ssutils.getBrowserId());
    var wd = ssutils.getWebDriver();
    var url = ssutils.waitForURL(5000);
    if (url.startsWith(jsUrl)) {
      logger("url: " + url + " setting token " + token);
      var script =
        "document.cookie = 'token=" +
        token +
        "';\n" +
        "window.localStorage.setItem('token', '" +
        token +
        "');";
      wd.executeScript(script);
    }
  } else {
    logger("no token defined");
  }
}


////
////

// Logging with the script name is super helpful!
function logger() {
  print("[" + this["zap.script.name"] + "] " + arguments[0]);
}



/*
This script will fill the OTP if MFA is configured on web-app. Browser-based auth is the pre-requisite for this script.
You need to analyze DOM of the web app this script needs to run on and modify the parameters accordingly.
This script assumes that the web app has fixed OTP for testing which can be stored in the variable below.
 */

function browserLaunched(utils) {
  var By = Java.type("org.openqa.selenium.By");
  var Thread = Java.type("java.lang.Thread");
  var url = utils.waitForURL(5000);
  var wd = utils.getWebDriver();
  var OTP = "123456";

  wd.get(url + "#/login");
  Thread.sleep(30000); //Wait for ZAP to handle the auth.
  wd.findElement(By.id("one-time-code")).sendKeys(OTP); //Replace the input field as per your web-app's DOM
  Thread.sleep(1000);
  wd.executeScript(
    "document.querySelector('[aria-label=\"Verify Code\"]').click()"
  ); //Replace the submit label as per your web-app's DOM
}


////
////

/*
 * Session Management script for OWASP Juice Shop
 *
 * For Authentication select:
 * 		Authentication method:		JSON-based authentication
 * 		Login FORM target URL:		http://localhost:3000/rest/user/login
 * 		URL to GET Login Page:		http://localhost:3000/
 * 		Login Request POST data:	{"email":"test@test.com","password":"test1"}
 * 		Username Parameter:			email
 * 		Password Parameter:			password
 * 		Logged out regex:			\Q{"user":{}}\E
 *
 * Obviously update with any local changes as necessary.
 */

var COOKIE_TYPE = org.parosproxy.paros.network.HtmlParameter.Type.cookie;
var HtmlParameter = Java.type("org.parosproxy.paros.network.HtmlParameter");
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");

function extractWebSession(sessionWrapper) {
  // parse the authentication response
  var json = JSON.parse(
    sessionWrapper.getHttpMessage().getResponseBody().toString()
  );
  var token = json.authentication.token;
  // save the authentication token
  sessionWrapper.getSession().setValue("token", token);
  ScriptVars.setGlobalVar("juiceshop.token", token);
}

function clearWebSessionIdentifiers(sessionWrapper) {
  var headers = sessionWrapper.getHttpMessage().getRequestHeader();
  headers.setHeader("Authorization", null);
  ScriptVars.setGlobalVar("juiceshop.token", null);
}

function processMessageToMatchSession(sessionWrapper) {
  var token = sessionWrapper.getSession().getValue("token");
  if (token === null) {
    print("JS mgmt script: no token");
    return;
  }
  var cookie = new HtmlParameter(COOKIE_TYPE, "token", token);
  // add the saved authentication token as an Authentication header and a cookie
  var msg = sessionWrapper.getHttpMessage();
  msg.getRequestHeader().setHeader("Authorization", "Bearer " + token);
  var cookies = msg.getRequestHeader().getCookieParams();
  cookies.add(cookie);
  msg.getRequestHeader().setCookieParams(cookies);
}

function getRequiredParamsNames() {
  return [];
}

function getOptionalParamsNames() {
  return [];
}

////
////

