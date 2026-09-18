// Generic CSRF form-login authentication for ZAP (script-based auth).
// Works for ANY app whose login form carries an anti-CSRF token in a hidden
// field (e.g. DVWA user_token, Django csrfmiddlewaretoken, Rails authenticity_token):
//   1. GET the login page, scrape the token from the named hidden field
//   2. POST the login with username + password + the fresh token
// Params: loginUrl (GET+POST target), csrfField (hidden field name),
//         loginData (body template with {%username%}/{%password%}/{%csrf%}).
var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type("org.apache.commons.httpclient.URI");

function authenticate(helper, paramsValues, credentials) {
    var loginUrl = paramsValues.get("loginUrl");
    var csrfField = paramsValues.get("csrfField");
    var loginData = paramsValues.get("loginData");
    var username = credentials.getParam("username");
    var password = credentials.getParam("password");

    // 1) GET the login page for the token
    var getMsg = helper.prepareMessage();
    getMsg.setRequestHeader(new HttpRequestHeader(HttpRequestHeader.GET, new URI(loginUrl, false), HttpHeader.HTTP11));
    helper.sendAndReceive(getMsg);
    var body = "" + getMsg.getResponseBody().toString();

    // 2) scrape the token (name-before-value OR value-before-name)
    var token = "";
    if (csrfField) {
        var f = csrfField.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        var m = new RegExp("name=[\"']" + f + "[\"'][^>]*value=[\"']([^\"']+)", "i").exec(body);
        if (!m) m = new RegExp("value=[\"']([^\"']+)[\"'][^>]*name=[\"']" + f, "i").exec(body);
        if (m) token = m[1];
    }

    // 3) POST the login with creds + token
    var postData = ("" + loginData)
        .replace("{%username%}", encodeURIComponent(username))
        .replace("{%password%}", encodeURIComponent(password))
        .replace("{%csrf%}", encodeURIComponent(token));

    var postMsg = helper.prepareMessage();
    postMsg.setRequestHeader(new HttpRequestHeader(HttpRequestHeader.POST, new URI(loginUrl, false), HttpHeader.HTTP11));
    postMsg.setRequestBody(postData);
    postMsg.getRequestHeader().setContentLength(postMsg.getRequestBody().length());
    postMsg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, "application/x-www-form-urlencoded");
    helper.sendAndReceive(postMsg);
    return postMsg;
}

function getRequiredParamsNames() { return ["loginUrl", "csrfField", "loginData"]; }
function getOptionalParamsNames() { return []; }
function getCredentialsParamsNames() { return ["username", "password"]; }
