//
// https://gist.github.com/wcarson/c7ee460b3514b0667dc4b4fd3149782d
//
//
using MyCompany.Okta.OAuth2SamlBridge.Models;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Mvc;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Multiformats.Base;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.Caching;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using static MyCompany.Okta.OAuth2SamlBridge.Models.ApiResponse;
using SecurityAlgorithms = Microsoft.IdentityModel.Tokens.SecurityAlgorithms;
using SecurityTokenValidationException = Microsoft.IdentityModel.Tokens.SecurityTokenValidationException;

namespace MyCompany.Okta.OAuth2SamlBridge.Controllers
{
    // Bridge process
    // 1. App: request SSO link from API with access token
    // 2. API: validate access token
    // 3. API: Construct SAML Response
    // 4. API: Store SAML Response
    // 5. API: Return SSO link to app
    // 6. App: Launch SSO link from WebView
    // 7. API: Retrieve SAML Response for link
    // 8. API: Perform IdP initiated SSO with Okta
    // 9. Okta: Return browser to relay state with Okta session
    public class DefaultController : Controller
    {
        private static readonly Dictionary<String, ConfigurationManager<OpenIdConnectConfiguration>> AuthorizationServerCache =
            new Dictionary<string, ConfigurationManager<OpenIdConnectConfiguration>>();
        private static readonly Dictionary<String, App> AppCache = new Dictionary<string, App>();

        private static JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

        [HttpGet]
        [Route("")]
        public ActionResult Index()
        {
            return View();
        }

        [HttpGet]
        [Route("api/oauth2saml/initiate")]
        public async Task<ActionResult> Initiate(string targetUrl)
        {
            try
            {
                var accessToken = await ValidateAccessToken();
                var userId = accessToken.Claims.Where(c => c.Type == "sub").First().Value;
                var samlBinding = GenerateSamlAssertion(userId, targetUrl);

                var cacheKey = Multibase.Encode(MultibaseEncoding.Base58Btc, 
                    Encoding.UTF8.GetBytes(Guid.NewGuid().ToString()));

                MemoryCache.Default.Add(cacheKey, samlBinding, new CacheItemPolicy()
                {
                    AbsoluteExpiration = DateTimeOffset.UtcNow.AddMinutes(1)
                });

                return JsonResult(new SsoLinkResponse()
                {
                    SsoLink = $"{AppUrl}api/oauth2saml/sso/{cacheKey}"
                });
            }
            catch(HttpException ex)
            {
                Response.StatusCode = ex.GetHttpCode();
                return JsonResult(new ApiResponse()
                {
                    Status = ApiResponseStatus.Failed,
                    Message = ex.Message
                });
            }
            catch(Exception ex)
            {
                Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                return JsonResult(new ApiResponse()
                {
                    Status = ApiResponseStatus.Failed,
                    Message = ex.Message
                });
            }
        }

        [HttpGet]
        [Route("api/oauth2saml/sso/{id}")]
        public ActionResult Sso(string id)
        {
            var samlBinding = (Saml2PostBinding)MemoryCache.Default.Get(id);
            MemoryCache.Default.Remove(id);
            return samlBinding.ToActionResult();
        }

        private async Task<JwtSecurityToken> ValidateAccessToken()
        {
            string authorization = Request.Headers["Authorization"];
            
            if(AuthenticationHeaderValue.TryParse(authorization, out var headerValue)
                && headerValue.Scheme.ToLower() == "bearer") 
            {
                var accessToken = headerValue.Parameter;
                var jwt = tokenHandler.ReadJwtToken(accessToken);
                var clientId = jwt.Claims.Where(c => c.Type == "cid").First().Value;

                var app = GetApp(clientId);
                var oAuthConfig = GetOAuthConfig(app.Issuer);
                
                var discoveryDocument = await oAuthConfig.GetConfigurationAsync();
                var signingKeys = discoveryDocument.SigningKeys;

                var validationParameters = new TokenValidationParameters
                {
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidateIssuer = true,
                    ValidIssuer = app.Issuer,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = signingKeys,
                    ValidateLifetime = true,
                    ValidAlgorithms = new List<string> { SecurityAlgorithms.RsaSha256 },
                    ClockSkew = TimeSpan.FromMinutes(2),
                    ValidateAudience = true,
                    ValidAudience = app.Audience
                };

                try
                {
                    var principal = tokenHandler.ValidateToken(accessToken, validationParameters, 
                        out var rawValidatedToken);
                    return (JwtSecurityToken) rawValidatedToken;
                }
                catch (SecurityTokenValidationException ex)
                {
                    throw new HttpException((int)HttpStatusCode.Forbidden, 
                        $"Invalid access token: {ex.Message}");
                }
            }
            else
            {
                throw new HttpException((int) HttpStatusCode.Unauthorized, 
                    "Access token is required");
            }
        }

        private ActionResult JsonResult(object entity)
        {
            return Content(JsonConvert.SerializeObject(entity), "application/json");
        }

        private Saml2PostBinding GenerateSamlAssertion(string userId, string relayState)
        {
            var spAcsUrl = ConfigurationManager.AppSettings["okta:SPAcsUrl"];
            var spAudience = ConfigurationManager.AppSettings["okta:SPAudience"];

            var certPath = Server.MapPath("~/signing.pfx");
            var signingCert = new X509Certificate2(certPath, "changeit");
            var config = new Saml2Configuration()
            {
                Issuer = "http://okta-oauth2saml-bridge",
                SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                SigningCertificate = signingCert
            };

            var responseBinding = new Saml2PostBinding()
            {
                RelayState = relayState
            };

            var saml2AuthnResponse = new Saml2AuthnResponse(config)
            {
                Status = Saml2StatusCodes.Success,
                NameId = new Saml2NameIdentifier(userId),
                Destination = new Uri(spAcsUrl),
                ClaimsIdentity = new System.Security.Claims.ClaimsIdentity()
            };

            // TODO shorten lifetimes
            saml2AuthnResponse.CreateSecurityToken(spAudience, subjectConfirmationLifetime: 5, 
                issuedTokenLifetime: 60);

            return responseBinding.Bind(saml2AuthnResponse);
        }

        private App GetApp(string clientId)
        {
            if (AppCache.Count == 0)
            {
                LoadMetadata();
            }

            return AppCache[clientId];
        }

        private ConfigurationManager<OpenIdConnectConfiguration> GetOAuthConfig(string issuer)
        {
            if (AuthorizationServerCache.Count == 0)
            {
                LoadMetadata();
            }

            return AuthorizationServerCache[issuer];
        }

        private void LoadMetadata()
        {
            var json = System.IO.File.ReadAllText(Server.MapPath("~/App_Data/clients.json"));
            var apps = JsonConvert.DeserializeObject<List<App>>(json);
            foreach (var app in apps)
            {
                AppCache.Add(app.ClientId, app);
                AuthorizationServerCache.Add(
                    app.Issuer,
                    new ConfigurationManager<OpenIdConnectConfiguration>(
                        $"{app.Issuer}/.well-known/oauth-authorization-server",
                        new OpenIdConnectConfigurationRetriever(),
                        new HttpDocumentRetriever()));
            }
        }

        private string AppUrl
        {
            get
            {
                var url = Request.Url;
                return string.Format("{0}://{1}{2}{3}",
                    url.Scheme,
                    url.Host,
                    (url.Port == 80 || url.Port == 443) ? "" : ":" + url.Port,
                    Request.ApplicationPath);
            }
        }
    }
}
