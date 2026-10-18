//  Hack to make twitter4s support Application-only ('bearer') authentication for higher quota limits 
//
//

package com.danielasfregola.twitter4s

import java.net.URLEncoder

import akka.actor.ActorSystem
import akka.http.scaladsl.model.HttpRequest
import akka.http.scaladsl.model.headers._
import akka.stream.{ActorMaterializer, Materializer}
import com.danielasfregola.twitter4s
import com.danielasfregola.twitter4s.entities.{AccessToken, ConsumerToken}
import com.danielasfregola.twitter4s.util.Configurations.apiTwitterUrl

import scala.concurrent.Future

/** The Twitter API offers applications the ability to issue authenticated requests on behalf of the
  * *application itself*, (as opposed to, on behalf of a specific user):
  *
  * https://developer.twitter.com/en/docs/basics/authentication/overview/application-only.html)
  *
  * Requests using Application-only ('bearer') authentication get **much higher API quota limits**,
  * so we want to use that in preference to user-auth.
  *
  * App-only auth is not yet supported in twitter4s - see https://github.com/DanielaSfregola/twitter4s/issues/237 - so
  * this is a hack, extending the package-private com.danielasfregola.twitter4s.http.clients.rest.RestClient class to
  * override the critical authentication headers.
  */
object AppOnlyAuthentication {
  case class TokenRequest(grant_type: String) extends Product

  case class Token(token_type: String, access_token: String)

  val DummyAccessToken = AccessToken("no need to configure an access token with app-only authentication", "")

  class TwitterRestClient(consumerToken: ConsumerToken)(implicit _system: ActorSystem = ActorSystem("twitter4s-rest"))
    extends twitter4s.TwitterRestClient(consumerToken, DummyAccessToken) {

    override val restClient = new RestClient(consumerToken)
  }

  class RestClient(consumerToken: ConsumerToken)(implicit _system: ActorSystem)
    extends twitter4s.http.clients.rest.RestClient(consumerToken, DummyAccessToken) {

    val tokenUrl = s"$apiTwitterUrl/oauth2/token"

    /** Consumer-token encoded as Basic-Auth HTTP credentials, including superfluous RFC 1738 url-encoding specified by:
      * https://developer.twitter.com/en/docs/basics/authentication/overview/application-only.html#step-1-encode-consumer-key-and-secret
      */
    val consumerTokenAuth = BasicHttpCredentials(
      URLEncoder.encode(consumerToken.key,"UTF-8"),
      URLEncoder.encode(consumerToken.secret,"UTF-8")
    )

    /** One-off fetch of bearer-token - the token apparently has indefinite validity.
      */
    val bearerTokenF: Future[Token] = {
      implicit val materializer = ActorMaterializer()

      sendReceiveAs[Token](
        Post(tokenUrl, TokenRequest("client_credentials")).addHeader(Authorization(consumerTokenAuth))
      )
    }

    override def withOAuthHeader(c: Option[String])(implicit mat: Materializer): HttpRequest => Future[HttpRequest] = { request =>
      implicit val ec = mat.executionContext
      for (token <- bearerTokenF) yield request.addHeader(Authorization(OAuth2BearerToken(token.access_token)))
    }

    override def withSimpleOAuthHeader(c: Option[String])(implicit mat: Materializer): HttpRequest => Future[HttpRequest] = withOAuthHeader(c)
  }

}
