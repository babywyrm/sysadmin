
//
//

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	pb "your_protobuf_package"
)

func main() {
	// Load client TLS certificate and key
	certificate, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		log.Fatalf("failed to load client certificate and key: %v", err)
	}

	// Load CA certificate
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatalf("failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create credentials with TLS and JWT token
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      caCertPool,
	})

	// Dial target server on port 6969
	conn, err := grpc.Dial("target_host:6969", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("failed to dial server: %v", err)
	}
	defer conn.Close()

	// Create gRPC client
	client := pb.NewYourGRPCServiceClient(conn)

	// Create JWT token
	token := "YOUR_JWT_TOKEN_HERE"

	// Invoke gRPC method with JWT token
	response, err := client.YourGRPCMethodWithJWT(context.Background(), &pb.Request{Token: token})
	if err != nil {
		log.Fatalf("failed to call YourGRPCMethodWithJWT: %v", err)
	}

	// Process the response
	fmt.Printf("Response: %v\n", response)
}


//
//


#
https://groups.google.com/g/grpc-io/c/IqDrqMKgduY
#

How does gRPC maintain sessions securely?
758 views
Subscribe 
Eric Robins's profile photo
Eric Robins
unread,
Mar 1, 2023, 2:27:45 PM
to grpc.io
Forgive the question if it's already been asked.  I've been digging through documentation on gRPC and how to secure it but I've been unable to find anything at a very detailed level that explains what I guess I'd call session management - the persistence of channels and underlying HTTP/2 streams between a client and server where both may have been previously authenticated.

Using gRPC, how does a server know that it is still talking to the same client it authenticated previously?  In HTTP/1.1 session management is achieved almost always through the use of cookies or other authorization grants given to the client by the server that are represented back to the server (in a header usually) every time a call is made during the active session.  How does this work in gRPC?

Thanks in advance.  Happy to go read more documentation if someone can point me to it.

Eric
sanjay...@google.com's profile photo
sanjay...@google.com
unread,
Mar 1, 2023, 3:02:31 PM
to grpc.io
Please take a look at https://github.com/grpc/proposal/blob/master/A43-grpc-authorization-api.md and see if that addresses your questions.
Eric Robins's profile photo
Eric Robins
unread,
Mar 2, 2023, 8:52:30 AM
to grpc.io
Thanks Sanjay.  The proposal in that link implies the use of gRPC interceptors, which we're considering.  What I was hoping to answer was whether or not there was anything built into gRPC to authorize a client on an active channel without the use of an interceptor.  Its documentation seemed to imply that after initial authentication of the client/server when a channel is established, that continued conversation could be trusted.  It's possible I've misread that however.
sanjay...@google.com's profile photo
sanjay...@google.com
unread,
Mar 2, 2023, 9:16:00 AM
to grpc.io
Need to be more precise than "when a channel is established, that continued conversation could be trusted." 

There is this notion called client authentication where a client's identity is established and authenticated. Client identity can be provided through a mTLS certificate or a header in an RPC. mTLS is at transport level whereas the header is per RPC.

Once authentication is done you can authorize an RPC based on client identity (and other attributes). Note this is per RPC but can use the client identity (established by mTLS at channel level or via a header in the current RPC) and an interceptor is an appropriate place to do it. If the interceptor is provided by the gRPC library you could think of it as "built into gRPC" and should not care that authorization is implemented through interceptors. The proposal talks about an authorization SDK you can use on the server side and use policies specified in JSON which will be enforced by this feature. Which languages do you want to use this in?
Eric Robins's profile photo
Eric Robins
unread,
Mar 2, 2023, 9:57:15 AM
to grpc.io
Thanks - this discussion is helpful.  When I mentioned interceptors I was looking specifically at Java, which is likely to be the language chosen.  I am however looking at this from a security perspective as an engineer attempting to evaluate the protocol and the implementation in Java.

I may be having trouble asking my question.  As I noted in my first post, it's easy in traditional REST services over HTTP/1.1 to see how continued communication between a client and server is authenticated and authorized.  With the popular OAuth 2.0 model as an example, the client may initially authenticate to an /auth endpoint with a token, cert, etc in order to get back a short-lived session grant (usually a JWT).  Subsequent calls to the server require that grant to be present in an HTTP header in order to access the requested services.  In this pattern, the client must always deliberately present a credential issued to them by the server in order to continue to access the necessary services and resources.  The server isn't relying on anything else - the TLS connection, TCP connection, etc to identify the client - only the grant.

I'm trying to relate that to how gRPC continues to identify a client after they've authenticated and a channel has been established.  Under the covers, is gRPC associating that channel to the TCP connection such that if the TCP connection is closed, the channel is closed?  Is it bound instead to the HTTP/2 stream, which binds a client to the server via TCP or TLS?  Or, is there something the client continuously presents with each subsequent call that the server uses to identify them?  The implication is that the server can continue to identify the client after a channel has been established; I'm trying to understand how.

Thanks again...
sanjay...@google.com's profile photo
sanjay...@google.com
unread,
Mar 2, 2023, 2:03:30 PM
to grpc.io
On Thursday, March 2, 2023 at 9:57:15 AM UTC-8 Eric Robins wrote:
Thanks - this discussion is helpful.  When I mentioned interceptors I was looking specifically at Java, which is likely to be the language chosen.  I am however looking at this from a security perspective as an engineer attempting to evaluate the protocol and the implementation in Java.

Okay. The SDK is also available although it only supports static config for now and I think file watcher is coming soon.
 

I may be having trouble asking my question.  As I noted in my first post, it's easy in traditional REST services over HTTP/1.1 to see how continued communication between a client and server is authenticated and authorized.  With the popular OAuth 2.0 model as an example, the client may initially authenticate to an /auth endpoint with a token, cert, etc in order to get back a short-lived session grant (usually a JWT).  Subsequent calls to the server require that grant to be present in an HTTP header in order to access the requested services.  In this pattern, the client must always deliberately present a credential issued to them by the server in order to continue to access the necessary services and resources.  The server isn't relying on anything else - the TLS connection, TCP connection, etc to identify the client - only the grant.

This is definitely possible in gRPC (provided you verify the JWT) - see the example https://github.com/grpc/grpc-java/tree/master/examples/example-jwt-auth . This uses interceptors which I would consider as the right way to do this.  

 

I'm trying to relate that to how gRPC continues to identify a client after they've authenticated and a channel has been established.  Under the covers, is gRPC associating that channel to the TCP connection such that if the TCP connection is closed, the channel is closed?  Is it bound instead to the HTTP/2 stream, which binds a client to the server via TCP or TLS?  Or, is there something the client continuously presents with each subsequent call that the server uses to identify them?  The implication is that the server can continue to identify the client after a channel has been established; I'm trying to understand how.

Good question. This is a bit involved - you can see how it's done in GrpcAuthorizationEngine.EvaluateArgs.getPrincipalNames when mTLS is used for client identity.  TRANSPORT_ATTR_SSL_SESSION allows you to access the  SSL session as a transport attribute of your current server call and you can get then get the peer cert and the principal name from the SSLSession. As you can see it is already done for you by the GrpcAuthorizationEngine which is the implementation of https://github.com/grpc/proposal/blob/master/A43-grpc-authorization-api.md .

 

Thanks again...

Eric Robins's profile photo
Eric Robins
unread,
Mar 17, 2023, 12:57:31 PM
to grpc.io
Ok, I have a simple POC of a bidrectional streaming RPC up in Java.  The client instantiates the non-blocking message stub a single time and the request and response StreamObservers are re-used throughout the communication between client/server.  I confirmed in Wireshark that the same HTTP/2 stream is being reused for all communications.  This is ideal and is how our organization will likely implement if/when we start using gRPC.

Implemented on the server is an interceptor - similar to what you've linked in above.  I'm noticing that it's only invoked once, when the channel is first established.  Subsequent communication with the server from the client doesn't result in any new hits to the interceptor.  If I don't reuse streams it will be invoked every time new streams are established.  Is this expected behavior - for interceptors only to fire during the first time a client makes a call over a newly established stream?  If so then I come back to my original question that started this thread: how would we consider the established stream and channel secure, how how does the server continue to trust that it's the same client with which it's communicating?

Thanks in advance.  If there's a more appropriate place to get ongoing support for questions such as these, please let me know.

Eric

sanjay...@google.com's profile photo
sanjay...@google.com
unread,
Mar 17, 2023, 2:55:08 PM
to grpc.io
Comments inline below:

On Friday, March 17, 2023 at 12:57:31 PM UTC-7 Eric Robins wrote:
Ok, I have a simple POC of a bidrectional streaming RPC up in Java.  The client instantiates the non-blocking message stub a single time and the request and response StreamObservers are re-used throughout the communication between client/server. 

Yes, your observation is consistent with how a streaming RPC is works. A single StreamObserver (one each on request and response side) will be used throughout the life of a streaming RPC.
 
I confirmed in Wireshark that the same HTTP/2 stream is being reused for all communications.  This is ideal and is how our organization will likely implement if/when we start using gRPC.

Yes a bidirectional streaming RPC *does* mean a single HTTP/2 stream will be used for that RPC and you could say is the definition of it.


Implemented on the server is an interceptor - similar to what you've linked in above. 

I think you are talking about the JwtServerInterceptor in  https://github.com/grpc/grpc-java/tree/master/examples/example-jwt-auth. This interceptor gets invoked per RPC but *does not* intercept (or listen to) messages in an RPC. It should be easy to modify your interceptor to intercept (listen to) each incoming request message. Take a look at https://github.com/grpc/grpc-java/blob/master/gcp-observability/src/main/java/io/grpc/gcp/observability/interceptors/InternalLoggingServerInterceptor.java to see how the interceptor returns a SimpleForwardingServerCallListener<ReqT> to intercept each (request) message in onMessage(ReqT message).   You add your authorization logic there.
 
I'm noticing that it's only invoked once, when the channel is first established. 

I would like to make sure you are clear about the distinction between channel, stream, message and so on. A channel is one or more TCP connections and is used for multiple RPCs. Each RPC is an http2 stream and consists of one or more request/response messages. What you are probably trying to say is that "...it's only invoked once, when an RPC is first started." Whereas what you want is an invocation per (request) message in an RPC. 

Subsequent communication with the server from the client doesn't result in any new hits to the interceptor.  If I don't reuse streams it will be invoked every time new streams are established.  Is this expected behavior - for interceptors only to fire during the first time a client makes a call over a newly established stream?  If so then I come back to my original question that started this thread: how would we consider the established stream and channel secure, how how does the server continue to trust that it's the same client with which it's communicating?

As mentioned above if you modify your server interceptor to "intercept" each request message in onMessage(ReqT message) then you are set. Having said that if you are trying to authorize each request message in the request stream then it may not be the right model - one of the reasons is there is metadata (headers) for the whole RPC and not per message so it does not make sense to authorize each request message.


Thanks in advance.  If there's a more appropriate place to get ongoing support for questions such as these, please let me know.

This is probably the right place for asking such questions.
Eric Robins's profile photo
Eric Robins
unread,
Mar 19, 2023, 2:10:28 PM
to grpc.io
Ok, I think I'm getting closer to understanding what I need to understand.  I'm admittedly being a bit loose with terminology, and I believe it's the instantiation and maintenance of an RPC on which I need to focus.  By default - without trying to intercept every message that the client sends to the server - is an RPC that has been authenticated initially expected to be secure throughout its lifecycle?  In other words, if the server authenticates the client upon RPC instantiation, can it trust that it's talking to the same client over the same RPC?  And if so, why?

Thanks.

Sanjay Pujare's profile photo
Sanjay Pujare
unread,
Mar 19, 2023, 7:37:52 PM
to Eric Robins, grpc.io
> can it trust that it's talking to the same client over the same RPC?  And if so, why?

Yes, because an RPC is an unbroken stream in an unbroken TCP connection which is always with one specific client.

I suggest you familiarize yourself with the concepts of a http2 stream, a TCP connection, a gRPC channel and so on. 

--
You received this message because you are subscribed to the Google Groups "grpc.io" group.
To unsubscribe from this group and stop receiving emails from it, send an email to grpc-io+u...@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/grpc-io/c28cc011-2889-4adb-9f50-093427ac4e2dn%40googlegroups.com.
Eric Robins's profile photo
Eric Robins
unread,
Mar 20, 2023, 7:03:14 AM
to grpc.io
I'm well aware of how TCP works. :)  As I've been communicating, traditional REST / HTTP/1.1 services don't trust it alone to guarantee constant communication with the same client.  It is susceptible to TCP/IP hijacking, which admittedly may not be easy to execute without a foothold on the client or server's networks but it's certainly not impossible, and if the traffic in question is valuable enough, it as an attack vector will be considered.  This is why web-based applications have session tokens/cookies, web services always authenticate or use tokens like JWTs, etc, where those credentials are protected cryptographically via TLS or other encryption/signing schemes.  The channel (stateful connection in this case - not to be confused with a gRPC channel) alone is only considered adequate if it binds the client to the server, which can be achieved via TLS but only if the server associates the TLS session with the client.  Many web servers don't do this.  This is why I was asking previously if gRPC or HTTP/2 bind in this fashion.  It's possible that they do and I'm just not aware, in which case a single authentication by the client during the establishment of an RPC is sufficient, as the gRPC server would know to tie the client's identity to the TLS session and invalidate the RPC when appropriate.  TCP alone isn't sufficient.

As a side note point of interest that might help give an example, it's common for mobile-based applications communicating with a server to be bound to connections through the use of previously agreed upon session keys (symmetric encryption), where part of the process of the authentication at the server side involves the use of the key.  That session key may be valid for an extended period of time, and it's carefully protected on the client side - something we normally can't get with browser-based apps (which is why TLS becomes the defacto confidentiality control).

I've sent communication to you offline as at this point it's prudent for me to perhaps work directly with someone at Google.  That could be you but I want to be sensitive to your time.  Thanks for the great feedback you've given so far.
Eric Anderson's profile photo
Eric Anderson
unread,
Mar 21, 2023, 9:45:07 AM
to Eric Robins, grpc.io
gRPC's security model is generally the same as in HTTP. A streaming RPC is simply one HTTP exchange, where the HTTP request and HTTP response can overlap in time. Since you've used HTTP for a while, I'll note that gRPC does not support OAuth HMACs nor "authenticate on first request" like NTLM.
 
how would we consider the established stream and channel secure, how how does the server continue to trust that it's the same client with which it's communicating?

If you are using TLS, then it provides that guarantee. If you are using insecure channel credentials, then you'd only be trusting your datacenter network.

On Mon, Mar 20, 2023 at 7:03 AM Eric Robins <ericro...@gmail.com> wrote:
This is why web-based applications have session tokens/cookies, web services always authenticate or use tokens like JWTs, etc, where those credentials are protected cryptographically via TLS or other encryption/signing schemes.

Right, there's the two parts: bearer tokens and TLS. That same model can be applied to gRPC. The commonly chosen security options for gRPC are 1) OAuth/JWT with TLS and 2) mTLS.

The channel (stateful connection in this case - not to be confused with a gRPC channel) alone is only considered adequate if it binds the client to the server, which can be achieved via TLS but only if the server associates the TLS session with the client. Many web servers don't do this.

gRPC does not support this. It interacts poorly with load balancing. In gRPC, if you want to authenticate only once per connection, use mTLS.

I'll note that a bearer token sent each RPC generally isn't a performance concern in gRPC. HTTP/2 can avoid resending the full token value in each request (via compression) and if the server has a cache, then there would be little per-RPC overhead.
Eric Robins's profile photo
Eric Robins
unread,
Mar 21, 2023, 12:02:24 PM
to grpc.io
Thanks Eric - this is helpful.

If you are using TLS, then it provides that guarantee. If you are using insecure channel credentials, then you'd only be trusting your datacenter network.

If I build a channel that's configured to use TLS, will the server tie that channel to that TLS session such that if that session is closed, the channel (or perhaps the RPC) is closed?  We'd want the server to close the channel after a period of inactivity (configurable I believe in gRPC) or when a TLS close_notify is sent by either party.  If that's the way a gRPC server works, that's what I've been calling a binding to TLS - the channel is established, the client is authenticated (at the channel level or at the RPC level) and communication continues until TLS is broken, at which time either a new authentication is required -or- a new channel is established.

Hopefully you can see where this is going.  I'd love to be able to say with confidence that once a line of communication is established between a client and server, it can't be hijacked.  That could be at either the gRPC channel or RPC level.  Most of today's web technologies don't do this and the only way to identify a previously authenticated client is via an ongoing token/grant/cookie, etc.
 
gRPC does not support this. It interacts poorly with load balancing. In gRPC, if you want to authenticate only once per connection, use mTLS.

Yep, makes sense.
 
I'll note that a bearer token sent each RPC generally isn't a performance concern in gRPC. HTTP/2 can avoid resending the full token value in each request (via compression) and if the server has a cache, then there would be little per-RPC overhead.

If as noted above the gRPC channel and subsequent HTTP/2 streams are tied to the TLS session then we'll likely be in good shape.  If it's not and it's possible to end TLS and still communicate over the channel/RPC then we'd want authN more at the request level.

Thanks Eric... 
