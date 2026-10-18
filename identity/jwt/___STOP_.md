// https://gist.github.com/samsch/0d1f3d3b4745d778f78b230cf6061452
//

# Stop using JWTs!

TLDR: JWTs should not be used for keeping your user logged in. They are not designed for this purpose, they are not secure, and there is a much better tool which is designed for it: regular cookie sessions.

If you've got a bit of time to watch a presentation on it, I highly recommend this talk: https://www.youtube.com/watch?v=pYeekwv3vC4 (Note that other topics are largely skimmed over, such as CSRF protection. You should learn about other topics from other sources. Also note that "valid" usecases for JWTs at the end of the video can also be easily handled by other, better, and more secure tools. Specifically, [PASETO](https://paseto.io/).)

A related topic: Don't use localStorage (or sessionStorage) for authentication credentials, including JWT tokens: https://www.rdegges.com/2018/please-stop-using-local-storage/

The reason to avoid JWTs comes down to a couple different points:
- The JWT specification is specifically designed only for very short-live tokens (~5 minute or less). Sessions need to have longer lifespans than that.
- "stateless" authentication simply is not feasible in a secure way. You must have some state to handle tokens securely, and if you must have a data store, it's better to just store all the data. Most of this article and the followup it links to describes the specific issues: http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/
  - (Yes, people are doing it, and yes, their applications are flawed, and you should not repeat that mistake.)
- JWTs which just store a simple session token are inefficient and less flexible than a regular session cookie, and don't gain you any advantage.
- The JWT specification itself is not trusted by security experts. This should preclude **all** usage of them for anything related to security and authentication. The original spec specifically made it possible to create fake tokens, and is likely to contain other mistakes. [This article](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid) delves deeper into the problems with the JWT (family) specification.

## Rebuttals

*But Google uses JWTs!* Google does **not** use JWTs for user sessions in the browser. They use regular cookie sessions. JWTs are used purely as Single Sign On transports so that your login session on one server or host can be transferred to a session on another server or host. This is within the reasonable usecases for JWTs, and Google has the resources (security experts) to create and maintain a more secure JWT implementation. Their JWTs are effectively not the same as anyone else's.

*But stateless is better!* You can't securely have truly stateless authentication without having massive resources, see the cryto.net link above. Also, [Stateless is a lie](https://gist.github.com/samsch/259517828ab4557c5c8b72ca1252992d).

*I don't know how to setup sessions!* You don't regularly see articles explaining sessions because the technology isn't particularly new. You also shouldn't need third party information for setup. A session implementation's documentation should take you through the setup process by itself. Almost any web server framework will contain an implementation for sessions, and usually it's very easy to enable if it isn't enabled by default. Express and other Node.js frameworks are somewhat exceptions to this rule, primarily because they are highly modular and single purpose. For Express, you simply use the `express-session` middleware and a store connector which works with your store (I recommend `connect-session-knex`, to be used with Postgres, MySQL, or possibly SQLite).

## Short term tokens

If you do need a short-lived, signed token for something, there is a better spec called [PASETO](https://paseto.io/) which *is* designed to be secure. Just make sure you aren't using them for sessions.

## How sessions work

I recommend checking out [this gist by joepie91](https://gist.github.com/joepie91/cf5fd6481a31477b12dc33af453f9a1d) to learn more how sessions work.



Skip to content
All gists
Back to GitHub
Sign in
Sign up

Instantly share code, notes, and snippets.
@samsch
samsch/stop-using-jwts.md
Last active November 3, 2023 04:57

Code
Revisions 9
Stars 169
Forks 10
Stop using JWTs
stop-using-jwts.md
Stop using JWTs!

TLDR: JWTs should not be used for keeping your user logged in. They are not designed for this purpose, they are not secure, and there is a much better tool which is designed for it: regular cookie sessions.

If you've got a bit of time to watch a presentation on it, I highly recommend this talk: https://www.youtube.com/watch?v=pYeekwv3vC4 (Note that other topics are largely skimmed over, such as CSRF protection. You should learn about other topics from other sources. Also note that "valid" usecases for JWTs at the end of the video can also be easily handled by other, better, and more secure tools. Specifically, PASETO.)

A related topic: Don't use localStorage (or sessionStorage) for authentication credentials, including JWT tokens: https://www.rdegges.com/2018/please-stop-using-local-storage/

The reason to avoid JWTs comes down to a couple different points:

    The JWT specification is specifically designed only for very short-live tokens (~5 minute or less). Sessions need to have longer lifespans than that.
    "stateless" authentication simply is not feasible in a secure way. You must have some state to handle tokens securely, and if you must have a data store, it's better to just store all the data. Most of this article and the followup it links to describes the specific issues: http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/
        (Yes, people are doing it, and yes, their applications are flawed, and you should not repeat that mistake.)
    JWTs which just store a simple session token are inefficient and less flexible than a regular session cookie, and don't gain you any advantage.
    The JWT specification itself is not trusted by security experts. This should preclude all usage of them for anything related to security and authentication. The original spec specifically made it possible to create fake tokens, and is likely to contain other mistakes. This article delves deeper into the problems with the JWT (family) specification.

Rebuttals

But Google uses JWTs! Google does not use JWTs for user sessions in the browser. They use regular cookie sessions. JWTs are used purely as Single Sign On transports so that your login session on one server or host can be transferred to a session on another server or host. This is within the reasonable usecases for JWTs, and Google has the resources (security experts) to create and maintain a more secure JWT implementation. Their JWTs are effectively not the same as anyone else's.

But stateless is better! You can't securely have truly stateless authentication without having massive resources, see the cryto.net link above. Also, Stateless is a lie.

I don't know how to setup sessions! You don't regularly see articles explaining sessions because the technology isn't particularly new. You also shouldn't need third party information for setup. A session implementation's documentation should take you through the setup process by itself. Almost any web server framework will contain an implementation for sessions, and usually it's very easy to enable if it isn't enabled by default. Express and other Node.js frameworks are somewhat exceptions to this rule, primarily because they are highly modular and single purpose. For Express, you simply use the express-session middleware and a store connector which works with your store (I recommend connect-session-knex, to be used with Postgres, MySQL, or possibly SQLite).
Short term tokens

If you do need a short-lived, signed token for something, there is a better spec called PASETO which is designed to be secure. Just make sure you aren't using them for sessions.
How sessions work

I recommend checking out this gist by joepie91 to learn more how sessions work.
@samsch
Author
samsch commented Apr 13, 2019

"Sessions don't make any sense in a stateless API."

Users, and any other data in your application, are state.

If you have users, you have a stateful service. If you have a stateful service, you most likely have a DB of some kind. If you have a DB of some kind, you can use sessions (while keeping your API services "stateless").

Sessions can be shared between servers that the client accesses (since the sessions are in the shared DB). Where those services are on different hosts, you use one-time tokens to identify that a new connection should be attached to a current session. Alternatively, separate services can use separate session mechanisms, and that's where a tool similar to JWTs (trusted (signed), encrypted, one-time-use tokens containing user ID or other identification) can be used to do an autht transfer.
@samsch
Author
samsch commented Jul 5, 2019 •

"Why does everyone recommend JWTs then?" or "Why are JWTs so popular?"

You probably didn't catch the YouTube link above, which explains how it got started near the end. The short version is that a certain subset of engineers got excited and started writing posts about JWTs when the spec was written. These articles were misunderstood, and the idea to use JWTs for sessions propagated largely through more blog posts. Primarily these articles were written by users who simply didn't understand the technology, but because the existing tools for sessions weren't "exciting" or new enough to be written about, the topic effectively flooded the Google results for how to do authentication with new and hip technologies (Angular, Node, React, etc).

After building up like this for a few years, the coding bootcamps started including JWTs in their lessons, furthering the myth that they are good for authentication by acting as an authority who should know. This happens because sadly bootcamps teach things that are popular, not real best practices and the best tools.

Cookies are an "old" tech. But being old doesn't make something better or worse, and often when it comes to security, something being older and unbroken is much better than something newer and less proven.
@vcarl
vcarl commented Sep 29, 2020

I think this followup to a linked blog post is also a good resource (a flow chart of basically all the responses I've seen) http://cryto.net/~joepie91/blog/2016/06/19/stop-using-jwt-for-sessions-part-2-why-your-solution-doesnt-work/

And I like this slide of good uses for JWTs from this deck as well, (PDF) https://owasp.org/www-chapter-vancouver/assets/presentations/2020-01_Attacking_and_Securing_JWT.pdf

    tokens used for authorization, but not session management
    short lived (few minutes)
    expected to be used once (confirm authentication/authorization and get a
    session ID)

@HosMercury
HosMercury commented Jul 14, 2021

thanx for the great article
@Longwater1234
Longwater1234 commented Dec 4, 2021

Definitely. Good old sessions with SECURE, HTTP-only cookies for the win. Best used with Redis store.
@samsch
Author
samsch commented Dec 5, 2021

@Longwater1234 Unless you have performance issues with your sessions in your primary data store, using Redis is unnecessary added complexity. Also, when using something like the knex connector with express-session, if needed, you can directly query across your session data joined to something like your users table.
@ManasN
ManasN commented Apr 12, 2022 •

Hi, I've been reading about this since couple of days and every-time I feel like I am back to square one whenever I try to implement something real.

suppose I want to develop a backend API for mobile applications. It need not follow REST as per religion. I will be using a single centralised server to keep track of everything. Basically a cruddy TODO app with users and roles.

Also, please consider that I am by no means a security expert. Just a developer who wants to collect the paycheque while delivering reasonably secure system. How would I go about doing that in day-to-day development in a secure way? Are there any frameworks/libraries that use cookies to persist sessions on mobile applications? Please help.
@samsch
Author
samsch commented Apr 12, 2022

@ManasN There's no practical difference for the backend between mobile and web apps. You can use exactly the same tools and follow the same steps and rules as for web when building for mobile.

The difference with mobile is that you don't have CSRF to deal with anymore (though you might want to ensure you can't make cross-origin requests via browser anyway, like by always requiring a matched Origin header (something you can easily include on mobile but the browser controls for web)), and that cookies are "just headers" to a basic http client (though you may be able to use a client which automatically handles cookies in a browser-like way as well). As long as the cookies are sent back with each request (to the correct domain! make sure you don't send all cookies with all requests!) similar to what a browser does, that's all you really need on the client-side.

Most web frameworks for platforms/languages other than Node will includes a built-in (or at least integrated) cookie-based sessions mechanism that you can turn on (or leave on by default) and use for your autht system. Some frameworks have full simple autht systems ready to go out of the box (e.g., Laravel). For Node, the best tools are express-session (and appropriate DB connector) with Express, but you will need to build the login system on top of it.
@kishoreandra
kishoreandra commented Sep 22, 2022

Thanks for info samsch 🙏, the video by R Degges is 🔥 JWT 0 - 100 Session 😉
@arantisi
arantisi commented Feb 22, 2023

hello im new to spring security. and with spring boot 3 just being released. is there any example code base to look at with a restful api? thank you
@SeiwonPark
SeiwonPark commented Mar 17, 2023 •

Thank you for sharing this article. And here's the reason for Google does not use JWTs for user sessions in the browser. They use regular cookie sessions on its Security section

For example, cookies called ‘SID’ and ‘HSID’ contain digitally signed and encrypted records of a user’s Google Account ID and most recent sign-in time. The combination of these cookies allows Google to block many types of attack, such as attempts to steal the content of forms submitted in Google services.

@omidp
omidp commented Apr 2, 2023

As far as I can remember I stopped using sessions because it was hard to scale. clustering your webserver is cumbersome even when you are lucky enough that your webserver implements it right that's why the extra layer of complexity of adding a distributed cache is required in large scale app. I prefer to use Hazelcast or Redis.

Cookie sessions and local storage also have their own downsides.

You don't have to put sensitive info in JWT. You can put an identifier / user id in a JWT token and retrieve those data from cache by using that identifier.

I wouldn't say Stop using JWT, I would say use it in a right way.
@samsch
Author
samsch commented Apr 3, 2023

@omidp Refer here: http://cryto.net/%7Ejoepie91/blog/2016/06/19/stop-using-jwt-for-sessions-part-2-why-your-solution-doesnt-work/

If you can retrieve your user from the cache, you can retrieve a session for the same (probably cheaper, actually) "cost".

There is no right way to use JWTs for sessions. Like, it's not an opinion, it can be objectively and logically shown.
@dragosstancu
dragosstancu commented Jul 21, 2023

funny how cryto.net is over http :)
to join this conversation on GitHub. Already have an account? Sign in to comment
Footer
© 2023 GitHub, Inc.
Footer navigation

    Terms
    Privacy
    Security
    Status
    Docs
    Contact GitHub
    Pricing
    API
    Training
    Blog
    About

