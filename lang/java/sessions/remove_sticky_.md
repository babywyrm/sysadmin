
##
#
https://www.couchbase.com/blog/sticky-sessions/#:~:text=Sticky%20Sessions%20refers%20to%20the,it%20will%20lose%20their%20sessions.
#
https://gkoniaris.gr/design-patterns/why-you-should-never-use-sticky-sessions/
#
https://gvnix.medium.com/sticky-sessions-with-spring-session-redis-bdc6f7438cc3
#
##


Getting Rid of Sticky Sessions in Java | Couchbase Spring Session
 Denis Rosa, Developer Advocate, Couchbase on June 3, 2019
Sticky Sessions refers to the need to redirect the requests of a given user to the same server where his session lives in. It is considered an anti-pattern as in case of a server failure, all users connected to it will lose their sessions.

The association between the user and the server is usually configured via Load Balancer, and simple load balancing strategies like Round‑robin are often not enough to ensure an even distribution of the requests, as heavy users might end up all in the same node. There are many ways in which sticky sessions could be avoided, but if your application stores user’s data in the  HTTPSession, the options without requiring a substantial refactoring are a little bit limited.

One quick fix to this problem is to store the session in the database instead of using the server’s memory. In this scenario, no matter what node receives the request, it will load the user’s session directly from the data store. This approach is simpler than container specific solutions, and also allow you to query sessions like anything else in your database.

Couchbase fits particularly well in this scenario: It uses the internal key-value engine and also leverages the internal cache layer to keep the recently used sessions in memory. In practice, it means that this is a solution that will perform well even at scale. That is why we are adding community support Spring Session:

Couchbase Spring Session makes it trivial to support clustered sessions by storing it on the database and from the developer point of view it is totally transparent. All you have to do is to add the following dependency:
```
<dependency>
	<groupId>io.github.couchbaselabs</groupId>
	<artifactId>spring-session-data-couchbase</artifactId>
	<version>1.1</version>
</dependency>
and then, in your main class, add the @EnableCouchbaseHttpSession annotation:

@SpringBootApplication
@EnableCouchbaseHttpSession
public class SessionStoreApplication {
 
	public static void main(String[] args) {
		SpringApplication.run(SessionStoreApplication.class, args);
	}
 
}
and that is it!. Spring will automatically save the HTTPSession in the Couchbase from now on:

    @GetMapping("/newSession")
    public String newSession(HttpServletRequest request, Model model) throws Exception {
 
        request.getSession().invalidate();
        HttpSession newSession = request.getSession();
        newSession.setAttribute("foo", new Foo("key", "value"));
        return defaultPage(model, newSession);
    }
By default, the session will be stored in the database in a document with a type equals to “sessions“:

//key : 5b357ade-6059-4d16-aea3-6f784765e7b5
 
 
{
  "_principal": null,
  "_interval": 1800,
  "_expireAt": 1554743279889,
  "_created": 1554741479889,
  "_accessed": 1554741479889,
  "_type": "sessions",
  "_attr": "\"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAADZm9vc3IAHWNvbS5jYi5zZXNzaW9uc3RvcmUubW9kZWwuRm9vO5F+XaK9pV0CAAJMAAphdHRyaWJ1dGUxdAASTGphdmEvbGFuZy9TdHJpbmc7TAAKYXR0cmlidXRlMnEAfgAEeHB0AAZ2YWx1ZTF0AAZ2YWx1ZTJ4\""
}
But you can change the name of the type attribute, the type value and how long the session should last:

@SpringBootApplication
@EnableCouchbaseHttpSession(typeName = "myType",  typeValue = "myValueType", maxInactiveIntervalInSeconds = 1800)
public class SessionStoreApplication {
 
	public static void main(String[] args) {
		SpringApplication.run(SessionStoreApplication.class, args);
	}
 
}
 ```

Querying the user’s session
Note that, all session’s data is binary stored in an attribute called _attr:

{
...
  "_attr": "\"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAADZm9vc3IAHWNvbS5jYi5zZXNzaW9uc3RvcmUubW9kZWwuRm9vO5F+XaK9pV0CAAJMAAphdHRyaWJ1dGUxdAASTGphdmEvbGFuZy9TdHJpbmc7TAAKYXR0cmlidXRlMnEAfgAEeHB0AAZ2YWx1ZTF0AAZ2YWx1ZTJ4\""
}
Spring doesn’t know which objects types are in the session, so there is no easy way to convert it to human-readable format. You can overcome this limitation by setting the attribute keepStringAsLiteral as true in the EnableCouchbaseHttpSession annotation:

@SpringBootApplication
@EnableCouchbaseHttpSession(keepStringAsLiteral = true)
public class SessionStoreApplication {
 
	public static void main(String[] args) {
		SpringApplication.run(SessionStoreApplication.class, args);
	}
 
}
keepStringAsLiteral will tell Couchbase Spring Session to store all session’s String attributes as top-level properties within the document. For instance, instead of adding an instance directly to the session, we could convert the object to a JSON-encoded String format using Jackson’s ObjectMapper:

ObjectMapper mapper = new ObjectMapper();
session.setAttribute("key", mapper.writeValueAsString(myClassInstance))
And then, when you need to read the session cart, convert it back to an object:

ObjectMapper mapper = new ObjectMapper();
mapper.readValue( session.getAttribute("key").toString(), MyClass.class);
This will add a small extra effort when you need to add/remove/update data from the session, but on the flip side, you will able to query sessions. Here is how the document will look like in the database:
//key : 5b2a2487-4825-43de-b089-1b61703556b2
 
{
  "_principal": null,
  "_interval": 1800,
  "_expireAt": 1554746972015,
  "_created": 1554745163803,
  "_accessed": 1554745172015,
  "key": "{\"shoppingCart\":{\"created\":1554745170784,\"items\":[{\"itemName\":\"Tennis Shoes\",\"price\":38.25186017511709,\"quantity\":3}]},\"user\":{\"username\":\"robertst\",\"phoneNumber\":\"(500)-383-1668\"},\"location\":{\"address\":\"90 Arrowhead Avenue Jonesboro, GA 30236\",\"country\":\"USA\",\"coordinates\":{\"lat\":10,\"lon\":37}}}",
  "_type": "sessions",
  "_attr": "\"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeA==\""
}

Note that we still have the _att attribute for objects which are not a String. However, now we also have an attribute called key, which is exactly the object we added to the session in the previous example.
Now, if you want to query your session, N1QL has a function called DECODE_JSON, which can unmarshal a JSON-encoded String to an object:

SELECT
    meta().id as id, _created, ARRAY_COUNT(DECODE_JSON(sessionCart).shoppingCart.items)
FROM sessionstore
ORDER BY _created DESC
LIMIT 10
Note: In a production environment, we recommend you to create an index with the decoded object instead of decoding it on query time.

If you want to read more about Couchbase Spring Session, check out this tutorial

If you have any questions, feel free to pint me at @deniswrosa





WHY YOU SHOULD NEVER USE STICKY SESSIONS
  
 May 5, 2020  George Koniaris Comments 0 Comment
0
SHARES

Sticky sessions grant the ability to route incoming requests to a specific server, based on their session identifier. We usually find them in applications that keep their state in a non-sharable service. An example is keeping state in memory or the server’s hard disk. In this article, we will discuss what sticky sessions are. We will also explain why they are “bad”, and how to design an application so we can fully avoid them.

How do sticky sessions work?
Binding a sessionID to a specific server on our infrastructure, overrides our default load-balance strategy. Below, you can see a diagram showing how a user can request a session from our servers. The load balancer routes the request in a random server, in our example, Server 2.

Initial request that is performed for sticky sessions to work
Request session process to use sticky sessions
After getting a sessionID, the session is bounded to Server 2. In that case, the load balancer forwards each consecutive request to this server.

Sticky sessions default routing policy after getting a sessionID
Route all requests to specific session, based on sticky sessions pattern
This usually happens by applications that keep their state in some local storage, like memory or an HDD. This way, Server 1 doesn’t have access to the actions performed by previous requests. Server 2 is now obliged to serve these requests.

Why you should avoid sticky sessions?
They can make our application go down easily
Imagine that one of our servers goes down. Because of the architecture we chose to follow, even if we use persistent storage like HDD for example, to keep our application’s state, we won’t be able to access this data from other servers. Furthermore, if we use the application’s memory as our state storage, we are doomed to lose all data that were bounded to this server’s sessions in case of a server restart.

Our application doesn’t scale correctly
Another key point that we have to mention is, that sticky sessions don’t allow our application to scale correctly. When we bind a server to a specific request, we directly remove the ability to use our other servers’ capacity to fulfill consecutive requests. As a result, when we perform a CPU intensive task in the specific session, we force one instance of our infrastructure to handle all its load.

They can be dangerous.
Furthermore, binding sessions to specific servers can cause security concerns too. What if someone decides to create a session, and then perform a set of very CPU intensive requests on our application? See the example below.

How to exploit sticky sessions to perform DOS attacks
Exploit sticky session to perform DOS attack on server
The load balancer forwards each request to the server that the session is bounded to. This is called a DOS attack, and it greatly increases the server load. By using sticky sessions, an attacker can perform this operation with half the resources that would be required if we were not using them. That’s only true for the specific example. The bigger the infrastructure, the higher the chances that someone would bother to exploit this “vulnerability”. This would allow the attacker to take our servers down one by one, with a considerably lower cost. Also, it would require us to create extra monitoring rules to recognize this type of attack, because the total server load of our servers will not be that high when only one server is attacked.

Is there an alternative?
Yes, there is, and you should probably use it. An application can get rid of sticky sessions by using an external service for keeping its state. See the example below.

The correct way to handle your state using a central database service
How to correctly design our application
Each server performs actions, saving the process of each task or request to a shareable resource, like MySQL or Redis, making it available to all other servers of our infrastructure. This way, the load balancer forwards each request between all available servers, instead of just one. Also, servers can serve consecutive requests no matter which server served the previous one.

If you found this blog post useful, you can subscribe to my newsletter and get to know first about any new posts.

##
##
