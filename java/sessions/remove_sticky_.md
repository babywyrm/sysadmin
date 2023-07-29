
##
#
https://www.couchbase.com/blog/sticky-sessions/#:~:text=Sticky%20Sessions%20refers%20to%20the,it%20will%20lose%20their%20sessions.
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
