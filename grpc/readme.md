
##
#
https://www.trendmicro.com/en_us/research/20/h/how-unsecure-grpc-implementations-can-compromise-apis.html
#
##

Enterprises are turning to microservice architecture to build future-facing applications. Microservices allow enterprises to efficiently manage infrastructure, easily deploy updates or improvements, and help IT teams innovate, fail, and learn faster. It also allows enterprises to craft applications that can easily scale with demand. Additionally, as enterprises switch architectures — jumping from the traditional monolithic to microservices — the need for efficient communication between microservices arises. This critical and complex communication between client and server applications can be handled by gRPC, a universal remote procedure call (RPC) framework that facilitates the transparent and efficient communication between connected systems. Although quite new (having only been developed by Google in 2015), it has quickly gained popularity and adoption.

In this blog, we will discuss the security pitfalls that developers might face when shifting to gRPC and implementing gRPC in their projects. Because secure gRPC APIs play a pivotal role in overall application security, we provide recommendations on how to protect gRPC implementations from threats and mitigate against risks.

What is gRPC?
gRPC can be used to design new protocols that require accuracy, efficiency, and language independence as it supports multiple languages for both servers and clients. It is a Cloud Native Computing (CNCF) project and has been adopted by major companies such as popular video-streaming site Netflix, financial services company Square, and platform as a Service (PaaS) company Docker.

gRPC is compared to other RPC frameworks, such as SOAP and REST. Though RESTful APIs are widely used and typically use HTTP to exchange information between apps or services and the JavaScript Object Notation (JSON) data format, they have performance and text-based orientation limitations.

Many organizations have migrated their APIs from REST to gRPC to take advantage of gRPC’s binary protocol that is better suited for interservice communications. gRPC uses the HTTP/2, a binary-based protocol, as an underlayer by default. HTTP/2 supports multiple streams and requests within one TCP connection, unlike its predecessor, HTTP/1.0, which was designed to have a “single request, single reply” scheme. HTTP pipelining addressed this issue in HTTP/1.1; however, HTTP 2.0 is still more performant and supported.

Visualization of difference of HTTP/1.0 and HTTP/2 when it comes to requests and replies
Figure 1. A visualization of how HTTP/1.0 differs from HTTP/2 when it comes to requests and replies
The gRPC is built on top of protocol buffers (or protobuf),  Google’s platform- and language-neutral mechanism for serializing structured data. Serialization is a process of converting in-memory objects into a byte stream that can be easily saved into a file or transmitted through the network for other applications. Developers describe the data interface once and then compile it using a protocol buffer compiler for a chosen language. In the case of gRPC, protocol buffers are also used for defining the RPC interface.

Illustration of how the gRPC framework works
Figure 2. An illustration of how the gRPC framework works in an online retail application that has the product and payment services interacting via APIs
example of  a gRPC “HelloWorld” demonstration. Image credit: gRPC Quick Start
Figure 3. An example of a gRPC “HelloWorld” demonstration sending a string message. Image credit: gRPC Quick Start
Potential Threats and Risks to gRPC

Vulnerabilities

gRPC supports multiple programming languages. There are two types of implementations used within the supported languages: a) implementation using the language itself, and b) wrappers around the gRPC C-core written code. These wrappers enable the translation of calls written in different supported languages into C calls. Though the C language implementations generally perform well, there is a higher chance that a developer will introduce a vulnerability into the system as there is a need to implement more functionalities together with memory management capabilities. On the other hand, using languages such as Java or Go, which already have a lot of functionalities implemented and also take care of memory management concerns, reduces the chances of a developer introducing high-impact bugs to the system. Notably, the importance of choosing suitable languages might play a significant role in keeping systems more secure.

Supported Programming Languages	Actual Implementation
C/C++	Yes
C#	Yes*
Dart	Yes
Go	Yes
Java	Yes
Kotlin/JVM	Yes
Node.js	Yes**
Objective-C	No
PHP	No
Python	No
Ruby	No
WebJS	Yes
* It is possible to have a purely C# implementation or a C# wrapper around C
** Purely JavaScript implementation as well as bindings to gRPC C-core (using a C++ add-on)


Unsecure data transmission channels and channel credentials

It is highly probable that during a remote procedure call, data will be transferred to the target server. This is why developers should prioritize setting up secure channels for data transmission. Doing this not only prevents data leaks but also limits Man-in-the-Middle (MiTM) attacks, as skilled attackers may leak service data or inject malicious data to the connection that will interfere with the server.

A data leak can reveal implementation details about your service or infrastructure that can enable further attacks and even lead to service or infrastructure compromise. Here’s an example of a packet capture from an insecure gRPC call:
Example of a packet capture from an unsecure gRPC call
Figure 4. An example of a packet capture from an unsecure gRPC call
gRPC supports TLS over the whole underlying HTTP/2 protocol as well as various authentication mechanisms. It’s a developer’s responsibility to choose a secure implementation. Copying and pasting patterns with keywords like “InsecureChannelCredentials” should be avoided for obvious reasons.

We have performed a Github.com code search for  the “InsecureChannelCredentials”  keyword together with a C++ language limitation (which is common to gRPC usage). The search yielded over 11,000 code results.  We believe that the significant number of search occurrences are associated with demos and examples. However, there are still some projects that use them.

Code search results for “InsecureChannelCredentials”
Figure 5. “InsecureChannelCredentials” code search results
Procedure implementation concerns

Similarly, for AWS Lambda functions, the biggest vulnerability surface is hidden inside the actual remote procedure implementation. Because gRPC supports multiple languages, we suggest that novice developers use memory-safe languages in order to avoid high-impact memory management bugs such as buffer overflows or use-after-free (UaF) bugs leading to the remote code execution (RCE).

However, using memory-safe languages will still not be able to mitigate the logical bugs that might appear in the code. For that purpose, developers should set a high standard for developing processes, consistently follow the secure software development best practices, and implement proactive controls by using the OWASP Top 10 Proactive Controls recommendations in the OWASP Secure Coding Practices.

Having a centralized authentication mechanism for critical parts of the system is highly recommended even inside isolated networks or private clouds. In the case of misconfigurations, vulnerability exploitation inside the environment may serve as an entry point for unauthorized access that could significantly interfere with the gRPC service.

We also suggest not to hard-code or commit gRPC authentication details to supply chain management (SCM) systems, especially public-facing ones. Just like any other credential information, those should be stored inside a secure location and accessed only when needed. Here’s an example of a gRPC credential leakage we found just by searching on GitHub:

Example of gRPC service credentials found on GitHub
Figure 6. An example of gRPC service credentials found on GitHub
Denial of service attacks

Lastly, we would like to discuss our denial of service (DoS) attack findings. gRPC can serve as a “hidden” messaging service inside isolated environment as well as an API replacement to public-facing REST API services using the JSON format.

We would like to warn C/C++ gRPC users of an already known yet still unfixed bug that effectively denies service calls until the service is restarted. The bug is triggered when a higher number of connections is opened within a short period of time. In fact, this is due to the limitation on the number of opened file descriptors on Linux systems.

Example of a DoS attack inside a C/C++ implementation of a gRPC library
Figure 7. An example of a DoS attack inside a C/C++ implementation of a gRPC library
Based on our research, the bug is triggered when socket connections are opened within a short amount of time and even after the opened socket has been closed. We tested this implementation in other languages that are not C-wrapped such as Java and Go and discovered that they are not affected by this issue.

We propose the following workarounds to help mitigate the risk of DoS attacks in case switching from one platform to another is not an option:

Increase the limit of file descriptors by executing “sudo ulimit -n increasedNumber”.
Use an external load balancer and service watchdogs to reduce the load for a single instance and to keep an eye on status of the service.

Security Recommendations for gRPC

As the number of enterprises using the gRPC framework continues to increase because of its reliability and scalability of services, there should be a more widespread awareness of how the protocol must be kept protected against risks and threats.

Though gRPC enables the efficient communications between systems, it must be emphasized that it is the developer’s responsibility to ensure that the communications between these systems are kept secure. gRPC has a comprehensive guide on the supported authentication mechanisms that will work with the protocol, such as SSL/TLS with or without Google token-based authentication, that developers should follow. Developers also have the option of plugging in their own authentication system via the Credentials plugin API.

Developers should also use security solutions that will validate content, ensuring that no malicious payload will be able to infiltrate the system through the messages that are transferred from the client to the server and vice versa.

Solutions that will ensure that critical data is kept secure in transit, keep an eye on the status of a service, and enforce authentication and authorization to keep data secure will also be vital for enterprises.

The gRPC framework is an effective tool for developers and enterprises to build APIs, applications, and microservices. But like its predecessors, it is likewise not impervious to risks and threats — hence the need for security solutions, checks, and controls should be highlighted.

Trend Micro solutions

The Trend Micro Cloud One™ security services platform, which powers Trend Micro™ Hybrid Cloud Security, enables software developers to build and run applications their way. It has security controls that work across existing infrastructure or modern code streams, development toolchains, and multiplatform requirements.

Application Security, which is offered by Cloud One, provides full diagnostic details about code vulnerabilities and runtime protection against automated attacks and the most common threats like SQL injection and RCE. It also offers complete coverage and reporting of every attack instance, as well as insight into an attacker’s identity and attack methodology.

Cloud One also offers the following cloud security technologies to further help developers identify and resolve security issues sooner and improve delivery time for DevOps teams:




# protoc-gen-map
WARNING: This project is no longer maintained. For SQL data mapping, use [Carta](https://github.com/jackskj/carta). 

protoc-gen-map simplifies the management of complex datasets by mapping SQL data to protocol buffers. 
Aside from defining proto messages and SQL statements, the developer does not need to write any data retrieval or mapping code. 

## Approach
protoc-gen-map adopts the "database mapping" approach (described in Martin Fowler's [book](https://books.google.com/books?id=FyWZt5DdvFkC&lpg=PA1&dq=Patterns%20of%20Enterprise%20Application%20Architecture%20by%20Martin%20Fowler&pg=PT187#v=onepage&q=active%20record&f=false)) which is useful among organizations with strict code review processes and dedicated database modeler teams.

protoc-gen-map is language agnostic. Any language with protocol buffer support can request and retrieve data over gRPC using defined messages.

This framework is not an object-relational mapper(ORM). With large and complex datasets, using ORMs becomes restrictive and reduces performance when working with complex queries. 

## SQL Templating

protoc-gen-map uses golang's template engine (text/template). This allows developers to dynamically modify sql parameters based on the gRPC request message, use if statements or for loops, as well as split large SQL statements into multiple logical blocks. More in the examples below.  

## Examples and Guides
### Simple example
Let's use a very simple schema

[![SimpleSchema](https://i.ibb.co/DQsBgBv/Simple-Schema.png "SimpleSchema")](https://i.ibb.co/DQsBgBv/Simple-Schema.png "SimpleSchema")

Say we want to retrieve blog information based on some request.
To do so we can create a gRPC service and SQL template as follows

proto file:
```
service BlogService {
    rpc SelectBlog (BlogRequest) returns (BlogResponse) {}
    rpc SelectBlogs (BlogRequest) returns (stream BlogResponse) {}
}

message BlogRequest {
    uint32 id = 1;
    string author_id  = 2;
}

message BlogResponse {
    uint32 id = 1;
    string title  = 2;
    string author_id  = 3;
}
```
SQL statement using go's template:
```
{{ define "SelectBlog" }}
    select id, title, author_id from blog where id = {{ .Id }}  limit 1
{{ end }}

{{ define "SelectBlogs" }}
    select id, title, author_id from blog where author_id = {{ .AuthorId }}
{{ end }}
```
Now we would need to template the SQL statements based on an incoming request, map the retrieved SQL data to the response, and return the response. protoc-gen-map generates code that accomplishes all this.

In the above example, the client sending a request to SelectBlog receives a BlogResponse with sql response properly mapped to the BlogResponse proto message.
Streaming services indicate that we are requesting multiple responses. In this case. SelectBlogs would return all BlogResponses for a given author. 

### When things get complex
Things usually aren't as simple. SQL statements often tend to be complex and lengthy, especially when projects grow in size and feature. 
protoc-gen-map helps manage those complexities. All that is required are the SQL statement and the corresponding proto messages

Now Lets use a more complex schema, one with has-one and has-many relationships.

[![ComplexSchema](https://i.ibb.co/QQRpTCV/Complex-Schema.png)](https://i.ibb.co/QQRpTCV/Complex-Schema.png)

Now, say we need to retrieve a much more detailed information about a blog, as with the following query.
```
{{ define "SelectDetailedBlog" }}
select
       id                  as  blog_id,
       title               as  blog_title,
       A.id                as  author_id,
       A.username          as  author_username,
       A.password          as  author_password,
       A.email             as  author_email,
       A.bio               as  author_bio,
       A.favourite_section as  author_favourite_section,
       P.id                as  post_id,
       P.blog_id           as  post_blog_id,
       P.author_id         as  post_author_id,
       P.created_on        as  post_created_on,
       P.section           as  post_section,
       P.subject           as  post_subject,
       P.draft             as  draft,
       P.body              as  post_body,
       C.id                as  comment_id,
       C.post_id           as  comment_post_id,
       C.comment           as  comment_text,
       T.id                as  tag_id,
       T.name              as  tag_name
from blog
       left outer join author A    on  blog.author_id = A.id
       left outer join post P      on  blog.id = P.blog_id
       left outer join comment C   on  P.id = C.post_id
       left outer join post_tag PT on  PT.post_id = P.id
       left outer join tag T       on  PT.tag_id = T.id
where blog.id =  {{ .Id }}
{{ end }}
```
Note that this query involves a number of has-one and has-many relationships. With protoc-gen-map, all the retrieved rows are mapped into structured proto messages, defined below. There is no need to write any data retrieval or mapping code.

``` 
service BlogQueryService {
  rpc SelectDetailedBlog (BlogRequest) returns (DetailedBlogResponse) {}
}

message BlogRequest {
  uint32 id = 1;
}

message DetailedBlogResponse {
  uint32 blog_id = 1;
  string blog_title = 2;
  Author author = 3;
  repeated Post posts = 4;
}

message Author {
  uint32 author_id = 1;
  string author_username = 2;
  string author_password = 3;
  string author_email = 4;
  string author_bio = 5;
  Section author_favourite_section = 6;
}

message Post {
  uint32 post_id = 1;
  uint32 post_blog_id = 2;
  uint32 post_author_id = 3;
  google.protobuf.Timestamp post_created_on = 4;
  Section post_section = 5;
  string post_subject = 6;
  string draft = 7;
  string post_body = 8;
  repeated Comment comments = 9;
  repeated Tag tags = 10;
}

message Comment {
  uint32 comment_id = 1;
  uint32 comment_post_id = 2;
  string comment_name = 3;
  string comment_text = 4;
}

message Tag {
  uint32 tag_id = 1;
  string tag_name = 2;
}

enum Section {
  cooking = 0;
  painting = 1;
  woodworking = 2;
  snowboarding = 3;
}
```
Client requesting a detailed blog information will receive the DetailedBlogResponse with properly mapped data from the rows retrieved by the query

## Installation 
```
go get -u github.com/jackskj/protoc-gen-map
```
## Workflow
protoc-sql-map is a code-generating proto plugin and a data mapping framework. This section explains the 3 steps to get started.
For an example case, head over to [examples](https://github.com/jackskj/protoc-gen-map/tree/master/examples) 
### 1. Define SQL and Proto
Define your SQL statements with go's templating syntax in a file directory. protoc-gen-map will recursively read all sql files in the directory.
Next, define the corresponding gRPC services and protobuf messages. 
For instructions on defining SQL/proto head over to [SQL/Proto Definition](https://github.com/jackskj/protoc-gen-map#sqlproto-definition).

### 2. Generate Code
Once proto message and SQL templates are created, protoc-gen-map will generate ".pb.map.go" files containing service servers for each defined server in your proto. The name of the generated servers is your name of the server followed by "MapServer".

To generate the protoc-gem-map, make sure that the protoc-gem-map binary (located in $GOPATH/bin) is in your in your PATH.
The following will generate ".pb.go" (protoc-gen-go with grpc) and ".pb.map.go" (sql data mapper).
```
protoc --map_out="sql=/my/SQL/directory:/my/out/directory"   \
       --go_out="plugins=grpc:/my/out/directory"   \
       -I=. \
       ./my_proto_file.proto
```
Make sure to change the SQL directory, proto files, and out location. 

### 3. Create the Server

To create a server, register an instance of "MapServer" struct created by protoc-gen-map. Make sure to provide a database connection object and dialect name.

```
lis, err := net.Listen("tcp", fmt.Sprintf(":%d", myPort))
if err != nil {
	// error when listening on the port fails
}
grpcServer := grpc.NewServer()
db, err := sql.Open(dialect, connectionString)
if err != nil {
	// error when connection to DB fails
}
mapServer := BlogQueryServiceMapServer{DB: db, Dialect: dialect}
RegisterBlogQueryServiceServer(grpcServer, &mapServer)
... 
grpcServer.Serve(lis)
```

protoc-gen-map intends to be a bridge between complex sql statements and defined proto messages. Any languages with protobuf support can be a client. 

## Templating Guide
protoc-gen-map uses go's "text/template" therefore, any valid template function will work. This includes if statements, for loops, and the template command. 
In addition, any helper functions from [Masterminds/sprig](https://github.com/Masterminds/sprig/) are supported.

### If Statements / For Loops
We are able to modify out sql statements based on, say, the request message. In the following example, we will receive blog information for the provided ID. If we do not provide the ID, we get the latest Blog.
```
{{ define "SelectBlog" }}
    select id, title, author_id from blog  
    {{ if .Id }}
       where id = {{ .Id }}  
    {{ else }}
       order by created_at limit 1
    {{ end }}
{{ end }}
```
We are also able to use for loops, for more information head over to the [template](https://golang.org/pkg/text/template/) package.

### Sprig functions.
protoc-gen-map uses [sprig](https://github.com/Masterminds/sprig/) helper functions, which can come in handy. For example, when client request message contains a list or when we want to filter based on the request, we can use sprig functions like so.

Proto:
```
message BlogRequest {
  repeated uint32 ids = 1;
}
```
SQL:
```
{{ define "SelectBlog" }}
    select id, title, author_id from blog  
    where id in (
    {{ .Ids | join " , " }} 
    )
{{ end }}
```
Note that we are  joining each title with a comma. In some cases, we will need to quote our input. 

### Quoting functions.
To  generate correct SQL syntax, we often need to quote our values. To do that, you can use built in function "quote" and "squote" for  double or single quotations. 
In addition, you can use "qouteall" or "squoteall" to quote all repeated items. For example, lets say we want to retrieve blob based on ids or titles. 
```
message BlogRequest {
  repeated uint32 ids = 1;
  repeated string titles = 2;
}
```
SQL:
```
{{ define "SelectBlog" }}
    select id, title, author_id from blog  
    where id in (
    {{ .Ids | join " , " }} 
    ) or 
    title in (
    {{ .Titles | squoteall | join " , " }} --strings must be quoted
    )
{{ end }}
```

### Splitting SQL Statements 
At some point, SQL queries can get big, very big. To help manage lengthy statements, you can divide your sql statement into logical components. Say that we may or may not want to receive blog responses in order. Our request would look like this.
```
message BlogRequest {
  repeated uint32 ids = 1;
  bool order = 2;
}
```

We could template our statement in multiple parts like this.  
```
{{ define "myOrderStatement" }}
    order by title
{{ end }}

{{ define "SelectBlog" }}
    select id, title, author_id from blog  
    where id in (
    {{ .Ids | join " , " }} 
    )
    {{ if .Order }}
        {{ template "myOrderStatement" }}
    {{end}}
{{ end }}
```

## Parameterized Queries

To prevent potential SQL injection when exposing your service, you can use the built in "param" function to pass arguments as sql parameters.


This is expecially usefull if your request messages contain sensitive fields of string type.


For example, assumme the following request and sql pairs.

```
message AddrRequest {
  string username = 1;
}
```

```
{{ define "ParameterizedQuerie" }}
    select addr from user_addresses where username = {{ param .Username }} 
{{ end }}
```
The above query will translate to "select addr from user_addresses where username = $1" for postgres (? for mysql).

Note: You must specify the database dialect name in the mapper object to use this feature. Supported dialects include: mysql, postgres, mssql, and sqlite3.

## Callbacks

To customise protoc-gen-map to your logic needs, the developer is able to specify callback functions which will be run before or after query execution. 

If your application requires query caching, custom monitoring, sending custom API request, or etc, callbacks are they way to go.

### Defining Callbacks

To register a callback function for a particular RPC. protoc-gen-map creates a register methods in the format: 
1. Before query execution: 
```
Register{{ RPC Name}}BeforeQueryCallback(myFunc func(queryString string, req {{ Proto Request Type }}) error)
```

2. After query execution:
```
Register{{ RPC Name}}AfterQueryCallback(myFunc func(queryString string, req {{ Request Type }}, resp {{ Response Type }}) error)
```

3. For Caching (described below):
```
Register{{ RPC Name}}Cache(myFunc func(queryString string, req {{ Request Type }}) ({{ Response Type }}, error))
```
Where the Response Type is:

   a. Pointer to a proto response for unary services.

   b. Slice of pointers to a proto responses for streaming services.

For example, If we would like to run custom monitoring before the query is run, We can create the callbacks like so:
```
// Instantiate MapServer if not done yet
mapServer := BlogQueryServiceMapServer{DB: db, Dialect: "postgres"}

// Define custom function
func MyFunction(queryString string, req *BlogRequest) error {
	// Do some monitoritg
	return nil
}
// Register the Callback 
mapServer.RegisterSelectBlogBeforeQueryCallback(MyFunction)

// Move on to register the gRPC and run the server

```
Similarly, if we wish to run custom logic after the query has been executed, we can do it like so:
```
// For Unary RPC
func MyFunctionU(queryString string, req *BlogRequest, resp *BlogResponse) error {
	 // run custom logic
	return nil
}
// For Streaming RPC
func MyFunctionS(queryString string, req *BlogRequest, resp []*BlogResponse) error {
	// run custom logic
	return nil
}
// Register the Callbacks
mapServer.RegisterSelectBlogAfterQueryCallback(MyFunctionU)
mapServer.RegisterSelectBlogsAfterQueryCallback(MyFunctionS)
```
And that's it, your registered functions will run every time the RPC is run. 
You can register multiple callbacks, if you wish.

### Caching
With large and complex queries, it's a good idea to implement some caching layer. This can lead to major improvements in performance of your service, especially if your database grows in size and/or your app becomes more complex. 

To populate your cache, use the AfterQueryCallback described above. It provides proto response for specific proto request and query string. For example,
```
func UpdateCache(queryString string, req *BlogRequest, resp []*BlogResponse) error {
	// populate your cache with query or request as keys 
	// and response as values
	return nil
}
```
To implement your cache, simply create a function which returns a proto response.
```
func MyCache(queryString string, req *BlogRequest) ([]*BlogResponse, error) {
	// retrieve response from my cache
	return response, nil
}
// Register the Cache
mapServer.RegisterSelectBlogCache(MyCache)
```
And that's it. Your custom caching function will be execute before querying the DB. 
If the caching function returns nil response, query will be executed and client will receive a response based on the result.
Only one cache function can be registered.

## SQL/Proto Definition
Here is a list of things to keep in mind when writing your SQL statements and proto files
1. The name of the defined SQL template must match your proto rpc name.
For example, in the following SQL snippet
```
{{ define "SelectBlog" }}
```
corresponds to the following rpc 
```
rpc SelectBlog (BlogRequest) returns (BlogResponse) {}
```
2. The SQL Template can be populated with request message.
For example, for the following rpc
```
BlogQueryService {
  rpc SelectBlog (BlogRequest) returns (BlogResponse) {}
}
message BlogRequest {
  uint32 id = 1;
  uint32 author_id  = 2;
}
```
the developer can populate the SQL template with ".AuthorId" and ".Id" as follows
```
{{ .AuthorId }}
{{ .Id }}
```
3. protoc-gen-map expects the returned column names to match either
 - The response message field name or
 - Field name of the response struct generated by go proto compiler or 
 - Lower case of either of the above 

If there exists a discrepancy, you can use the standard SQL "as" statement to name an alias. For example, the following SQL/proto pairs would match correctly.
```
select
       id as  blog_id,
       title as  BlogTitle,
from blog
```
```
message BlogResponse {
  uint32 blog_id = 1;
  string blog_title  = 2;
}
```
4. Has-one relationships (associations) are identified by nested fields. For example, a Blog has one Author
```
message Blog {
  uint32 blog_id = 1;
  Author author = 2;
}
```
5. Has-many relationships (collections) are identified by a repeated and nested fields. For example, a Blog has many Posts
```
message Blog {
  uint32 blog_id = 1;
  repeated Post posts = 2;
}
```
6. If we expect the SQL query to map to multiple responses, the rpc must be server-streaming. For example, if we query for many Blogs
```
  rpc SelectBlogs (BlogRequest) returns (stream BlogResponse) {}
```
7. At least one primitive, timestamp.Timestamp or enum field must be present in a message. 
8. For time definitions, use Timestamp from "google/protobuf/timestamp.proto"
9. When using Timestamp from google/protobuf/timestamp.proto as input, you must use the helper functions "time", "date", and "timestamp" to correctly generate input for your column type. For example, 
```
INSERT INTO logins
VALUES (
 {{ .Id }},
 {{ .CreatedOn | date | squote }}, --column type: date
 {{ .LastLogin | timestamp | squote }}, --column type: timestamp
 {{ .LoginTime | time | squote }} --column type: time
);
{{ end }}
```
```
message InsertLoginRequest {
  uint32 blog_id = 1;
  google.protobuf.Timestamp created_on = 2;
  google.protobuf.Timestamp last_login = 3;
  google.protobuf.Timestamp login_time = 4;
}
```

## Important Notes 
1. protoc-gen-map automatically removes any duplicate rows returned by your query. If this is not a desired outcome, you should include a uniquely identifiable columns in your query and the corresponding fields in your message.

2. Data mapping blueprint is generated with the first query request. Successive requests should be consistent. For example, column names should not change depending on the request message.

3. Queries that do not expect any returned records (insert, update, create, delete operations) must satisfy one of the following criteria. Note that queries may fail if at least one is not satisfied. 
 - RPC mame name must begin with keywords "insert", "update", "create", or "delete"(case not sensitive)
 - Response name must begin with "empty","nil" or "null"(case not sensitive)
 
 Example
 ```
  rpc InsertBlog (InsertBlogRequest) returns (EmptyResponse) {}
 ```
### Roadmap

| Goal | Status | Label |
| :--- | --- | --- | 
| Proto Enum Support | `ready` | `enhancement` |
| Allow developer to specify callback methods | `ready` | `enhancement` |
| Implement Caching  | `ready` | `enhancement` |
| Add parameterized query support | `ready` | `enhancement` |
| Performance improvements around go reflection | `in progress` | `enhancement` |
| Reduce ammount of generated code | `in progress` | `enhancement` |

### License
Apache License

