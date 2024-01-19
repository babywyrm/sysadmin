Download & Run MongoDB
Grab the latest stable release from the download page
Unzip the archive to a folder called ${MONGO_HOME} on your disk
Create a folder /data/db on the same drive/partition
Go to ${MONGO_HOME}/bin
Execute the binary mongod (or mongod.exe on Windows)
For a more detailed explanation, see the MongoDB installation guide.

Import Test Data
Before we start, we need some test data.

Start the MongoDB shell by exectuing mongo
Paste the code from 02_geospatial.js into the shell
Paste the code from 03_map_reduce.js into the shell
01b_crud_queries.js
// dbs
show dbs
use oops
show collections

##
##

// insert data
db.foo.insert({a: 1, b: "zwei"})
// show mongod console -> oop.ns oop.0 oop.1

db.foo.find()
db.foo.insert({a: 2, b: "drei"})
db.foo.find()
db.foo.insert({a: -1, b: "fünf"})

// queries
db.foo.find({a: {$gt: 1}})
db.foo.find({a: {$gt: 1}}, {_id:0}) // restrict fields

// index
db.foo.find({a:2}).explain()
db.foo.ensureIndex({a:1})
db.foo.find({a:2}).explain()
db.system.indexes.find()
db.system.namespaces.find()

// limit + sort
db.foo.find().limit(2)
db.foo.find().sort({a:-1})
db.foo.find().sort({a:-1}).limit(2)
db.foo.find().sort({a:-1}).limit(2).explain()

// update
db.foo.find()
db.foo.update( {a:1}, {b:"vier"}) // ersetzt Dokument komplett
db.foo.find()
db.foo.update({a:2}, {$set: {b: "sechs"}})
db.foo.find()

// upsert
db.foo.update({a:5}, {$inc: {a:1}}, true)
db.foo.find()

// remove
db.foo.remove({a: {$lt: 0}})
db.foo.find()

// drop
db.foo.drop()
02_geospatial.js
db.location.remove()
db.location.insert({ "_id" : "A", "position" : [ 0.001, -0.002 ] })
db.location.insert({ "_id" : "B", "position" : [ 0.75, 0.75 ] })
db.location.insert({ "_id" : "C", "position" : [ 0.5, 0.5 ] })
db.location.insert({ "_id" : "D", "position" : [ -0.5, -0.5 ] })
db.location.ensureIndex( {position: "2d"} )
02b_geospatial.js
// blue circle
db.location.find( {position: { $near: [0,0], $maxDistance: 0.75 }  } )

// smaller circle
db.location.find( {position: { $near: [0,0], $maxDistance: 0.5 }  } )

// red box
db.location.find( {position: { $within: { $box: [ [0.25, 0.25], [1.0,1.0] ]  } } } )
03_map_reduce.js
db.docs.remove()
db.docs.insert({ "name" : "Doc 1", "tags" : [ "cc", "mongodb", "nosql" ] } )
db.docs.insert({ "name" : "Doc 2", "tags" : [ "cc", "agile" ] } )
db.docs.insert({ "name" : "Doc 3", "tags" : [ "cc", "nosql" ] } )

map = function () {
    this.tags.forEach(function (tag) {emit(tag, 1);});
};
reduce = function (key, values) {
    return values.length;
};

db.result.remove()
db.docs.mapReduce(map, reduce, {out: "result"})

db.result.find()
db.result.find().sort({value:-1})
04_aggregation.js
// since 2.2 -> aggregation framework
db.docs.aggregate( 
   {$project:{_id:0,tags:1}}, 
   {$unwind: "$tags"}, 
   {$group:{_id:"$tags", n:{$sum:1}}} 
)

db.docs.aggregate( 
   {$project:{_id:0,tags:1}}, 
   {$unwind: "$tags"}, 
   {$group:{_id:"$tags", n:{$sum:1}}}, 
   {$sort:{n:-1}} 
)
05_text_search.js
// enable text search
use admin
db.runCommand( {setParameter:1, textSearchEnabled: true} )
use txt

// create text index
db.txt.drop()
db.txt.ensureIndex( {txt: "text"} )
db.txt.getIndices()

// insert data
db.txt.insert( {txt: "I am your father, Luke"} )
db.txt.validate()

// search
db.txt.runCommand( "text", { search : "father" } )
50_replica_set.sh
start mongod --port 8000 --dbpath /var/rs/master --replSet cluster0
start mongod --port 8001 --dbpath /var/rs/slave1 --replSet cluster0
start mongod --port 8002 --dbpath /var/rs/slave2 --replSet cluster0
51_master.js
// connect to master on port 8000 + setup replica set
rs.initiate()
rs.add("localhost:8001")
rs.add("localhost:8002")

// use primary: mongo --port 8000
rs.isMaster()
rs.status()
use test
db.foo.insert({hello: "mongo"})

// use secondary: mongo --port 8001
rs.isMaster()
use test
db.foo.insert({hello: "mongo"})
db.foo.find()
60_sharding.sh
start mongod --shardsvr --port 9000 --dbpath /var/sh/shard1
start mongod --shardsvr --port 9001 --dbpath /var/sh/shard2
start mongod --configsvr --port 9002 --dbpath /var/sh/conf1
pause
start mongos --port 9003 --configdb localhost:9002 --chunkSize 2
61_init_sharding.js
use admin
sh.addShard("localhost:9000")
sh.addShard("localhost:9001")
sh.status()

use data
db.createCollection("foo")

use admin
sh.enableSharding("data")
sh.shardCollection("data.foo", {age:1})
sh.status()

// insert some data
use data
for (i=0; i<1000000;i++) { db.foo.insert( {name:"Person_"+i, age: 50 + i%20} ); }
62_search_shards.js
// connect to mongos instance

use data
sh.status()

// hits all shards -> bad
db.foo.find().limit(100).explain()

// using sharding hits only one shard -> good
db.foo.find({age:51}).limit(100).explain()
