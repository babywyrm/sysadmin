# First steps with AWS Athena

## Getting started

[AWS documentation](https://docs.aws.amazon.com/athena/latest/ug/getting-started.html)

### Presto

Athena uses the
[Presto distributed SQL query engine](https://prestodb.io/docs/0.172/overview.html).

Presto is a tool designed to efficiently query vast amounts of data using distributed
queries. I

Presto is *not** a general-purpose relational database. It is not a replacement for
databases like MySQL, PostgreSQL or Oracle. Presto was not designed to handle Online
Transaction Processing (OLTP). This is also true for many other databases designed
and optimized for data warehousing or analytics. Presto was designed to handle data
warehousing and analytics: data analysis, aggregating large amounts of data and producing
reports. These workloads are often classified as Online Analytical Processing (OLAP).

### Creating a new database and new tables

[Source](https://docs.aws.amazon.com/athena/latest/ug/creating-tables.html)

When you create a new table schema in Athena, Athena stores the schema in a data catalog
and uses it when you run queries. Athena uses Apache Hive to define tables and create
databases, which are essentially a logical namespace of tables.
[Apache Hive documentation](https://cwiki.apache.org/confluence/display/Hive/LanguageManual+DDL)

When you create a database and table in Athena, you are simply describing the schema and
the location where the table data are located in Amazon S3 for read-time querying.
Database and table, therefore, have a slightly different meaning than they do for
traditional relational database systems because the data isn't stored along with the
schema definition for the database and table.

#### Create a database using Hive DDL

A database in Athena is a logical grouping for tables you create in it.

1. Open the Athena console at https://console.aws.amazon.com/athena/.
2. Choose Query Editor.
3. Enter `CREATE DATABASE myDataBase` and choose Run Query.

#### Create a table using Hive DDL

[Console](https://us-west-2.console.aws.amazon.com/athena/home?region=us-west-2#query)

Athena reads all files in an Amazon S3 location you specify in the `CREATE TABLE`
statement, and cannot ignore any files included in the prefix. 

When you create tables, include in the Amazon S3 path only the files you want Athena to
read. Use AWS Lambda functions to scan files in the source location, remove any empty
files, and move unneeded files to another location.

In the LOCATION clause, use a trailing slash for your folder or bucket.
In the database that you created, we now create a table for the example data that is
available in the `s3://athena-examples-us-west-2/cloudfront/plaintext/` prefix on AWS S3.
It is 
[Apache Weblog Data](https://cwiki.apache.org/confluence/display/Hive/GettingStarted#GettingStarted-ApacheWeblogData)
and a table with the right schema can be created by entering the following statement and
choosing `Run Query`:

```
CREATE EXTERNAL TABLE IF NOT EXISTS cloudfront_logs (
    `Date` Date,
    Time STRING,
    Location STRING,
    Bytes INT,
    RequestIP STRING,
    Method STRING,
    Host STRING,
    Uri STRING,
    Status INT,
    Referrer STRING,
    OS String,
    Browser String,
    BrowserVersion String
) ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe'
WITH SERDEPROPERTIES (
"input.regex" = "^(?!#)([^ ]+)\\s+([^ ]+)\\s+([^ ]+)\\s+([^ ]+)\\s+([^ ]+)\\s+([^ ]+)\\s+([^ ]+)\\s+([^ ]+)\\s+([^ ]+)\\s+([^ ]+)\\s+[^\(]+[\(]([^\;]+).*\%20([^\/]+)[\/](.*)$"
) LOCATION 's3://athena-examples-us-west-2/cloudfront/plaintext/';
```

If the table was successfully created, you can then run queries against your data.

#### Requirements for Tables in Athena and Data in Amazon S3

When you create a table, you specify an Amazon S3 bucket location for the underlying data
using the `LOCATION clause`. Consider the following:

- You must have the appropriate permissions to work with data in the Amazon S3 location.
- If the data is encrypted in Amazon S3, it must be stored in the same region.
- Athena does not support the `GLACIER` storage class.

#### Functions Supported

The functions supported in Athena queries are those found within Presto.
For more information, see Presto 0.172 Functions and Operators in the 
[Presto documentation](https://prestodb.io/docs/0.172/functions.html).

#### All Tables Are EXTERNAL

If you use `CREATE TABLE` without the `EXTERNAL` keyword, Athena issues an error; 
only tables with the EXTERNAL keyword can be created. When you drop a table in Athena,
only the table metadata is removed; the data remains in Amazon S3.

### Querying a database

Now that you have the cloudfront_logs table created in Athena based on the data in Amazon
S3, you can run queries on the table and see the results in Athena.


Choose `New Query`, enter the following statement anywhere in the query pane, and then
choose `Run Query`:

```
SELECT os, COUNT(*) count
FROM cloudfront_logs
WHERE date BETWEEN date '2014-07-05' AND date '2014-08-05'
GROUP BY os;
```

## Partitioning Data

[Source](https://docs.aws.amazon.com/athena/latest/ug/partitions.html)

By partitioning your data, you can restrict the amount of data scanned by each
query, thus improving performance and reducing cost. Athena leverages Hive for
partitioning data. You can partition your data by any key. A common practice is
to partition the data based on time, often leading to a multi-level partitioning
scheme. For example, a customer who has data coming in every hour might decide
to partition by year, month, date, and hour. Another customer, who has data
coming from many different sources but loaded one time per day, may partition by
a data source identifier and date.

To create a table with partitions, you must define it during the `CREATE TABLE`
statement. Use `PARTITIONED BY` to define the keys by which to partition data.
There are two scenarios discussed below:

### Data is already partitioned, stored on Amazon S3, and you need to access the data on Athena.

Partitions are stored in separate folders in Amazon S3. For example, here is the partial
listing for sample ad impressions:

```
aws s3 ls s3://elasticmapreduce/samples/hive-ads/tables/impressions/

    PRE dt=2009-04-12-13-00/
    PRE dt=2009-04-12-13-05/
    PRE dt=2009-04-12-13-10/
    PRE dt=2009-04-12-13-15/
    PRE dt=2009-04-12-13-20/
    PRE dt=2009-04-12-14-00/
    PRE dt=2009-04-12-14-05/
    PRE dt=2009-04-12-14-10/
    PRE dt=2009-04-12-14-15/
    PRE dt=2009-04-12-14-20/
    PRE dt=2009-04-12-15-00/
    PRE dt=2009-04-12-15-05/
```

### Data is not partitioned.

In this case, you would have to use ALTER TABLE ADD PARTITION to add each partition manually.

For example, to load the data in `s3://athena-examples/elb/plaintext/2015/01/01/`,
you can run the following:

```
ALTER TABLE elb_logs_raw_native_part ADD PARTITION (year='2015',month='01',day='01') location 's3://athena-examples/elb/plaintext/2015/01/01/'
```
You can also automate adding partitions by using the JDBC driver.

## AWS Athena and R

- [Source](https://aws.amazon.com/blogs/big-data/running-r-on-amazon-athena/)
- [dplyr issue](https://github.com/tidyverse/dplyr/issues/2939)
