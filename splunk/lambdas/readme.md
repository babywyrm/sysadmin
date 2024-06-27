##
#
https://community.splunk.com/t5/Splunk-Dev/Incapsula-s3-to-lambda-to-Splunk-CLOUD/m-p/437457
#
##

Incapsula s3 to lambda to Splunk CLOUD
MatthewH007
MatthewH007
Path Finder
‎12-13-2018 06:04 PM

I have our Incapsula logs that get written to an s3 bucket. What I want is to get that into Splunk. I have setup an HEC and have the following flow:

s3 (object created) -> Lambda function -> Splunk

Now I can pass the 'event' data just fine using the Splunk blueprint for logging. The issue is I don't want the 'event' data as all that tells me is that an object was created. I want the object (log file) itself. I reached out to AWS support to ensure that the KMS key had the proper permissions (as s3 bucket is encrypted) and that everything was setup correctly.

I have the following code being used in the 'index.js'. This has been modified and as of right now, passes NO data. I get events in Splunk but they are just brackets with no data. Example
{}

I would greatly appreciate any critiques of the code below and any pointers on what needs to be modified. Thanks in advance.

'use strict';

const loggerConfig = {
    url: process.env.SPLUNK_HEC_URL,                                   //Provide the Splunk HEC url
    token: process.env.SPLUNK_HEC_TOKEN,                              //Provide the Splunk HEC Token
};
var region='us-east-1'                                               //Change the region accordingly 
const SplunkLogger = require('./lib/mysplunklogger');
const aws = require('aws-sdk');
const logger = new SplunkLogger(loggerConfig);
const s3 = new aws.S3({
            apiVersion: '2006-03-01',
            region: region

 });

exports.handler = (event, context, callback) => {
    var objData = {};
    var objectData
    var obj1 ;
    console.log('Received event:', JSON.stringify(event, null, 2));
    // Log JSON objects to Splunk
    var srcBucket = event.Records[0].s3.bucket.name;                 //Read the name of S3 bucket from the event object
    var srcKey    = event['Records'][0]['s3']['object']['key'];     //Read the name of S3 object from the event object
    var params = {
    Bucket: srcBucket, 
    Key: srcKey
    };
    s3.getObject(params, function(err, data)                        //Get object API call to S3 bucket to fetch the object
    {
    if (err) console.log(err, err.stack); // an error occurred
    else {
        objectData = data.Body.toString('utf-8');                  //convert the object to string
        console.log(objectData);
        //obj1=objectData;
        objData = JSON.parse(objectData);
        console.log(objData)
        logger.log(objData);                      
        }           // successful response
    });

    // Log JSON objects with optional 'context' argument (recommended)
    // This adds valuable Lambda metadata including functionName as source, awsRequestId as field
    //logger.log(event, context);

    // Log strings
   // logger.log(`value1 = ${event.key1}`, context);

    // Log with user-specified timestamp - useful for forwarding events with embedded
    // timestamps, such as from AWS IoT, AWS Kinesis, AWS CloudWatch Logs
    // Change "Date.now()" below to event timestamp if specified in event payload
    //logger.logWithTime(Date.now(), event, context);

    // Advanced:
    // Log event with user-specified request parameters - useful to set input settings per event vs token-level
    // Full list of request parameters available here:
    // http://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTinput#services.2Fcollector
    logger.logEvent({
        time: Date.now(),
        host: 'serverless',
        source: `lambda:${context.functionName}`,
        sourcetype: 'httpevent',
        event:  objectData
    });

    // Send all the events in a single batch to Splunk
    logger.flushAsync((error, response) => {
        if (error) {
            callback(error);
        } else {
            console.log(`Response from Splunk:\n${response}`);
            callback(null, event.key1); // Echo back the first key value
        }
    });
};

    Tags:aws-s3node.jss3splunk-cloud 

1 Solution
Solution
MatthewH007
MatthewH007
Path Finder
‎12-26-2018 11:31 AM

I reached out to AWS Support and they wrote most of this re-write. A minor change was made to it but if you need it, this will work! The only downside is you need to change your props.conf file on your indexer (don't have access to it so dealing with Splunk support now) so that you wont have 500 events grouped together as 1 event in Splunk.

```
/**
 * Splunk logging for AWS Lambda
 *
 * This function logs to a Splunk host using Splunk's HTTP event collector API.
 *
 * Define the following Environment Variables in the console below to configure
 * this function to log to your Splunk host:
 *
 * 1. SPLUNK_HEC_URL: URL address for your Splunk HTTP event collector endpoint.
 * Default port for event collector is 8088. Example: https://host.com:8088/services/collector
 *
 * 2. SPLUNK_HEC_TOKEN: Token for your Splunk HTTP event collector.
 * To create a new token for this Lambda function, refer to Splunk Docs:
 * http://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector#Create_an_Event_Col...
 */

'use strict';

const loggerConfig = {
    url: process.env.SPLUNK_HEC_URL,                                   //Provide the Splunk HEC url
    token: process.env.SPLUNK_HEC_TOKEN,                              //Provide the Splunk HEC Token
};
var region='<input_region>'                                               //Change the region accordingly 
const SplunkLogger = require('./lib/mysplunklogger');
const aws = require('aws-sdk');
const logger = new SplunkLogger(loggerConfig);
const s3 = new aws.S3({
            apiVersion: '2006-03-01',
            region: region

 });

exports.handler = (event, context, callback) => {
    var objData = {};
    var objectData
    var obj1 ;
    console.log('Received event:', JSON.stringify(event, null, 2));
    // Log JSON objects to Splunk
    var srcBucket = event.Records[0].s3.bucket.name;                 //Read the name of S3 bucket from the event object
    var srcKey    = event['Records'][0]['s3']['object']['key'];     //Read the name of S3 object from the event object
    var params = {
    Bucket: srcBucket, 
    Key: srcKey
    };
    s3.getObject(params, function(err, data)                        //Get object API call to S3 bucket to fetch the object
    {
    if (err) console.log(err, err.stack); // an error occurred
    else {
        objectData = data.Body.toString('utf-8');                  //convert the object to string
        console.log(objectData);
        //obj1=objectData;
        objData = objectData; //JSON.parse(objectData);
        console.log(objData);
        logger.log(objData);                      
        }           // successful response
    });

    // Log JSON objects with optional 'context' argument (recommended)
    // This adds valuable Lambda metadata including functionName as source, awsRequestId as field
    //logger.log(event, context);

    // Log strings
   // logger.log(`value1 = ${event.key1}`, context);

    // Log with user-specified timestamp - useful for forwarding events with embedded
    // timestamps, such as from AWS IoT, AWS Kinesis, AWS CloudWatch Logs
    // Change "Date.now()" below to event timestamp if specified in event payload
    //logger.logWithTime(Date.now(), event, context);

    // Advanced:
    // Log event with user-specified request parameters - useful to set input settings per event vs token-level
    // Full list of request parameters available here:
    // http://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTinput#services.2Fcollector
    logger.logEvent({
        time: Date.now(),
        host: 'serverless',
        source: `lambda:${context.functionName}`,
        sourcetype: 'httpevent',
        event:  objData
    });

    // Send all the events in a single batch to Splunk
    logger.flushAsync((error, response) => {
        if (error) {
            callback(error);
        } else {
            console.log(`Response from Splunk:\n${response}`);
            callback(null, event.key1); // Echo back the first key value
        }
    });
};
