#!/usr/bin/env python3

##
##
################
################

import requests
import requests.exceptions
import os, time, json, datetime

#Regex to match following
#kafka.log:type=Log,name=Size,topic=connect-offsets-webtrekk-connect-kafka-to-s3-stg-2018-10-09,partition=19
#{'topic': 'connect-offsets-webtrekk-connect-kafka-to-s3-stg-2018-10-09', 'partition': '19'}
REGEX = r'.*topic=(?P<topic>.*),partition=(?P<partition>\d+)'


def parse_mbean(mbean):
    import re
    m = re.match(REGEX, mbean)
    return m.groupdict()

def transform_jmxbeans(input_files, filter_string):
    json_output = {}
    for file in input_files:
        mbean_arr = json.load(file)
        for mbean in mbean_arr:
            topic_partition = parse_mbean(mbean['mBeanName'])
            if(not topic_partition['topic'] in json_output):
                json_output[topic_partition['topic']] = {}
            json_output[topic_partition['topic']][topic_partition['partition']] = {"Size": int(mbean['value'])} #python3 int is long
            #print(mbean['Value'])
    with open('result.json', 'w') as fp:
        json.dump(json_output, fp, indent=4, sort_keys=True)

def main():

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=argparse.FileType('r'), nargs='+',
        help="input file names", required=True)
    parser.add_argument("--filter_string", type=str, default="kafka.log:type=Log,name=Size,", 
        help="input file name")
    args = parser.parse_args()
    transform_jmxbeans(args.inputs, filter_string=args.filter_string)

if __name__== "__main__":
    main()

######################
##
##    
