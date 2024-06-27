##
## https://gist.github.com/ongzexuan/6feebf1ff42cccf882a30f7a4646ebfc
##

import boto3
import csv
import json
import os
import pymysql
import sys

from os.path import join, dirname

# Load environment settings if exists
if os.path.isfile('.env'):
    from dotenv import load_dotenv
    dotenv_path = join(dirname(__file__), '.env')
    load_dotenv(dotenv_path)

s3 = boto3.client('s3')
STAGING_FOLDER = 'staging'
TEMP_FILE = '/tmp/temp.csv' # Only directory that can be written to for Lambda

# Lambda is triggered by new file in S3
def lambda_handler(event, context):    

    # Get the name of bucket and key (name)
    print('Lambda function invoked')
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    
    try:
        # Get file from S3
        response = s3.get_object(Bucket=bucket, Key=key)
        file_content = response['Body'].read().decode('utf-8')
        rows = json.loads(file_content)   # My file is a JSON file
        print('JSON data loaded')

        # Iterate over each row, transform
        staging_rows = []
        for row in rows:
            new_row = TRANSFORM(row)          # Your own transform function here
            staging_rows.append(new_row)
        print('{} rows transformed'.format(len(rows)))

        # Write to staging file
        with open(TEMP_FILE, 'w') as f:
            writer = csv.DictWriter(f, fieldnames=list(staging_rows[0].keys()),
                                       quoting=csv.QUOTE_ALL,
                                       lineterminator='\n')
            writer.writeheader()
            for data in staging_rows:
                writer.writerow(data)
        print('Written to {}'.format(TEMP_FILE))

        # Get filename and upload staging file to S3 bucket
        filename = key[key.rfind('/') + 1:]
        filename = filename.replace('.json', '.csv')
        staging_key = '{}/{}'.format(STAGING_FOLDER, filename)
        s3.upload_file(TEMP_FILE, bucket, staging_key)
        print('Uploaded {} to {}'.format(TEMP_FILE, staging_key))

        # Execute the upload of the temp file to the DB
        sql_statement = ""
        with open('load_local_infile.sql', 'r') as f:
            lines = []
            for line in f:
                lines.append(line)
            sql_statement = " ".join(lines)
        sql_statement = sql_statement.format(TEMP_FILE)
        print("SQL statement created")

        # Get DB connection credentials from environment
        host = os.environ.get('HOST')
        port = int(os.environ.get('PORT'))
        dbname = os.environ.get('DBNAME')
        user = os.environ.get('USERNAME')
        password = os.environ.get('PASSWORD')

        # Actually execute the SQL statement to load data
        conn = pymysql.connect(host, 
                               user=user, 
                               port=port, 
                               password=password, 
                               db=dbname, 
                               local_infile=True) # This last keyword argument is vital
        conn.cursor().execute(sql_statement)
        conn.commit()
        conn.cursor().close()
        conn.close()
        print("SQL executed")

        return "ok"

    except Exception as e:
        print(e)
        print('Error getting object {} from bucket {}.'.format(key, bucket))
        raise e
