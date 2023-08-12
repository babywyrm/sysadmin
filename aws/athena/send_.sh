#!/bin/bash

##
## https://gist.github.com/ayosec/7a984821584797627115697ccf96d454
##

#
# This program sends a query to Athena, and download the results in CSV when
# the execution is completed. It expects the database name and the query as
# arguments:
#
#     $ query-athena -d mydb 'select ...'
#
# The CSV file is downloaded in /tmp/QUERYID.csv by default. To use a different
# file, use -w:
#
#     $ query-athena -d mydb -w results.csv 'select ...'
#
# The region is eu-west-1 by default. It can be modified with -r.
#
# The results are stored in the "aws-athena-query-results-ACCOUNT-REGION"
# bucket. To use something else, use the -o option:
#
#     $ query-athena -o s3://some-bucket/path/to/results/ -d mydb 'select ...'
#

set -eu -o pipefail

AWS_DEFAULT_REGION=eu-west-1
DATABASE=""
CSV_FILE="/tmp/"
S3_OUTPUT=""


# Extract options from command line

while getopts "r:d:o:w:h" opt
do
  case "$opt" in
    r)
      AWS_DEFAULT_REGION="$OPTARG"
      ;;

    d):
      DATABASE="$OPTARG"
      ;;

    o)
      S3_OUTPUT="$OPTARG"
      ;;

    w)
      CSV_FILE="$OPTARG"
      ;;

    h)
      echo "Usage: $0 [-r region] [-d database] [-o s3://output] [-w results.csv] 'query'"
      exit
      ;;

    *)
      echo "Use -h to see options."
      exit 1
      ;;
  esac
done

shift $((OPTIND - 1))
QUERY="$*"

if [ -z "$QUERY" ]
then
  echo "Missing query."
  exit 1
fi

if [ -z "$DATABASE" ]
then
  echo "Missing database."
  exit 1
fi


# If the S3 address is not given, we assume that we have a bucket for Athena
# results in "aws-athena-query-results-ACCOUNT-REGION".

if [ -z "$S3_OUTPUT" ]
then
  ACCOUNT_ID="$(aws sts get-caller-identity --output text --query Account)"
  S3_OUTPUT="s3://aws-athena-query-results-$ACCOUNT_ID-$AWS_DEFAULT_REGION"
fi


# Execute the query and get an id to get the result

export AWS_DEFAULT_REGION

QUERY_ID=$(
  aws athena start-query-execution                 \
    --query-string "$QUERY"                        \
    --query-execution-context "Database=$DATABASE" \
    --query QueryExecutionId                       \
    --output text                                  \
    --result-configuration "OutputLocation=$S3_OUTPUT"
)


# Iteration to check the result of the execution.
#
# If the state is SUCCEEDED, download the file to /tmp
# If the state is FAILED, show the error from Athena
# If the state is something else, keep waiting

check() {
  aws athena get-query-execution     \
    --query-execution-id "$QUERY_ID" \
    --output text                    \
    --query 'QueryExecution.[
        Status.State,
        ResultConfiguration.OutputLocation,
        Statistics.EngineExecutionTimeInMillis,
        Statistics.DataScannedInBytes
      ]
    ' \
  | while read -r STATE OUTPUT EXEC_TIME DATA_BYTES
  do
    case "$STATE" in
      SUCCEEDED)
        echo "Succeeded in $EXEC_TIME ms ($DATA_BYTES bytes scanned)"
        aws s3 cp "$OUTPUT" "$CSV_FILE"
        return 1
        ;;

      FAILED)
        echo "Failed!"
        aws athena get-query-execution     \
          --query-execution-id "$QUERY_ID" \
          --output text                    \
          --query "QueryExecution.Status.StateChangeReason"
        return 1
        ;;

      *)
        echo -en "\\r$STATE ... "
        ;;
    esac
  done
}

while check; do sleep 1; done
