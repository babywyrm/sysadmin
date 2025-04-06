#!/bin/bash

# AWS CLI CloudTrail Lookup Script - Improved Version, Probably

# Help message
function usage() {
    echo "Usage: $0 <command> [options]"
    echo "Commands:"
    echo "  consolelogins        - Get list of console logins"
    echo "  stopinstances        - Get a list of stopped EC2 instances"
    echo "  recentlogins         - Get the last N console logins"
    echo "  events               - Get events with custom filters"
    echo ""
    echo "Options:"
    echo "  -r <region>           - AWS region (default: us-east-1)"
    echo "  -n <number_of_events> - Number of events to fetch (default: 10)"
    echo "  -s <start_date>       - Start date for filtering (e.g., '2023-01-01')"
    echo "  -e <end_date>         - End date for filtering (e.g., '2023-12-31')"
    echo "  -u <username>         - Filter by username"
    echo "  -t <event_type>       - Filter by event type (e.g., 'ConsoleLogin')"
    echo "  -f <output_format>    - Output format (json, table, text)"
    echo "  -d                    - Enable debug mode"
    exit 1
}

# Debug mode
DEBUG=false

# Default values
REGION="us-east-1"
NUM_EVENTS=10
START_DATE=""
END_DATE=""
USERNAME=""
EVENT_TYPE=""
OUTPUT_FORMAT="json"

# Parse options
while getopts "r:n:s:e:u:t:f:d" opt; do
  case $opt in
    r) REGION="$OPTARG" ;;
    n) NUM_EVENTS="$OPTARG" ;;
    s) START_DATE="$OPTARG" ;;
    e) END_DATE="$OPTARG" ;;
    u) USERNAME="$OPTARG" ;;
    t) EVENT_TYPE="$OPTARG" ;;
    f) OUTPUT_FORMAT="$OPTARG" ;;
    d) DEBUG=true ;;
    *) usage ;;
  esac
done

# Log function for debugging
function log_debug() {
    if [ "$DEBUG" == true ]; then
        echo "[DEBUG] $1"
    fi
}

# Base query for fetching CloudTrail events
base_query=""

# Console Login Events
function console_logins() {
    echo "Fetching console login events..."
    aws cloudtrail lookup-events \
        --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
        --region "$REGION" \
        --output "$OUTPUT_FORMAT" \
        --max-results "$NUM_EVENTS"
}

# EC2 Stop Instances Events
function stop_instances() {
    echo "Fetching EC2 stop instances events..."
    aws cloudtrail lookup-events \
        --lookup-attributes AttributeKey=EventName,AttributeValue=StopInstances \
        --query "Events[*].{User:Username,ETime:EventTime,Instance:Resources[0].ResourceName}" \
        --region "$REGION" \
        --output "$OUTPUT_FORMAT"
}

# Last N Console Logins
function recent_logins() {
    echo "Fetching the last $NUM_EVENTS console login events..."
    aws cloudtrail lookup-events \
        --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
        --max-items "$NUM_EVENTS" \
        --region "$REGION" \
        --output "$OUTPUT_FORMAT" | jq -r '.Events[] | {User: .Username, Time: .EventTime, IP: .SourceIPAddress}'
}

# General Event Lookup with Filters
function general_events() {
    log_debug "Fetching CloudTrail events with filters: username=$USERNAME, event_type=$EVENT_TYPE, region=$REGION"

    # Build the query based on provided filters
    query="Events[*].{User:Username,ETime:EventTime,EventName:EventName}"

    # Add filters for username or event type if specified
    if [ -n "$USERNAME" ]; then
        query="select(.Username == '$USERNAME') | $query"
    fi
    if [ -n "$EVENT_TYPE" ]; then
        query="select(.EventName == '$EVENT_TYPE') | $query"
    fi

    # Apply the time filters if specified
    if [ -n "$START_DATE" ]; then
        query="select(.EventTime >= '$START_DATE') | $query"
    fi
    if [ -n "$END_DATE" ]; then
        query="select(.EventTime <= '$END_DATE') | $query"
    fi

    # Execute the query
    aws cloudtrail lookup-events \
        --start-time "$START_DATE" \
        --end-time "$END_DATE" \
        --region "$REGION" \
        --max-results "$NUM_EVENTS" \
        --output "$OUTPUT_FORMAT" \
        --query "$query"
}

# Main function to select the correct action
function main() {
    case "$1" in
        consolelogins)
            console_logins
            ;;
        stopinstances)
            stop_instances
            ;;
        recentlogins)
            recent_logins
            ;;
        events)
            general_events
            ;;
        *)
            usage
            ;;
    esac
}

# Execute the selected function
main "$1"


## ./cloudtrail_lookup.sh consolelogins -r us-east-1 -n 5 -f json
## Get a list of EC2 stop instance events in eu-west-1:
## ./cloudtrail_lookup.sh stopinstances -r eu-west-1 -f table
## Get the last 10 ConsoleLogin events, with debug info:
## ./cloudtrail_lookup.sh recentlogins -r us-east-1 -n 10 -d true
## General event lookup with a specific username and date range:
## ./cloudtrail_lookup.sh events -u peroiznz.com -s 2023-01-01 -e 2023-12-31 -f json
## General event lookup with event type and output as a table:
## ./cloudtrail_lookup.sh events -t ConsoleLogin -r us-east-1 -n 10 -f table

