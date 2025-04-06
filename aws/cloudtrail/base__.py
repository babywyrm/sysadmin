import boto3
import os,sys,re
from datetime import datetime, timedelta

##
##

def fetch_cloudtrail_events(username_filter, string_filter, days_to_search, debug=False):
    # Calculate the start and end times for the past 'days_to_search' days
    start_time = (datetime.utcnow() - timedelta(days=days_to_search)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Initialize CloudTrail client
    client = boto3.client('cloudtrail')

    # Initialize pagination variables
    next_token = None
    all_events = []

    # Debugging: Print the search parameters
    if debug:
        print(f"Searching CloudTrail for events from {start_time} to {end_time}")
        print(f"Filtering by username: {username_filter}")
        print(f"Filtering by string: {string_filter}")

    while True:
        # Prepare the lookup events parameters
        params = {
            'StartTime': start_time,
            'EndTime': end_time,
            'MaxResults': 50  # Fetch 50 events per request
        }

        if next_token:
            params['NextToken'] = next_token

        # Make the API request
        if debug:
            print(f"Requesting events with params: {params}")
        
        response = client.lookup_events(**params)

        # Debugging: Output the raw response (useful for debugging API responses)
        if debug:
            print(f"API Response: {response}")

        # Filter events based on the provided username and/or string
        for event in response.get('Events', []):
            event_json = event.get('CloudTrailEvent', '')
            user_identity_arn = event.get('UserIdentity', {}).get('Arn', '')

            # Debugging: Print the event being processed
            if debug:
                print(f"Processing event: {event_json}")

            # Handle "capture all" for string filter
            if string_filter == "ALL" or not string_filter:
                # If the string filter is "ALL" or empty, capture all events for the username
                if username_filter.lower() in user_identity_arn.lower():
                    all_events.append(event)
                    if debug:
                        print(f"Captured event (all): {event_json}")
            else:
                # Otherwise, filter both by username and string
                if username_filter.lower() in user_identity_arn.lower() and string_filter.lower() in event_json.lower():
                    all_events.append(event)
                    if debug:
                        print(f"Captured event (filtered): {event_json}")

        # Check if there is a next token for pagination
        next_token = response.get('NextToken')
        if not next_token:
            break

    return all_events

def save_events(events, filename='cloudtrail_events.json'):
    with open(filename, 'w') as f:
        for event in events:
            f.write(f"{event}\n")

    print(f"Saved {len(events)} filtered events to {filename}")

if __name__ == '__main__':
    # Check if arguments are provided
    if len(sys.argv) != 5:
        print("Usage: python fetch_cloudtrail_events.py <username_filter> <string_filter> <days_to_search> <debug>")
        sys.exit(1)

    # Get arguments from command line
    username_filter = sys.argv[1]
    string_filter = sys.argv[2]
    days_to_search = int(sys.argv[3])
    debug = sys.argv[4].lower() == 'true'

    # Fetch filtered events
    filtered_events = fetch_cloudtrail_events(username_filter, string_filter, days_to_search, debug)

    # Save the filtered events to a file
    save_events(filtered_events)

##
##
