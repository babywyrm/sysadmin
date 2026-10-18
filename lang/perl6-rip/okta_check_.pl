use strict;
use warnings;
use LWP::UserAgent;
use JSON;

# Set up API request parameters
my $base_url = "https://your.okta.domain/api/v1";
my $app_id = "your_app_id";
my $api_key = "your_api_key";

# Create a user agent object
my $ua = LWP::UserAgent->new;
$ua->default_header('Accept' => 'application/json');
$ua->default_header('Content-Type' => 'application/json');
$ua->default_header('Authorization' => "SSWS $api_key");

# Get all users assigned to the app
my $url = "$base_url/apps/$app_id/users";
my $response = $ua->get($url);
die "Failed to retrieve users: ", $response->status_line unless $response->is_success;
my $users = decode_json($response->content);

# Create an array to store user information
my @user_list;

# Loop through each user and get their app-specific permissions
foreach my $user (@$users) {
    my $user_id = $user->{id};
    my $url = "$base_url/apps/$app_id/users/$user_id/roles";
    my $response = $ua->get($url);
    die "Failed to retrieve permissions: ", $response->status_line unless $response->is_success;
    my $permissions = decode_json($response->content);

    # Create a hash to store user information
    my %user_info = (
        firstName => $user->{profile}->{firstName},
        lastName  => $user->{profile}->{lastName},
        permissions => [ map { $_->{type} } @$permissions ],
    );

    # Add the user hash to the list
    push @user_list, \%user_info;
}

# Save the user list to a JSON file
my $json = encode_json(\@user_list);
open(my $file, '>', 'user_permissions.json') or die "Failed to open file: $!";
print $file $json;
close $file;

print "User permissions saved to user_permissions.json\n";
