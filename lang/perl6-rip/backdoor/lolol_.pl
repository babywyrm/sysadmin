#!/usr/bin/perl

##
##

use strict;
use warnings;
use Socket;
use Authen::Simple;
use Authen::Simple::PAM;
use IO::Socket::INET;
use Proc::Daemon;

my $PORT = 6699;
my $PID_FILE = '/var/run/perl_service.pid';

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

# Set up server socket
my $server = IO::Socket::INET->new(
    LocalPort => $PORT,
    Proto => 'tcp',
    Listen => SOMAXCONN,
    Reuse => 1
) or die "Can't create server: $!";

print "Listening on port $PORT...\n";

while (my $client = $server->accept()) {
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


##
##
