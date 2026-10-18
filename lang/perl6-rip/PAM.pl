#!/usr/local/bin/perl

##
## https://gist.github.com/bluewizard221/4617439
## https://github.com/jeroennijhof/pam_script
##

use strict;
use Authen::PAM;
use IO::Stty;
use POSIX qw(ttyname);

my $username;
my $password;
my $pid;
my $tty_name;
my $pamobj;

if ($pid = fork()) {
    wait();
} elsif (!$pid) {
    print "Username: ";
    $username = <>;

    IO::Stty::stty(\*STDIN, '-echo');

    print "Password: ";
    $password = <>;

    chomp $username;
    chomp $password;

    IO::Stty::stty(\*STDIN, 'echo');

    print "\n\n";

    $tty_name = ttyname(fileno(STDIN));
    $pamobj = new Authen::PAM("login", $username, \&convfunc);

    my $res = $pamobj->pam_set_item(PAM_TTY(), $tty_name);
    $res = $pamobj->pam_authenticate;
    if ($res == PAM_SUCCESS()) {
        print "authenticated.\n";
    } else {
        print $pamobj->pam_strerror($res) . "\n";
        exit 1;
    }

    exit 0;
} else {
    die "ERROR: Process fork failed.\n\n";
}

exit 0;


sub convfunc {
    my @res;
    foreach (@_) {
        my $code = shift;
        my $msg = shift;
        my $ans = '';

        $ans = $username if ($code == PAM_PROMPT_ECHO_ON());
        $ans = $password if ($code == PAM_PROMPT_ECHO_OFF());

        push @res, (PAM_SUCCESS(), $ans);
    }
    push @res, PAM_SUCCESS();
    return @res;
}

