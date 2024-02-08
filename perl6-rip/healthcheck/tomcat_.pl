#!/usr/bin/perl

##
## again to be fair this is garbaggio
##

use strict;
use warnings;

sub find_tomcat_directory {
    my $tomcat_directory = `find / -type d -name "tomcat9" 2>/dev/null | head -n 1`;
    chomp $tomcat_directory;
    return $tomcat_directory;
}

sub display_tomcat_processes {
    my $processes = `ps aux | grep -E 'tomcat|java|jdk'`;

    print "\nTomcat Processes:\n";
    print "------------------\n";
    print "$processes";
}

sub display_deployed_web_apps {
    my $tomcat_directory = find_tomcat_directory();
    my $webapps_dir = "$tomcat_directory/webapps";

    # List currently deployed web applications in subdirectories
    my $web_apps = `ls -1 "$webapps_dir" 2>/dev/null`;

    print "\nDeployed Web Applications:\n";
    print "-------------------------\n";
    print "$web_apps";
}

sub read_tomcat_logs {
    my $tomcat_directory = find_tomcat_directory();
    my $log_file = "/var/log/tomcat9/catalina.out";

    if (-e $log_file) {
        my $logs = `tail -n 99 "$log_file"`;

        print "\nTomcat Logs (last 99 lines):\n";
        print "-----------------------------\n";
        print "$logs";
    } else {
        print "Tomcat log file not found.\n";
    }
}

sub main_menu {
    while (1) {
        print "\nSelect an option:\n";
        print "1. Display Tomcat Processes\n";
        print "2. Display Deployed Web Applications\n";
        print "3. Read Tomcat Logs (last 99 lines)\n";
        print "4. Exit\n";

        my $choice = <STDIN>;
        chomp $choice;

        if ($choice eq '1') {
            display_tomcat_processes();
        }
        elsif ($choice eq '2') {
            display_deployed_web_apps();
        }
        elsif ($choice eq '3') {
            read_tomcat_logs();
        }
        elsif ($choice eq '4') {
            last;
        }
        else {
            print "Invalid option. Please try again.\n";
        }
    }
}

# Run the main menu
main_menu();

##
##

