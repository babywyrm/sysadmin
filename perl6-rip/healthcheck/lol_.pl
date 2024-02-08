#!/usr/bin/perl

## probably
## not
## something
## for
## prod
## tbh

use strict;
use warnings;

sub display_system_info {
    my $input = shift;

    # Validate input to prevent command injection
    if ($input =~ /^[a-zA-Z0-9\s\-]+$/) {
        my $uname = `uname -a "$input"`;
        my $uptime = `uptime`;
        my $df = `df -h`;

        print "\nSystem Information:\n";
        print "-------------------\n";
        print "Kernel: $uname";
        print "Uptime: $uptime";
        print "Disk Space:\n$df";
    } else {
        print "Invalid input. Please enter a valid option.\n";
    }
}

sub display_last_logins {
    my $last = `last -n 5`;

    print "\nLast Logins:\n";
    print "-------------\n";
    print "$last";
}

sub display_user_info {
    my $users = `cut -d: -f1 /etc/passwd`;

    print "\nUser Information:\n";
    print "-----------------\n";
    print "Users:\n$users";
}

sub display_apache_logs {
    my $recent_logs = `tail -n 100 /var/log/apache2/*`;

    print "\nRecent Apache2 Logs:\n";
    print "---------------------\n";
    print "$recent_logs";
}

sub search_files {
    my $query = shift;

    # Simulate command injection vulnerability (for educational purposes)
    my $locatedb_command = "locate $query";
    my $locatedb_results = `$locatedb_command`;

    my $find_command = "find / -name \"*$query*\" 2>/dev/null";
    my $find_results = `$find_command`;

    print "\nFiles matching '$query' (from locate):\n";
    print "-------------------------------------\n";
    print "$locatedb_results";

    print "\nFiles matching '$query' (from find):\n";
    print "-----------------------------------\n";
    print "$find_results";
}

sub main_menu {
    while (1) {
        print "\nSelect an option:\n";
        print "1. Display System Information (with input)\n";
        print "2. Display Last Logins\n";
        print "3. Display User Information\n";
        print "4. Display Recent Apache2 Logs\n";
        print "5. Search Files\n";
        print "6. Exit\n";

        my $choice = <STDIN>;
        chomp $choice;

        if ($choice eq '1') {
            print "\nEnter a parameter (e.g., '; ls -l'):\n";
            my $input = <STDIN>;
            chomp $input;

            display_system_info($input);
        }
        elsif ($choice eq '2') {
            display_last_logins();
        }
        elsif ($choice eq '3') {
            display_user_info();
        }
        elsif ($choice eq '4') {
            display_apache_logs();
        }
        elsif ($choice eq '5') {
            print "\nEnter a search query (potentially inject command, e.g., '; ls -l'):\n";
            my $query = <STDIN>;
            chomp $query;

            search_files($query);
        }
        elsif ($choice eq '6') {
            last;
        }
        else {
            print "Invalid option. Please try again.\n";
        }
    }
}

##
##

# Run the main menu
main_menu();
