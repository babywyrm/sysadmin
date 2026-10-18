#!/usr/bin/perl

use strict;
use warnings;

# Function to execute a command and capture the output
sub run_command {
    my ($command) = @_;
    my $output = `$command`;
    return $output;
}

# Check if the script is run as root
die "Please run this script as root." unless $> == 0;

# Check for pending updates
sub check_updates {
    my $update_output = run_command("apt list --upgradable 2>/dev/null | grep -v Listing");
    if ($update_output) {
        print "Pending updates:\n$update_output\n";
    } else {
        print "No pending updates.\n";
    }
}

# Check if the firewall is enabled
sub check_firewall {
    my $firewall_status = run_command("ufw status");
    if ($firewall_status =~ /Status: active/) {
        print "Firewall is active.\n";
    } else {
        print "Firewall is not active.\n";
    }
}

# Check for AppArmor or SELinux
sub check_mandatory_access_control {
    my $apparmor_status = run_command("apparmor_status");
    my $selinux_status  = run_command("sestatus");

    if ($apparmor_status =~ /apparmor module is loaded/) {
        print "AppArmor is enabled.\n";
    } elsif ($selinux_status =~ /SELinux status: enabled/) {
        print "SELinux is enabled.\n";
    } else {
        print "Neither AppArmor nor SELinux is enabled.\n";
    }
}

# Disable unnecessary services
sub disable_unnecessary_services {
    my @services_to_disable = qw( avahi-daemon bluetooth );

    foreach my $service (@services_to_disable) {
        my $disable_output = run_command("systemctl is-enabled $service 2>/dev/null");
        if ($disable_output =~ /enabled/) {
            print "Disabling $service service...\n";
            run_command("systemctl disable $service");
        } else {
            print "$service service is already disabled.\n";
        }
    }
}

# Set strict permissions on sensitive files
sub set_file_permissions {
    my @sensitive_files = qw( /path/to/sensitive/file /path/to/another/sensitive/file );

    foreach my $file (@sensitive_files) {
        if (-e $file) {
            print "Setting strict permissions for $file...\n";
            run_command("chmod 600 $file");
        } else {
            print "$file does not exist.\n";
        }
    }
}

# Add more checks as needed...

# Main script
print "System Hardening Checks:\n";

# Check pending updates
check_updates();

# Check firewall status
check_firewall();

# Check for mandatory access control
check_mandatory_access_control();

# Disable unnecessary services
disable_unnecessary_services();

# Set strict permissions on sensitive files
set_file_permissions();

# Add more checks...

# End of script
