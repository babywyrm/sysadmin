#!/usr/bin/perl

##
##

use strict;
use warnings;
use File::Find;

my $dir = '/path/to/directory';

sub extract_ips {
    my $filename = $_;
    return unless $filename =~ /\.tfvars$/;  # only process .tfvars files
    open(my $fh, '<', $File::Find::name) or die "Could not open file '$filename' $!";
    while (my $line = <$fh>) {
        chomp $line;
        while ($line =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g) {
            print "$1\n";
        }
    }
    close($fh);
}

find(\&extract_ips, $dir);

##
##
