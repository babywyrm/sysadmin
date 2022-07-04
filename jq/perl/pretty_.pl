#!/usr/bin/env perl

use strict;
use warnings;

use JSON;

sub recursive_inplace_stringification {
    my $reftype = ref( $_[0] );
    if ( !length($reftype) ) {
        $_[0] = "$_[0]" if defined( $_[0] );
    }
    elsif ( $reftype eq 'ARRAY' ) {
        recursive_inplace_stringification($_) for @{ $_[0] };
    }
    elsif ( $reftype eq 'HASH' ) {
        recursive_inplace_stringification($_) for values %{ $_[0] };
    }
    elsif ( $reftype eq 'JSON::PP::Boolean' ) {
        if ( defined( $_[0] ) && $_[0] ) {
            $_[0] = "true";
        }
        else {
            $_[0] = "false";
        }
    }
    else {
        die("Unsupported reference to $reftype\n");
    }
}

# Get JSON parser
my $json = JSON->new();

# Read JSON from in-data and convert to Perl hash
my $hash = $json->decode(<>);

# Convert numbers and booleans into strings
recursive_inplace_stringification($hash);

# Convert to JSON and print
print $json->allow_nonref->utf8->pretty->encode($hash);
