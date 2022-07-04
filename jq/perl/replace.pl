echo -n '{"a":5,"b":7}' | jsonmap -r '$_->{"a"}." and ".$_->{"b"}'
#!/usr/bin/perl

# usage: $0 [options] <perlcode> [<inputfile>]
#
# reads json from stdin/inputfile, or if -R given, reads whole input as a string
# perlcode gets the json/string as a perl object in $_
# return object from perlcode is encoded as json to stdout, or passed as-is if -r given
# pretty-printed by default, -c for compact
# all input/output is in UTF-8
# please note that hash key order is randomized due to JSON:PP using perl's default hash implementation
#
# Examples:
# $ echo -n '{"a":5,"b":7}' | jsonmap '[ keys %$_ ]'
# [
#    "a",
#    "b"
# ]
# $ ( echo foo ; echo bar ) | jsonmap -R '[ split(/\n/) ]'
# [
#    "foo",
#    "bar"
# ]
# $ echo -n '{"a":5,"b":7}' | jsonmap -r '$_->{"a"}." and ".$_->{"b"}'
# 5 and 7
# $ echo -n '{"a":5,"b":7}' | jsonmap -r '$a=$_; join(" and ", map { $a->{$_} } qw(a b))'
# 5 and 7


use strict;
use warnings;

use JSON::PP;
use Getopt::Std;

$Getopt::Std::STANDARD_HELP_VERSION = 1;

my %opts;
getopts('crR', \%opts) or exit 32;

undef $/;
my $code = shift @ARGV;
unless(defined($code)) {
    print STDERR "ERROR: No perl script given\n";
    exit 33;
}

if ($opts{'R'}) {
    binmode(STDIN, ':utf8');
    $_ = <>;
} else {
    my $i = <>;
    unless(length($i)) {
        print STDERR "ERROR: No data on input (expected JSON)\n";
        exit 2;
    }
    eval {
        $_ = decode_json($i);
        1;
    } or do {
        $_ = decode_json('['.$i.']')->[0];
    };
}

my $o = eval($code);

if($@) {
    print STDERR 'ERROR: Broken perl script: ', $@;
    exit 1;
} elsif ($opts{'r'}) {
    if (defined($o)) {
        binmode(STDOUT, ':utf8');
        print $o,"\n";
    } # else don't print anything
} else {
    if (defined($o)) {
        binmode(STDOUT); # raw mode
        my $pp = JSON::PP->new->utf8->allow_nonref;
        $pp = $pp->pretty unless ($opts{'c'});
        print $pp->encode($o, allow_nonref => 1);
    } else {
        print "null\n";
    }
}
