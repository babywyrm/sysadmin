
#!/usr/bin/env perl

use strict;
use warnings;
use autodie;

use open IN => ':encoding(UTF-8)';
use open OUT => ':encoding(ascii)';

my $buffer;

open(my $ifh, '<', 'utf_WHATEVER_THO_.txt');
read($ifh, $buffer, -s $ifh);
close($ifh);

open(my $ofh, '>', 'ascii.txt');
print($ofh $buffer);
close($ofh);

######################
##
##
