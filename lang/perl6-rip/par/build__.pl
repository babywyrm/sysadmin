#!/usr/bin/perl
# build.pl - Creates a standalone executable from ImplantDetector.pl ~~~example~~~
##

use strict;
use warnings;

# Check if pp is installed
system("which pp >/dev/null 2>&1");
if ($? != 0) {
    die "Error: PAR::Packer (pp) is not installed. Install with: cpan PAR::Packer\n";
}

# Define required modules
my @modules = qw(
    File::Find
    File::Spec
    Digest::SHA
    Term::ANSIColor
    Net::DNS
    LWP::UserAgent
    JSON::XS
    List::Util
);

# Build the command
my $output = "implant_detector";
my $cmd = "pp -o $output";

# Add modules
foreach my $module (@modules) {
    $cmd .= " -M $module";
}

# Add icon for Windows if available
if (-f "detector.ico") {
    $cmd .= " --icon=detector.ico";
}

# Add source file
$cmd .= " ImplantDetector.pl";

print "Building standalone executable...\n";
print "Command: $cmd\n";

# Execute the build
system($cmd);

if ($? == 0) {
    chmod 0755, $output;
    print "Build successful! Created: $output\n";
} else {
    print "Build failed with error code: " . ($? >> 8) . "\n";
}
