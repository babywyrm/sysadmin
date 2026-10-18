#!/usr/bin/perl
use strict;
use warnings;

##
##

# Check for the correct number of command-line arguments
if (@ARGV != 3) {
    die "Usage: $0 <source_tarball> <dest_encrypted_tarball> <passphrase>\n";
}

# Get command-line arguments
my $source_tarball = $ARGV[0];
my $dest_encrypted_tarball = $ARGV[1];
my $passphrase = $ARGV[2];

# Check if the source tarball file exists
unless (-e $source_tarball) {
    die "Source tarball '$source_tarball' does not exist.\n";
}

# Encrypt the source tarball using OpenSSL with the specified passphrase
my $encryption_command = "openssl enc -aes-256-cbc -salt -in '$source_tarball' -out '$dest_encrypted_tarball' -k '$passphrase'";
system($encryption_command);

# Check the result of the encryption
if ($? == 0) {
    print "Tarball encrypted and saved as '$dest_encrypted_tarball'.\n";
    # Optionally, you can remove the original tarball for security
    unlink $source_tarball;
} else {
    die "Encryption failed. Check the source tarball and passphrase.\n";
}

