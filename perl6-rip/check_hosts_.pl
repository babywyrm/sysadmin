use strict;
use warnings;
use Net::Ping;

##
##

# Input file containing hostnames (one hostname per line)
my $input_file = 'hostnames.txt';

# Output file to store the results
my $output_file = 'hostname_status.txt';

# Open the input and output files
open(my $input_fh, '<', $input_file) or die "Failed to open input file: $!";
open(my $output_fh, '>', $output_file) or die "Failed to open output file: $!";

# Array to store the results
my @results;

# Create a Net::Ping object
my $pinger = Net::Ping->new();

# Read each hostname from the input file
while (my $hostname = <$input_fh>) {
  chomp($hostname);
  
  # Ping the hostname to check its status
  my $status = $pinger->ping($hostname) ? 'UP' : 'DOWN';
  
  # Get the IP address of the hostname
  my $ip = gethostbyname($hostname);
  
  # Push the results into the array
  push @results, {
    hostname => $hostname,
    status   => $status,
    ip       => $ip,
  };
}

# Close the input file and pinger object
close $input_fh;
$pinger->close();

# Print the results in a table format
print $output_fh "Hostname\tStatus\tIP Address\n";
print $output_fh "--------\t------\t----------\n";
foreach my $result (@results) {
  print $output_fh "$result->{hostname}\t$result->{status}\t$result->{ip}\n";
}

# Close the output file
close $output_fh;

print "Hostnames and their status have been written to $output_file.\n";

