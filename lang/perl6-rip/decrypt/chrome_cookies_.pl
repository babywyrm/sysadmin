#!/usr/bin/perl -w

use File::Copy qw(copy);
use DBI;
use Win32::API;

use strict;
use warnings;
use MIME::Base64;
use File::Copy;
use DBI;
use Win32;
use Win32::API;

##
##

use strict;
use warnings;

print ("Decrypting cookies...\n") && &fix_cookies && print ("Cookies decrypted!\n");

sub fix_cookies
{
	#Chrome has been encrypting cookie values since Chrome..33?
	#We need to decrypt the value before we can use it.

	my $chrome_cookie_file = 'C:/Users/'.$ENV{"USERNAME"}.'/AppData/Local/Google/Chrome/User Data/Default/Cookies';
	copy($chrome_cookie_file, 'Cookies') || die "Failed to move files: $!";;

	my $dbc = DBI->connect("dbi:SQLite:dbname=Cookies", '', '', { RaiseError => 1, AutoCommit => 0});

	my @rows = @{$dbc->selectall_arrayref("SELECT host_key, name, value, encrypted_value FROM cookies")};
	foreach my $row (@rows){
		my ($host_key, $name, $value, $encrypted_value) = @{$row};

		my $new_value = decryptData($encrypted_value) || $value || '0';

		#This is optional, but it allows us to use any session cookies that may exist at the time of running this.
		#This is assuming that you will be generating a new decrypted session file whenever you run your script.
		my $sth = $dbc->prepare(qq{
			UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1
			WHERE host_key = ?
			AND name = ?
		});
		$sth->execute($new_value, $host_key, $name);
	}

	$dbc->commit(); #SQLite is slow at excuting one row at a time. SEE: http://stackoverflow.com/a/8882184
	$dbc->disconnect();
}

sub decryptData
{
	#Cleaned up version of http://www.perlmonks.org/?node_id=776481
	my $encryptedData = shift;

	if($encryptedData eq ''){ return undef; } #avoid errors...

	my $pDataIn = pack('LL', length($encryptedData)+1, unpack('L!', pack('P', $encryptedData)));

	my $DataOut;
	my $pDataOut = pack('LL', 0, 0);

	my $CryptUnprotectData = Win32::API->new('Crypt32', 'CryptUnprotectData', ['P', 'P', 'P', 'P', 'P', 'N', 'P'], 'N');
	if($CryptUnprotectData->Call($pDataIn, pack('L', 0), 0, pack('L', 0), pack('L4', 16, 0, 0, unpack('L!', pack('P', 0))), 0, $pDataOut)){
		my($len, $ptr) = unpack('LL', $pDataOut);
		$DataOut = unpack('P'.$len, pack('L!', $ptr));
		return $DataOut;
	}else{
		return undef;
	}
}

##
##
