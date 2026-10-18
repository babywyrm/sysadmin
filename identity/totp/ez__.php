#!/usr/bin/env php
<?php 

/*
 * echo -n "KEY" | php totp.php
 *
 * --debug: Print the output of each step of the algorithm
 * --raw  : Use the KEY as is.  By default (without --raw), KEY is treated as base32 encoded
 */

$t0 = 0;
$x = 30;
$n = 6;

function base32_decode( $string ) {
	$rfc_base32_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	$php_base32_alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

	$string = preg_replace( '/[^A-Za-z2-7]/', '', $string );

	$out = '';

	foreach ( str_split( $string, 8 ) as $chunk ) {
		for ( $i = 0, $l = strlen( $chunk ); $i < $l; $i++ ) {
			$pos = strpos( $rfc_base32_alphabet, strtoupper( $chunk[$i] ) );
			if ( false !== $pos ) {
				$chunk[$i] = $php_base32_alphabet[$pos];
			}
		}

		$out .= base_convert( $chunk, 32, 16 );
	}

	return hex2bin( $out );
}

if ( in_array( '--debug', $argv ) ) {
	function debug() {
		fwrite( STDERR, call_user_func_array( 'sprintf', func_get_args() ) . "\n" );
	}
} else {
	function debug() {}
}


$key = file_get_contents( 'php://stdin' );
if ( ! in_array( '--raw', $argv ) ) {
	$key = base32_decode( $key );
}
debug( 'KEY   : 0x%s', bin2hex( $key ) );

$now = time();
debug( 'NOW   : %s', $now );

debug( 'T0    : %s', $t0 );
debug( 'X     : %s', $x );

$t = ( $now - $t0 ) / $x;
debug( 'T     : 0x%x', $t );

// 64-bit integer
$t_packed = pack( 'NN', ( $t & 0xffffffff00000000 ) >> 32, $t & 0x00000000ffffffff );
debug( 'T_PACK: 0x%s', bin2hex( $t_packed ) );

$hmac = hash_hmac( 'sha1', $t_packed, $key, true );
debug( 'HMAC  : 0x%s', bin2hex( $hmac ) );

$offset = ord( substr( $hmac, -1 ) ) & 0b1111;
debug( 'OFFSET: %d', $offset );

$bytes = bin2hex( substr( $hmac, $offset, 4 ) );
debug( 'BYTES : 0x%s', $bytes );

$token = hexdec( $bytes ) & 0x7FFFFFFF;
debug( 'TOKEN : %d', $token );

//                         substr( $token, -1 * $n )
printf( "%06s\n", $token % pow( 10, $n ) );
