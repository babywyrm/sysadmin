#!/usr/bin/env perl
##
##  https://gist.github.com/hexfusion/6a74570bfd93f6fe9a38f127e5211f7f
##
#############################

use strict;
use warnings;

use Digest::Bcrypt;
use Digest::MD5;
use Crypt::Random;
use MIME::Base64;
use Data::Dumper;

# constants
my $ocost = 13; 
my $cipher = '$2y$';
my $password = '';
my $bcrypt_pepper = '';
# this is assuming an existing password in db
my $bcrypt_password = '';

# Map between bcrypt identifier letter and "pre-digested" encryption type
my %cipher_map = qw/ 
    s   sha1
    m   md5
    n   md5_salted
    c   default
/;

my %enc_subs = ( 
    default => \&enc_default,
    md5 => \&enc_md5,
    md5_salted => \&enc_md5_salted,
    sha1 => \&enc_sha1,
    bcrypt => \&enc_bcrypt,
);

my $store = bmarshal($bcrypt_password);

# use the salt from the existing password or make new
my $salt = $store->{salt} ||
    Crypt::Random::makerandom_octet(
        Length   => 16, # bcrypt requirement
        Strength =>  0, # /dev/urandom instead of /dev/random
    );  

my $opt = ({
    bcrypt_pepper => $bcrypt_pepper,
    cost          => $ocost
});

# do bcrypt
my $bcrypt = Digest::Bcrypt->new;

my $cost = $store->{cost} || $opt->{cost};

$bcrypt->cost($cost);
$bcrypt->salt($salt);
$bcrypt->add(&brpad($password, $opt, $cipher));

print 'txt password: ' . $password . "\n";
print 'bcrypt password: ' . bserialize($bcrypt, $cipher) . "\n";
print 'stored password: ' . $bcrypt_password . "\n";

sub bmarshal {
    local $_ = shift;

    my $cipher = ''; 
    s/^(\$2(?:[yms]|[nc]\$..)\$)//
        and $cipher = $1; 

    return {} unless $cipher;

    my ($cost, $combined) = grep { /\S/ } split /\$/;
    my ($encoded_salt, $hash) = $combined =~ /^(.{22})(.*)$/;

    return {} if
        $cost < 1 
        ||  
        $cost > 31
        ||  
        $encoded_salt =~ m{[^a-z0-9+/]}i
        ||  
        ($hash || '-') =~ m{[^a-z0-9+/]}i
    ;   

    return {
        cipher => $cipher,
        salt => MIME::Base64::decode_base64("$encoded_salt=="),
        cost => $cost,
        hash => $hash,
    };  
}

sub bcost {
    my $opt = shift;
    my $store = shift || {}; 
    return $store->{cost} || $opt->{cost};
}

sub brpad {
    my ($data, $opt, $cipher) = @_; 

    # If passwords are already stored SHA1, MD5, or crypt(),
    # and there is no desire to allow promote to organically
    # update them, the existing encrypted passwords can be
    # bcrypted wholesale and future submission by users will
    # "pre-digest" to the original encrypted structure
    # for comparison against the bcrypt hashes.
    #    
    # This is indicated by the structure of the cipher:
    # * $2c$XX$ - original crypt() password with XX salt
    # * $2m$ - plain MD5 digest on password
    # * $2n$XX$ - salted MD5 digest on password
    # * $2s$ - plain SHA1 digest on password

    $data = &pre_digest($data, $cipher);

    # Increase difficulty to brute force passwords by right padding out
    # to at least 72 character length. Most effective with "pepper" set
    # in catalog config.

    while (length ($data) < 72) {
        my $md5 = Digest::MD5->new;
        $md5->add($opt->{bcrypt_pepper})
            if $opt->{bcrypt_pepper};
        $data .= $md5->add($data)->b64digest;
    }
    return $data;
}

sub pre_digest {
    my ($data, $cipher) = @_;
    $cipher ||= '';
    my $obj;
    my ($id, $salt) = grep { /\S/ } split /\$/, $cipher;

    # Starts with "2" or not bcrypt
    $id =~ s/^2//
        or return $data;

    # Must have routine key defined in %cipher_map
    my $key = $cipher_map{$id}
        or return $data;

    return $enc_subs{$key}->($obj, $data, $salt);
}

sub bserialize {
    my $bcrypt = shift;
    my $cipher = shift || '$2y$';

    my $encoded_salt = substr (MIME::Base64::encode_base64($bcrypt->salt,''),0,-2);

    return $cipher .
        join (
            '$',
            sprintf ('%02d', $bcrypt->cost),
            $encoded_salt . $bcrypt->b64digest,
        )
    ;
}

1;
