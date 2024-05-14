#!/usr/bin/perl -w
#!/usr/bin/perl

#  Scribe Decode using perl modules for capture. 
## scribe_decode.pl <dev> <port>

use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use MIME::Base64;
use Term::ANSIColor qw(:constants);
use strict;

my $err;
my $dev = $ARGV[0];
my $port = $ARGV[1];

unless (defined $dev) {
  $dev = Net::Pcap::lookupdev(\$err);
  if (defined $err) {
    die 'Unable to determine network device for monitoring - ', $err;
  }
}

my ($address, $netmask);
if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) { die 'Unable to look up device information for ', $dev, ' - ', $err; }

my $object;
$object = Net::Pcap::open_live($dev, 1500, 0, 0, \$err);

unless (defined $object) { die 'Unable to create packet capture on device ', $dev, ' - ', $err; }

my $filter;
Net::Pcap::compile( $object, \$filter, "port $port", 0, $netmask) && die 'Unable to compile packet capture filter';
Net::Pcap::setfilter($object, $filter) &&
  die 'Unable to set packet capture filter';

Net::Pcap::loop($object, -1, \&syn_packets, '') ||
  die 'Unable to perform packet capture';

Net::Pcap::close($object);

sub syn_packets {
  my ($user_data, $header, $packet) = @_;
  my $ether_data = NetPacket::Ethernet::strip($packet);
  my $ip = NetPacket::IP->decode($ether_data);
  my $tcp = NetPacket::TCP->decode($ip->{'data'});

  print $ip->{'src_ip'}, ":", $tcp->{'src_port'}, " -> ", $ip->{'dest_ip'}, ":", $tcp->{'dest_port'}, "\n";

  my $hexstring = $tcp->{'data'};
  $hexstring =~ s/[^[:print:]]+/ /g;
#  while ($hexstring =~ /(cg[A-Z] +[A-Za-z0-9+]+=*\s*)?/g) {
  while ($hexstring =~ /(cg[A-Z] +(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?)?/g) {
    (my $cat, my $encoded) = split(/\s+/,$1);
    #print YELLOW, "encoded:$1\n", RESET unless ($encoded eq "");
    my $decoded = decode_base64($encoded);
    $decoded =~ s/[^[:print:]]+/ /g;
    print GREEN, "decoded:$cat $decoded\n-\n", RESET unless ($decoded eq "");
  };
  print BLUE, "***next packet***\n", RESET;
}


##
##


#!/usr/bin/perl

##
##
use strict;
use warnings;
use utf8;

open FILE, "enc.txt" or die $!;
binmode FILE, ":utf8";
my $text = 0;
foreach my $line (<FILE>)
{
        $text .= $line;
}
close FILE;
#print $text;

my %stat = ();

my $nletters = 0;

binmode STDOUT, ":utf8";

foreach my $letter (map { chr } ( ord("А") .. ord("Я") ))
{
    $stat{$letter}++ while ($text =~ /$letter/g);
}

print ">>> The size of the input alphabet is ".keys(%stat)." symbols.\n";

#foreach my $key (sort { $b <=> $a } keys %stat)
#{
#    print "\t$stat{$key} \t\t $key\n";
#}

my @ru_letters = (map { chr } ( ord("А") .. ord("Я") ));
my %ru_letters_freq = (
"О" => 52295949,
"Е" => 40392978,
"А" => 38081816,
"И" => 35075552,
"Н" => 31900994,
"Т" => 30084462,
"С" => 26058590,
"Р" => 22595850,
"В" => 21582499,
"Л" => 20678280,
"К" => 16599539,
"М" => 15252377,
"Д" => 14173134,
"П" => 13349597,
"У" => 12452612,
"Я" => 9528713,
"Ы" => 9036813,
"Ь" => 8263123,
"Г" => 8031521,
"З" => 7811723,
"Б" => 7579289,
"Ч" => 6904749,
"Й" => 5753983,
"Х" => 4597146,
"Ж" => 4476464,
"Ш" => 3420179,
"Ю" => 3044673,
"Ц" => 2314208,
"Щ" => 1719607,
"Э" => 1573696,
"Ф" => 1268926,
"Ъ" => 175908,
"Ё" => 63623
);
my %ru_letter_rank = (
#" " => 0,
"О" => 0,
"Е" => 1,
"А" => 2,
"И" => 3,
"Н" => 4,
"Т" => 5,
"С" => 6,
"Р" => 7,
"В" => 8,
"Л" => 9,
"К" => 10,
"М" => 11,
"Д" => 12,
"П" => 13,
"У" => 14,
"Я" => 15,
"Ы" => 16,
"Ь" => 17,
"Г" => 18,
"З" => 19,
"Б" => 20,
"Ч" => 21,
"Й" => 22,
"Х" => 23,
"Ж" => 24,
"Ш" => 25,
"Ю" => 26,
"Ц" => 27,
"Щ" => 28,
"Э" => 29,
"Ф" => 30,
"Ъ" => 31,
"Ё" => 32
);

my %rev_ru_letter_rank = reverse %ru_letter_rank;

my @stat_rank = ();

foreach my $value (sort { $stat{$b} <=> $stat{$a} } keys %stat)
{
    print "$value => $stat{$value} ($ru_letter_rank{$value})\n";

    push(@stat_rank, $value);

    #$sorted_stat{$value} = $stat{$value};
}

my @offset = ();

for (my $i = 0; $i < $#stat_rank + 1; $i ++)
{
    print "$i: the truth is... $stat_rank[$i] is $rev_ru_letter_rank{$i} ";
    $offset[$i] = ord($stat_rank[$i]) - ord($rev_ru_letter_rank{$i});
    print "(offset=$offset[$i])\n";
}

my %mode = ();

foreach my $gap (@offset)
{
        $mode{$gap} ++;
}

my $cur_gap = 0;
my $cur_text;
foreach my $value (sort { $mode{$b} <=> $mode{$a} } keys %mode)
{
    #if ($mode{$value} != $cur_gap)
    {
        $cur_gap = $mode{$value};
        print "$value => $mode{$value}\n";

        $cur_text = $text;
        for (my $i = 0; $i < $#stat_rank + 1; $i ++)
        {
            $cur_text =~ s/$ru_letters[$i]/$ru_letters[($i + $value) % 32]/g;
        }

        print "$cur_text\n\n";
    }
}

#use List::Util qw(sum);

#for (my $i = 0; $i < $#ru_letters + 1; $i ++)
#{
#       print "offset($ru_letters[$i], $ru_letters[$i+5])=".(ord($ru_letters[$i]) - ord($ru_letters[$i+5]))."\n";
#}

#while ( (my $k,my $v) = each %mode )
#{
#    print "$k => $v\n";
#}
            
