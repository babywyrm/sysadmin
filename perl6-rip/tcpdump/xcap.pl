#!/usr/bin/perl -w
##
##
##
use strict;
use Compress::Zlib;
use Getopt::Long;
Getopt::Long::Configure ("bundling");

##
## https://github.com/nlitsme/xpcapperl/blob/master/xpcap
##

# xpcap shows the payloads of udp and tcp connections, parsing
# the output of tcpdump -x
#
# note: not displaying these packets:
#    - ARP  who-has, is-at
#    - some IPv6
#
#    - 'Supervisory??
#17:57:20.425596 78:31:c1:ca:db:c8 > ff:ff:ff:ff:ff:ff Null Supervisory, Receiver not Ready, rcv seq 64, Flags [Poll], length 46
#     0x0000:  0000 f581 8000 0059 0000 0000 0000 0000
#     0x0010:  0000 0000 0000 0000 0000 0000 0000 0000
#     0x0020:  0000 0000 0000 0000 0000 0000 0000

#    - STP bridge-id
#17:57:19.595032 STP 802.1d, Config, Flags [none], bridge-id 8000.64:66:b3:5f:af:2a.8001, length 43
#     0x0000:  4242 0300 0000 0000 8000 6466 b35f af2a
#     0x0010:  0000 0000 8000 6466 b35f af2a 8001 0000
#     0x0020:  1400 0200 0000 0000 0000 0000 0000

$|=1;

my $ascii;           # -aa : no hex, print byte count
my $usetcpdump;
my $gzip;
my $noempty;
my $filterports;
my $verbose;
my $savedir;

my %ctcp;
my %cudp;

GetOptions(
    "a+"=>\$ascii,
    "t"=>\$usetcpdump,
    "z"=>\$gzip,
    "v"=>\$verbose,
    "p=s"=>\$filterports,
    "w=s"=>\$savedir,
    "n"=>\$noempty) or die "Usage: xpcap [-a[a]] [-t] [-z] [-v] [-p PORT(S)] [-w SAVEDIR] [-n]\n";


my ($t, $p, $d, $previnf);
$filterports= ",$filterports," if $filterports;

while (<>) {
    # todo: output beacon + probes

    # match optional date, followed by time with usec precision.
    if (/^((?:\d\d\d\d-\d\d-\d\d )?\d\d:\d\d:\d\d\.\d\d\d\d\d\d) (.*)/) {
        my ($curt, $line)= ($1, $2);
        if (defined $d && length($p)) {
            if (length($d)>=4 && substr($d,0,4) eq "\x02\x00\x00\x00\x45") {
                $d = substr($d,4);
            }
            if (length($d)>=15 && substr($d,12,3) eq "\x08\x00\x45") {
                $d = substr($d,14);
            }
            if (!dumppkt($t, $p, $d, $previnf) && $verbose) {
                print "ignoring $t\n";
            }
        }

        ($t, $d)= ($curt, "");
        next if $line =~ / bad-fcs /;
        if ($line =~  /^(.*?\s\S+\s>\s\S+):(.*)/) {
            my ($curp, $curinf)= ($1, $2);
            $curp =~ s/\d+us.*?Mb\/s.*?noise\santenna\s\d+//;
            ($p, $previnf)= ($curp, $curinf);
        }
        else {
            ($p, $previnf)= ("", "");
        }
    }
    elsif (/^\s+0x\w+:\s+((?:\s\w+)+)/) {
        my $x=$1; $x=~s/\s//g;
        $d.=pack("H*", $x);
    }
}
if (defined $d && length($p)) {
    if (!dumppkt($t, $p, $d, $previnf) && $verbose) {
        print "ignoring $t\n";
    }
}
flushdata() if $savedir;

sub dumppkt {
    my ($t,$p,$d, $info)=@_;
    return if (length($d)==0);
    my $pos= 0;
    if (length($d)>8 && unpack("n", substr($d, $pos, 2))==0xaaaa) {      # wifi header
        $pos+= 8;
    }
    if (length($d)>4 && unpack("n", substr($d, $pos+2, 2))==0x0800) {  # found in pcap-ng files
        $pos+= 4;
    }
    my $ipv=ord(substr($d,$pos,1))>>4;

    my $type=0;
    my $ethextra;  # leftover in ethernet packet beyond ip packet

    my ($srcaddr, $dstaddr);

    if ($ipv==4) {
        return if $pos+4>length($d);

        my $iplen= unpack("n", substr($d,$pos+2,2));
        $ethextra=substr($d,$pos+$iplen) if $iplen<length($d);
        # todo: not ethextra
        $d= substr($d,0,$iplen+$pos);
        
        my $ihl=ord(substr($d,$pos,1))&15;
        return if $ihl<5;
        return if (length($d)<$pos+$ihl*4);

        $type= unpack("C", substr($d, $pos+9,1));

        $srcaddr= join(".", unpack("C4", substr($d, $pos+12, 4)));
        $dstaddr= join(".", unpack("C4", substr($d, $pos+16, 4)));

        $pos+= $ihl*4;

        return if $pos>=length($d);
    }
    elsif ($ipv==6) {
        return if $pos+0x28>length($d);
        #return if (unpack("N", substr($d, $pos, 4))!=0x60000000);
        my $datalen= unpack("n", substr($d, $pos+4, 2));
        $type= unpack("C", substr($d, $pos+6, 1));

        $srcaddr= join(":", map { sprintf("%x", $_) } unpack("n8", substr($d, $pos+12, 16)));  $srcaddr =~ s/::+/::/g;
        $dstaddr= join(":", map { sprintf("%x", $_) } unpack("n8", substr($d, $pos+16, 16)));  $dstaddr =~ s/::+/::/g;

        $pos+= 0x28;
        while (hasnext($type) && $pos<length($d)) {
            $type= unpack("C", substr($d, $pos, 1));
            my $hdlen= $type==44 ? 8 : (8+unpack("C", substr($d, $pos+1, 1)));
            $pos += $hdlen;
        }
        return if $pos>=length($d);
    }
    else {
        return;
    }

    my $flags;     # tcp flags
    my ($srcport, $dstport);
    my $data;
    my $s;  # sequencenr
    if ($type==6) {
        return if $pos+20>length($d);
        my $thl= ord(substr($d,$pos+12,1))>>4;
        return if $pos+$thl*4>length($d);
        $data= substr($d, $pos+4*$thl);

        $p =~ s/\bIP\b/TCP/;

        $flags= "";
        if ($info =~ /Flags \[(.*?)\]/) {
            $flags= $1;
            $flags=~ s/[.P]//g;
        }
        ($srcport, $dstport, $s)= unpack("n2N", substr($d, $pos, 8));

        savetcpdata(tag($p), $data, $s) if $savedir;
    }
    elsif ($type==17) {  # udp
        return if $pos+8>length($d);
        my $udplen= unpack("n", substr($d,$pos+4,2));
        if ($udplen!=0xffff && $pos+$udplen > length($d)) {
            warn sprintf("udplen too large: %04x > %04x\n", $udplen, length($d)-$pos);
        }
        my $ipextra= substr($d, $pos+$udplen) if $udplen!=0xffff && $pos+$udplen<length($d);
        # todo: not ipextra
        $data= $udplen!=0xffff ? substr($d, $pos+8, $udplen-8) : substr($d, $pos+8);

        $p =~ s/\bIP\b/UDP/;

        ($srcport, $dstport)= unpack("n2", substr($d, $pos, 4));

        saveudpdata(tag($p), $data) if $savedir;
    }
    elsif ($type==1) {  # icmp
#       return if $pos+8>length($d);
#       my ($type, $code, $chk, $ident, $seq)= unpack("CCnnn", substr($d, $pos, 8));
#       my %types= (0=>'echoreply', 3=>'unreachable', 4=>'srcquench', 5=>'redirect',
#           6=>'altaddr', 8=>'echoreq', 9=>'routeradv', 10=>'routersel', 11=>'timeexceeded',
#           12=>'paramproblem', 13=>'timestampreq', 14=>'timestampreply', 15=>'inforeq', 16=>'inforeply',
#           17=>'maskreq', 18=>'maskreply', 30=>'traceroute'
#       );
        $p =~ s/\bIP\b/ICMP/;
    }
    else {
        $data= substr($d, $pos);
    }


    if ($filterports) {
        my $msrc= (!$srcport || index($filterports, ",$srcport,")<0);
        my $mdst= (!$dstport || index($filterports, ",$dstport,")<0);
        return if $msrc && $mdst;
    }

    if ($type==1) {  # icmp
        printf("%s %-45s            %s\n", $t, tag($p), $info);
    }
    elsif ($usetcpdump && $type==17 && ($srcport==53 || $dstport==53 || $srcport==68 || $dstport==68 || $srcport==67 || $dstport==67 || $srcport==5353 || $dstport==5353)) {
        printf("%s %-45s            %s\n", $t, tag($p), $info);
    }
    elsif ($ascii && $data =~ /^[\t\r\n\x20-\xef]{8,}/) {
        my $a= $&;
        my $d= substr($data, length($a));
        if ($gzip && substr($d,0,2) eq "\x1f\x8b") {
            my $o= Compress::Zlib::memGunzip($d) || "";

            $a .= $o;
        }
        my $l= length($d);
        if (defined $s) {
            printf("%s %-45s %1s[%08x] %s\n", $t, tag($p), $flags, $s, $l ? "... ".($ascii>1 ? sprintf("%d bytes", $l) : unpack("H*", $d)) : "");
        }
        else {
            printf("%s %-45s            %s\n", $t, tag($p), $l ? "... ".($ascii>1 ? sprintf("%d bytes", $l) : unpack("H*", $d)) : "");
        }
        $a =~ s/^/   | /gm;
        print "$a\n";
    }
    elsif (!defined $s) {
        printf("%s %-45s          %s\n", $t, tag($p), unpack("H*", $data));
    }
    elsif (length($data) || !$noempty) {
        printf("%s %-45s %1s[%08x] %s\n", $t, tag($p), $flags, $s, unpack("H*", $data));
    }

    return 1;
}
sub hasnext {
    my $t= shift;
    return $t==0 || $t==43 || $t==44 || $t==60;
}
my %t;
sub tag {
    my $dir=shift;
    if ($dir =~ /(?:(\w+)\s+)?(\S+) > (\S+)/) {
        my ($p, $A, $B) = ($1 || "", $2, $3);

        my $fwd= "$p $A > $B";
        my $rev= "$p $B > $A";
        if (exists $t{$fwd}) {
            return $t{$fwd};
        }
        elsif (exists $t{$rev}) {
            return $t{$dir}= "$p $B < $A";
        }
        else {
            return $t{$dir}= "$p $A > $B";
        }
    }
    printf("!!!!!!! %s\n", $dir);
    return "";
}

sub saveudpdata {
    my ($tag, $data)= @_;
    $tag =~ s/ > /-/;
    open(my $fh, ">> $savedir/$tag") or die "$tag: $!\n";
    $fh->print($data);
    $fh->close();
}

sub savetcpdata {
    my ($tag, $data, $seq)= @_;
    $tag =~ s/ > /-/;

    if (!exists $ctcp{$tag}{$seq} || length($data)>length($ctcp{$tag}{$seq})) {
        $ctcp{$tag}{$seq}= $data;
    }
}

sub flushdata {
    for my $tag (keys %ctcp) {
        my @seq= sort { $a<=>$b } keys %{$ctcp{$tag}};

        my $curseq;
        my $curdata= "";
        for my $seq (@seq) {
            if (!defined $curseq) {
                $curseq= $seq;
                $curdata= $ctcp{$tag}{$seq};
                $curseq += length($ctcp{$tag}{$seq});
            }
            elsif ($seq-$curseq<0x10000) {
                $curdata .= "\x00" x ($seq-$curseq);
                $curseq = $seq;
                $curdata .= $ctcp{$tag}{$seq};
                $curseq += length($ctcp{$tag}{$seq});
            }
            else {
                if (defined $curdata) {
                    open(my $fh, "> $savedir/$tag-$curseq") or die "$tag: $!\n";
                    $fh->print($curdata);
                    $fh->close();
                }
                
                $curseq= $seq;
                $curdata= $ctcp{$tag}{$seq};
                $curseq += length($ctcp{$tag}{$seq});
            }
        }
        if (defined $curdata) {
            open(my $fh, "> $savedir/$tag-$curseq") or die "$tag: $!\n";
            $fh->print($curdata);
            $fh->close();
        }
    }
}
