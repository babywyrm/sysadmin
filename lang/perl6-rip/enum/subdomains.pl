
##
##

use strict;
use warnings;
use LWP::UserAgent;

# Prompt user for target domain
print "Enter target domain: ";
my $target = <STDIN>;
chomp($target);

# Create an array of subdomains to check
my @subdomains = ("www", "ftp", "mail", "test", "docs", "localhost", "webmail", "smtp","pop","ns1","webdisk","ns2","cpanel","whm","autodiscover","autoconfig","m","imap","test","ns","blog","pop3","dev","www2","admin","forum","news","vpn","ns3","mail2","new","mysql","old","lists","support","mobile","mx","static","docs","beta","shop","sql","secure","demo","cp","calendar","wiki","web","media","email","images","img","www1","intranet","portal","video","sip","dns2","api","cdn","stats","dns1","ns4","www3","dns","search","staging","server","mx1","chat","wap","my","svn","mail1","sites","proxy","ads","host","crm","cms","backup","mx2","lyncdiscover","info","apps","download","remote","db","forums","store","relay","files","newsletter","app","live","owa","en","start","sms","office","exchange","ipv4","footer");

# Create an instance of LWP::UserAgent
my $ua = LWP::UserAgent->new;

# Check each subdomain
foreach my $sub (@subdomains) {
    my $url = "http://$sub.$target";
    my $response = $ua->get($url);

    if ($response->is_success) {
        print "Subdomain found: $url\n";
    }
}
