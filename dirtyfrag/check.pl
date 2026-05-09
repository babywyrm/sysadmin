#!/usr/bin/env perl
use strict;
use warnings;
use feature 'say';
use JSON::PP qw(encode_json);

my $json = 0;
for my $arg (@ARGV) {
    if ($arg eq '--json') {
        $json = 1;
    }
}

my @copyfail_modules = qw(algif_aead af_alg);
my @dirtyfrag_modules = qw(esp4 esp6 rxrpc ipcomp ipcomp6 xfrm_user);
my @all_modules = sort (@copyfail_modules, @dirtyfrag_modules);

sub slurp {
    my ($path) = @_;
    return '' unless -e $path;
    open my $fh, '<', $path or return '';
    local $/;
    return <$fh>;
}

sub read_os_release {
    my %data;
    my $content = slurp('/etc/os-release');

    for my $line (split /\n/, $content) {
        next if $line =~ /^\s*#/;
        next unless $line =~ /^([A-Za-z0-9_]+)=(.*)$/;

        my ($key, $value) = ($1, $2);
        $value =~ s/^"//;
        $value =~ s/"$//;
        $data{$key} = $value;
    }

    return \%data;
}

sub loaded_modules {
    my %mods;
    my $content = slurp('/proc/modules');

    for my $line (split /\n/, $content) {
        my ($name) = split /\s+/, $line;
        $mods{$name} = 1 if $name;
    }

    return \%mods;
}

sub module_available {
    my ($module, $kernel) = @_;
    my $base = "/lib/modules/$kernel";

    return 0 unless -d $base;

    my $cmd = "find " . shell_quote($base) . " -type f \\( " .
              "-name " . shell_quote("$module.ko") . " -o " .
              "-name " . shell_quote("$module.ko.xz") . " -o " .
              "-name " . shell_quote("$module.ko.zst") . " -o " .
              "-name " . shell_quote("$module.ko.gz") .
              " \\) 2>/dev/null | head -n 1";

    my $out = `$cmd`;
    chomp $out;

    return $out ne '' ? 1 : 0;
}

sub shell_quote {
    my ($s) = @_;
    $s =~ s/'/'"'"'/g;
    return "'$s'";
}

sub blacklist_text {
    my @dirs = qw(
        /etc/modprobe.d
        /run/modprobe.d
        /usr/lib/modprobe.d
        /lib/modprobe.d
    );

    my $text = '';

    for my $dir (@dirs) {
        next unless -d $dir;

        opendir my $dh, $dir or next;
        my @files = sort grep { /\.conf$/ } readdir $dh;
        closedir $dh;

        for my $file (@files) {
            $text .= "\n# $dir/$file\n";
            $text .= slurp("$dir/$file");
        }
    }

    return $text;
}

sub is_blacklisted {
    my ($module, $text) = @_;
    my $m = quotemeta($module);

    return 1 if $text =~ /^\s*blacklist\s+$m\s*(?:#.*)?$/m;
    return 1 if $text =~ /^\s*install\s+$m\s+\/(?:bin\/)?(?:true|false)\s*(?:#.*)?$/m;

    return 0;
}

my $kernel = `uname -r`;
chomp $kernel;

my $hostname = `hostname`;
chomp $hostname;

my $arch = `uname -m`;
chomp $arch;

my $distro = read_os_release();
my $loaded = loaded_modules();
my $blacklists = blacklist_text();

my @modules;
for my $module (@all_modules) {
    push @modules, {
        name        => $module,
        loaded      => $loaded->{$module} ? JSON::PP::true : JSON::PP::false,
        available   => module_available($module, $kernel) ? JSON::PP::true : JSON::PP::false,
        blacklisted => is_blacklisted($module, $blacklists) ? JSON::PP::true : JSON::PP::false,
    };
}

my @risk_notes;
my @mitigation_notes;

for my $m (@modules) {
    if ($m->{loaded}) {
        push @risk_notes, "$m->{name} is currently loaded";
    }
    if ($m->{available} && !$m->{blacklisted}) {
        push @mitigation_notes, "$m->{name} is available and not blacklisted";
    }
}

push @risk_notes, "No watched modules are loaded" unless @risk_notes;
push @mitigation_notes, "No unblacklisted watched modules found" unless @mitigation_notes;

my %report = (
    hostname         => $hostname,
    distro           => $distro,
    kernel_release   => $kernel,
    architecture     => $arch,
    modules          => \@modules,
    risk_notes       => \@risk_notes,
    mitigation_notes => \@mitigation_notes,
);

if ($json) {
    say encode_json(\%report);
    exit 0;
}

say "Dirty Frag / CopyFail defensive exposure check";
say "=" x 58;
say "Host:         $hostname";
say "Distro:       " . ($distro->{PRETTY_NAME} || $distro->{NAME} || "unknown");
say "Kernel:       $kernel";
say "Architecture: $arch";
say "";

printf "%-16s %-8s %-10s %-11s\n", "module", "loaded", "available", "blacklisted";
for my $m (@modules) {
    printf "%-16s %-8s %-10s %-11s\n",
        $m->{name},
        $m->{loaded} ? "true" : "false",
        $m->{available} ? "true" : "false",
        $m->{blacklisted} ? "true" : "false";
}

say "";
say "Risk notes:";
say "- $_" for @risk_notes;

say "";
say "Mitigation notes:";
say "- $_" for @mitigation_notes;
