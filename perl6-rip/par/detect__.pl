#!/usr/bin/perl
# ImplantDetector.pl - Security tool to detect system implants, ~~~under development~~~~
# For security training and purple team exercises

use strict;
use warnings;
use File::Find;
use File::Spec;
use Digest::SHA qw(sha256_hex);
use Term::ANSIColor;
use Net::DNS;
use LWP::UserAgent;
use JSON::XS;
use List::Util qw(any);

our $VERSION = '1.0.0';
our $SCAN_DEPTH = 4; # Default depth for recursive scans

# Locations commonly targeted by implants
our @CRITICAL_DIRS = (
    '/etc/init.d',
    '/etc/systemd/system',
    '/etc/cron.d',
    '/etc/cron.daily',
    '/etc/cron.hourly',
    '/var/spool/cron',
    '/usr/local/bin',
    '/tmp',
    '/var/tmp',
    '/dev/shm',
    '/lib/systemd/system',
    '/etc/profile.d',
    '/etc/bash_completion.d'
);

# Files that are often modified to achieve persistence
our @CRITICAL_FILES = (
    '/etc/rc.local',
    '/etc/passwd',
    '/etc/shadow',
    '/etc/ssh/sshd_config',
    '/etc/sudoers',
    '/etc/hosts',
    '/root/.ssh/authorized_keys',
    '/root/.bashrc',
    '/root/.bash_profile',
    '/etc/ld.so.preload'
);

# Patterns that might indicate malicious code
our @SUSPICIOUS_PATTERNS = (
    qr/base64_decode/i,
    qr/eval\(/i,
    qr/exec\(/i,
    qr/system\(/i,
    qr/netcat|nc -e|nc -l/i,
    qr/bash -i/i,
    qr/reverse shell/i,
    qr/python -c/i,
    qr/perl -e/i,
    qr/\/dev\/tcp\//i,
    qr/wget|curl.*\|.*sh/i,
    qr/chmod \+[xs]/i,
    qr/socat/i,
    qr/xterm -display/i,
    qr/backdoor|rootkit/i,
    qr/0\.0\.0\.0:4444/i,
    qr/mknod.*p.*\/bin\/sh/i,
    qr/msfvenom/i,
    qr/metasploit/i,
    qr/openssl.*enc/i,
    qr/\/tmp\/.*\.sh/i,
    qr/TOR|\.onion/i
);

# Known malicious processes
our @SUSPICIOUS_PROCESSES = (
    'nc',
    'netcat',
    'ncat',
    'socat',
    'cryptminer',
    'miner',
    'xmrig'
);

# Domain names often used for C2
our @SUSPICIOUS_DOMAINS = (
    'pastebin.com',
    'raw.githubusercontent.com',
    'ngrok.io',
    'dyndns.org'
);

# Main scanning subroutines
sub scan_system {
    print_banner();
    
    print colored(['bold green'], "\n[+] Starting comprehensive system scan\n");
    
    # Scan directories for suspicious files
    scan_critical_directories();
    
    # Check critical system files for modifications
    scan_critical_files();
    
    # Check for suspicious processes
    scan_running_processes();
    
    # Check for suspicious network connections
    scan_network_connections();
    
    # Look for unusual cron jobs
    scan_cron_jobs();
    
    # Scan for suspicious DNS queries
    scan_dns_cache();
    
    # Look for unusual users and groups
    scan_users_and_groups();
    
    # Check for kernel modules that might be rootkits
    scan_kernel_modules();
    
    print colored(['bold green'], "\n[+] Scan complete. Review the findings above.\n");
}

sub print_banner {
    print colored(['bold blue'], qq{
╔══════════════════════════════════════════════════════╗
║                  ImplantDetector                     ║
║        Security Tool for Finding Backdoors           ║
║                 Version: $VERSION                      ║
╚══════════════════════════════════════════════════════╝
});
}

sub scan_critical_directories {
    print colored(['bold yellow'], "\n[*] Scanning critical directories for suspicious files\n");
    
    foreach my $dir (@CRITICAL_DIRS) {
        next unless -d $dir;
        print "  → Checking $dir\n";
        
        find({
            wanted => \&check_suspicious_file,
            no_chdir => 1,
            bydepth => 0,
            preprocess => sub { 
                my @filtered = grep { $_ ne '.' && $_ ne '..' } @_; 
                @filtered[0..($SCAN_DEPTH-1)]; # Limit recursion depth
            },
        }, $dir);
    }
}

sub check_suspicious_file {
    my $file = $_;
    return unless -f $file;
    
    # Skip very large files
    my $size = -s $file;
    return if $size > 10_000_000; # Skip files > 10MB
    
    # Check file permissions
    my $mode = (stat($file))[2];
    my $is_executable = ($mode & 0111);
    
    # Check if it was modified recently
    my $mtime = (stat($file))[9];
    my $recent_modified = (time() - $mtime) < 86400 * 7; # 7 days
    
    # Calculate hash for known malware comparison (in a real tool)
    my $suspicious = 0;
    
    # Check file content for suspicious patterns
    if ($size < 1_000_000) { # Only scan files smaller than 1MB
        open my $fh, '<', $file or return;
        my $content = do { local $/; <$fh> };
        close $fh;
        
        foreach my $pattern (@SUSPICIOUS_PATTERNS) {
            if ($content =~ $pattern) {
                $suspicious = 1;
                report_suspicious_file($file, "Contains pattern: $pattern");
                last;
            }
        }
        
        # Special check for Perl files
        if ($file =~ /\.p[lm]$/ || $content =~ /^#!.*perl/) {
            check_perl_code($file, $content);
        }
        
        # Special check for shell scripts
        if ($file =~ /\.sh$/ || $content =~ /^#!/ && $content =~ /sh\s*$/) {
            check_shell_script($file, $content);
        }
    }
    
    # Also report based on permissions and modification time if in sensitive locations
    if (!$suspicious && $is_executable && $recent_modified) {
        if ($file =~ m{/(tmp|var/tmp|dev/shm)/} || 
            $file =~ /\.(sh|pl|py|rb)$/ || 
            -u $file || -g $file) {
            report_suspicious_file($file, "Recently modified executable in sensitive location");
        }
    }
}

sub report_suspicious_file {
    my ($file, $reason) = @_;
    print colored(['bold red'], "  [!] Suspicious file: $file\n");
    print colored(['red'], "      Reason: $reason\n");
    
    # Get file details
    my @stat = stat($file);
    my $mode = sprintf("%04o", $stat[2] & 07777);
    my $owner = getpwuid($stat[4]) || $stat[4];
    my $group = getgrgid($stat[5]) || $stat[5];
    my $size = $stat[7];
    my $mtime = scalar localtime($stat[9]);
    
    print "      Permissions: $mode (Owner: $owner, Group: $group)\n";
    print "      Size: $size bytes\n";
    print "      Last modified: $mtime\n";
}

sub check_perl_code {
    my ($file, $content) = @_;
    
    # Check for obfuscation techniques
    if ($content =~ /eval\s*\(\s*pack\s*\(/i ||
        $content =~ /eval\s*\(\s*decode_base64\s*\(/i ||
        $content =~ /\$[a-zA-Z0-9_]+\s*=\s*~\s*\$[a-zA-Z0-9_]+/i) {
        report_suspicious_file($file, "Contains obfuscated Perl code");
    }
    
    # Check for network indicators
    if ($content =~ /IO::Socket|Net::SSH|Net::Raw|LWP::UserAgent|HTTP::Tiny|fork|socket\(/i &&
        $content =~ /while\s*\(1\)|for\s*\(;;\)/i) {
        report_suspicious_file($file, "Contains persistent network code");
    }
}

sub check_shell_script {
    my ($file, $content) = @_;
    
    # Check for common backdoor techniques in shell scripts
    if ($content =~ /mkfifo|\/dev\/tcp\/|telnet|nc\s+.*\s+-e/) {
        report_suspicious_file($file, "Contains shell backdoor code");
    }
    
    # Check for stealth techniques
    if ($content =~ /unset\s+HISTFILE|HISTFILESIZE=0|HISTSIZE=0/) {
        report_suspicious_file($file, "Attempts to hide command history");
    }
}

sub scan_critical_files {
    print colored(['bold yellow'], "\n[*] Checking critical system files for modifications\n");
    
    foreach my $file (@CRITICAL_FILES) {
        next unless -f $file;
        
        my $mtime = (stat($file))[9];
        my $recent_modified = (time() - $mtime) < 86400 * 3; # 3 days
        
        if ($recent_modified) {
            print colored(['bold red'], "  [!] Recently modified critical file: $file\n");
            print "      Last modified: " . scalar localtime($mtime) . "\n";
            
            # For small text files, show diff with backup if available
            if (-f "$file.bak" && -s $file < 100000) {
                print "      Differences from backup:\n";
                system("diff -u '$file.bak' '$file' | tail -n 20");
            }
        } else {
            print "  → Checked $file (not recently modified)\n";
        }
    }
}

sub scan_running_processes {
    print colored(['bold yellow'], "\n[*] Scanning for suspicious processes\n");
    
    # Get list of running processes
    open my $ps_fh, '-|', 'ps aux' or do {
        print colored(['red'], "  [!] Failed to run 'ps' command: $!\n");
        return;
    };
    
    while (my $line = <$ps_fh>) {
        foreach my $proc (@SUSPICIOUS_PROCESSES) {
            if ($line =~ /\b$proc\b/) {
                print colored(['bold red'], "  [!] Suspicious process found:\n");
                print colored(['red'], "      $line");
            }
        }
        
        # Look for strange paths or command lines
        if ($line =~ m{(/tmp|/dev/shm|/var/tmp)/\S+} ||
            $line =~ /bash -i/ ||
            $line =~ /perl -e/ ||
            $line =~ /python -c/) {
            print colored(['bold red'], "  [!] Process with suspicious command line:\n");
            print colored(['red'], "      $line");
        }
    }
    close $ps_fh;
}

sub scan_network_connections {
    print colored(['bold yellow'], "\n[*] Checking for suspicious network connections\n");
    
    # Get list of network connections
    open my $netstat_fh, '-|', 'netstat -tuapn 2>/dev/null' or do {
        print colored(['red'], "  [!] Failed to run 'netstat' command: $!\n");
        return;
    };
    
    my %known_ports = (
        22 => 'SSH',
        80 => 'HTTP',
        443 => 'HTTPS',
        25 => 'SMTP',
        53 => 'DNS',
    );
    
    while (my $line = <$netstat_fh>) {
        # Skip header lines
        next if $line =~ /^(Active|Proto)/;
        
        # Check for unusual listening ports
        if ($line =~ /LISTEN/) {
            my @parts = split(/\s+/, $line);
            my ($ip, $port) = split(/:/, $parts[3]);
            $port = 0 unless defined $port;
            
            # If it's not a common port and it's listening for external connections
            if (!exists $known_ports{$port} && $ip =~ /^(0\.0\.0\.0|::)$/) {
                print colored(['bold red'], "  [!] Unusual listening port detected:\n");
                print colored(['red'], "      $line");
            }
        }
        
        # Check for outbound connections to unusual destinations
        if ($line =~ /ESTABLISHED/) {
            my @parts = split(/\s+/, $line);
            my ($local_ip, $local_port) = split(/:/, $parts[3]);
            my ($remote_ip, $remote_port) = split(/:/, $parts[4]);
            
            # Check for connections to unusual ports
            if ($remote_port && $remote_port =~ /^(4444|1337|31337|8080|8443)$/) {
                print colored(['bold red'], "  [!] Connection to suspicious port detected:\n");
                print colored(['red'], "      $line");
            }
        }
    }
    close $netstat_fh;
}

sub scan_cron_jobs {
    print colored(['bold yellow'], "\n[*] Scanning cron jobs for unusual entries\n");
    
    # Check system-wide cron directories
    foreach my $dir ('/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.monthly', '/etc/cron.weekly') {
        next unless -d $dir;
        print "  → Checking $dir\n";
        
        opendir(my $dh, $dir) or next;
        while (my $file = readdir($dh)) {
            next if $file =~ /^\.\.?$/;
            my $path = "$dir/$file";
            next unless -f $path;
            
            open my $fh, '<', $path or next;
            my $content = do { local $/; <$fh> };
            close $fh;
            
            # Check for suspicious commands
            foreach my $pattern (@SUSPICIOUS_PATTERNS) {
                if ($content =~ $pattern) {
                    print colored(['bold red'], "  [!] Suspicious cron job in $path:\n");
                    print colored(['red'], "      Contains pattern: $pattern\n");
                    # Show the relevant line
                    my @lines = split(/\n/, $content);
                    foreach my $line (@lines) {
                        if ($line =~ $pattern) {
                            print "      $line\n";
                        }
                    }
                    last;
                }
            }
        }
        closedir($dh);
    }
    
    # Check user crontabs if we have permission
    if (-r '/var/spool/cron') {
        print "  → Checking user crontabs\n";
        find({
            wanted => sub {
                return unless -f $_;
                open my $fh, '<', $_ or return;
                my $content = do { local $/; <$fh> };
                close $fh;
                
                foreach my $pattern (@SUSPICIOUS_PATTERNS) {
                    if ($content =~ $pattern) {
                        print colored(['bold red'], "  [!] Suspicious user crontab in $_:\n");
                        print colored(['red'], "      Contains pattern: $pattern\n");
                        last;
                    }
                }
            },
            no_chdir => 1,
        }, '/var/spool/cron');
    }
}

sub scan_dns_cache {
    print colored(['bold yellow'], "\n[*] Checking for suspicious DNS queries\n");
    
    # Try to access the DNS cache
    my $has_nscd = 0;
    foreach my $cmd ('nscd -g', 'rndc dumpdb -cache', 'killall -USR1 systemd-resolved') {
        system("$cmd >/dev/null 2>&1");
        $has_nscd = 1 if $? == 0;
    }
    
    if (!$has_nscd) {
        print "  → Unable to access DNS cache directly\n";
        
        # Try to check recent DNS lookups via dnsmasq logs
        if (-r '/var/log/dnsmasq.log') {
            print "  → Checking dnsmasq logs for unusual domains\n";
            open my $log_fh, '<', '/var/log/dnsmasq.log' or return;
            while (my $line = <$log_fh>) {
                foreach my $domain (@SUSPICIOUS_DOMAINS) {
                    if ($line =~ /query\[\w+\]\s+(\S+)\s+from/ && $1 =~ /$domain/) {
                        print colored(['bold red'], "  [!] Query for suspicious domain: $1\n");
                        print colored(['red'], "      $line");
                    }
                }
            }
            close $log_fh;
        }
    }
    
    # Try to actively resolve some domains to check for DNS hijacking
    print "  → Checking for DNS hijacking\n";
    my $dns = Net::DNS::Resolver->new;
    my @test_domains = ('google.com', 'microsoft.com', 'cloudflare.com');
    
    foreach my $domain (@test_domains) {
        my $query = $dns->search($domain);
        if ($query) {
            foreach my $rr ($query->answer) {
                next unless $rr->type eq 'A';
                my $ip = $rr->address;
                if ($ip =~ /^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/ && 
                    !($domain =~ /local$/)) {
                    print colored(['bold red'], "  [!] Potential DNS hijacking detected!\n");
                    print colored(['red'], "      $domain resolves to private IP $ip\n");
                }
            }
        }
    }
}

sub scan_users_and_groups {
    print colored(['bold yellow'], "\n[*] Scanning for unusual users and groups\n");
    
    # Check /etc/passwd for unusual users
    open my $passwd_fh, '<', '/etc/passwd' or do {
        print colored(['red'], "  [!] Failed to open /etc/passwd: $!\n");
        return;
    };
    
    while (my $line = <$passwd_fh>) {
        chomp $line;
        my @fields = split(/:/, $line);
        
        # Check for users with UID 0 other than root
        if ($fields[2] == 0 && $fields[0] ne 'root') {
            print colored(['bold red'], "  [!] User with UID 0 (root) detected: $fields[0]\n");
        }
        
        # Check for users with unusual shells
        if ($fields[6] && $fields[6] =~ /\b(python|perl|ruby|bash -i|nc|ncat|netcat)\b/) {
            print colored(['bold red'], "  [!] User with suspicious shell: $fields[0]\n");
            print colored(['red'], "      Shell: $fields[6]\n");
        }
        
        # Check for recently added users
        my $home = $fields[5];
        if (-d $home && (time() - (stat($home))[9]) < 86400 * 7) {
            print colored(['yellow'], "  [*] Recently created user home directory: $fields[0]\n");
            print "      Home: $home\n";
        }
    }
    close $passwd_fh;
    
    # Check sudoers files
    if (-r '/etc/sudoers') {
        print "  → Checking sudoers configuration\n";
        open my $sudo_fh, '-|', 'cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null' or return;
        while (my $line = <$sudo_fh>) {
            # Look for ALL=(ALL) NOPASSWD: ALL
            if ($line =~ /\bALL\s*=\s*\(\s*ALL\s*\)\s*NOPASSWD\s*:\s*ALL\b/ && 
                $line !~ /^#/ && $line !~ /\b(root|wheel|sudo)\b/) {
                print colored(['bold red'], "  [!] Dangerous sudo configuration detected:\n");
                print colored(['red'], "      $line");
            }
        }
        close $sudo_fh;
    }
}

sub scan_kernel_modules {
    print colored(['bold yellow'], "\n[*] Checking for suspicious kernel modules\n");
    
    # Get the list of loaded kernel modules
    open my $lsmod_fh, '-|', 'lsmod' or do {
        print colored(['red'], "  [!] Failed to run 'lsmod' command: $!\n");
        return;
    };
    
    # Skip the header line
    <$lsmod_fh>;
    
    while (my $line = <$lsmod_fh>) {
        my @fields = split(/\s+/, $line);
        my $module_name = $fields[0];
        
        # Check if the module has a file on disk
        my $module_file = "/lib/modules/$(uname -r)/kernel/$module_name.ko";
        if (!-f $module_file && !-f "/lib/modules/$(uname -r)/extra/$module_name.ko") {
            print colored(['bold red'], "  [!] Kernel module with no file on disk: $module_name\n");
        }
        
        # Check for suspicious module names
        if ($module_name =~ /hide|intercept|hook|rootkit|hide/) {
            print colored(['bold red'], "  [!] Suspicious kernel module name: $module_name\n");
        }
    }
    close $lsmod_fh;
    
    # Check for signs of rootkits
    print "  → Running rootkit checks\n";
    
    # Check for /dev/tcp redirection in startup scripts
    system("grep -r '/dev/tcp' /etc 2>/dev/null | grep -v '^Binary'");
    
    # Check for preloaded libraries
    if (-f '/etc/ld.so.preload') {
        print colored(['bold red'], "  [!] /etc/ld.so.preload exists - this is often used by rootkits\n");
        system("cat /etc/ld.so.preload");
    }
}

# Run the scanner
scan_system();

__END__

=head1 NAME

ImplantDetector - A security tool for finding backdoors and implants

=head1 SYNOPSIS

./implant_detector [options]

Options:
  --help        Display this help message
  --depth=N     Set scan depth for recursive directory searches (default: 4)
  --fast        Perform a quick scan of only the most critical locations
  --thorough    Perform an intensive scan (may take longer)
  --report=FILE Save findings to a report file

=head1 DESCRIPTION

ImplantDetector is a security tool designed to locate potential backdoors, 
implants, and other malicious code on Linux systems. It scans common locations
where attackers might leave persistence mechanisms and checks for suspicious 
patterns that could indicate malicious activity.

=head1 AUTHOR

Security Training Familia Beta Mode Edition

=cut
