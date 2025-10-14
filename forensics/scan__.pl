#!/usr/bin/env perl
#
# Linux Persistence & Backdoor Detection Tool
# Advanced Perl implementation with improved detection capabilities
# Version: 2.0.0
#
use strict;
use warnings;
use v5.20;
use Getopt::Long qw(:config no_ignore_case bundling);
use Pod::Usage;
use JSON::PP;
use File::Find;
use File::Spec;
use File::Basename;
use POSIX qw(strftime getuid);
use Term::ANSIColor qw(colored);
use Data::Dumper;
use Time::HiRes qw(gettimeofday tv_interval);

# Constants and configuration
our $VERSION = "2.0.0";
our $SCRIPT_NAME = "Linux Persistence Hunter";
our $TIMESTAMP = strftime("%Y-%m-%d_%H-%M-%S", localtime);
our $LOGDIR = "/var/log/persist_hunter";
our $LOGFILE = "$LOGDIR/scan_$TIMESTAMP.log";
our $JSON_OUTPUT = "$LOGDIR/scan_$TIMESTAMP.json";

# Global state
our %CONFIG = (
    verbose => 0,
    json_export => 0,
    safe_mode => 1,
    max_depth => 3,
    timeout => 300,
    parallel => 1,
);

our @FINDINGS = ();
our %STATS = (
    files_scanned => 0,
    start_time => [gettimeofday],
    findings_by_severity => {},
);

# Check modules configuration
our %CHECKS = (
    processes => 1,
    cron => 1,
    shells => 1,
    suid => 1,
    ssh => 1,
    users => 1,
    services => 1,
    network => 1,
    temp => 1,
    integrity => 1,
    modules => 1,
    capabilities => 1,
    preload => 1,
    docker => 1,
    yara => 1,
    timeline => 1,
    hidden => 1,
    webshells => 1,
    packages => 1,
    writable => 1,
    # New checks
    environment => 1,
    logs => 1,
    memory => 1,
    startup => 1,
    databases => 1,
);

# Threat intelligence patterns
our %THREAT_PATTERNS = (
    webshells => [
        qr/eval\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)/i,
        qr/base64_decode\s*\(\s*\$_/i,
        qr/system\s*\(\s*\$_/i,
        qr/exec\s*\(\s*\$_/i,
        qr/passthru\s*\(\s*\$_/i,
        qr/shell_exec\s*\(\s*\$_/i,
        qr/assert\s*\(\s*\$_/i,
        qr/preg_replace.*\/e/i,
        qr/create_function/i,
        qr/file_get_contents.*php:\/\/input/i,
    ],
    reverse_shells => [
        qr/\/bin\/(?:ba)?sh\s+-i/,
        qr/nc\s+.*-e\s*\/bin/i,
        qr/ncat\s+.*-e/i,
        qr/socat.*exec/i,
        qr/python.*pty\.spawn/i,
        qr/perl.*socket/i,
        qr/ruby.*socket/i,
        qr/\/dev\/tcp\//,
        qr/bash.*>&/,
    ],
    suspicious_commands => [
        qr/curl.*\|\s*(?:bash|sh|python)/i,
        qr/wget.*-O-.*\|\s*(?:bash|sh)/i,
        qr/echo.*base64.*decode/i,
        qr/dd.*\/dev\/.*\|\s*nc/i,
        qr/mkfifo.*nc/i,
        qr/telnet.*\|\s*\/bin/i,
    ],
    crypto_miners => [
        qr/xmrig/i,
        qr/minergate/i,
        qr/cryptonight/i,
        qr/stratum\+tcp/i,
        qr/mining\.pool/i,
        qr/--donate-level/i,
    ],
    persistence_locations => [
        qr/\/etc\/rc\.local/,
        qr/\/etc\/init\.d\//,
        qr/\/etc\/systemd\/system\//,
        qr/\/etc\/cron/,
        qr/\/var\/spool\/cron/,
        qr/\.bash_profile/,
        qr/\.bashrc/,
        qr/\.profile/,
    ],
);

# Known good SUID binaries by distribution
our %KNOWN_SUID_BINARIES = (
    common => [qw(
        /usr/bin/sudo /usr/bin/passwd /usr/bin/chsh /usr/bin/chfn
        /usr/bin/newgrp /usr/bin/su /usr/bin/mount /usr/bin/umount
        /usr/bin/pkexec /bin/su /bin/mount /bin/umount /bin/ping
        /usr/bin/gpasswd /usr/bin/wall /usr/sbin/unix_chkpwd
    )],
    debian => [qw(
        /usr/lib/dbus-1.0/dbus-daemon-launch-helper
        /usr/lib/openssh/ssh-keysign /usr/bin/at
    )],
    rhel => [qw(
        /usr/libexec/dbus-1/dbus-daemon-launch-helper
        /usr/sbin/usernetctl /usr/sbin/userhelper
    )],
);

# Common backdoor ports
our @BACKDOOR_PORTS = qw(
    4444 4445 5555 6666 7777 8888 9999 31337 12345
    1234 2222 3333 8080 9090 10000 65535
);

#==============================================================================
# UTILITY FUNCTIONS
#==============================================================================

sub init_logging {
    system("mkdir -p '$LOGDIR'") unless -d $LOGDIR;
    open(my $fh, '>', $LOGFILE) or die "Cannot create log file: $!";
    close($fh);
}

sub log_msg {
    my ($level, $msg, $path) = @_;
    $path //= 'N/A';
    
    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
    my $log_line = "[$timestamp] [$level] $msg";
    $log_line .= " ($path)" if $path ne 'N/A';
    
    # Append to log file
    open(my $fh, '>>', $LOGFILE) or warn "Cannot write to log: $!";
    print $fh "$log_line\n" if $fh;
    close($fh) if $fh;
    
    # Console output with colors
    my $colored_msg = $msg;
    $colored_msg .= " ($path)" if $path ne 'N/A';
    
    given ($level) {
        when ('CRITICAL') { say colored(['bold red'], "[⚠] $colored_msg") }
        when ('HIGH')     { say colored(['red'], "[!] $colored_msg") }
        when ('MEDIUM')   { say colored(['yellow'], "[!] $colored_msg") }
        when ('LOW')      { say colored(['cyan'], "[*] $colored_msg") }
        when ('INFO')     { say colored(['green'], "[✓] $colored_msg") }
        default           { say colored(['white'], "[*] $colored_msg") }
    }
}

sub add_finding {
    my ($category, $severity, $description, $path, $extra_data) = @_;
    $path //= 'N/A';
    $extra_data //= {};
    
    my $finding = {
        timestamp => time(),
        category => $category,
        severity => $severity,
        description => $description,
        path => $path,
        hostname => `hostname`,
        %$extra_data
    };
    
    chomp($finding->{hostname});
    push @FINDINGS, $finding;
    
    $STATS{findings_by_severity}{$severity}++;
    log_msg($severity, $description, $path);
}

sub section_header {
    my $title = shift;
    my $line = "━" x 60;
    say colored(['bold blue'], "\n$line");
    say colored(['bold blue'], "▶ $title");
    say colored(['bold blue'], "$line");
}

sub show_banner {
    say colored(['cyan'], <<'EOF');
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   █░░ █ █▄░█ █░█ ▀▄▀   █▀█ █▀▀ █▀█ █▀ █ █▀ ▀█▀ █▀▀ █▀█   ║
║   █▄▄ █ █░▀█ █▄█ █░█   █▀▀ ██▄ █▀▄ ▄█ █ ▄█ ░█░ ██▄ █▀▄   ║
║                                                           ║
║                  █░█ █░█ █▄░█ ▀█▀ █▀▀ █▀█                 ║
║                  █▀█ █▄█ █░▀█ ░█░ ██▄ █▀▄                 ║
║                                                           ║
║                      PERL EDITION                        ║
╚═══════════════════════════════════════════════════════════╝
EOF
    say colored(['blue'], "Version: $VERSION");
    say colored(['blue'], "Scan started: " . strftime("%Y-%m-%d %H:%M:%S %Z", localtime));
    say colored(['blue'], "Hostname: " . `hostname`);
}

sub detect_distro {
    return 'unknown' unless -f '/etc/os-release';
    
    open(my $fh, '<', '/etc/os-release') or return 'unknown';
    my %os_info;
    
    while (my $line = <$fh>) {
        chomp $line;
        next unless $line =~ /^(\w+)=(.*)$/;
        my ($key, $value) = ($1, $2);
        $value =~ s/^"(.*)"$/$1/;  # Remove quotes
        $os_info{$key} = $value;
    }
    close($fh);
    
    return lc($os_info{ID} // 'unknown');
}

sub require_root {
    if (getuid() != 0) {
        die colored(['red'], "This script must be run as root\n");
    }
}

sub get_command_output {
    my ($cmd, $timeout) = @_;
    $timeout //= 30;
    
    local $SIG{ALRM} = sub { die "Command timeout: $cmd\n" };
    alarm($timeout);
    
    my $output = eval { `$cmd 2>/dev/null` };
    alarm(0);
    
    if ($@) {
        warn "Command failed or timed out: $cmd\n" if $CONFIG{verbose};
        return '';
    }
    
    return $output // '';
}

sub scan_file_content {
    my ($file, $patterns) = @_;
    return () unless -f $file && -r $file;
    
    my @matches;
    open(my $fh, '<', $file) or return ();
    
    my $line_num = 0;
    while (my $line = <$fh>) {
        $line_num++;
        chomp $line;
        
        for my $pattern (@$patterns) {
            if ($line =~ /$pattern/) {
                push @matches, {
                    line => $line_num,
                    content => $line,
                    pattern => $pattern
                };
            }
        }
        
        last if $line_num > 1000; # Prevent huge file scanning
    }
    close($fh);
    
    $STATS{files_scanned}++;
    return @matches;
}

sub is_binary_suspicious {
    my $file = shift;
    return 0 unless -f $file;
    
    # Check if it's a known system binary
    my @system_paths = qw(/bin /sbin /usr/bin /usr/sbin /usr/local/bin);
    my $in_system_path = grep { index($file, $_) == 0 } @system_paths;
    
    # Check file metadata
    my @stat = stat($file);
    return 0 unless @stat;
    
    my ($size, $mtime, $mode) = @stat[7, 9, 2];
    
    # Suspicious indicators
    my $recently_modified = (time() - $mtime) < (7 * 24 * 3600); # 7 days
    my $unusual_permissions = ($mode & 07777) == 0777; # World writable/executable
    my $small_size = $size < 100; # Suspiciously small
    my $large_size = $size > 10_000_000; # Suspiciously large (10MB+)
    
    return $recently_modified || $unusual_permissions || 
           ($small_size && $in_system_path) || $large_size;
}

#==============================================================================
# CORE DETECTION MODULES
#==============================================================================

sub check_processes {
    section_header("Process Analysis");
    
    my $ps_output = get_command_output('ps aux --no-headers');
    return unless $ps_output;
    
    my @suspicious_found;
    
    for my $line (split /\n/, $ps_output) {
        next unless $line;
        my @fields = split /\s+/, $line, 11;
        next unless @fields >= 11;
        
        my ($user, $pid, $cmd) = @fields[0, 1, 10];
        
        # Check against reverse shell patterns
        for my $pattern (@{$THREAT_PATTERNS{reverse_shells}}) {
            if ($cmd =~ /$pattern/) {
                add_finding('processes', 'CRITICAL', 
                    "Reverse shell process detected", "PID:$pid CMD:$cmd",
                    { user => $user, pid => $pid });
                push @suspicious_found, $pid;
            }
        }
        
        # Check for crypto miners
        for my $pattern (@{$THREAT_PATTERNS{crypto_miners}}) {
            if ($cmd =~ /$pattern/) {
                add_finding('processes', 'HIGH',
                    "Crypto mining process detected", "PID:$pid CMD:$cmd",
                    { user => $user, pid => $pid });
            }
        }
        
        # Check for suspicious commands
        for my $pattern (@{$THREAT_PATTERNS{suspicious_commands}}) {
            if ($cmd =~ /$pattern/) {
                add_finding('processes', 'MEDIUM',
                    "Suspicious command detected", "PID:$pid CMD:$cmd",
                    { user => $user, pid => $pid });
            }
        }
    }
    
    # Process hiding detection
    my $proc_count = scalar(glob('/proc/[0-9]*'));
    my $ps_count = split(/\n/, $ps_output);
    
    if (abs($proc_count - $ps_count) > 15) {
        add_finding('processes', 'HIGH',
            "Process hiding detected (count mismatch)",
            "/proc count: $proc_count, ps count: $ps_count");
    }
    
    # Check for processes with unusual parent relationships
    my $ps_tree = get_command_output('ps axfo pid,ppid,command');
    if ($ps_tree) {
        check_process_relationships($ps_tree);
    }
    
    log_msg('INFO', "Process analysis complete");
}

sub check_process_relationships {
    my $ps_tree = shift;
    
    # Look for processes that should have init as parent but don't
    for my $line (split /\n/, $ps_tree) {
        next unless $line =~ /^\s*(\d+)\s+(\d+)\s+(.*)/;
        my ($pid, $ppid, $cmd) = ($1, $2, $3);
        
        # Suspicious: systemd/networking processes not parented by init
        if ($cmd =~ /systemd|network|ssh/ && $ppid != 1 && $ppid > 10) {
            add_finding('processes', 'MEDIUM',
                "Suspicious process parentage", "PID:$pid PPID:$ppid CMD:$cmd");
        }
    }
}

sub check_cron {
    section_header("Cron Jobs Analysis");
    
    # System crontab
    if (-f '/etc/crontab') {
        my @matches = scan_file_content('/etc/crontab', [
            @{$THREAT_PATTERNS{reverse_shells}},
            @{$THREAT_PATTERNS{suspicious_commands}}
        ]);
        
        for my $match (@matches) {
            add_finding('cron', 'HIGH',
                "Suspicious entry in system crontab",
                "/etc/crontab:$match->{line}",
                { content => $match->{content} });
        }
    }
    
    # User crontabs
    my @users = map { (split /:/)[0] } split /\n/, 
                get_command_output('getent passwd');
    
    for my $user (@users) {
        my $cron_output = get_command_output("crontab -u $user -l");
        next unless $cron_output;
        
        for my $line (split /\n/, $cron_output) {
            next if $line =~ /^#/ || $line =~ /^\s*$/;
            
            for my $pattern (@{$THREAT_PATTERNS{suspicious_commands}}) {
                if ($line =~ /$pattern/) {
                    add_finding('cron', 'HIGH',
                        "Suspicious cron job for user $user",
                        "crontab:$user", { content => $line });
                }
            }
        }
    }
    
    # Cron directories
    my @cron_dirs = qw(/etc/cron.d /etc/cron.daily /etc/cron.hourly 
                      /etc/cron.weekly /etc/cron.monthly);
    
    for my $dir (@cron_dirs) {
        next unless -d $dir;
        
        find(sub {
            return unless -f $_;
            my @matches = scan_file_content($File::Find::name, [
                @{$THREAT_PATTERNS{reverse_shells}},
                @{$THREAT_PATTERNS{suspicious_commands}}
            ]);
            
            for my $match (@matches) {
                add_finding('cron', 'HIGH',
                    "Suspicious cron script", $File::Find::name,
                    { line => $match->{line}, content => $match->{content} });
            }
        }, $dir);
    }
    
    log_msg('INFO', "Cron analysis complete");
}

sub check_shells {
    section_header("Shell Configuration Analysis");
    
    my @shell_files = qw(
        /etc/profile /etc/bash.bashrc /etc/bashrc
        /root/.bashrc /root/.bash_profile /root/.profile
        /root/.zshrc /root/.cshrc /root/.tcshrc
    );
    
    # Add user shell files
    my @users_dirs = glob('/home/*');
    for my $dir (@users_dirs) {
        next unless -d $dir;
        push @shell_files, map { "$dir/$_" } 
            qw(.bashrc .bash_profile .profile .zshrc .cshrc .tcshrc);
    }
    
    for my $file (@shell_files) {
        next unless -f $file;
        
        my @matches = scan_file_content($file, [
            @{$THREAT_PATTERNS{reverse_shells}},
            @{$THREAT_PATTERNS{suspicious_commands}}
        ]);
        
        for my $match (@matches) {
            add_finding('shells', 'CRITICAL',
                "Backdoor detected in shell configuration",
                "$file:$match->{line}",
                { content => $match->{content} });
        }
        
        # Check for alias backdoors
        open(my $fh, '<', $file) or next;
        my $line_num = 0;
        while (my $line = <$fh>) {
            $line_num++;
            chomp $line;
            
            if ($line =~ /alias\s+(\w+)=.*(?:nc|bash|sh).*-/) {
                add_finding('shells', 'HIGH',
                    "Suspicious alias definition", "$file:$line_num",
                    { content => $line });
            }
        }
        close($fh);
    }
    
    log_msg('INFO', "Shell configuration analysis complete");
}

sub check_suid {
    section_header("SUID/SGID Binary Analysis");
    
    my $distro = detect_distro();
    my @known_good = (
        @{$KNOWN_SUID_BINARIES{common}},
        @{$KNOWN_SUID_BINARIES{$distro} // []}
    );
    
    my %known_good_hash = map { $_ => 1 } @known_good;
    
    # Find SUID/SGID binaries
    my $find_output = get_command_output('find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null');
    
    for my $binary (split /\n/, $find_output) {
        next unless $binary && -f $binary;
        
        unless ($known_good_hash{$binary}) {
            my @stat = stat($binary);
            my $mode = sprintf("%04o", $stat[2] & 07777) if @stat;
            
            add_finding('suid', 'HIGH',
                "Unusual SUID/SGID binary detected", $binary,
                { permissions => $mode });
            
            # Extra scrutiny for shells
            if ($binary =~ /sh$/ || basename($binary) =~ /^(bash|zsh|csh|tcsh|ksh)$/) {
                add_finding('suid', 'CRITICAL',
                    "SUID shell detected", $binary);
            }
        }
        
        # Check if binary is suspicious
        if (is_binary_suspicious($binary)) {
            add_finding('suid', 'MEDIUM',
                "Suspicious SUID binary characteristics", $binary);
        }
    }
    
    log_msg('INFO', "SUID/SGID analysis complete");
}

sub check_ssh {
    section_header("SSH Configuration Analysis");
    
    # Authorized keys
    my @auth_key_locations = qw(/root/.ssh/authorized_keys);
    push @auth_key_locations, glob('/home/*/.ssh/authorized_keys');
    
    for my $keyfile (@auth_key_locations) {
        next unless -f $keyfile;
        
        open(my $fh, '<', $keyfile) or next;
        my $line_num = 0;
        my $key_count = 0;
        
        while (my $line = <$fh>) {
            $line_num++;
            chomp $line;
            next if $line =~ /^\s*#/ || $line =~ /^\s*$/;
            
            if ($line =~ /^ssh-\w+/) {
                $key_count++;
                
                # Check for suspicious key comments or unusual key types
                if ($line =~ /root@|admin@|hacker@|backdoor/i) {
                    add_finding('ssh', 'HIGH',
                        "Suspicious SSH key comment", "$keyfile:$line_num",
                        { content => substr($line, 0, 100) });
                }
                
                # Check for keys with command restrictions that might be backdoors
                if ($line =~ /command="([^"]*)"/ && $1 =~ /nc|bash|sh/i) {
                    add_finding('ssh', 'CRITICAL',
                        "SSH key with backdoor command", "$keyfile:$line_num",
                        { command => $1 });
                }
            }
        }
        close($fh);
        
        if ($key_count > 0) {
            add_finding('ssh', 'INFO',
                "SSH authorized keys found", "$keyfile ($key_count keys)");
        }
    }
    
    # SSH daemon configuration
    if (-f '/etc/ssh/sshd_config') {
        my @matches = scan_file_content('/etc/ssh/sshd_config', [
            qr/^PermitRootLogin\s+yes/i,
            qr/^PasswordAuthentication\s+yes/i,
            qr/^PermitEmptyPasswords\s+yes/i,
            qr/^AllowUsers\s+.*(?:root|admin)/i,
        ]);
        
        for my $match (@matches) {
            add_finding('ssh', 'MEDIUM',
                "Potentially insecure SSH configuration",
                "/etc/ssh/sshd_config:$match->{line}",
                { content => $match->{content} });
        }
    }
    
    # Check for SSH host keys in unusual locations
    find(sub {
        return unless /ssh_host_.*_key$/;
        return if $File::Find::dir =~ m{^/etc/ssh};
        
        add_finding('ssh', 'MEDIUM',
            "SSH host key in unusual location", $File::Find::name);
    }, '/');
    
    log_msg('INFO', "SSH analysis complete");
}

sub check_users {
    section_header("User Account Analysis");
    
    # Parse passwd file
    open(my $fh, '<', '/etc/passwd') or return;
    while (my $line = <$fh>) {
        chomp $line;
        my ($user, $x, $uid, $gid, $gecos, $home, $shell) = split /:/, $line;
        
        # UID 0 accounts that aren't root
        if ($uid == 0 && $user ne 'root') {
            add_finding('users', 'CRITICAL',
                "Non-root account with UID 0", $user);
        }
        
        # Service accounts with shells
        if ($uid < 1000 && $uid != 0 && $shell =~ m{/(bash|sh|zsh|csh|tcsh|ksh|fish)$}) {
            add_finding('users', 'MEDIUM',
                "Service account with interactive shell", 
                "$user (UID:$uid, shell:$shell)");
        }
        
        # Accounts with unusual home directories
        if ($home && $home =~ m{^/(tmp|var/tmp|dev/shm)/}) {
            add_finding('users', 'HIGH',
                "User account with suspicious home directory", 
                "$user (home:$home)");
        }
    }
    close($fh);
    
    # Check shadow file for empty passwords
    if (-r '/etc/shadow') {
        open($fh, '<', '/etc/shadow') or return;
        while (my $line = <$fh>) {
            chomp $line;
            my ($user, $passwd) = split /:/, $line, 3;
            
            if (defined $passwd && $passwd eq '') {
                add_finding('users', 'HIGH',
                    "User account with empty password", $user);
            }
        }
        close($fh);
    }
    
    # Check for recently created accounts
    my $lastlog_output = get_command_output('lastlog -t 7');
    if ($lastlog_output) {
        for my $line (split /\n/, $lastlog_output) {
            next unless $line =~ /Never logged in/;
            next if $line =~ /^(daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody)/;
            
            my ($user) = $line =~ /^(\S+)/;
            if ($user) {
                add_finding('users', 'LOW',
                    "Recently created account that never logged in", $user);
            }
        }
    }
    
    log_msg('INFO', "User account analysis complete");
}

sub check_services {
    section_header("Service Analysis");
    
    # Systemd services
    if (-x '/bin/systemctl' || -x '/usr/bin/systemctl') {
        my $services_output = get_command_output('systemctl list-unit-files --type=service --state=enabled --no-pager');
        
        for my $line (split /\n/, $services_output) {
            next unless $line =~ /^(\S+\.service)\s+enabled/;
            my $service = $1;
            
            # Skip well-known services
            next if $service =~ /^(getty|systemd|dbus|network|rsyslog|cron|ssh|apache|nginx|mysql|postgresql)/;
            
            my $service_file = find_systemd_service_file($service);
            if ($service_file && -f $service_file) {
                my @matches = scan_file_content($service_file, [
                    @{$THREAT_PATTERNS{reverse_shells}},
                    @{$THREAT_PATTERNS{suspicious_commands}}
                ]);
                
                for my $match (@matches) {
                    add_finding('services', 'CRITICAL',
                        "Suspicious systemd service", $service_file,
                        { service => $service, line => $match->{line}, 
                          content => $match->{content} });
                }
                
                # Check for unusual service configurations
                open(my $fh, '<', $service_file) or next;
                while (my $line = <$fh>) {
                    chomp $line;
                    
                    # Services running as root unnecessarily
                    if ($line =~ /User=root/ && $service !~ /ssh|apache|nginx/) {
                        add_finding('services', 'LOW',
                            "Service unnecessarily running as root", $service);
                    }
                    
                    # Services with network access
                    if ($line =~ /ExecStart=.*(?:nc|ncat|socat|curl|wget)/) {
                        add_finding('services', 'MEDIUM',
                            "Service with network tools in ExecStart", $service);
                    }
                }
                close($fh);
            }
        }
    }
    
    # Init.d services (legacy)
    if (-d '/etc/init.d') {
        find(sub {
            return unless -f $_ && -x $_;
            
            my @matches = scan_file_content($File::Find::name, [
                @{$THREAT_PATTERNS{reverse_shells}},
                @{$THREAT_PATTERNS{suspicious_commands}}
            ]);
            
            for my $match (@matches) {
                add_finding('services', 'HIGH',
                    "Suspicious init.d script", $File::Find::name,
                    { line => $match->{line}, content => $match->{content} });
            }
        }, '/etc/init.d');
    }
    
    log_msg('INFO', "Service analysis complete");
}

sub find_systemd_service_file {
    my $service = shift;
    
    my @search_paths = qw(
        /etc/systemd/system
        /usr/lib/systemd/system
        /lib/systemd/system
    );
    
    for my $path (@search_paths) {
        my $full_path = "$path/$service";
        return $full_path if -f $full_path;
    }
    
    return undef;
}

sub check_network {
    section_header("Network Analysis");
    
    # Get listening ports
    my $netstat_output = get_command_output('ss -tulpn') || 
                        get_command_output('netstat -tulpn');
    
    return unless $netstat_output;
    
    # Check for backdoor ports
    for my $port (@BACKDOOR_PORTS) {
        if ($netstat_output =~ /:$port\s/) {
            add_finding('network', 'CRITICAL',
                "Known backdoor port listening", "Port $port");
        }
    }
    
    # Parse listening services
    for my $line (split /\n/, $netstat_output) {
        next unless $line =~ /LISTEN/;
        
        # Extract port and process info
        if ($line =~ /:(\d+)\s.*?(\S+)\s*$/) {
            my ($port, $process) = ($1, $2);
            
            # Unusual high ports
            if ($port > 49152 && $process !~ /sshd|systemd/) {
                add_finding('network', 'MEDIUM',
                    "Service listening on high port", "Port $port ($process)");
            }
            
            # Processes that shouldn't be listening
            if ($process =~ /(python|perl|ruby|nc|ncat|socat)/ && $port != 22) {
                add_finding('network', 'HIGH',
                    "Suspicious process listening on network", 
                    "Port $port ($process)");
            }
        }
    }
    
    # Check active connections for suspicious activity
    my $connections = get_command_output('ss -tupn') || 
                     get_command_output('netstat -tupn');
    
    if ($connections) {
        for my $line (split /\n/, $connections) {
            # Look for connections to suspicious ports or IPs
            if ($line =~ /ESTABLISHED.*:(\d+)\s/) {
                my $port = $1;
                if (grep { $_ == $port } @BACKDOOR_PORTS) {
                    add_finding('network', 'HIGH',
                        "Active connection to backdoor port", "Port $port");
                }
            }
        }
    }
    
    log_msg('INFO', "Network analysis complete");
}

sub check_startup {
    section_header("System Startup Analysis");
    
    # Check various startup locations
    my @startup_locations = (
        '/etc/rc.local',
        '/etc/rc.d/rc.local',
        glob('/etc/rc[0-6].d/*'),
        glob('/etc/init.d/*'),
    );
    
    for my $location (@startup_locations) {
        next unless -f $location && -x $location;
        
        my @matches = scan_file_content($location, [
            @{$THREAT_PATTERNS{reverse_shells}},
            @{$THREAT_PATTERNS{suspicious_commands}}
        ]);
        
        for my $match (@matches) {
            add_finding('startup', 'CRITICAL',
                "Malicious startup script detected", $location,
                { line => $match->{line}, content => $match->{content} });
        }
    }
    
    # Check for unusual entries in common startup files
    if (-f '/etc/rc.local') {
        open(my $fh, '<', '/etc/rc.local') or return;
        my $line_num = 0;
        while (my $line = <$fh>) {
            $line_num++;
            chomp $line;
            next if $line =~ /^\s*#/ || $line =~ /^\s*$/;
            next if $line =~ /exit\s+0/;
            
            # Any non-comment, non-empty line in rc.local is worth noting
            add_finding('startup', 'LOW',
                "Custom startup command in rc.local", "/etc/rc.local:$line_num",
                { content => $line });
        }
        close($fh);
    }
    
    log_msg('INFO', "Startup analysis complete");
}

sub check_webshells {
    section_header("Webshell Detection");
    
    my @web_directories = qw(
        /var/www /var/www/html /usr/share/nginx/html
        /srv/www /srv/http /opt/lampp/htdocs
        /home/*/public_html /home/*/www
    );
    
    # Expand globs
    @web_directories = map { glob($_) } @web_directories;
    @web_directories = grep { -d $_ } @web_directories;
    
    for my $web_dir (@web_directories) {
        find({
            wanted => sub {
                return unless -f $_;
                return unless /\.(php|jsp|asp|aspx|pl|py|rb)$/i;
                
                my @matches = scan_file_content($File::Find::name, 
                    $THREAT_PATTERNS{webshells});
                
                for my $match (@matches) {
                    add_finding('webshells', 'CRITICAL',
                        "Webshell detected", $File::Find::name,
                        { line => $match->{line}, content => substr($match->{content}, 0, 200) });
                }
                
                # Check for suspicious filenames
                my $basename = basename($_);
                if ($basename =~ /(shell|cmd|backdoor|c99|r57|b374k|wso|bypass|exploit)/i) {
                    add_finding('webshells', 'HIGH',
                        "Suspicious web file name", $File::Find::name);
                }
            },
            no_chdir => 1
        }, $web_dir);
    }
    
    log_msg('INFO', "Webshell detection complete");
}

sub check_environment {
    section_header("Environment Variable Analysis");
    
    # Check system-wide environment
    my @env_files = qw(
        /etc/environment /etc/profile
        /etc/bash.bashrc /etc/csh.cshrc
    );
    
    for my $file (@env_files) {
        next unless -f $file;
        
        my @matches = scan_file_content($file, [
            qr/LD_PRELOAD/i,
            qr/LD_LIBRARY_PATH.*\/tmp/i,
            qr/PATH=.*\/tmp/i,
            qr/HISTFILE=.*\/dev\/null/i,
            qr/HISTSIZE=0/i,
        ]);
        
        for my $match (@matches) {
            add_finding('environment', 'MEDIUM',
                "Suspicious environment variable", $file,
                { line => $match->{line}, content => $match->{content} });
        }
    }
    
    # Check current environment
    for my $env_var (keys %ENV) {
        if ($env_var eq 'LD_PRELOAD' && $ENV{$env_var}) {
            add_finding('environment', 'CRITICAL',
                "LD_PRELOAD environment variable set", $ENV{$env_var});
        }
        
        if ($env_var eq 'LD_LIBRARY_PATH' && $ENV{$env_var} =~ m{/(tmp|var/tmp|dev/shm)/}) {
            add_finding('environment', 'HIGH',
                "LD_LIBRARY_PATH points to temp directory", $ENV{$env_var});
        }
    }
    
    log_msg('INFO', "Environment analysis complete");
}

sub check_logs {
    section_header("Log File Analysis");
    
    my @log_files = qw(
        /var/log/auth.log /var/log/secure
        /var/log/syslog /var/log/messages
        /var/log/lastlog /var/log/wtmp
    );
    
    for my $log_file (@log_files) {
        next unless -f $log_file && -r $log_file;
        
        # Check for log clearing evidence
        if (-z $log_file) {
            add_finding('logs', 'MEDIUM',
                "Empty log file (possible log clearing)", $log_file);
            next;
        }
        
        # Check last modification time
        my @stat = stat($log_file);
        if (@stat && (time() - $stat[9]) > 86400) { # More than 24 hours old
            add_finding('logs', 'LOW',
                "Log file not recently updated", $log_file);
        }
        
        # Look for suspicious log entries (last 1000 lines only for performance)
        my $tail_output = get_command_output("tail -1000 '$log_file'");
        next unless $tail_output;
        
        # Check for failed login attempts from unusual sources
        for my $line (split /\n/, $tail_output) {
            if ($line =~ /Failed password.*from (\d+\.\d+\.\d+\.\d+)/) {
                my $ip = $1;
                # Simple check for private IP ranges
                unless ($ip =~ /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/) {
                    add_finding('logs', 'LOW',
                        "Failed login from external IP", $ip);
                }
            }
            
            # Look for suspicious commands in logs
            for my $pattern (@{$THREAT_PATTERNS{suspicious_commands}}) {
                if ($line =~ /$pattern/) {
                    add_finding('logs', 'MEDIUM',
                        "Suspicious command in logs", $log_file,
                        { content => substr($line, 0, 200) });
                }
            }
        }
    }
    
    log_msg('INFO', "Log analysis complete");
}

#==============================================================================
# MAIN EXECUTION & REPORTING
#==============================================================================

sub export_json {
    return unless $CONFIG{json_export};
    
    my $report = {
        scan_info => {
            version => $VERSION,
            timestamp => time(),
            hostname => `hostname`,
            distro => detect_distro(),
            scan_duration => tv_interval($STATS{start_time}),
            files_scanned => $STATS{files_scanned},
        },
        statistics => {
            total_findings => scalar(@FINDINGS),
            by_severity => $STATS{findings_by_severity},
        },
        findings => \@FINDINGS,
    };
    
    chomp($report->{scan_info}{hostname});
    
    open(my $fh, '>', $JSON_OUTPUT) or do {
        warn "Cannot create JSON output file: $!";
        return;
    };
    
    print $fh JSON::PP->new->pretty->encode($report);
    close($fh);
    
    log_msg('INFO', "JSON report exported to $JSON_OUTPUT");
}

sub generate_summary {
    section_header("Scan Summary");
    
    my $total_findings = scalar(@FINDINGS);
    my $scan_duration = tv_interval($STATS{start_time});
    
    say colored(['cyan'], "Scan Duration: " . sprintf("%.2f seconds", $scan_duration));
    say colored(['cyan'], "Files Scanned: $STATS{files_scanned}");
    say colored(['cyan'], "Total Findings: $total_findings");
    
    if ($total_findings == 0) {
        say colored(['green'], "\n✓ No suspicious activity detected");
    } else {
        say colored(['yellow'], "\n⚠ Suspicious activity detected!");
        
        for my $severity (qw(CRITICAL HIGH MEDIUM LOW)) {
            my $count = $STATS{findings_by_severity}{$severity} || 0;
            next unless $count;
            
            my $color = $severity eq 'CRITICAL' ? 'red' :
                       $severity eq 'HIGH' ? 'yellow' :
                       $severity eq 'MEDIUM' ? 'blue' : 'cyan';
            
            say colored([$color], "  $severity: $count findings");
        }
    }
    
    say colored(['cyan'], "\nFull log: $LOGFILE");
    say colored(['cyan'], "JSON report: $JSON_OUTPUT") if $CONFIG{json_export};
    
    # Top findings by category
    my %by_category;
    for my $finding (@FINDINGS) {
        $by_category{$finding->{category}}++;
    }
    
    if (%by_category) {
        say colored(['blue'], "\nFindings by Category:");
        for my $category (sort { $by_category{$b} <=> $by_category{$a} } keys %by_category) {
            say colored(['white'], sprintf("  %-15s: %d", $category, $by_category{$category}));
        }
    }
}

sub main {
    my %opts;
    GetOptions(
        'help|h'        => \$opts{help},
        'all|a'         => \$opts{all},
        'processes|p'   => \$opts{processes},
        'cron|c'        => \$opts{cron},
        'shells|s'      => \$opts{shells},
        'suid|u'        => \$opts{suid},
        'ssh|k'         => \$opts{ssh},
        'users|U'       => \$opts{users},
        'services|S'    => \$opts{services},
        'network|n'     => \$opts{network},
        'startup|t'     => \$opts{startup},
        'webshells|w'   => \$opts{webshells},
        'environment|e' => \$opts{environment},
        'logs|l'        => \$opts{logs},
        'json|j'        => \$CONFIG{json_export},
        'verbose|v'     => \$CONFIG{verbose},
    ) or pod2usage(2);
    
    if ($opts{help}) {
        pod2usage(-verbose => 2);
        exit 0;
    }
    
    # If specific checks are requested, disable all others first
    my $specific_checks = grep { $opts{$_} } keys %CHECKS;
    if ($specific_checks && !$opts{all}) {
        $CHECKS{$_} = 0 for keys %CHECKS;
        $CHECKS{$_} = 1 for grep { $opts{$_} } keys %CHECKS;
    }
    
    require_root();
    init_logging();
    show_banner();
    
    log_msg('INFO', "Starting $SCRIPT_NAME v$VERSION");
    log_msg('INFO', "Hostname: " . `hostname`);
    log_msg('INFO', "Distribution: " . detect_distro());
    log_msg('INFO', "Kernel: " . `uname -r`);
    
    # Run enabled checks
    check_processes() if $CHECKS{processes};
    check_cron() if $CHECKS{cron};
    check_shells() if $CHECKS{shells};
    check_suid() if $CHECKS{suid};
    check_ssh() if $CHECKS{ssh};
    check_users() if $CHECKS{users};
    check_services() if $CHECKS{services};
    check_network() if $CHECKS{network};
    check_startup() if $CHECKS{startup};
    check_webshells() if $CHECKS{webshells};
    check_environment() if $CHECKS{environment};
    check_logs() if $CHECKS{logs};
    
    generate_summary();
    export_json();
    
    say colored(['green'], "\nScan complete!");
    
    # Exit with error code if critical findings
    my $critical_count = $STATS{findings_by_severity}{CRITICAL} || 0;
    exit($critical_count > 0 ? 1 : 0);
}

main(@ARGV);

__END__

=head1 NAME

Linux Persistence Hunter - Advanced Perl Edition

=head1 SYNOPSIS

linux_persistence_hunter.pl [OPTIONS]

=head1 OPTIONS

=over 8

=item B<-a, --all>

Run all available checks (default)

=item B<-p, --processes>

Check for suspicious processes

=item B<-c, --cron>

Analyze cron jobs

=item B<-s, --shells>

Check shell initialization scripts

=item B<-u, --suid>

Check SUID/SGID binaries

=item B<-k, --ssh>

Analyze SSH configuration and keys

=item B<-U, --users>

Check user accounts

=item B<-S, --services>

Analyze system services

=item B<-n, --network>

Check network listeners

=item B<-t, --startup>

Check system startup scripts

=item B<-w, --webshells>

Detect webshells in web directories

=item B<-e, --environment>

Analyze environment variables

=item B<-l, --logs>

Check system logs

=item B<-j, --json>

Export findings to JSON format

=item B<-v, --verbose>

Enable verbose output

=item B<-h, --help>

Show detailed help message

=back

=head1 DESCRIPTION

This tool performs comprehensive analysis of Linux systems to detect
persistence mechanisms, backdoors, and other security threats. It's
written in Perl for better performance and extensibility compared
to the original bash version.

=head1 EXAMPLES

  # Run all checks with JSON export
  sudo ./linux_persistence_hunter.pl -a -j
  
  # Check only processes and network
  sudo ./linux_persistence_hunter.pl -p -n
  
  # Full scan with verbose output
  sudo ./linux_persistence_hunter.pl -a -v

=cut
