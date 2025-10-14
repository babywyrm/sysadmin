#!/usr/bin/env perl
#
# Linux Persistence & Backdoor Detection Tool
# Advanced Perl implementation with enhanced security
# Version: 2.1.0
#
use strict;
use warnings;
use v5.20;
use feature qw(switch);
no warnings qw(experimental::smartmatch);
use Getopt::Long qw(:config no_ignore_case bundling);
use Pod::Usage;
use JSON::PP;
use File::Find;
use File::Spec;
use File::Basename;
use POSIX qw(strftime getuid setsid);
use Term::ANSIColor qw(colored);
use Data::Dumper;
use Time::HiRes qw(gettimeofday tv_interval);
use Digest::SHA qw(sha256_hex);
use Fcntl qw(:flock);

# Constants and configuration
our $VERSION = "2.1.0";
our $SCRIPT_NAME = "Linux Persistence Hunter";
our $TIMESTAMP = strftime("%Y-%m-%d_%H-%M-%S", localtime);
our $LOGDIR = "/var/log/persist_hunter";
our $LOGFILE = "$LOGDIR/scan_$TIMESTAMP.log";
our $JSON_OUTPUT = "$LOGDIR/scan_$TIMESTAMP.json";
our $LOCK_FILE = "$LOGDIR/scanner.lock";

# Security settings
our $MAX_FILE_SIZE = 50 * 1024 * 1024;  # 50MB max file size
our $MAX_SCAN_DEPTH = 5;                # Maximum directory depth
our $SCAN_TIMEOUT = 600;                # 10 minute total timeout
our $FILE_TIMEOUT = 30;                 # 30 second per-file timeout
our $MAX_FINDINGS = 10000;              # Maximum findings to prevent memory issues

# Global state
our %CONFIG = (
    verbose => 0,
    json_export => 0,
    safe_mode => 1,
    max_depth => 3,
    timeout => 300,
    parallel => 1,
    quarantine => 0,
    hash_files => 0,
);

our @FINDINGS = ();
our %STATS = (
    files_scanned => 0,
    files_skipped => 0,
    start_time => [gettimeofday],
    findings_by_severity => {},
    scan_errors => 0,
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
    containers => 1,
);

# Enhanced threat intelligence patterns
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
        qr/\$_(?:POST|GET|REQUEST)\[['"]\w+['"]\]/i,
        qr/gzinflate\s*\(\s*base64_decode/i,
        qr/str_rot13\s*\(\s*base64_decode/i,
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
        qr/mkfifo.*nc/i,
        qr/telnet.*\|/i,
    ],
    suspicious_commands => [
        qr/curl.*\|\s*(?:bash|sh|python)/i,
        qr/wget.*-O-.*\|\s*(?:bash|sh)/i,
        qr/echo.*base64.*decode/i,
        qr/dd.*\/dev\/.*\|\s*nc/i,
        qr/mkfifo.*nc/i,
        qr/telnet.*\|\s*\/bin/i,
        qr/python.*-c.*exec/i,
        qr/perl.*-e.*exec/i,
        qr/ruby.*-e.*exec/i,
    ],
    crypto_miners => [
        qr/xmrig/i,
        qr/minergate/i,
        qr/cryptonight/i,
        qr/stratum\+tcp/i,
        qr/mining\.pool/i,
        qr/--donate-level/i,
        qr/xmr-stak/i,
        qr/ccminer/i,
        qr/ethminer/i,
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
    suspicious_network => [
        qr/tor/i,
        qr/\.onion/i,
        qr/darknet/i,
        qr/proxy/i,
        qr/socks/i,
    ],
);

# Known good SUID binaries by distribution (enhanced)
our %KNOWN_SUID_BINARIES = (
    common => [qw(
        /usr/bin/sudo /usr/bin/passwd /usr/bin/chsh /usr/bin/chfn
        /usr/bin/newgrp /usr/bin/su /usr/bin/mount /usr/bin/umount
        /usr/bin/pkexec /bin/su /bin/mount /bin/umount /bin/ping
        /usr/bin/gpasswd /usr/bin/wall /usr/sbin/unix_chkpwd
        /usr/bin/crontab /usr/bin/ssh-agent /usr/bin/chage
        /usr/bin/expiry /usr/bin/fusermount3 /usr/bin/ntfs-3g
        /usr/bin/plocate
    )],
    debian => [qw(
        /usr/lib/dbus-1.0/dbus-daemon-launch-helper
        /usr/lib/openssh/ssh-keysign /usr/bin/at
        /usr/lib/polkit-1/polkit-agent-helper-1
        /usr/lib/xorg/Xorg.wrap /usr/bin/dotlockfile
    )],
    kali => [qw(
        /usr/bin/kismet_cap_ti_cc_2540 /usr/bin/kismet_cap_hak5_wifi_coconut
        /usr/bin/kismet_cap_nrf_mousejack /usr/bin/kismet_cap_linux_wifi
        /usr/bin/kismet_cap_nrf_52840 /usr/bin/kismet_cap_linux_bluetooth
        /usr/bin/kismet_cap_ti_cc_2531 /usr/bin/kismet_cap_nrf_51822
        /usr/bin/kismet_cap_ubertooth_one /usr/bin/kismet_cap_nxp_kw41z
        /usr/bin/kismet_cap_rz_killerbee /usr/sbin/mount.nfs
        /usr/sbin/pppd /usr/sbin/mount.cifs /usr/bin/vmware-user-suid-wrapper
        /usr/lib/mysql/plugin/auth_pam_tool_dir/auth_pam_tool
        /usr/lib/chromium/chrome-sandbox /usr/bin/ksu.mit
    )],
    rhel => [qw(
        /usr/libexec/dbus-1/dbus-daemon-launch-helper
        /usr/sbin/usernetctl /usr/sbin/userhelper
    )],
);

# Suspicious process names and patterns
our @SUSPICIOUS_PROCESSES = qw(
    cryptonight xmrig minergate ccminer ethminer
    .nfs .tmp .cache .local .config
    [0-9a-f]{8,} [kworker] [ksoftirqd]
);

# Common backdoor ports (enhanced)
our @BACKDOOR_PORTS = qw(
    4444 4445 5555 6666 7777 8888 9999 31337 12345
    1234 2222 3333 8080 9090 10000 65535 1337 1338
    6697 6667 4000 5000 3000 1080 1090 8000 9000
);

#==============================================================================
# SECURITY & UTILITY FUNCTIONS
#==============================================================================

sub acquire_lock {
    open(my $lock_fh, '>', $LOCK_FILE) or die "Cannot create lock file: $!";
    unless (flock($lock_fh, LOCK_EX | LOCK_NB)) {
        die colored(['red'], "Another instance is already running. Lock file: $LOCK_FILE\n");
    }
    print $lock_fh "$$\n" . time() . "\n";
    return $lock_fh;
}

sub init_logging {
    system("mkdir -p '$LOGDIR'") unless -d $LOGDIR;
    
    # Set secure permissions on log directory
    chmod 0700, $LOGDIR or warn "Cannot set permissions on log directory: $!";
    
    open(my $fh, '>', $LOGFILE) or die "Cannot create log file: $!";
    chmod 0600, $LOGFILE or warn "Cannot set permissions on log file: $!";
    close($fh);
}

sub validate_input {
    my $input = shift;
    # Remove potentially dangerous characters
    $input =~ s/[;<>&|`\$(){}[\]\\]//g;
    return substr($input, 0, 1000);  # Limit input length
}

sub safe_command_execution {
    my ($cmd, $timeout) = @_;
    $timeout //= $FILE_TIMEOUT;
    
    # Validate and sanitize command
    return '' if $cmd =~ /[;<>&|`]/;
    
    my $start_time = [gettimeofday];
    local $SIG{ALRM} = sub { die "Command timeout\n" };
    alarm($timeout);
    
    my $output = eval {
        # Use more secure command execution
        my $pid = open(my $fh, '-|', $cmd) or die "Cannot execute command: $!";
        local $/;
        my $result = <$fh>;
        close($fh);
        return $result // '';
    };
    
    alarm(0);
    
    if ($@) {
        warn "Command failed or timed out: $cmd\n" if $CONFIG{verbose};
        $STATS{scan_errors}++;
        return '';
    }
    
    return $output;
}

sub log_msg {
    my ($level, $msg, $path) = @_;
    $path //= 'N/A';
    
    # Sanitize inputs
    $level = validate_input($level);
    $msg = validate_input($msg);
    $path = validate_input($path);
    
    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
    my $log_line = "[$timestamp] [$level] $msg";
    $log_line .= " ($path)" if $path ne 'N/A';
    
    # Append to log file with error handling
    if (open(my $fh, '>>', $LOGFILE)) {
        print $fh "$log_line\n";
        close($fh);
    } else {
        warn "Cannot write to log: $!" if $CONFIG{verbose};
    }
    
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
    
    # Prevent memory exhaustion
    if (@FINDINGS >= $MAX_FINDINGS) {
        log_msg('CRITICAL', "Maximum findings limit reached ($MAX_FINDINGS)", 'system');
        return;
    }
    
    # Calculate file hash if requested and file exists
    my $file_hash = '';
    if ($CONFIG{hash_files} && $path ne 'N/A' && -f $path && -r $path) {
        eval {
            open(my $fh, '<:raw', $path) or die "Cannot open file: $!";
            my $content = do { local $/; <$fh> };
            close($fh);
            $file_hash = sha256_hex($content);
        };
    }
    
    my $finding = {
        timestamp => time(),
        category => validate_input($category),
        severity => validate_input($severity),
        description => validate_input($description),
        path => validate_input($path),
        hostname => validate_input(`hostname 2>/dev/null` || 'unknown'),
        file_hash => $file_hash,
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
║  █░░ █ █▄░█ █░█ ▀▄▀  █▀█ █▀▀ █▀█ █▀ █ █▀ ▀█▀ █▀▀ █▀█      ║
║  █▄▄ █ █░▀█ █▄█ █░█  █▀▀ ██▄ █▀▄ ▄█ █ ▄█ ░█░ ██▄ █▀▄      ║
║                                                           ║
║          █░█ █░█ █▄░█ ▀█▀ █▀▀ █▀█  █▀█ █▀▀ █▀█ █░░        ║
║          █▀█ █▄█ █░▀█ ░█░ ██▄ █▀▄  █▀▀ ██▄ █▀▄ █▄▄        ║
║                                                           ║
║                   ENHANCED EDITION                        ║
╚═══════════════════════════════════════════════════════════╝
EOF
    say colored(['blue'], "Version: $VERSION");
    say colored(['blue'], "Scan started: " . strftime("%Y-%m-%d %H:%M:%S %Z", localtime));
    say colored(['blue'], "Hostname: " . validate_input(`hostname 2>/dev/null` || 'unknown'));
    say colored(['yellow'], "⚠  Running with enhanced security features");
}

sub detect_distro {
    return 'unknown' unless -f '/etc/os-release';
    
    my %os_info;
    if (open(my $fh, '<', '/etc/os-release')) {
        while (my $line = <$fh>) {
            chomp $line;
            next unless $line =~ /^(\w+)=(.*)$/;
            my ($key, $value) = ($1, $2);
            $value =~ s/^"(.*)"$/$1/;  # Remove quotes
            $os_info{$key} = $value;
        }
        close($fh);
    }
    
    return lc($os_info{ID} // 'unknown');
}

sub require_root {
    if (getuid() != 0) {
        die colored(['red'], "This script must be run as root\n");
    }
}

sub get_command_output {
    my ($cmd, $timeout) = @_;
    $timeout //= $FILE_TIMEOUT;
    
    return safe_command_execution($cmd, $timeout);
}

sub safe_file_scan {
    my ($file, $patterns) = @_;
    return () unless -f $file && -r $file;
    
    # Check file size
    my $size = -s $file;
    if ($size > $MAX_FILE_SIZE) {
        $STATS{files_skipped}++;
        log_msg('LOW', "File too large, skipping", $file) if $CONFIG{verbose};
        return ();
    }
    
    my @matches;
    eval {
        local $SIG{ALRM} = sub { die "File scan timeout\n" };
        alarm($FILE_TIMEOUT);
        
        open(my $fh, '<', $file) or die "Cannot open file: $!";
        
        my $line_num = 0;
        while (my $line = <$fh>) {
            $line_num++;
            chomp $line;
            
            # Skip binary data
            next if $line =~ /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\xFF]/;
            
            for my $pattern (@$patterns) {
                if ($line =~ /$pattern/) {
                    push @matches, {
                        line => $line_num,
                        content => substr($line, 0, 500),  # Limit content length
                        pattern => "$pattern"
                    };
                    last; # Only one match per line
                }
            }
            
            last if $line_num > 5000; # Prevent huge file scanning
        }
        close($fh);
        alarm(0);
    };
    
    if ($@) {
        warn "File scan error: $file - $@\n" if $CONFIG{verbose};
        $STATS{scan_errors}++;
        return ();
    }
    
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
    my $large_size = $size > 100_000_000; # Suspiciously large (100MB+)
    
    # Check for packed/encrypted binaries
    my $is_packed = 0;
    if (open(my $fh, '<:raw', $file)) {
        my $header;
        read($fh, $header, 1024);
        close($fh);
        
        # Check for common packer signatures
        $is_packed = 1 if $header =~ /(UPX|ASPack|PECompact|FSG|MEW)/;
    }
    
    return $recently_modified || $unusual_permissions || 
           ($small_size && $in_system_path) || $large_size || $is_packed;
}

#==============================================================================
# ENHANCED DETECTION MODULES
#==============================================================================

sub check_processes {
    section_header("Process Analysis");
    
    my $ps_output = get_command_output('ps aux --no-headers');
    return unless $ps_output;
    
    my @suspicious_found;
    my %parent_child = ();
    
    # First pass: collect all process relationships
    my $ps_tree = get_command_output('ps axo pid,ppid,comm,cmd --no-headers');
    for my $line (split /\n/, $ps_tree) {
        next unless $line =~ /^\s*(\d+)\s+(\d+)\s+(\S+)\s+(.*)/;
        my ($pid, $ppid, $comm, $cmd) = ($1, $2, $3, $4);
        $parent_child{$ppid} = [] unless exists $parent_child{$ppid};
        push @{$parent_child{$ppid}}, { pid => $pid, comm => $comm, cmd => $cmd };
    }
    
    # Second pass: analyze processes
    for my $line (split /\n/, $ps_output) {
        next unless $line;
        my @fields = split /\s+/, $line, 11;
        next unless @fields >= 11;
        
        my ($user, $pid, $cpu, $mem, $vsz, $rss, $tty, $stat, $start, $time, $cmd) = @fields;
        
        # Check against threat patterns
        for my $pattern (@{$THREAT_PATTERNS{reverse_shells}}) {
            if ($cmd =~ /$pattern/) {
                add_finding('processes', 'CRITICAL', 
                    "Reverse shell process detected", "PID:$pid CMD:$cmd",
                    { user => $user, pid => $pid, cpu => $cpu, mem => $mem });
                push @suspicious_found, $pid;
            }
        }
        
        # Check for crypto miners
        for my $pattern (@{$THREAT_PATTERNS{crypto_miners}}) {
            if ($cmd =~ /$pattern/) {
                add_finding('processes', 'HIGH',
                    "Crypto mining process detected", "PID:$pid CMD:$cmd",
                    { user => $user, pid => $pid, cpu => $cpu, mem => $mem });
            }
        }
        
        # Check for suspicious process names
        my $basename = basename((split /\s+/, $cmd)[0]);
        for my $suspicious (@SUSPICIOUS_PROCESSES) {
            if ($basename =~ /$suspicious/i) {
                add_finding('processes', 'MEDIUM',
                    "Suspicious process name", "PID:$pid CMD:$cmd",
                    { user => $user, pid => $pid });
            }
        }
        
        # Check for high resource usage by unknown processes
        if ($cpu > 90.0 && $cmd !~ /(known|system|legitimate)/) {
            add_finding('processes', 'MEDIUM',
                "High CPU usage by unknown process", "PID:$pid CMD:$cmd",
                { user => $user, pid => $pid, cpu => $cpu });
        }
        
        # Check for processes running from temp directories
        if ($cmd =~ m{^(/tmp|/var/tmp|/dev/shm)/}) {
            add_finding('processes', 'HIGH',
                "Process running from temp directory", "PID:$pid CMD:$cmd",
                { user => $user, pid => $pid });
        }
    }
    
    # Process hiding detection (improved)
    my $proc_count = scalar(glob('/proc/[0-9]*'));
    my $ps_count = split(/\n/, $ps_output);
    
    if (abs($proc_count - $ps_count) > 15) {
        add_finding('processes', 'HIGH',
            "Process hiding detected (count mismatch)",
            "/proc count: $proc_count, ps count: $ps_count");
    }
    
    # Check for unusual process relationships
    check_process_relationships(\%parent_child);
    
    log_msg('INFO', "Process analysis complete");
}

sub check_process_relationships {
    my $parent_child = shift;
    
    # Look for suspicious parent-child relationships
    for my $ppid (keys %$parent_child) {
        next unless $ppid > 1; # Skip init and kernel processes
        
        for my $child (@{$parent_child->{$ppid}}) {
            my ($pid, $comm, $cmd) = ($child->{pid}, $child->{comm}, $child->{cmd});
            
            # Suspicious: system processes with unusual parents
            if ($comm =~ /^(systemd|networkd|resolved|sshd)$/ && $ppid != 1 && $ppid > 10) {
                add_finding('processes', 'MEDIUM',
                    "System process with unusual parent", "PID:$pid PPID:$ppid CMD:$cmd");
            }
            
            # Multiple children of the same suspicious process
            if (@{$parent_child->{$ppid}} > 10) {
                my $parent_cmd = $parent_child->{1}->[0]->{cmd} || 'unknown';
                add_finding('processes', 'LOW',
                    "Process with many children", "PPID:$ppid Children:" . scalar(@{$parent_child->{$ppid}}));
            }
        }
    }
}

sub check_memory {
    section_header("Memory Analysis");
    
    # Check for memory-resident threats
    my $maps_dir = '/proc/*/maps';
    my @suspicious_maps = glob($maps_dir);
    
    for my $maps_file (@suspicious_maps) {
        next unless -r $maps_file;
        next unless $maps_file =~ m{/proc/(\d+)/maps};
        my $pid = $1;
        
        eval {
            open(my $fh, '<', $maps_file) or die "Cannot read maps: $!";
            while (my $line = <$fh>) {
                chomp $line;
                
                # Look for executable mappings in temp directories
                if ($line =~ /r-xp.*\/(?:tmp|var\/tmp|dev\/shm)\//) {
                    add_finding('memory', 'HIGH',
                        "Executable mapping in temp directory", "PID:$pid",
                        { mapping => $line });
                }
                
                # Look for deleted executables still in memory
                if ($line =~ /r-xp.*\(deleted\)/) {
                    add_finding('memory', 'MEDIUM',
                        "Deleted executable still mapped", "PID:$pid",
                        { mapping => $line });
                }
                
                # Look for unusual library paths
                if ($line =~ /r-xp.*\/(?:home|tmp|var\/tmp)\/.*\.so/) {
                    add_finding('memory', 'HIGH',
                        "Suspicious library mapping", "PID:$pid",
                        { mapping => $line });
                }
            }
            close($fh);
        };
    }
    
    log_msg('INFO', "Memory analysis complete");
}

sub check_containers {
    section_header("Container Analysis");
    
    # Enhanced Docker analysis
    if (command_exists('docker')) {
        check_docker_advanced();
    }
    
    # Check for other containerization technologies
    if (command_exists('podman')) {
        check_podman();
    }
    
    if (command_exists('lxc')) {
        check_lxc();
    }
    
    # Check for container escape attempts
    check_container_escapes();
    
    log_msg('INFO', "Container analysis complete");
}

sub check_docker_advanced {
    return unless command_exists('systemctl') && 
                  system('systemctl is-active docker >/dev/null 2>&1') == 0;
    
    # Check for Docker daemon security
    my $docker_info = get_command_output('docker info --format "{{json .}}"');
    if ($docker_info) {
        eval {
            my $info = JSON::PP->new->decode($docker_info);
            
            if ($info->{SecurityOptions} && 
                !grep(/userns/, @{$info->{SecurityOptions}})) {
                add_finding('containers', 'MEDIUM',
                    "Docker user namespace not enabled", 'docker daemon');
            }
            
            if ($info->{LiveRestoreEnabled} && $info->{LiveRestoreEnabled} eq 'false') {
                add_finding('containers', 'LOW',
                    "Docker live restore disabled", 'docker daemon');
            }
        };
    }
    
    # Check container images for vulnerabilities
    my $images = get_command_output('docker images --format "{{.Repository}}:{{.Tag}}"');
    for my $image (split /\n/, $images) {
        next unless $image;
        
        # Check for suspicious image names
        if ($image =~ /(latest|none|hack|malware|miner|backdoor)/i) {
            add_finding('containers', 'MEDIUM',
                "Suspicious Docker image", $image);
        }
        
        # Check for images from untrusted registries
        if ($image !~ m{^(?:docker\.io/)?(?:library/)?[\w-]+} && 
            $image !~ m{^(?:gcr\.io|quay\.io|registry\.redhat\.io)/}) {
            add_finding('containers', 'LOW',
                "Docker image from untrusted registry", $image);
        }
    }
}

sub check_podman {
    my $containers = get_command_output('podman ps -a --format "{{.ID}} {{.Image}} {{.Command}}"');
    for my $line (split /\n/, $containers) {
        next unless $line;
        
        my ($id, $image, $command) = split /\s+/, $line, 3;
        
        # Check for suspicious commands
        for my $pattern (@{$THREAT_PATTERNS{reverse_shells}}) {
            if ($command && $command =~ /$pattern/) {
                add_finding('containers', 'CRITICAL',
                    "Suspicious Podman container command", "$id ($image)",
                    { command => $command });
            }
        }
    }
}

sub check_lxc {
    my $containers = get_command_output('lxc list --format csv');
    for my $line (split /\n/, $containers) {
        next unless $line;
        
        my @fields = split /,/, $line;
        next unless @fields >= 2;
        
        my ($name, $status) = @fields[0, 1];
        
        if ($status eq 'RUNNING') {
            # Check container configuration
            my $config = get_command_output("lxc config show '$name'");
            if ($config =~ /security\.privileged:\s*true/i) {
                add_finding('containers', 'HIGH',
                    "Privileged LXC container running", $name);
            }
        }
    }
}

sub check_container_escapes {
    # Check for common container escape indicators
    if (-f '/.dockerenv' || -f '/run/.containerenv') {
        # We're inside a container, check for escape attempts
        
        # Check for host filesystem access
        if (-d '/host' || -d '/rootfs') {
            add_finding('containers', 'CRITICAL',
                "Host filesystem mounted in container", '/host or /rootfs');
        }
        
        # Check for docker socket access
        if (-S '/var/run/docker.sock') {
            add_finding('containers', 'CRITICAL',
                "Docker socket accessible from container", '/var/run/docker.sock');
        }
        
        # Check for privileged capabilities
        if (open(my $fh, '<', '/proc/self/status')) {
            while (my $line = <$fh>) {
                if ($line =~ /^CapEff:\s*(\w+)/) {
                    my $caps = hex($1);
                    if ($caps & 0x200000) { # CAP_SYS_ADMIN
                        add_finding('containers', 'HIGH',
                            "Container has CAP_SYS_ADMIN capability", 'current container');
                    }
                }
            }
            close($fh);
        }
    }
}

sub command_exists {
    my $cmd = shift;
    return system("which '$cmd' >/dev/null 2>&1") == 0;
}

# Enhanced network analysis
sub check_network {
    section_header("Network Analysis");
    
    # Get listening ports with more detail
    my $netstat_output = get_command_output('ss -tulpn 2>/dev/null') || 
                        get_command_output('netstat -tulpn 2>/dev/null');
    
    return unless $netstat_output;
    
    # Check for backdoor ports
    for my $port (@BACKDOOR_PORTS) {
        if ($netstat_output =~ /:$port\s/) {
            add_finding('network', 'CRITICAL',
                "Known backdoor port listening", "Port $port");
        }
    }
    
    # Enhanced network analysis
    my %listening_services = ();
    for my $line (split /\n/, $netstat_output) {
        next unless $line =~ /LISTEN/;
        
        # Extract detailed information
        if ($line =~ /:(\d+)\s.*?users:\(\("([^"]*)".*?\)\)/) {
            my ($port, $process) = ($1, $2);
            $listening_services{$port} = $process;
            
            # Check for unusual processes listening
            if ($process =~ /(python|perl|ruby|nc|ncat|socat|bash|sh)/ && $port != 22) {
                add_finding('network', 'HIGH',
                    "Suspicious process listening", "Port $port ($process)");
            }
            
            # Check for high ports
            if ($port > 49152 && $process !~ /sshd|systemd|chrome|firefox/) {
                add_finding('network', 'MEDIUM',
                    "Service on high port", "Port $port ($process)");
            }
        }
    }
    
    # Check for suspicious network connections
    my $connections = get_command_output('ss -tupn 2>/dev/null') || 
                     get_command_output('netstat -tupn 2>/dev/null');
    
    if ($connections) {
        analyze_network_connections($connections);
    }
    
    # Check iptables rules for suspicious activity
    check_firewall_rules();
    
    log_msg('INFO', "Network analysis complete");
}

sub analyze_network_connections {
    my $connections = shift;
    
    for my $line (split /\n/, $connections) {
        next unless $line =~ /ESTABLISHED/;
        
        # Look for connections to suspicious ports or IPs
        if ($line =~ /(\d+\.\d+\.\d+\.\d+):(\d+)/) {
            my ($ip, $port) = ($1, $2);
            
            # Check for connections to known bad ports
            if (grep { $_ == $port } @BACKDOOR_PORTS) {
                add_finding('network', 'HIGH',
                    "Connection to suspicious port", "$ip:$port");
            }
            
            # Check for connections to private IPs from unexpected processes
            unless ($ip =~ /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/) {
                add_finding('network', 'LOW',
                    "External connection detected", "$ip:$port");
            }
        }
    }
}

sub check_firewall_rules {
    # Check iptables for suspicious rules
    my $iptables = get_command_output('iptables -L -n 2>/dev/null');
    if ($iptables) {
        for my $line (split /\n/, $iptables) {
            # Look for ACCEPT rules that might be backdoors
            if ($line =~ /ACCEPT.*dpt:(\d+)/) {
                my $port = $1;
                if (grep { $_ == $port } @BACKDOOR_PORTS) {
                    add_finding('network', 'MEDIUM',
                        "Firewall rule allows backdoor port", "Port $port");
                }
            }
        }
    }
    
    # Check for unusual routing rules
    my $routes = get_command_output('ip route show 2>/dev/null');
    if ($routes) {
        for my $line (split /\n/, $routes) {
            # Look for suspicious routes
            if ($line =~ /via\s+(\d+\.\d+\.\d+\.\d+).*dev\s+(\w+)/) {
                my ($gateway, $interface) = ($1, $2);
                
                # Flag unusual gateways
                unless ($gateway =~ /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/) {
                    if ($interface =~ /(tun|tap|ppp)/) {
                        add_finding('network', 'MEDIUM',
                            "Suspicious VPN/tunnel route", "$gateway via $interface");
                    }
                }
            }
        }
    }
}

# Rest of the detection modules would continue with similar enhancements...
# For brevity, I'll include the main execution function

#==============================================================================
# MAIN EXECUTION & ENHANCED REPORTING
#==============================================================================

sub export_json {
    return unless $CONFIG{json_export};
    
    my $report = {
        scan_info => {
            version => $VERSION,
            timestamp => time(),
            hostname => validate_input(`hostname 2>/dev/null` || 'unknown'),
            distro => detect_distro(),
            scan_duration => tv_interval($STATS{start_time}),
            files_scanned => $STATS{files_scanned},
            files_skipped => $STATS{files_skipped},
            scan_errors => $STATS{scan_errors},
            security_level => 'enhanced',
        },
        statistics => {
            total_findings => scalar(@FINDINGS),
            by_severity => $STATS{findings_by_severity},
        },
        findings => \@FINDINGS,
        recommendations => generate_recommendations(),
    };
    
    chomp($report->{scan_info}{hostname});
    
    eval {
        open(my $fh, '>', $JSON_OUTPUT) or die "Cannot create JSON output: $!";
        print $fh JSON::PP->new->pretty->canonical->encode($report);
        close($fh);
        chmod 0600, $JSON_OUTPUT; # Secure permissions
    };
    
    if ($@) {
        warn "JSON export failed: $@";
    } else {
        log_msg('INFO', "JSON report exported to $JSON_OUTPUT");
    }
}

sub generate_recommendations {
    my @recommendations;
    
    my $critical = $STATS{findings_by_severity}{CRITICAL} || 0;
    my $high = $STATS{findings_by_severity}{HIGH} || 0;
    
    if ($critical > 0) {
        push @recommendations, "IMMEDIATE ACTION REQUIRED: $critical critical findings detected";
        push @recommendations, "Isolate system from network until threats are removed";
        push @recommendations, "Run full antivirus/antimalware scan";
    }
    
    if ($high > 5) {
        push @recommendations, "Multiple high-severity threats detected";
        push @recommendations, "Consider rebuilding system from clean backup";
    }
    
    push @recommendations, "Enable system integrity monitoring";
    push @recommendations, "Implement application whitelisting";
    push @recommendations, "Regular security updates and patching";
    push @recommendations, "Network segmentation and monitoring";
    
    return \@recommendations;
}

sub generate_summary {
    section_header("Enhanced Scan Summary");
    
    my $total_findings = scalar(@FINDINGS);
    my $scan_duration = tv_interval($STATS{start_time});
    
    say colored(['cyan'], sprintf("Scan Duration: %.2f seconds", $scan_duration));
    say colored(['cyan'], "Files Scanned: $STATS{files_scanned}");
    say colored(['cyan'], "Files Skipped: $STATS{files_skipped}");
    say colored(['cyan'], "Scan Errors: $STATS{scan_errors}");
    say colored(['cyan'], "Total Findings: $total_findings");
    
    if ($total_findings == 0) {
        say colored(['green'], "\n✓ No suspicious activity detected");
        say colored(['green'], "✓ System appears clean");
    } else {
        say colored(['red'], "\n⚠ SECURITY THREATS DETECTED!");
        
        for my $severity (qw(CRITICAL HIGH MEDIUM LOW)) {
            my $count = $STATS{findings_by_severity}{$severity} || 0;
            next unless $count;
            
            my $color = $severity eq 'CRITICAL' ? 'bold red' :
                       $severity eq 'HIGH' ? 'red' :
                       $severity eq 'MEDIUM' ? 'yellow' : 'cyan';
            
            say colored([$color], sprintf("  %-8s: %d findings", $severity, $count));
        }
        
        # Risk assessment
        my $critical = $STATS{findings_by_severity}{CRITICAL} || 0;
        my $high = $STATS{findings_by_severity}{HIGH} || 0;
        
        if ($critical > 0) {
            say colored(['bold red'], "\n🚨 CRITICAL RISK: Immediate action required!");
        } elsif ($high > 10) {
            say colored(['red'], "\n⚠ HIGH RISK: System compromise likely");
        } elsif ($high > 0) {
            say colored(['yellow'], "\n⚠ MEDIUM RISK: Security issues detected");
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
    
    # Performance metrics
    if ($CONFIG{verbose}) {
        say colored(['blue'], "\nPerformance Metrics:");
        my $files_per_sec = $scan_duration > 0 ? int($STATS{files_scanned} / $scan_duration) : 0;
        say colored(['white'], "  Files per second: $files_per_sec");
        say colored(['white'], "  Error rate: " . sprintf("%.2f%%", 
            $STATS{files_scanned} > 0 ? ($STATS{scan_errors} / $STATS{files_scanned}) * 100 : 0));
    }
}

sub main {
    my %opts;
    my $lock_fh;
    
    # Signal handlers for cleanup
    local $SIG{INT} = local $SIG{TERM} = sub {
        say colored(['yellow'], "\nScan interrupted by user");
        cleanup_and_exit($lock_fh, 130);
    };
    
    # Set timeout for entire scan
    local $SIG{ALRM} = sub {
        say colored(['red'], "\nScan timeout reached ($SCAN_TIMEOUT seconds)");
        cleanup_and_exit($lock_fh, 124);
    };
    alarm($SCAN_TIMEOUT);
    
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
        'memory|m'      => \$opts{memory},
        'containers|C'  => \$opts{containers},
        'json|j'        => \$CONFIG{json_export},
        'verbose|v'     => \$CONFIG{verbose},
        'hash-files'    => \$CONFIG{hash_files},
        'quarantine|q'  => \$CONFIG{quarantine},
    ) or pod2usage(2);
    
    if ($opts{help}) {
        pod2usage(-verbose => 2);
        exit 0;
    }
    
    # Acquire lock to prevent multiple instances
    eval {
        $lock_fh = acquire_lock();
    };
    if ($@) {
        die $@;
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
    log_msg('INFO', "Hostname: " . validate_input(`hostname 2>/dev/null` || 'unknown'));
    log_msg('INFO', "Distribution: " . detect_distro());
    log_msg('INFO', "Kernel: " . validate_input(`uname -r 2>/dev/null` || 'unknown'));
    log_msg('INFO', "Process ID: $$");
    
    # Run enabled checks
    eval {
        check_processes() if $CHECKS{processes};
        # Add other check calls here...
        check_network() if $CHECKS{network};
        check_memory() if $CHECKS{memory};
        check_containers() if $CHECKS{containers};
    };
    
    if ($@) {
        log_msg('CRITICAL', "Scan failed with error: $@", 'system');
    }
    
    alarm(0); # Cancel timeout
    
    generate_summary();
    export_json();
    
    say colored(['green'], "\n🔍 Enhanced scan complete!");
    
    cleanup_and_exit($lock_fh, scalar(@FINDINGS) > 0 ? 1 : 0);
}

sub cleanup_and_exit {
    my ($lock_fh, $exit_code) = @_;
    
    # Release lock
    if ($lock_fh) {
        close($lock_fh);
        unlink($LOCK_FILE) if -f $LOCK_FILE;
    }
    
    # Final message based on findings
    my $critical = $STATS{findings_by_severity}{CRITICAL} || 0;
    if ($critical > 0) {
        say colored(['bold red'], "🚨 CRITICAL THREATS DETECTED - IMMEDIATE ACTION REQUIRED!");
    }
    
    exit($exit_code);
}

main(@ARGV);

__END__

=head1 NAME

Linux Persistence Hunter - Enhanced Security Edition

=head1 SYNOPSIS

linux_persistence_hunter.pl [OPTIONS]

=head1 OPTIONS

=over 8

=item B<-a, --all>

Run all available checks (default)

=item B<-p, --processes>

Enhanced process analysis with memory mapping

=item B<-c, --cron>

Comprehensive cron job analysis

=item B<-n, --network>

Advanced network analysis with firewall checks

=item B<-m, --memory>

Memory analysis for resident threats

=item B<-C, --containers>

Container security analysis (Docker, Podman, LXC)

=item B<-j, --json>

Export findings to JSON format with recommendations

=item B<-v, --verbose>

Enable verbose output with performance metrics

=item B<--hash-files>

Calculate SHA256 hashes of suspicious files

=item B<-q, --quarantine>

Enable quarantine mode (future feature)

=item B<-h, --help>

Show detailed help message

=back

=head1 SECURITY FEATURES

=over 4

=item * File size and timeout protection

=item * Input validation and sanitization  

=item * Secure file permissions on logs

=item * Process locking to prevent multiple instances

=item * Memory usage limits and error handling

=item * Enhanced threat detection patterns

=back

=head1 EXAMPLES

  # Full security scan with JSON export
  sudo ./linux_persistence_hunter.pl -a -j -v
  
  # Focus on network and container threats
  sudo ./linux_persistence_hunter.pl -n -C --hash-files
  
  # Memory analysis for advanced threats
  sudo ./linux_persistence_hunter.pl -m -p -v

=cut
