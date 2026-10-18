#!/usr/bin/env perl
use strict;
use warnings;
use Mojolicious::Lite -signatures;
use File::Basename qw(dirname);
use File::Spec;
use Cwd qw(realpath);
use Proc::ProcessTable;

# -----------------------------------------------------
# Configuration
# -----------------------------------------------------
my $AUTH_TOKEN     = $ENV{ADMIN_TOKEN} // "changeme123";  
my $ROOT           = realpath(".");     
my $UPLOAD_MAX_MB  = 5;                 # safe upload limit
my $LOG_DIR        = "/var/log";         # logs allowed for tailing
my $PROC_ENABLED   = 1;                  # toggle for process listing
my $METRICS_ENABLED= 1;                  # toggle for system metrics

# -----------------------------------------------------
# Helpers
# -----------------------------------------------------
helper require_auth => sub ($c) {
    my $hdr = $c->req->headers->header("X-Auth-Token") // "";
    if ($hdr ne $AUTH_TOKEN) {
        $c->render(status => 401, json => { error => "Unauthorized" });
        return undef;
    }
    return 1;
};

helper safe_path => sub ($c, $path) {
    $path =~ s{\.\.}{}g;    # remove traversal attempts
    my $full = realpath(File::Spec->catfile($ROOT, $path));
    return undef unless $full && index($full, $ROOT) == 0;
    return $full;
};

helper safe_log_path => sub ($c, $file) {
    $file =~ s{\.\.}{}g;
    my $full = realpath(File::Spec->catfile($LOG_DIR, $file));
    return undef unless $full && index($full, $LOG_DIR) == 0;
    return $full;
};

# -----------------------------------------------------
# Basic Routes
# -----------------------------------------------------

get '/health' => sub ($c) {
    $c->render(json => { status => "ok", time => time() });
};

get '/info' => sub ($c) {
    return unless $c->require_auth;

    $c->render(json => {
        perl_version => $],
        root         => $ROOT,
        hostname     => $c->req->url->to_abs->host,
        uptime       => scalar(`uptime 2>/dev/null`),
    });
};

get '/file/list' => sub ($c) {
    return unless $c->require_auth;

    opendir(my $dh, $ROOT)
        or return $c->render(status => 500, json => { error => "Cannot read dir" });

    my @files = grep { $_ ne "." && $_ ne ".." } readdir($dh);
    closedir($dh);

    $c->render(json => { root => $ROOT, files => \@files });
};

get '/file/view/*path' => sub ($c) {
    return unless $c->require_auth;

    my $p = $c->stash('path');
    my $full = $c->safe_path($p);

    unless ($full && -f $full) {
        return $c->render(status => 404, json => { error => "File not found" });
    }

    $c->render_file($full);
};

# -----------------------------------------------------
# File Upload
# -----------------------------------------------------

post '/file/upload' => sub ($c) {
    return unless $c->require_auth;

    my $upload = $c->req->upload('file');
    unless ($upload) {
        return $c->render(status => 400, json => { error => "no file provided" });
    }

    if ($upload->size > $UPLOAD_MAX_MB * 1024 * 1024) {
        return $c->render(status => 400, json => { error => "file too large" });
    }

    my $name = $upload->filename;
    $name =~ s{[^a-zA-Z0-9._-]}{}g;  # sanitize filename

    my $dest = File::Spec->catfile($ROOT, $name);
    $upload->move_to($dest);

    $c->render(json => {
        status => "ok",
        saved_as => $dest
    });
};

# -----------------------------------------------------
# Log Tailing
# -----------------------------------------------------

get '/logs/*file' => sub ($c) {
    return unless $c->require_auth;

    my $file = $c->stash('file');
    my $lines = $c->param('lines') // 50;
    $lines = 50 if $lines !~ /^\d+$/;  # sanitize

    my $path = $c->safe_log_path($file);
    unless ($path && -f $path) {
        return $c->render(status => 404, json => { error => "log not found" });
    }

    my @out = `tail -n $lines $path 2>/dev/null`;

    $c->render(json => {
        file  => $file,
        lines => scalar(@out),
        data  => \@out,
    });
};

# -----------------------------------------------------
# Process Listing
# -----------------------------------------------------

get '/processes' => sub ($c) {
    return unless $c->require_auth;
    return $c->render(status => 403, json => { error => "disabled" }) unless $PROC_ENABLED;

    my $table = Proc::ProcessTable->new;
    my @procs = map {{
        pid  => $_->pid,
        ppid => $_->ppid,
        uid  => $_->uid,
        gid  => $_->gid,
        cpu  => $_->pctcpu,
        mem  => $_->pctmem,
        size => $_->size,
        rss  => $_->rss,
        state => $_->state,
        cmndline => $_->cmndline,
    }} @{$table->table};

    $c->render(json => {
        count => scalar(@procs),
        processes => \@procs,
    });
};

# -----------------------------------------------------
# System Metrics
# -----------------------------------------------------

get '/metrics/system' => sub ($c) {
    return unless $c->require_auth;
    return $c->render(status => 403, json => { error => "disabled" }) unless $METRICS_ENABLED;

    my $load = [ split /\s+/, scalar(`uptime`) =~ /\bload averages?: (.+)$/ ? $1 : "" ];
    my $meminfo = do {
        my %h;
        if (open my $fh, '<', "/proc/meminfo") {
            while (<$fh>) {
                if (/^(\w+):\s+(\d+)/) { $h{$1} = $2; }
            }
            close $fh;
        }
        \%h;
    };

    $c->render(json => {
        load_avg => $load,
        memory_kb => $meminfo,
        timestamp => time(),
    });
};

# -----------------------------------------------------
# Start server
# -----------------------------------------------------
app->start;
