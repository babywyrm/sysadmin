#!/usr/bin/env perl
use strict;
use warnings;
use Mojolicious::Lite -signatures;
use File::Basename qw(dirname);
use File::Spec;
use Cwd qw(realpath);

# -----------------------------------------------------
# Configuration
# -----------------------------------------------------
my $AUTH_TOKEN = $ENV{ADMIN_TOKEN} // "changeme123";   # Override via env
my $ROOT       = realpath(".");                         # File root

# -----------------------------------------------------
# Helpers
# -----------------------------------------------------
helper require_auth => sub ($c) {
    my $hdr = $c->req->headers->header("X-Auth-Token") // "";

    if ($hdr ne $AUTH_TOKEN) {
        $c->render(
            status => 401,
            json   => { error => "Unauthorized" },
        );
        return undef;
    }
    return 1;
};

helper safe_path => sub ($c, $path) {
    # Normalize requested file path
    $path =~ s{\.\.}{ }g;    # forbid traversal
    my $full = realpath(File::Spec->catfile($ROOT, $path));

    # Ensure it stays inside root
    return undef unless $full && index($full, $ROOT) == 0;
    return $full;
};

# -----------------------------------------------------
# Routes
# -----------------------------------------------------

# Health check
get '/health' => sub ($c) {
    $c->render(json => { status => "ok", time => time() });
};

# Basic server info
get '/info' => sub ($c) {
    return unless $c->require_auth;

    $c->render(json => {
        perl_version => $],
        root         => $ROOT,
        hostname     => $c->req->url->to_abs->host,
        uptime       => `uptime`,
    });
};

# List files in root
get '/file/list' => sub ($c) {
    return unless $c->require_auth;

    opendir(my $dh, $ROOT) or return $c->render(
        status => 500,
        json   => { error => "Unable to open directory" }
    );

    my @files = grep { $_ ne "." && $_ ne ".." } readdir($dh);
    closedir($dh);

    $c->render(json => { root => $ROOT, files => \@files });
};

# Serve one file safely
get '/file/view/*path' => sub ($c) {
    return unless $c->require_auth;

    my $req_path = $c->stash('path');
    my $full = $c->safe_path($req_path);

    unless ($full && -f $full) {
        return $c->render(
            status => 404,
            json   => { error => "File not found" }
        );
    }

    $c->render_file($full);
};

# -----------------------------------------------------
# Start server
# -----------------------------------------------------
app->start;
