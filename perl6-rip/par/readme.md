# Comprehensive Perl PAR Toolkit Examples and Snippets

## Basic PAR Usage Examples

### 1. Creating a Simple Standalone Executable

```perl
# Compile script.pl into an executable
pp -o myapp.exe script.pl

# Automatically include required modules
pp -o myapp.exe -M JSON::XS -M LWP::UserAgent script.pl

# Include module trees
pp -o myapp.exe -M Moose:: script.pl
```

### 2. Including Resources in PAR Files

```perl
# Include individual files
pp -o myapp.exe -a config.json -a template.html script.pl

# Include entire directories
pp -o myapp.exe -a /path/to/data/ script.pl

# Include and rename resources
pp -o myapp.exe -a template.html:html/main.tpl script.pl
```

### 3. Basic PAR Archive (Without Executable)

```perl
# Create a PAR archive without making it executable
pp -p -o mylib.par Module.pm

# Use a PAR archive in code
use PAR 'mylib.par';
require Module;
```

## Advanced Compilation Options

### 4. Platform-Specific Compilation

```perl
# Create Windows executable with icon
pp -o myapp.exe -I lib -g --icon=app.ico script.pl

# Create GUI application (no console)
pp -o myapp.exe --gui script.pl

# Create executable with custom version info (Windows)
pp -o myapp.exe --versioninfo "FileVersion=1.2.3.4;ProductName=MyApp" script.pl
```

### 5. Compression Options

```perl
# Set compression level (0-9)
pp -o myapp.exe -z 9 script.pl  # Maximum compression

# Disable compression
pp -o myapp.exe -z 0 script.pl
```

### 6. Filtering Modules

```perl
# Include specific module versions
pp -o myapp.exe -x -M Module::Name~1.23 script.pl

# Exclude certain modules
pp -o myapp.exe -X Module::To::Exclude script.pl

# Force inclusion of modules that may be missed
pp -o myapp.exe -f -M Crypto::Module script.pl
```

## Working with PAR in Code

### 7. Loading Modules from PAR

```perl
use PAR;

# Load a module from PAR archive
require PAR;
PAR::Heavy::_find_par_last('myapp.par', 'Module/Name.pm');

# Access files inside PAR
my $data = PAR::read_file('data/config.json');
```

### 8. Creating a PAR Archive Programmatically

```perl
use Archive::Zip;
use PAR::Filter;

# Create a PAR file programmatically
my $zip = Archive::Zip->new();
$zip->addFile('script.pl', 'script.pl');
$zip->addDirectory('lib/');
$zip->writeToFileNamed('myapp.par');
```

### 9. Detecting PAR Environment

```perl
# Detect if running from PAR
sub is_par {
    return defined $ENV{PAR_TEMP} && length $ENV{PAR_TEMP};
}

# Get PAR temp directory
sub par_temp {
    return $ENV{PAR_TEMP} if is_par();
    return undef;
}

print "Running from PAR\n" if is_par();
```

## Custom PAR Build Systems

### 10. Makefile for Building PAR Executables

```perl
#!/usr/bin/perl
# build.pl - Custom build script for PAR

use strict;
use warnings;
use File::Find;
use File::Path qw(make_path);

my $VERSION = '1.0.0';
my @modules = qw(DBI DBD::SQLite Moose::Util Config::Simple);
my @resources = ('templates', 'config.json', 'data');

# Create build directory
make_path('build');

# Build command
my $cmd = "pp -o build/myapp-$VERSION.exe";
$cmd .= " -M $_" for @modules;
$cmd .= " -a $_" for @resources;
$cmd .= " -I lib";
$cmd .= " -z 9";
$cmd .= " bin/app.pl";

print "Building executable: $cmd\n";
system($cmd);
```

### 11. Dynamic Module Detection

```perl
#!/usr/bin/perl
# scan_deps.pl - Scan for dependencies

use strict;
use warnings;
use Module::ScanDeps;
use Data::Dumper;

# Scan script for dependencies
my $deps = scan_deps(
    files   => ['app.pl'],
    recurse => 1,
);

# Print module list for pp command
my @modules = sort keys %$deps;
print "-M $_\n" for @modules;

# Generate pp command
my $pp_cmd = "pp -o app.exe " . join(" ", map {"-M $_"} @modules) . " app.pl";
print "\nFull command:\n$pp_cmd\n";
```

## Working with Resources in PAR Applications

### 12. Reading Packaged Resources

```perl
use PAR;
use JSON::XS;

# Read a configuration file from the PAR archive
sub get_config {
    my $config_file = 'config.json';
    my $config_path;
    
    if ($ENV{PAR_TEMP}) {
        # We're running from a PAR archive
        $config_path = "$ENV{PAR_TEMP}/inc/$config_file";
    } else {
        # We're running from source
        $config_path = $config_file;
    }
    
    open my $fh, '<', $config_path or die "Cannot open config: $!";
    local $/;
    my $json = <$fh>;
    close $fh;
    
    return decode_json($json);
}

my $config = get_config();
print "Config loaded: ", $config->{app_name}, "\n";
```

### 13. Working with Templates in PAR

```perl
use PAR;
use Template;

# Helper to locate template files in both PAR and normal environments
sub get_template_path {
    my ($template_name) = @_;
    
    if ($ENV{PAR_TEMP}) {
        return "$ENV{PAR_TEMP}/inc/templates/$template_name";
    } else {
        return "templates/$template_name";
    }
}

# Process a template
sub process_template {
    my ($template_name, $vars) = @_;
    
    my $template = Template->new({
        INCLUDE_PATH => $ENV{PAR_TEMP} ? "$ENV{PAR_TEMP}/inc/templates" : "templates",
    });
    
    my $output = '';
    $template->process($template_name, $vars, \$output) 
        or die $template->error();
        
    return $output;
}

my $html = process_template('user.html', { name => 'John', age => 30 });
print $html;
```

## Advanced PAR Techniques

### 14. Custom PAR Startup Script

```perl
#!/usr/bin/perl
# parl.pl - Custom PAR loader

use strict;
use warnings;
use FindBin;
use PAR;

# Find all PAR files in the application directory
my @par_files = glob("$FindBin::Bin/*.par");

# Load each PAR file
foreach my $par (@par_files) {
    print "Loading PAR: $par\n";
    PAR->import($par);
}

# Run the requested script
my $script = shift @ARGV || 'main.pl';
if (-f $script) {
    do $script;
} else {
    die "Cannot find script: $script";
}
```

### 15. Self-Extracting PAR

```perl
#!/usr/bin/perl
# make_self_extract.pl - Create a self-extracting PAR

use strict;
use warnings;
use PAR::Packer;
use File::Copy;

# Create PAR archive
system("pp -p -o app.par lib/App.pm script.pl");

# Create the self-extracting script
open my $out, '>', 'extract.pl' or die "Cannot write: $!";
print $out <<'EOF';
#!/usr/bin/perl
use strict;
use warnings;
use Archive::Zip;

# Extract embedded PAR archive
my $zip = Archive::Zip->new();
$zip->read($0) == Archive::Zip::AZ_OK or die "Cannot read archive";
$zip->extractTree('', 'extracted/');
print "Extracted PAR to ./extracted/\n";
__DATA__
EOF
close $out;

# Append the PAR archive to the script
open my $self, '>>', 'extract.pl' or die "Cannot append: $!";
open my $par, '<', 'app.par' or die "Cannot read PAR: $!";
binmode $self;
binmode $par;
my $buffer;
while (read($par, $buffer, 4096)) {
    print $self $buffer;
}
close $par;
close $self;
chmod 0755, 'extract.pl';
```

### 16. Multi-Platform PAR Build

```perl
#!/usr/bin/perl
# build_multi.pl - Build for multiple platforms

use strict;
use warnings;

my $script = 'app.pl';
my $version = '1.0.0';
my @modules = qw(DBI Moose Template);
my @resources = qw(templates config);

# Common options
my $common_opts = join(' ', 
    (map { "-M $_" } @modules),
    (map { "-a $_" } @resources),
    "-I lib",
    "-z 9"
);

# Platform-specific builds
my %builds = (
    'win32' => {
        output => "app-$version-win32.exe",
        opts   => "--gui --icon=app.ico"
    },
    'linux' => {
        output => "app-$version-linux",
        opts   => ""
    },
    'macos' => {
        output => "app-$version-macos",
        opts   => ""
    }
);

# Only build for current platform by default
my $current_platform = $^O =~ /MSWin/ ? 'win32' : 
                      ($^O =~ /darwin/ ? 'macos' : 'linux');

# Build executable
my $build = $builds{$current_platform};
my $cmd = "pp -o $build->{output} $common_opts $build->{opts} $script";

print "Building for $current_platform: $cmd\n";
system($cmd);
```

## PAR Plugin System

### 17. Plugin System with PAR

```perl
# app.pl - Main application with plugin system
use strict;
use warnings;
use File::Find;
use PAR;

# Load all plugin PAR files
sub load_plugins {
    my $plugin_dir = 'plugins';
    my @plugins;
    
    find(sub {
        return unless /\.par$/;
        my $plugin_path = $File::Find::name;
        print "Loading plugin: $plugin_path\n";
        
        # Import the PAR file
        PAR->import($plugin_path);
        
        # Try to load the plugin main module
        my $plugin_name = $_;
        $plugin_name =~ s/\.par$//;
        my $module = "Plugin::$plugin_name";
        
        eval "require $module";
        if ($@) {
            warn "Failed to load plugin $plugin_name: $@";
        } else {
            push @plugins, $module->new();
        }
    }, $plugin_dir);
    
    return \@plugins;
}

# Main application
my $plugins = load_plugins();
print "Loaded ", scalar(@$plugins), " plugins\n";

# Invoke plugin hooks
foreach my $plugin (@$plugins) {
    $plugin->initialize();
}

# Plugin definition example (saved as plugins/MyPlugin.par)
package Plugin::MyPlugin;
use strict;
use warnings;

sub new {
    my $class = shift;
    return bless {}, $class;
}

sub initialize {
    my $self = shift;
    print "MyPlugin initialized\n";
}

1;
```

## Testing PAR Packages

### 18. PAR Testing Framework

```perl
#!/usr/bin/perl
# test_par.pl - Test PAR packages

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use IPC::Run3;

# Create a temporary directory for extracting
my $temp_dir = tempdir(CLEANUP => 1);

# Test if executable runs
sub test_executable {
    my ($exe_path, $args, $exp_output) = @_;
    
    ok(-f $exe_path, "Executable exists: $exe_path");
    ok(-x $exe_path, "Executable has execute permissions");
    
    my $output;
    run3([$exe_path, @$args], \undef, \$output, \my $stderr);
    my $exit_code = $? >> 8;
    
    is($exit_code, 0, "Executable ran successfully");
    like($output, $exp_output, "Output matches expected pattern");
    
    return $output;
}

# Test if resource is packaged
sub test_resource {
    my ($exe_path, $resource_path) = @_;
    
    # Extract the PAR
    my $extract_cmd = "pp -u -o $temp_dir $exe_path";
    system($extract_cmd);
    
    ok(-e "$temp_dir/$resource_path", "Resource exists: $resource_path");
    
    return -e "$temp_dir/$resource_path";
}

# Test the application
test_executable("build/app.exe", [], qr/Application started/);
test_resource("build/app.exe", "config.json");

done_testing();
```

## PAR with Database Applications

### 19. SQLite Database in PAR

```perl
#!/usr/bin/perl
# db_app.pl - PAR application with embedded SQLite database

use strict;
use warnings;
use DBI;
use File::Copy;
use File::Spec;

# Get database path - handles both PAR and normal execution
sub get_db_path {
    my $db_file = 'data.db';
    
    if ($ENV{PAR_TEMP}) {
        # We're in a PAR environment
        my $temp_db = File::Spec->catfile($ENV{PAR_TEMP}, 'inc', $db_file);
        my $local_db = $db_file;
        
        # Copy the database to local directory if it doesn't exist
        if (-f $temp_db && (!-f $local_db || -M $local_db > -M $temp_db)) {
            copy($temp_db, $local_db) or die "Cannot copy DB: $!";
        }
        
        return $local_db;
    } else {
        # Regular environment
        return $db_file;
    }
}

# Connect to database
my $db_path = get_db_path();
my $dbh = DBI->connect("dbi:SQLite:dbname=$db_path", "", "", 
                     { RaiseError => 1, AutoCommit => 1 });

# Use the database
my $sth = $dbh->prepare("SELECT * FROM users");
$sth->execute();
while (my $row = $sth->fetchrow_hashref) {
    print "User: $row->{username}, Email: $row->{email}\n";
}

$dbh->disconnect();
```

## PAR Update System

### 20. Self-Updating PAR Application

```perl
#!/usr/bin/perl
# updater.pl - Self-updating PAR application

use strict;
use warnings;
use LWP::UserAgent;
use File::Copy;
use Digest::SHA qw(sha256_hex);
use JSON::XS;

my $VERSION = '1.0.0';
my $UPDATE_URL = 'https://example.com/updates/';

# Check for updates
sub check_for_updates {
    my $ua = LWP::UserAgent->new;
    $ua->timeout(10);
    
    # Get the version info
    my $response = $ua->get("$UPDATE_URL/version.json");
    return if !$response->is_success;
    
    my $info = decode_json($response->decoded_content);
    return if !$info->{version};
    
    # Compare versions
    if ($info->{version} gt $VERSION) {
        print "New version available: $info->{version}\n";
        print "Current version: $VERSION\n";
        print "Do you want to update? (y/n): ";
        my $answer = <STDIN>;
        chomp($answer);
        
        if (lc($answer) eq 'y') {
            download_update($info);
        }
    } else {
        print "You have the latest version.\n";
    }
}

# Download and apply update
sub download_update {
    my ($info) = @_;
    my $ua = LWP::UserAgent->new;
    
    print "Downloading update...\n";
    my $download_url = "$UPDATE_URL/$info->{filename}";
    my $response = $ua->get($download_url, ':content_file' => "update.exe");
    
    if (!$response->is_success) {
        print "Failed to download update: ", $response->status_line, "\n";
        return;
    }
    
    # Verify checksum
    open my $fh, '<', "update.exe" or die "Cannot open downloaded file: $!";
    binmode $fh;
    my $data = do { local $/; <$fh> };
    close $fh;
    
    my $checksum = sha256_hex($data);
    if ($checksum ne $info->{checksum}) {
        print "Checksum verification failed!\n";
        unlink "update.exe";
        return;
    }
    
    # Prepare for update
    print "Update downloaded successfully.\n";
    print "The application will now exit and complete the update.\n";
    
    # Create update script
    open my $script, '>', "update.bat" or die "Cannot create update script: $!";
    print $script <<'EOF';
@echo off
timeout /t 2 /nobreak > NUL
move /y update.exe app.exe
start app.exe
del update.bat
EOF
    close $script;
    
    # Execute update script and exit
    system("start update.bat");
    exit;
}

# Main application logic
print "Application v$VERSION starting...\n";
check_for_updates();

# Rest of application
print "Application running...\n";
```

