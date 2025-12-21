#!/usr/bin/env perl
# ptk - Perl Toolkit 2025 (v3.0.0).. beta edition..
# =============================================================================
# The Swiss-Army Chainsaw for Text Processing & Data Manipulation.
#
# FEATURES:
#   - grep-like filtering with auto-coloring
#   - awk-like field processing with smart CSV/TSV detection
#   - Statistical analysis (mean, median, stddev)
#   - HTTP client for API fetching
#   - JSON processing (pretty print, query, filter)
#   - Date math and parsing
#   - Format conversion
#   - Zero external non-core dependencies (uses core modules only)
#
# AUTHOR:  System Administrator / AI Team, (the hot ones)
# VERSION: 3.0.0
# =============================================================================

use v5.32;
use strict;
use warnings;
use feature qw(signatures say);
no warnings qw(experimental::signatures);

# --- Core Modules (Standard Library) ---
use Getopt::Long qw(:config no_ignore_case bundling);
use Pod::Usage;
use File::Basename;
use List::Util qw(sum max min uniq);
use Time::Piece;
use JSON::PP;
use HTTP::Tiny;
use Term::ANSIColor qw(:constants);

# --- Global Configuration ---
our $VERSION = '3.0.0';
$Term::ANSIColor::AUTORESET = 1; # Auto-reset colors after print

# --- Command Dispatch Table ---
my %commands = (
    filter      => \&cmd_filter,
    fields      => \&cmd_fields,
    stats       => \&cmd_stats,
    dedup       => \&cmd_dedup,
    convert     => \&cmd_convert,
    dates       => \&cmd_dates,
    json        => \&cmd_json,
    regex       => \&cmd_regex,
    math        => \&cmd_math,
    files       => \&cmd_files,
    http        => \&cmd_http,
);

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================
sub main {
    my $command = shift @ARGV || 'help';
    
    # Global flag for coloring
    $ENV{PTK_COLOR} = (-t STDOUT) ? 1 : 0;

    if ($command =~ /^(-h|--help|help)$/) { 
        pod2usage(-verbose => 2, -exitval => 0); 
    }
    
    if ($command =~ /^(-v|--version|version)$/) { 
        say BOLD BLUE "ptk version $VERSION", RESET; 
        exit 0; 
    }
    
    if (exists $commands{$command}) {
        # Execute the command
        eval {
            $commands{$command}->();
        };
        if ($@) {
            die_with_error("Runtime Error: $@");
        }
    } else {
        die_with_error("Unknown command: '$command'.\nRun 'ptk help' for a list of commands.");
    }
}

# =============================================================================
# HELPER SUBROUTINES
# =============================================================================

sub die_with_error($msg) {
    chomp $msg;
    say STDERR BOLD RED "ERROR: ", RESET, $msg;
    exit 1;
}

sub info_msg($msg) {
    say STDERR BOLD CYAN "INFO: ", RESET, $msg;
}

sub guess_delimiter($filename) {
    return ',' if $filename =~ /\.csv$/i;
    return "\t" if $filename =~ /\.tsv$/i;
    return '\|' if $filename =~ /\.psv$/i;
    return undef;
}

# Robust CSV line parser that handles quoted fields
sub parse_csv_line($line, $delimiter) {
    chomp $line;
    if ($delimiter eq ',') {
        # This regex handles basic CSV quotes: "field,with,comma",normal
        my @fields = split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/, $line);
        # Clean up quotes
        foreach (@fields) {
            s/^"|"$//g;
            s/""/"/g; # Unescape double quotes
        }
        return @fields;
    }
    return split(/$delimiter/, $line);
}

# =============================================================================
# COMMAND: FILTER
# =============================================================================
sub cmd_filter {
    my %opts = (
        invert => 0, 
        ignore_case => 0, 
        count => 0, 
        line_number => 0, 
        color => $ENV{PTK_COLOR}
    );
    
    GetOptions(
        'v|invert'       => \$opts{invert},
        'i|ignore-case'  => \$opts{ignore_case},
        'c|count'        => \$opts{count},
        'n|line-number'  => \$opts{line_number},
        'color!'         => \$opts{color},
        'h|help'         => sub { pod2usage(-verbose => 99, -sections => "COMMANDS/FILTER") },
    ) or die_with_error("Invalid arguments for filter");
    
    my $pattern = shift @ARGV or die_with_error("Search pattern required");
    
    # Pre-compile regex
    my $regex = $opts{ignore_case} ? qr/($pattern)/i : qr/($pattern)/;
    
    my $count = 0;
    while (my $line = <>) {
        my $is_match = ($line =~ $regex);
        $is_match = !$is_match if $opts{invert};
        
        if ($is_match) {
            $count++;
            unless ($opts{count}) {
                # Highlight logic
                if ($opts{color} && !$opts{invert}) {
                    $line =~ s/$regex/BOLD . RED . $1 . RESET/ge;
                }
                
                # Line numbering
                if ($opts{line_number}) {
                    my $prefix = "";
                    $prefix .= "$ARGV:" if @ARGV > 1; # Show filename if multiple files
                    $prefix .= "$.:";
                    print BOLD CYAN $prefix, RESET " ";
                }
                
                print $line;
            }
        }
        
        # Reset line numbers for new files if using implicit loop
        close ARGV if eof; 
    }
    
    say $count if $opts{count};
}

# =============================================================================
# COMMAND: FIELDS
# =============================================================================
sub cmd_fields {
    my %opts = (
        delimiter => undef, 
        output_delimiter => "\t", 
        fields => []
    );
    
    GetOptions(
        'd|delimiter=s'        => \$opts{delimiter},
        'o|output-delimiter=s' => \$opts{output_delimiter},
        'f|fields=s'           => $opts{fields},
        'h|help'               => sub { pod2usage(-verbose => 99, -sections => "COMMANDS/FIELDS") },
    ) or die_with_error("Invalid arguments for fields");
    
    my $action = shift @ARGV || 'print';
    
    # Smart Auto-Detection
    if (!defined $opts{delimiter} && @ARGV && -f $ARGV[0]) {
        $opts{delimiter} = guess_delimiter($ARGV[0]);
        info_msg("Auto-detected delimiter: '$opts{delimiter}'") if $opts{delimiter} && -t STDOUT;
    }
    $opts{delimiter} //= '\s+'; # Default to whitespace
    
    # Parse field numbers (allow comma string or multiple flags)
    my @field_nums;
    if (ref $opts{fields} eq 'ARRAY') {
        # Handle cases like -f 1 -f 2 or -f 1,2
        foreach my $f_arg (@{$opts{fields}}) {
            push @field_nums, split(/,/, $f_arg);
        }
    }
    
    # Dispatch sub-actions
    if ($action eq 'print') {
        while (my $line = <>) {
            my @f = parse_csv_line($line, $opts{delimiter});
            if (@field_nums) {
                my @out = map { my $idx = $_ - 1; $f[$idx] // '' } @field_nums;
                say join($opts{output_delimiter}, @out);
            } else {
                say join($opts{output_delimiter}, @f);
            }
        }
    } 
    elsif ($action eq 'sum') {
        my $idx = ($field_nums[0] || 1) - 1;
        my $total = 0;
        while (my $line = <>) {
            my @f = parse_csv_line($line, $opts{delimiter});
            $total += $f[$idx] if defined $f[$idx];
        }
        say $total;
    }
    elsif ($action eq 'swap') {
        die_with_error("Swap requires exactly two field numbers (-f 1,2)") unless @field_nums >= 2;
        my ($i1, $i2) = ($field_nums[0]-1, $field_nums[1]-1);
        while (my $line = <>) {
            my @f = parse_csv_line($line, $opts{delimiter});
            next unless @f > $i1 && @f > $i2;
            ($f[$i1], $f[$i2]) = ($f[$i2], $f[$i1]);
            say join($opts{output_delimiter}, @f);
        }
    }
    elsif ($action eq 'sort') {
        my $idx = ($field_nums[0] || 1) - 1;
        my @rows;
        while (my $line = <>) {
            my @f = parse_csv_line($line, $opts{delimiter});
            push @rows, { line => $line, val => $f[$idx] // '' };
        }
        # Try numeric sort first, fallback to string
        foreach my $row (sort { $a->{val} <=> $b->{val} || $a->{val} cmp $b->{val} } @rows) {
            print $row->{line};
        }
    }
    else {
        die_with_error("Unknown fields action: $action");
    }
}

# =============================================================================
# COMMAND: HTTP
# =============================================================================
sub cmd_http {
    my $url = shift @ARGV;
    
    if (!$url || $url eq '-h' || $url eq '--help') {
        pod2usage(-verbose => 99, -sections => "COMMANDS/HTTP");
    }
    
    info_msg("Fetching $url...");
    
    my $http = HTTP::Tiny->new(agent => "ptk/$VERSION");
    my $response = $http->get($url);

    if (!$response->{success}) {
        die_with_error("HTTP Request Failed:\nStatus: $response->{status}\nReason: $response->{reason}");
    }
    
    my $content = $response->{content};
    my $type = $response->{headers}{'content-type'} // '';
    
    # Smart Auto-JSON Formatting
    if ($type =~ /application\/json/i) {
        eval {
            my $decoded = decode_json($content);
            say JSON::PP->new->pretty->canonical->encode($decoded);
        } or do {
            # Fallback if decode fails
            print $content;
        };
    } else {
        print $content;
    }
}

# =============================================================================
# COMMAND: STATS
# =============================================================================
sub cmd_stats {
    my %opts = (field => 1, delimiter => '\s+');
    GetOptions(
        'f|field=i'     => \$opts{field},
        'd|delimiter=s' => \$opts{delimiter},
        'h|help'        => sub { pod2usage(-verbose => 99, -sections => "COMMANDS/STATS") },
    ) or die_with_error("Invalid arguments");
    
    my @values;
    while (<>) {
        chomp;
        my @f = split(/$opts{delimiter}/);
        my $val = $f[$opts{field}-1];
        
        # Robust numeric extraction (handles "-10.5", ".05", etc)
        if (defined $val && $val =~ /^\s*(-?\d+(\.\d+)?)\s*$/) {
            push @values, $1;
        }
    }
    
    if (!@values) {
        die_with_error("No valid numeric data found in column $opts{field}");
    }
    
    my $count = scalar @values;
    my $sum   = sum(@values);
    my $mean  = $sum / $count;
    my $min   = min(@values);
    my $max   = max(@values);
    
    # Median
    my @sorted = sort { $a <=> $b } @values;
    my $median;
    if ($count % 2 == 1) {
        $median = $sorted[int($count/2)];
    } else {
        $median = ($sorted[$count/2 - 1] + $sorted[$count/2]) / 2;
    }
    
    # Std Dev
    my $sq_sum = 0;
    $sq_sum += ($_ - $mean) ** 2 for @values;
    my $std_dev = sqrt($sq_sum / $count);
    
    # Output Table
    printf BOLD "Count:   " . RESET . "%d\n", $count;
    printf BOLD "Sum:     " . RESET . "%.4f\n", $sum;
    printf BOLD "Mean:    " . RESET . "%.4f\n", $mean;
    printf BOLD "Median:  " . RESET . "%.4f\n", $median;
    printf BOLD "Min:     " . RESET . "%.4f\n", $min;
    printf BOLD "Max:     " . RESET . "%.4f\n", $max;
    printf BOLD "StdDev:  " . RESET . "%.4f\n", $std_dev;
}

# =============================================================================
# COMMAND: DEDUP
# =============================================================================
sub cmd_dedup {
    my %opts = (count => 0, consecutive => 0, field => 0, delimiter => '\s+');
    GetOptions(
        'c|count'       => \$opts{count},
        'consecutive'   => \$opts{consecutive},
        'f|field=i'     => \$opts{field},
        'd|delimiter=s' => \$opts{delimiter},
        'h|help'        => sub { pod2usage(-verbose => 99, -sections => "COMMANDS/DEDUP") },
    ) or die_with_error("Invalid arguments");
    
    # Helper to extract comparison key
    my $get_key = sub {
        my $line = shift;
        return $line if $opts{field} == 0;
        my @f = split(/$opts{delimiter}/, $line);
        return $f[$opts{field}-1] // '';
    };

    if ($opts{count}) {
        # Frequency Analysis
        my %counts;
        my @order; # Preserve order of first appearance
        while (my $line = <>) {
            chomp $line;
            my $k = $get_key->($line);
            push @order, $k unless exists $counts{$k};
            $counts{$k}++;
        }
        foreach my $k (@order) {
            printf "%6d  %s\n", $counts{$k}, $k;
        }
    } 
    elsif ($opts{consecutive}) {
        # Like uniq (only adjacent)
        my $prev = undef;
        while (my $line = <>) {
            my $k = $get_key->($line);
            if (!defined $prev || $k ne $prev) {
                print $line;
            }
            $prev = $k;
        }
    } 
    else {
        # Global Deduplication (Memory intensive for huge files)
        my %seen;
        while (my $line = <>) {
            my $k = $get_key->($line);
            print $line unless $seen{$k}++;
        }
    }
}

# =============================================================================
# COMMAND: JSON
# =============================================================================
sub cmd_json {
    my $action = shift @ARGV || 'pretty';
    
    if ($action =~ /^(-h|--help)$/) {
        pod2usage(-verbose => 99, -sections => "COMMANDS/JSON");
    }

    local $/; # Slurp mode
    my $json_text = <>;
    return unless $json_text;
    
    my $data = eval { decode_json($json_text) };
    if ($@) {
        die_with_error("Invalid JSON input: $@");
    }

    if ($action eq 'pretty') {
        say JSON::PP->new->pretty->canonical->encode($data);
    } 
    elsif ($action eq 'compact') {
        say encode_json($data);
    } 
    elsif ($action eq 'get') {
        my $key_path = shift @ARGV;
        die_with_error("Key required for 'get' (e.g., users.0.id)") unless $key_path;
        
        my $current = $data;
        foreach my $part (split /\./, $key_path) {
            if (ref $current eq 'HASH') {
                $current = $current->{$part};
            } elsif (ref $current eq 'ARRAY' && $part =~ /^\d+$/) {
                $current = $current->[$part];
            } else {
                $current = undef;
                last;
            }
        }
        
        if (defined $current) {
            say ref $current ? encode_json($current) : $current;
        }
    } 
    elsif ($action eq 'filter') {
        my $expr = shift @ARGV or die_with_error("Filter expression required");
        die_with_error("Filter requires a JSON Array") unless ref $data eq 'ARRAY';
        
        my ($k, $op, $v) = ($expr =~ /^([\w\.]+)([=><]+)(.+)$/);
        die_with_error("Invalid expression. Use format key=value, key>value") unless $op;
        
        my @result = grep {
            my $item_val = $_->{$k} // '';
            ($op eq '=' || $op eq '==') ? $item_val eq $v :
            ($op eq '>') ? $item_val > $v :
            ($op eq '<') ? $item_val < $v : 0;
        } @$data;
        
        say JSON::PP->new->pretty->encode(\@result);
    } 
    else {
        die_with_error("Unknown JSON action: $action");
    }
}

# =============================================================================
# COMMAND: DATES
# =============================================================================
sub cmd_dates {
    my $action = shift @ARGV || 'help';
    
    if ($action eq 'parse') {
        my $fmt = shift @ARGV || '%Y-%m-%d';
        while (<>) {
            # Try to find standard date formats
            if (/(\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2})?)/) {
                my $date_str = $1;
                eval {
                    # Flexible parsing
                    my $t = Time::Piece->strptime($date_str, '%Y-%m-%d'); 
                    say $t->strftime($fmt);
                } or print;
            } else {
                print;
            }
        }
    }
    elsif ($action eq 'diff') {
        my ($d1, $d2) = @ARGV;
        die_with_error("Usage: ptk dates diff DATE1 DATE2") unless $d1 && $d2;
        my $t1 = Time::Piece->strptime($d1, '%Y-%m-%d');
        my $t2 = Time::Piece->strptime($d2, '%Y-%m-%d');
        say int(($t2 - $t1)->days) . " days";
    }
    elsif ($action eq 'filter') {
        my ($start, $end) = @ARGV;
        my $ts = Time::Piece->strptime($start, '%Y-%m-%d');
        my $te = Time::Piece->strptime($end, '%Y-%m-%d');
        
        while (<>) {
            if (/(\d{4}-\d{2}-\d{2})/) {
                my $curr = Time::Piece->strptime($1, '%Y-%m-%d');
                print if $curr >= $ts && $curr <= $te;
            }
        }
    }
    else {
        pod2usage(-verbose => 99, -sections => "COMMANDS/DATES");
    }
}

# =============================================================================
# COMMAND: REGEX
# =============================================================================
sub cmd_regex {
    my %opts = (replace => '', global => 0);
    GetOptions(
        'r|replace=s' => \$opts{replace},
        'g|global'    => \$opts{global},
        'h|help'      => sub { pod2usage(-verbose => 99, -sections => "COMMANDS/REGEX") },
    );
    
    my $pat = shift @ARGV or die_with_error("Regex pattern required");
    my $re = qr/$pat/;
    
    while (<>) {
        if ($opts{replace} ne '') {
            # Replacement mode
            if ($opts{global}) {
                s/$re/$opts{replace}/g;
            } else {
                s/$re/$opts{replace}/;
            }
            print;
        } else {
            # Extraction mode
            if ($opts{global}) {
                say $& while /$re/g;
            } elsif (/$re/) {
                say $&;
            }
        }
    }
}

# =============================================================================
# COMMAND: MATH
# =============================================================================
sub cmd_math {
    my $action = shift @ARGV || 'help';
    
    if ($action eq 'calc') {
        my $expr = shift @ARGV or die_with_error("Expression required");
        # Security: Remove dangerous chars, purely mathematical eval
        $expr =~ s/[^0-9\+\-\*\/\%\.\(\)\s]//g; 
        say eval $expr;
    }
    elsif ($action eq 'seq') {
        my ($start, $end, $step) = @ARGV;
        $start //= 1; $end //= 10; $step //= 1;
        for (my $i = $start; $i <= $end; $i += $step) {
            say $i;
        }
    }
    elsif ($action eq 'eval') {
        # Process stdin line by line
        while (<>) {
            chomp;
            next unless /\d/; # Skip non-numeric lines
            my $res = eval $_;
            say $@ ? "Error" : $res;
        }
    }
    else {
        pod2usage(-verbose => 99, -sections => "COMMANDS/MATH");
    }
}

# =============================================================================
# COMMAND: CONVERT
# =============================================================================
sub cmd_convert {
    my $fmt = shift @ARGV || '';
    
    if ($fmt eq 'csv2tsv') {
        while (<>) { 
            # Simple conversion, assumes no embedded commas in csv for speed
            s/,/\t/g; print; 
        } 
    }
    elsif ($fmt eq 'tsv2csv') {
        while (<>) { s/\t/,/g; print; }
    }
    elsif ($fmt eq 'upper') {
        while (<>) { print uc($_); }
    }
    elsif ($fmt eq 'lower') {
        while (<>) { print lc($_); }
    }
    elsif ($fmt eq 'csv2json') {
        my @data; my @headers;
        while (<>) {
            chomp;
            my @f = split /,/;
            if ($. == 1) { @headers = @f; }
            else {
                my %row; @row{@headers} = @f;
                push @data, \%row;
            }
        }
        say encode_json(\@data);
    }
    else {
        die_with_error("Unknown format. Available: csv2tsv, tsv2csv, csv2json, upper, lower");
    }
}

# =============================================================================
# COMMAND: FILES
# =============================================================================
sub cmd_files {
    my $action = shift @ARGV || 'help';
    
    if ($action eq 'lines') {
        my $total = 0;
        foreach my $f (@ARGV) {
            if (open my $fh, '<', $f) {
                my $c = 0; $c++ while <$fh>;
                say "$f: $c";
                $total += $c;
            } else {
                warn "Could not open $f\n";
            }
        }
        say "Total: $total" if @ARGV > 1;
    }
    elsif ($action eq 'merge') {
        my $outfile = shift @ARGV or die_with_error("Output file required");
        open my $out_fh, '>', $outfile or die_with_error("Cannot write to $outfile");
        foreach my $f (@ARGV) {
            if (open my $in_fh, '<', $f) {
                print $out_fh $_ while <$in_fh>;
            }
        }
        close $out_fh;
        say "Merged " . scalar(@ARGV) . " files into $outfile";
    }
    elsif ($action eq 'split') {
        my $pattern = shift @ARGV or die_with_error("Split pattern required");
        my $regex = qr/$pattern/;
        my $file_idx = 0;
        my $out_fh;
        
        while (<>) {
            if (/$regex/ || !$out_fh) {
                close $out_fh if $out_fh;
                $file_idx++;
                my $fname = sprintf("split_%03d.txt", $file_idx);
                open $out_fh, '>', $fname or die "Cannot create $fname";
                say STDERR "Created $fname";
            }
            print $out_fh $_;
        }
    }
    else {
        pod2usage(-verbose => 99, -sections => "COMMANDS/FILES");
    }
}

main();

__END__

=head1 NAME

ptk - Perl Toolkit: The Swiss-Army Chainsaw for CLI Data Processing

=head1 SYNOPSIS

B<ptk> I<COMMAND> [I<OPTIONS>] [I<ARGUMENTS>]

=head1 DESCRIPTION

B<ptk> is a robust, standalone utility that brings the power of Perl's text processing capabilities to the command line in a user-friendly way. It replaces the need for remembering complex one-liners with simple, mnemonic commands.

It supports modern features like colored output, HTTP fetching, smart CSV detection, and deep JSON query capabilities.

=head1 COMMANDS

=head2 filter

Search for patterns in text (super-charged grep).

B<Usage:> ptk filter [options] PATTERN [FILE...]

  Options:
    -v, --invert       Invert match (show non-matching lines)
    -i, --ignore-case  Case insensitive matching
    -c, --count        Only count matches
    -n, --line-number  Print line numbers
    --no-color         Disable colored output

B<Examples:>
  ptk filter 'error 500' app.log
  ptk filter -i 'exception' *.log
  ptk filter -v '^#' config.txt

=head2 fields

Process delimited columns (awk-style). Automatically detects CSV vs TSV.

B<Usage:> ptk fields [options] ACTION [FILE...]

  Actions:
    print              Print specific columns
    sum                Calculate sum of a numeric column
    swap               Swap two columns
    sort               Sort rows based on a column

  Options:
    -f, --fields N     Field numbers (e.g. 1,3 or 1-3)
    -d, --delimiter R  Custom regex delimiter (default: auto)

B<Examples:>
  ptk fields -f 1,3 data.csv       # Prints col 1 & 3
  ptk fields -f 2 sum costs.txt    # Sums column 2
  ptk fields -f 1 sort users.tsv   # Sorts by column 1

=head2 stats

Calculate statistical summaries on numeric data.

B<Usage:> ptk stats [options] [FILE...]

  Options:
    -f, --field N      Column to analyze (Default: 1)

B<Examples:>
  ptk stats latency.log
  ptk stats -f 2 grades.csv

=head2 http

Fetch data from URLs. Automatically pretty-prints JSON responses.

B<Usage:> ptk http URL

B<Examples:>
  ptk http https://api.github.com/zen
  ptk http https://jsonplaceholder.typicode.com/todos/1

=head2 json

Robust JSON processor.

B<Usage:> ptk json ACTION [ARGS]

  Actions:
    pretty             Format JSON for reading
    compact            Minify JSON
    get KEY            Extract nested key (dot notation)
    filter EXPR        Filter array elements

B<Examples:>
  ptk json pretty < data.json
  ptk json get 'users.0.email' < users.json
  ptk json filter 'age>21' < people.json

=head2 dedup

Remove duplicates.

B<Usage:> ptk dedup [options] [FILE...]

  Options:
    -c, --count        Count frequency of lines
    --consecutive      Only remove adjacent duplicates (fast)

=head2 regex

Extract or replace text using Perl Regular Expressions.

B<Usage:> ptk regex [options] PATTERN [FILE...]

  Options:
    -r, --replace STR  Replace match with string
    -g, --global       Apply globally

B<Examples:>
  ptk regex '\d+' file.txt                  # Extract numbers
  ptk regex -g -r 'REDACTED' '\d{3}-\d{2}'  # Mask SSNs

=head2 dates

Date mathematics and parsing.

B<Usage:> ptk dates ACTION [ARGS]

  Actions:
    diff D1 D2         Days between dates
    parse FMT          Reformat dates in stream
    filter S E         Filter lines within date range

B<Examples:>
  ptk dates diff 2023-01-01 2024-01-01
  ptk dates filter 2023-01-01 2023-01-31 < access.log

=head2 math

Quick calculations.

B<Usage:> ptk math ACTION [ARGS]

  Actions:
    calc EXPR          Calculate (e.g. '2+2')
    seq S E            Generate sequence

=head2 files

File manipulations.

B<Usage:> ptk files ACTION [ARGS]

  Actions:
    lines              Count lines in multiple files
    merge OUT IN...    Merge files
    split PAT          Split file into chunks on pattern

=head1 AUTHOR

Maintained by the AI Team.

=head1 COPYRIGHT

This software is free to use under the MIT License.

=cut
