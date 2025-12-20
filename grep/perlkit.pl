#!/usr/bin/env perl
# ptk - Perl Toolkit 2025
# A comprehensive CLI utility collection for text processing .. sorta

use v5.32;
use strict;
use warnings;
use feature qw(signatures say);
no warnings qw(experimental::signatures);

use Getopt::Long qw(:config no_ignore_case bundling);
use Pod::Usage;
use File::Basename;
use List::Util qw(sum max min uniq);
use Time::Piece;
use JSON::PP;

our $VERSION = '1.0.0';

# Command dispatch table
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
);

# Main entry point
sub main {
    my $command = shift @ARGV || 'help';
    
    if ($command eq 'help' || $command eq '-h' || $command eq '--help') {
        show_help();
        exit 0;
    }
    
    if ($command eq 'version' || $command eq '-v' || $command eq '--version') {
        say "ptk version $VERSION";
        exit 0;
    }
    
    if (exists $commands{$command}) {
        $commands{$command}->();
    } else {
        say STDERR "Unknown command: $command";
        say STDERR "Run 'ptk help' for usage information";
        exit 1;
    }
}

#############################################################################
# FILTER COMMANDS
#############################################################################

sub cmd_filter {
    my %opts = (
        invert => 0,
        ignore_case => 0,
        count => 0,
        line_number => 0,
    );
    
    GetOptions(
        'v|invert'       => \$opts{invert},
        'i|ignore-case'  => \$opts{ignore_case},
        'c|count'        => \$opts{count},
        'n|line-number'  => \$opts{line_number},
        'h|help'         => sub { filter_help(); exit 0 },
    ) or die "Error in command line arguments\n";
    
    my $pattern = shift @ARGV or die "Pattern required\n";
    my $regex = $opts{ignore_case} ? qr/$pattern/i : qr/$pattern/;
    
    my $count = 0;
    while (my $line = <>) {
        my $matches = $line =~ $regex;
        $matches = !$matches if $opts{invert};
        
        if ($matches) {
            $count++;
            unless ($opts{count}) {
                print "$ARGV:$.: " if $opts{line_number} && @ARGV > 1;
                print "$.: " if $opts{line_number} && @ARGV <= 1;
                print $line;
            }
        }
    }
    
    say $count if $opts{count};
}

sub filter_help {
    say "Usage: ptk filter [OPTIONS] PATTERN [FILE...]";
    say "";
    say "Search for PATTERN in files (or stdin)";
    say "";
    say "Options:";
    say "  -v, --invert         Invert match (show non-matching lines)";
    say "  -i, --ignore-case    Case-insensitive matching";
    say "  -c, --count          Only print count of matches";
    say "  -n, --line-number    Print line numbers";
    say "";
    say "Examples:";
    say "  ptk filter 'error' app.log";
    say "  ptk filter -i 'warning' *.log";
    say "  ptk filter -v '^#' config.txt";
}

#############################################################################
# FIELD PROCESSING COMMANDS
#############################################################################

sub cmd_fields {
    my %opts = (
        delimiter => '\s+',
        output_delimiter => ' ',
        fields => [],
    );
    
    GetOptions(
        'd|delimiter=s'        => \$opts{delimiter},
        'o|output-delimiter=s' => \$opts{output_delimiter},
        'f|fields=s'           => $opts{fields},
        'h|help'               => sub { fields_help(); exit 0 },
    ) or die "Error in command line arguments\n";
    
    my $action = shift @ARGV || 'print';
    
    if ($action eq 'print') {
        fields_print(\%opts);
    } elsif ($action eq 'sum') {
        fields_sum(\%opts);
    } elsif ($action eq 'swap') {
        fields_swap(\%opts);
    } elsif ($action eq 'sort') {
        fields_sort(\%opts);
    } else {
        die "Unknown action: $action\n";
    }
}

sub fields_print(%opts) {
    my $opts = shift;
    my @field_nums = @{$opts->{fields}};
    
    while (<>) {
        chomp;
        my @fields = split(/$opts->{delimiter}/, $_);
        
        if (@field_nums) {
            my @selected = map { 
                my $idx = $_ - 1;
                $idx >= 0 && $idx < @fields ? $fields[$idx] : '' 
            } @field_nums;
            say join($opts->{output_delimiter}, @selected);
        } else {
            say join($opts->{output_delimiter}, @fields);
        }
    }
}

sub fields_sum(%opts) {
    my $opts = shift;
    my $field_num = $opts->{fields}[0] || 1;
    my $total = 0;
    
    while (<>) {
        chomp;
        my @fields = split(/$opts->{delimiter}/, $_);
        my $idx = $field_num - 1;
        $total += $fields[$idx] if $idx >= 0 && $idx < @fields;
    }
    
    say $total;
}

sub fields_swap(%opts) {
    my $opts = shift;
    my ($f1, $f2) = @{$opts->{fields}};
    die "Need two field numbers to swap\n" unless $f1 && $f2;
    
    while (<>) {
        chomp;
        my @fields = split(/$opts->{delimiter}/, $_);
        ($fields[$f1-1], $fields[$f2-1]) = ($fields[$f2-1], $fields[$f1-1]);
        say join($opts->{output_delimiter}, @fields);
    }
}

sub fields_sort(%opts) {
    my $opts = shift;
    my $field_num = $opts->{fields}[0] || 1;
    my @lines;
    
    while (<>) {
        chomp;
        my @fields = split(/$opts->{delimiter}/, $_);
        push @lines, [$_, $fields[$field_num-1]];
    }
    
    for my $line (sort { $a->[1] cmp $b->[1] } @lines) {
        say $line->[0];
    }
}

sub fields_help {
    say "Usage: ptk fields [OPTIONS] ACTION [FILE...]";
    say "";
    say "Process and manipulate fields in text";
    say "";
    say "Actions:";
    say "  print              Print selected fields";
    say "  sum                Sum values in a field";
    say "  swap               Swap two fields";
    say "  sort               Sort lines by field value";
    say "";
    say "Options:";
    say "  -d, --delimiter REGEX       Field delimiter (default: whitespace)";
    say "  -o, --output-delimiter STR  Output delimiter (default: space)";
    say "  -f, --fields N[,N,...]      Field numbers (1-indexed)";
    say "";
    say "Examples:";
    say "  ptk fields print -f 1,3 data.txt";
    say "  ptk fields -d ',' print -f 2 data.csv";
    say "  ptk fields sum -f 4 numbers.txt";
    say "  ptk fields swap -f 1,2 data.txt";
    say "  ptk fields sort -f 3 data.txt";
}

#############################################################################
# STATISTICS COMMANDS
#############################################################################

sub cmd_stats {
    my %opts = (
        field => 1,
        delimiter => '\s+',
    );
    
    GetOptions(
        'f|field=i'      => \$opts{field},
        'd|delimiter=s'  => \$opts{delimiter},
        'h|help'         => sub { stats_help(); exit 0 },
    ) or die "Error in command line arguments\n";
    
    my @values;
    
    while (<>) {
        chomp;
        my @fields = split(/$opts{delimiter}/, $_);
        my $idx = $opts{field} - 1;
        push @values, $fields[$idx] if $idx >= 0 && $idx < @fields && $fields[$idx] =~ /^-?\d+\.?\d*$/;
    }
    
    unless (@values) {
        say "No numeric values found";
        exit 1;
    }
    
    my $count = @values;
    my $sum = sum(@values);
    my $mean = $sum / $count;
    my $min = min(@values);
    my $max = max(@values);
    
    # Calculate median
    my @sorted = sort { $a <=> $b } @values;
    my $median = $count % 2 
        ? $sorted[$count/2]
        : ($sorted[$count/2-1] + $sorted[$count/2]) / 2;
    
    # Calculate standard deviation
    my $sq_sum = sum(map { ($_ - $mean) ** 2 } @values);
    my $std_dev = sqrt($sq_sum / $count);
    
    printf "Count:   %d\n", $count;
    printf "Sum:     %.2f\n", $sum;
    printf "Mean:    %.2f\n", $mean;
    printf "Median:  %.2f\n", $median;
    printf "Min:     %.2f\n", $min;
    printf "Max:     %.2f\n", $max;
    printf "StdDev:  %.2f\n", $std_dev;
}

sub stats_help {
    say "Usage: ptk stats [OPTIONS] [FILE...]";
    say "";
    say "Calculate statistics on numeric data";
    say "";
    say "Options:";
    say "  -f, --field N        Field number to analyze (default: 1)";
    say "  -d, --delimiter STR  Field delimiter (default: whitespace)";
    say "";
    say "Example:";
    say "  ptk stats -f 3 data.txt";
}

#############################################################################
# DEDUPLICATION COMMANDS
#############################################################################

sub cmd_dedup {
    my %opts = (
        field => 0,
        delimiter => '\s+',
        count => 0,
        consecutive => 0,
    );
    
    GetOptions(
        'f|field=i'       => \$opts{field},
        'd|delimiter=s'   => \$opts{delimiter},
        'c|count'         => \$opts{count},
        'consecutive'     => \$opts{consecutive},
        'h|help'          => sub { dedup_help(); exit 0 },
    ) or die "Error in command line arguments\n";
    
    if ($opts{consecutive}) {
        dedup_consecutive(\%opts);
    } elsif ($opts{count}) {
        dedup_count(\%opts);
    } else {
        dedup_all(\%opts);
    }
}

sub dedup_all(%opts) {
    my $opts = shift;
    my %seen;
    
    while (<>) {
        my $key = get_dedup_key($_, $opts);
        print unless $seen{$key}++;
    }
}

sub dedup_consecutive(%opts) {
    my $opts = shift;
    my $prev_key = '';
    
    while (<>) {
        my $key = get_dedup_key($_, $opts);
        print unless $key eq $prev_key;
        $prev_key = $key;
    }
}

sub dedup_count(%opts) {
    my $opts = shift;
    my %count;
    my @lines;
    
    while (<>) {
        my $key = get_dedup_key($_, $opts);
        unless (exists $count{$key}) {
            push @lines, [$key, $_];
        }
        $count{$key}++;
    }
    
    for my $line (@lines) {
        my ($key, $text) = @$line;
        print "$count{$key} $text";
    }
}

sub get_dedup_key($line, $opts) {
    if ($opts->{field} > 0) {
        chomp(my $copy = $line);
        my @fields = split(/$opts->{delimiter}/, $copy);
        my $idx = $opts->{field} - 1;
        return $idx >= 0 && $idx < @fields ? $fields[$idx] : '';
    }
    return $line;
}

sub dedup_help {
    say "Usage: ptk dedup [OPTIONS] [FILE...]";
    say "";
    say "Remove duplicate lines";
    say "";
    say "Options:";
    say "  -f, --field N        Deduplicate by field (0 = whole line)";
    say "  -d, --delimiter STR  Field delimiter";
    say "  -c, --count          Show count of duplicates";
    say "  --consecutive        Only remove consecutive duplicates";
    say "";
    say "Examples:";
    say "  ptk dedup data.txt";
    say "  ptk dedup -f 2 data.txt";
    say "  ptk dedup --count data.txt";
}

#############################################################################
# CONVERSION COMMANDS
#############################################################################

sub cmd_convert {
    my $format = shift @ARGV or die "Format required\n";
    
    if ($format eq 'csv2tsv') {
        convert_csv2tsv();
    } elsif ($format eq 'tsv2csv') {
        convert_tsv2csv();
    } elsif ($format eq 'csv2json') {
        convert_csv2json();
    } elsif ($format eq 'json2csv') {
        convert_json2csv();
    } elsif ($format eq 'upper') {
        convert_upper();
    } elsif ($format eq 'lower') {
        convert_lower();
    } elsif ($format eq 'title') {
        convert_title();
    } else {
        die "Unknown format: $format\n";
    }
}

sub convert_csv2tsv {
    while (<>) {
        s/,/\t/g;
        print;
    }
}

sub convert_tsv2csv {
    while (<>) {
        s/\t/,/g;
        print;
    }
}

sub convert_csv2json {
    my @data;
    my @headers;
    
    while (<>) {
        chomp;
        my @fields = split /,/, $_;
        
        if ($. == 1) {
            @headers = @fields;
        } else {
            my %row;
            @row{@headers} = @fields;
            push @data, \%row;
        }
    }
    
    say encode_json(\@data);
}

sub convert_json2csv {
    local $/;
    my $json = <>;
    my $data = decode_json($json);
    
    if (ref $data eq 'ARRAY' && @$data > 0) {
        my @keys = keys %{$data->[0]};
        say join(',', @keys);
        
        for my $row (@$data) {
            say join(',', map { $row->{$_} // '' } @keys);
        }
    }
}

sub convert_upper {
    while (<>) {
        print uc($_);
    }
}

sub convert_lower {
    while (<>) {
        print lc($_);
    }
}

sub convert_title {
    while (<>) {
        s/\b(\w)/\u$1/g;
        print;
    }
}

#############################################################################
# DATE COMMANDS
#############################################################################

sub cmd_dates {
    my $action = shift @ARGV || 'help';
    
    if ($action eq 'parse') {
        dates_parse();
    } elsif ($action eq 'format') {
        dates_format();
    } elsif ($action eq 'diff') {
        dates_diff();
    } elsif ($action eq 'filter') {
        dates_filter();
    } else {
        dates_help();
    }
}

sub dates_parse {
    my $format = shift @ARGV || '%Y-%m-%d';
    
    while (<>) {
        if (/(\d{4}-\d{2}-\d{2})/) {
            my $t = Time::Piece->strptime($1, '%Y-%m-%d');
            say $t->strftime($format);
        } else {
            print;
        }
    }
}

sub dates_format {
    my $format = shift @ARGV || '%Y-%m-%d %H:%M:%S';
    
    while (<>) {
        if (/(\d+)/) {
            my $t = localtime($1);
            say $t->strftime($format);
        } else {
            print;
        }
    }
}

sub dates_diff {
    my ($date1, $date2) = @ARGV;
    die "Need two dates\n" unless $date1 && $date2;
    
    my $t1 = Time::Piece->strptime($date1, '%Y-%m-%d');
    my $t2 = Time::Piece->strptime($date2, '%Y-%m-%d');
    my $diff = $t2 - $t1;
    
    say int($diff->days) . " days";
}

sub dates_filter {
    my ($start, $end) = @ARGV;
    die "Need start and end dates\n" unless $start && $end;
    
    my $t_start = Time::Piece->strptime($start, '%Y-%m-%d');
    my $t_end = Time::Piece->strptime($end, '%Y-%m-%d');
    
    while (<>) {
        if (/(\d{4}-\d{2}-\d{2})/) {
            my $t = Time::Piece->strptime($1, '%Y-%m-%d');
            print if $t >= $t_start && $t <= $t_end;
        }
    }
}

sub dates_help {
    say "Usage: ptk dates ACTION [OPTIONS]";
    say "";
    say "Actions:";
    say "  parse [FORMAT]           Parse dates and reformat";
    say "  format [FORMAT]          Convert timestamps to dates";
    say "  diff DATE1 DATE2         Calculate difference";
    say "  filter START END         Filter lines by date range";
}

#############################################################################
# JSON COMMANDS
#############################################################################

sub cmd_json {
    my $action = shift @ARGV || 'pretty';
    
    if ($action eq 'pretty') {
        json_pretty();
    } elsif ($action eq 'compact') {
        json_compact();
    } elsif ($action eq 'get') {
        json_get();
    } elsif ($action eq 'filter') {
        json_filter();
    } else {
        json_help();
    }
}

sub json_pretty {
    local $/;
    my $json = <>;
    my $data = decode_json($json);
    say JSON::PP->new->pretty->canonical->encode($data);
}

sub json_compact {
    local $/;
    my $json = <>;
    my $data = decode_json($json);
    say encode_json($data);
}

sub json_get {
    my $key = shift @ARGV or die "Key required\n";
    
    local $/;
    my $json = <>;
    my $data = decode_json($json);
    
    my $value = get_nested_value($data, $key);
    say ref $value ? encode_json($value) : $value;
}

sub json_filter {
    my $expr = shift @ARGV or die "Expression required\n";
    
    local $/;
    my $json = <>;
    my $data = decode_json($json);
    
    if (ref $data eq 'ARRAY') {
        my @filtered = grep { eval_filter($_, $expr) } @$data;
        say encode_json(\@filtered);
    }
}

sub get_nested_value($data, $key) {
    my @parts = split /\./, $key;
    my $current = $data;
    
    for my $part (@parts) {
        if (ref $current eq 'HASH') {
            $current = $current->{$part};
        } elsif (ref $current eq 'ARRAY' && $part =~ /^\d+$/) {
            $current = $current->[$part];
        } else {
            return undef;
        }
    }
    
    return $current;
}

sub eval_filter($item, $expr) {
    # Simple field comparisons: field=value, field>value, etc.
    if ($expr =~ /^(\w+)\s*([=><]+)\s*(.+)$/) {
        my ($field, $op, $value) = ($1, $2, $3);
        my $field_val = $item->{$field} // '';
        
        if ($op eq '==' || $op eq '=') {
            return $field_val eq $value;
        } elsif ($op eq '>') {
            return $field_val > $value;
        } elsif ($op eq '<') {
            return $field_val < $value;
        }
    }
    return 1;
}

sub json_help {
    say "Usage: ptk json ACTION [OPTIONS]";
    say "";
    say "Actions:";
    say "  pretty               Pretty-print JSON";
    say "  compact              Compact JSON";
    say "  get KEY              Extract value by key (use dots for nesting)";
    say "  filter EXPR          Filter JSON array (e.g., 'age>25')";
    say "";
    say "Examples:";
    say "  ptk json pretty < data.json";
    say "  ptk json get 'user.name' < data.json";
    say "  ptk json filter 'age>25' < users.json";
}

#############################################################################
# REGEX COMMANDS
#############################################################################

sub cmd_regex {
    my %opts = (
        replace => '',
        global => 0,
    );
    
    GetOptions(
        'r|replace=s' => \$opts{replace},
        'g|global'    => \$opts{global},
        'h|help'      => sub { regex_help(); exit 0 },
    ) or die "Error in command line arguments\n";
    
    my $pattern = shift @ARGV or die "Pattern required\n";
    
    if ($opts{replace}) {
        regex_replace($pattern, $opts{replace}, $opts{global});
    } else {
        regex_extract($pattern, $opts{global});
    }
}

sub regex_extract($pattern, $global) {
    my $regex = qr/$pattern/;
    
    while (<>) {
        if ($global) {
            say $& while /$regex/g;
        } elsif (/$regex/) {
            say $&;
        }
    }
}

sub regex_replace($pattern, $replacement, $global) {
    my $regex = qr/$pattern/;
    
    while (<>) {
        if ($global) {
            s/$regex/$replacement/g;
        } else {
            s/$regex/$replacement/;
        }
        print;
    }
}

sub regex_help {
    say "Usage: ptk regex [OPTIONS] PATTERN [FILE...]";
    say "";
    say "Extract or replace using regex";
    say "";
    say "Options:";
    say "  -r, --replace STR    Replacement string";
    say "  -g, --global         Replace all occurrences";
    say "";
    say "Examples:";
    say "  ptk regex '\\d+' file.txt              # Extract numbers";
    say "  ptk regex -r 'X' -g '\\d+' file.txt   # Replace numbers with X";
}

#############################################################################
# MATH COMMANDS
#############################################################################

sub cmd_math {
    my $action = shift @ARGV || 'calc';
    
    if ($action eq 'calc') {
        math_calc();
    } elsif ($action eq 'seq') {
        math_seq();
    } elsif ($action eq 'eval') {
        math_eval();
    } else {
        math_help();
    }
}

sub math_calc {
    my $expr = shift @ARGV or die "Expression required\n";
    my $result = eval $expr;
    die "Error: $@\n" if $@;
    say $result;
}

sub math_seq {
    my ($start, $end, $step) = @ARGV;
    $start //= 1;
    $end //= 10;
    $step //= 1;
    
    for (my $i = $start; $i <= $end; $i += $step) {
        say $i;
    }
}

sub math_eval {
    while (<>) {
        chomp;
        my $result = eval $_;
        say "$_ = " . ($@ ? "Error: $@" : $result);
    }
}

sub math_help {
    say "Usage: ptk math ACTION [ARGS]";
    say "";
    say "Actions:";
    say "  calc EXPR                Calculate expression";
    say "  seq [START] END [STEP]   Generate sequence";
    say "  eval                     Evaluate expressions from stdin";
    say "";
    say "Examples:";
    say "  ptk math calc '2**10'";
    say "  ptk math seq 1 100 5";
}

#############################################################################
# FILE COMMANDS
#############################################################################

sub cmd_files {
    my $action = shift @ARGV || 'help';
    
    if ($action eq 'lines') {
        files_lines();
    } elsif ($action eq 'merge') {
        files_merge();
    } elsif ($action eq 'split') {
        files_split();
    } else {
        files_help();
    }
}

sub files_lines {
    my $total = 0;
    
    for my $file (@ARGV) {
        open my $fh, '<', $file or die "Can't open $file: $!\n";
        my $count = 0;
        $count++ while <$fh>;
        close $fh;
        
        say "$file: $count";
        $total += $count;
    }
    
    say "Total: $total" if @ARGV > 1;
}

sub files_merge {
    my $output = shift @ARGV or die "Output file required\n";
    open my $out, '>', $output or die "Can't open $output: $!\n";
    
    for my $file (@ARGV) {
        open my $in, '<', $file or die "Can't open $file: $!\n";
        print $out $_ while <$in>;
        close $in;
    }
    
    close $out;
    say "Merged " . scalar(@ARGV) . " files into $output";
}

sub files_split {
    my $pattern = shift @ARGV or die "Pattern required\n";
    my $regex = qr/$pattern/;
    my $count = 0;
    my $out;
    
    while (<>) {
        if (/$regex/) {
            close $out if $out;
            $count++;
            my $filename = sprintf("split_%03d.txt", $count);
            open $out, '>', $filename or die "Can't open $filename: $!\n";
            say STDERR "Created $filename";
        }
        print $out $_ if $out;
    }
    
    close $out if $out;
    say STDERR "Created $count files";
}

sub files_help {
    say "Usage: ptk files ACTION [ARGS]";
    say "";
    say "Actions:";
    say "  lines FILE...            Count lines in files";
    say "  merge OUT FILE...        Merge files";
    say "  split PATTERN [FILE]     Split on pattern";
}

#############################################################################
# HELP
#############################################################################

sub show_help {
    say "ptk - Perl Toolkit 2025";
    say "";
    say "Usage: ptk COMMAND [OPTIONS] [ARGS]";
    say "";
    say "Commands:";
    say "  filter     Search and filter text";
    say "  fields     Process delimited fields";
    say "  stats      Calculate statistics";
    say "  dedup      Remove duplicates";
    say "  convert    Convert between formats";
    say "  dates      Work with dates and times";
    say "  json       Process JSON data";
    say "  regex      Extract or replace with regex";
    say "  math       Mathematical operations";
    say "  files      File operations";
    say "";
    say "Run 'ptk COMMAND --help' for command-specific help";
    say "";
    say "Examples:";
    say "  ptk filter 'error' app.log";
    say "  ptk fields print -f 1,3 data.csv";
    say "  ptk stats -f 2 numbers.txt";
    say "  ptk json pretty < data.json";
    say "";
    say "Version: $VERSION";
}

# Run main
main() unless caller;

__END__

=head1 NAME

ptk - Perl Toolkit 2025

=head1 SYNOPSIS

  ptk COMMAND [OPTIONS] [ARGS]

=head1 DESCRIPTION

A comprehensive CLI toolkit for text processing, data manipulation,
and file operations using modern Perl.

=head1 AUTHOR

Your Name

=head1 LICENSE

MIT License

=cut
