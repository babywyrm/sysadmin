#Take an arrayref of numbers or a delimited string and returns a list of start-end pairs for runs of values above a threshold

##
##

sub runencode {
        my ($probs,%opts) = @_;
        
        #Some default optional parameters
        $opts{delimiter} //= ','; 
        $opts{threshold} //= 0.5;
        $opts{cmp} //= sub {$_[0] >= $_[1]};

        #If a string was passed split it into values
        $probs = [split /$opts{delimiter}/, $probs] if (ref $probs ne 'ARRAY');
        my @ranges = ();
        my $index = 1;
        my $start = undef;
        my $end = undef;

        foreach my $prob (@$probs) {
                if ($opts{cmp}->($prob, $opts{threshold})) {
                        $start = $index unless defined $start;
                } else {
                        $end = $index-1;
                        push @ranges, [$start, $end] if defined $start;
                        $start = undef;
                }
                $index++;
        }

        #Deal with the edge case where there is a region at the end of the sequence
        if ($probs->[-1] >= 0.5) {
                        $end = $index-1;
                        push @ranges, [$start, $end] if defined $start;
        }

        return @ranges;
}

##
##
##
