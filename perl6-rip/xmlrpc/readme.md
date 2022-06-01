

https://nemesis.sh/posts/movable-type-0day/

PERL THO



    unless (($class eq 'main') || $class->can($method_name)
        || exists($INC{join '/', split /::/, $class . '.pm'})) {

        # allow all for static and only specified path for dynamic bindings
        local @INC = (($static ? @INC : ()), grep {!ref && m![/\\.]!};
        $self->dispatch_to());
        eval 'local $^W; ' . "require $class";
        die "Failed to access class ($class): $@" if $@;
        $self->dispatched($class) unless $static;
    }

    die "Denied access to method ($method_name) in class ($class)"
        unless $static || grep {/^$class$/} $self->dispatched;

    return ($class, $method_uri, $method_name);
}
