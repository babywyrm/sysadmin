

https://nemesis.sh/posts/movable-type-0day/

PERL THO



 ```
sub mt_new {
    my $cfg
        = MT::Util::is_mod_perl1()
        ? Apache->request->dir_config('MTConfig')
        : ( $ENV{MT_CONFIG} || $MT::XMLRPCServer::MT_DIR . '/mt-config.cgi' );
	# ! This creates a new MT instance ! (that also acts as XMLRPCServer)
    my $mt = MT->new( Config => $cfg )
        or die MT::XMLRPCServer::_fault( MT->errstr );

    $mt->request->reset();

    $mt->config( 'DeleteFilesAfterRebuild', 0, 0 );

    $mt->run_callbacks( 'init_app', $mt, { App => 'xmlrpc' } );
    $mt;
}






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
