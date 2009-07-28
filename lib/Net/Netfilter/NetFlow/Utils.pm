package Net::Netfilter::NetFlow::Utils;

use strict;
use warnings FATAL => 'all';

use base 'Exporter';
our @EXPORT = qw(
    load_config
    format_args
    can_run
    merge_hashes
    quit_with_help
);

use File::ShareDir;
use Config::Any;

my $VERSION = '1.01';
$VERSION = eval $VERSION; # numify for warning-free dev releases

# use Config::Any to load a configuration file
sub load_config {
    my $file = shift;
    my $path = ($file =~ m{^/}
        ? (File::ShareDir::dist_dir('Net-Nfflowd') .'/') : '');
    my $name = $path . $file;

    my $config = eval{ Config::Any->load_files({
        files => [$name],
        flatten_to_hash => 1,
    })->{$name} };
    die "Failed to load config [$name]\n" if $@ or !defined $config;

    return $config;
}

# interpolate the config vars
sub format_args {
    my $stub = shift;
    my $pre  = shift || ''; # maybe init
    my $rv = sprintf $stub->{"${pre}format"},
        @{$stub->{"${pre}format"} || []};
    return split /\s+/, $rv;
}

# check if we have a program installed, and locate it
# borrowed from IPC::Cmd
sub can_run {
    my $command = shift;

    use Config;
    require File::Spec;
    require ExtUtils::MakeMaker;

    if( File::Spec->file_name_is_absolute($command) ) {
        return MM->maybe_command($command);
    }
    else {
        for my $dir (
            (split /\Q$Config{path_sep}\E/, $ENV{PATH}),
            File::Spec->curdir
        ) {           
            my $abs = File::Spec->catfile($dir, $command);
            return $abs if $abs = MM->maybe_command($abs);
        }
    }
}

# recursively merge two hashes together with right-hand precedence
# borrowed from Catalyst::Utils
sub merge_hashes {
    my ( $lefthash, $righthash ) = @_;
    return $lefthash unless defined $righthash;

    my %merged = %$lefthash;
    for my $key ( keys %$righthash ) {
        my $right_ref = ( ref $righthash->{ $key } || '' ) eq 'HASH';
        my $left_ref  = ( ( exists $lefthash->{ $key } && ref $lefthash->{ $key } ) || '' ) eq 'HASH';
        if( $right_ref and $left_ref ) {
            $merged{ $key } = merge_hashes(
                $lefthash->{ $key }, $righthash->{ $key }
            );
        }
        else {
            $merged{ $key } = $righthash->{ $key };
        }
    }

    return \%merged;
}

# bail out with a help message
sub quit_with_help {
    print <<HELPEND;
nfflowd - convert Linux NetFilter connection messages to Cisco Netflow
          (version $VERSION)
usage:
    nfflowd [--help] [--config=/etc/nfflowd.conf]

options:
    -h or --help
        Prints this help message.

    -c or --config=
        Pass a configuration file location to override the built-in
        defaults, or the default location of /etc/nfflowd.conf.

HELPEND
    exit 0;
}

__END__

=head1 AUTHOR

Oliver Gorwits C<< <oliver.gorwits@oucs.ox.ac.uk> >>

=head1 COPYRIGHT & LICENSE

Copyright (c) The University of Oxford 2008.

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut

