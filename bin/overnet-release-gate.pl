#!/usr/bin/env perl
use strict;
use warnings;
use File::Basename qw(dirname);
use File::Spec;

my $root = File::Spec->catdir(dirname(__FILE__), '..');
chdir $root
  or die "Can't chdir to $root: $!";

my $plx = File::Spec->catfile($ENV{HOME}, '.local', 'bin', 'plx');

exec $plx, 'prove', '-Ilib', '-Ilocal/lib/perl5',
  't/spec-conformance-irc-server.t',
  't/program-irc-server.t',
  't/program-irc-server-relay.t';

die "Can't exec $plx: $!";
