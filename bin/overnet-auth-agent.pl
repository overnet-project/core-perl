#!/usr/bin/env perl

use strict;
use warnings;

use Getopt::Long qw(GetOptions);

use Overnet::Auth::Daemon;

my %args;
my $help;
my $socket_mode;

GetOptions(
  'config-file=s' => \$args{config_file},
  'auth-sock=s'   => \$args{endpoint},
  'socket-mode=s' => \$socket_mode,
  'help'          => \$help,
) or die _usage();

if ($help) {
  print _usage();
  exit 0;
}

die _usage()
  unless defined($args{config_file}) && !ref($args{config_file}) && length($args{config_file});

if (defined $socket_mode) {
  die "--socket-mode must be an octal mode like 0600\n"
    unless $socket_mode =~ /\A0?[0-7]{3,4}\z/;
  $args{socket_mode} = oct($socket_mode);
}

my $daemon = Overnet::Auth::Daemon->new(%args);
$daemon->run;

sub _usage {
  return <<'USAGE';
Usage: overnet-auth-agent.pl --config-file PATH [--auth-sock PATH] [--socket-mode OCTAL]

Options:
  --config-file PATH  JSON auth-agent config file
  --auth-sock PATH    Override the configured local auth socket path
  --socket-mode MODE  Socket file mode, for example 0600
  --help              Show this help text
USAGE
}
