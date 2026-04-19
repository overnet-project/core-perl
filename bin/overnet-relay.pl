#!/usr/bin/env perl
use strict;
use warnings;

use FindBin;
use Getopt::Long qw(GetOptions);
use lib "$FindBin::Bin/../lib";
use lib "$FindBin::Bin/../local/lib/perl5";

use Overnet::Relay;
use Overnet::Relay::Store::File;

my %opt = (
  host => '127.0.0.1',
  port => 7447,
  name => 'Overnet Relay',
  description => 'Generic Overnet relay',
  software => 'https://example.invalid/overnet-relay',
  version => '0.1.0',
  core_version => '0.1.0',
  relay_profile => 'volunteer-basic',
  max_negentropy_sessions => 8,
  max_filters => 8,
  max_limit => 100,
  max_subscriptions => 32,
  max_message_length => 65536,
  max_content_length => 32768,
  store_file => undef,
);

my $help = 0;
my $host = $opt{host};
my $port = $opt{port};

GetOptions(
  'host=s' => \$host,
  'port=i' => \$port,
  'name=s' => \$opt{name},
  'description=s' => \$opt{description},
  'software=s' => \$opt{software},
  'version=s' => \$opt{version},
  'core-version=s' => \$opt{core_version},
  'relay-profile=s' => \$opt{relay_profile},
  'max-negentropy-sessions=i' => \$opt{max_negentropy_sessions},
  'max-filters=i' => \$opt{max_filters},
  'max-limit=i' => \$opt{max_limit},
  'max-subscriptions=i' => \$opt{max_subscriptions},
  'max-message-length=i' => \$opt{max_message_length},
  'max-content-length=i' => \$opt{max_content_length},
  'store-file=s' => \$opt{store_file},
  'help' => \$help,
) or die _usage();

if ($help) {
  print _usage();
  exit 0;
}

die "--host is required\n" if !defined($host) || $host eq '';
die "--port must be a non-negative integer\n"
  if !defined($port) || $port !~ /\A\d+\z/;

for my $int_opt (
  qw(
    max_negentropy_sessions
    max_filters
    max_limit
    max_subscriptions
    max_message_length
    max_content_length
  )
) {
  die "--$int_opt must be a positive integer\n"
    if !defined($opt{$int_opt}) || $opt{$int_opt} !~ /\A\d+\z/ || $opt{$int_opt} < 1;
}

delete $opt{host};
delete $opt{port};

my %relay_args = %opt;
if (defined $relay_args{store_file}) {
  die "--store-file must be a non-empty string\n"
    if ref($relay_args{store_file}) || $relay_args{store_file} eq '';
  $relay_args{store} = Overnet::Relay::Store::File->new(
    path => delete $relay_args{store_file},
  );
} else {
  delete $relay_args{store_file};
}

my $relay = Overnet::Relay->new(%relay_args);

$SIG{INT} = sub { $relay->stop };
$SIG{TERM} = sub { $relay->stop };

$relay->run($host, $port);
exit 0;

sub _usage {
  return <<'USAGE';
Usage: overnet-relay.pl [options]

  --host HOST
  --port PORT
  --name NAME
  --description TEXT
  --software URL
  --version VERSION
  --core-version VERSION
  --relay-profile NAME
  --max-negentropy-sessions N
  --max-filters N
  --max-limit N
  --max-subscriptions N
  --max-message-length N
  --max-content-length N
  --store-file PATH
  --help
USAGE
}
