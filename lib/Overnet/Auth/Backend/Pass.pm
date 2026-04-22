package Overnet::Auth::Backend::Pass;

use strict;
use warnings;

use parent 'Overnet::Auth::Backend';

use Overnet::Core::Nostr;

our $VERSION = '0.001';

sub backend_type { 'pass' }

sub load_signing_key {
  my ($self, %args) = @_;
  my $config = $args{backend_config} || {};
  my $entry = $config->{entry};

  return (undef, {
    code    => 'backend_unavailable',
    message => 'no pass entry is configured for the selected identity',
  }) unless defined $entry && !ref($entry) && length($entry);

  my $runner = $config->{command_runner} || $self->{command_runner} || \&_default_command_runner;
  my ($stdout, $error) = $runner->('pass', 'show', $entry);

  return (undef, {
    code    => 'backend_unavailable',
    message => $error,
  }) if defined $error;

  my $secret = $stdout // '';
  ($secret) = split /\R/, $secret, 2
    unless $secret =~ /\A-----BEGIN [^-]+-----\R/s;
  return (undef, {
    code    => 'backend_unavailable',
    message => "pass entry $entry did not return a usable secret",
  }) unless defined $secret && $secret =~ /\S/;

  my $key = eval { Overnet::Core::Nostr->load_key(privkey => $secret) };
  return (undef, {
    code    => 'backend_unavailable',
    message => "$@",
  }) unless $key;

  return ($key, undef);
}

sub _default_command_runner {
  my (@cmd) = @_;

  my $pid = open my $fh, '-|', @cmd;
  return (undef, "unable to execute @cmd: $!")
    unless defined $pid;

  my $stdout = do { local $/; <$fh> };
  close $fh;
  return (undef, "@cmd exited with status " . ($? >> 8))
    if $?;

  return ($stdout, undef);
}

1;
