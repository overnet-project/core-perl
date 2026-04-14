package Overnet::Program::TLSConfig;

use strict;
use warnings;
use IO::Socket::SSL qw(SSL_VERIFY_NONE SSL_VERIFY_PEER);

our $VERSION = '0.001';

sub normalize {
  my ($class, %args) = @_;

  return undef unless exists $args{tls};
  my $tls = $args{tls};
  my $implicit_mode = $args{implicit_mode};

  die "tls must be an object\n"
    unless ref($tls) eq 'HASH';
  die "implicit_mode must be client or server\n"
    if defined $implicit_mode && $implicit_mode ne 'client' && $implicit_mode ne 'server';

  die "tls.enabled is required\n"
    unless exists $tls->{enabled};

  my $enabled = _normalize_bool('tls.enabled', $tls->{enabled});
  my $mode = exists $tls->{mode} ? $tls->{mode} : $implicit_mode;
  if (defined $mode) {
    die "tls.mode must be client or server\n"
      unless !ref($mode) && ($mode eq 'client' || $mode eq 'server');
  }

  my %normalized = (
    enabled => $enabled,
  );
  $normalized{mode} = $mode
    if defined $mode;

  for my $field (qw(server_name cert_chain_file private_key_file ca_file)) {
    next unless exists $tls->{$field};
    die "tls.$field must be a non-empty string\n"
      unless defined $tls->{$field} && !ref($tls->{$field}) && length($tls->{$field});
    $normalized{$field} = $tls->{$field};
  }

  if (exists $tls->{verify_peer}) {
    $normalized{verify_peer} = _normalize_bool('tls.verify_peer', $tls->{verify_peer});
  }

  if (exists $tls->{min_version}) {
    die "tls.min_version must be TLSv1.2 or TLSv1.3\n"
      unless defined $tls->{min_version}
        && !ref($tls->{min_version})
        && ($tls->{min_version} eq 'TLSv1.2' || $tls->{min_version} eq 'TLSv1.3');
    $normalized{min_version} = $tls->{min_version};
  }

  if ($enabled && defined $mode && $mode eq 'server') {
    die "tls.cert_chain_file is required when tls.enabled is true for server mode\n"
      unless defined $normalized{cert_chain_file};
    die "tls.private_key_file is required when tls.enabled is true for server mode\n"
      unless defined $normalized{private_key_file};
  }

  if ($enabled && ($normalized{verify_peer} || 0)) {
    die "tls.ca_file is required when tls.verify_peer is true\n"
      unless defined $normalized{ca_file};
  }

  return \%normalized;
}

sub server_start_args {
  my ($class, $tls) = @_;

  return undef unless defined $tls;
  die "tls must be an object\n"
    unless ref($tls) eq 'HASH';
  return undef unless $tls->{enabled};
  die "tls.mode must be server when building server TLS arguments\n"
    unless ($tls->{mode} || '') eq 'server';

  my %args = (
    SSL_server      => 1,
    SSL_startHandshake => 1,
    SSL_cert_file   => $tls->{cert_chain_file},
    SSL_key_file    => $tls->{private_key_file},
    SSL_verify_mode => ($tls->{verify_peer} ? SSL_VERIFY_PEER() : SSL_VERIFY_NONE()),
  );
  $args{SSL_ca_file} = $tls->{ca_file}
    if defined $tls->{ca_file};
  $args{SSL_version} = _ssl_version_for_min_version($tls->{min_version})
    if defined $tls->{min_version};

  return \%args;
}

sub _normalize_bool {
  my ($label, $value) = @_;

  return $value ? 1 : 0
    if ref($value) eq 'JSON::PP::Boolean';
  return 0 + $value
    if defined $value && !ref($value) && ($value eq '0' || $value eq '1');

  die "$label must be a boolean\n";
}

sub _ssl_version_for_min_version {
  my ($min_version) = @_;

  return 'SSLv23:!SSLv3:!SSLv2:!TLSv1:!TLSv1_1'
    if $min_version eq 'TLSv1.2';
  return 'TLSv1_3'
    if $min_version eq 'TLSv1.3';

  die "Unsupported tls.min_version: $min_version\n";
}

1;

=head1 NAME

Overnet::Program::TLSConfig - Baseline TLS config normalization for Overnet programs

=head1 DESCRIPTION

Validates the baseline `tls` object shape used by Overnet program configuration
and produces `IO::Socket::SSL` server-side arguments for enabled server-mode
TLS listeners.

=cut
