package Overnet::Auth::Backend::DirectSecret;

use strict;
use warnings;

use parent 'Overnet::Auth::Backend';

use Overnet::Core::Nostr;

our $VERSION = '0.001';

sub backend_type { 'direct_secret' }

sub load_signing_key {
  my ($self, %args) = @_;
  my $identity = $args{identity} || {};
  my $config = $args{backend_config} || {};

  my $secret = $config->{secret};
  $secret = $identity->{private_key}
    unless defined $secret && !ref($secret) && length($secret);
  $secret = $identity->{privkey_secret}
    unless defined $secret && !ref($secret) && length($secret);

  return (undef, {
    code    => 'backend_unavailable',
    message => 'no direct secret is configured for the selected identity',
  }) unless defined $secret && !ref($secret) && length($secret);

  my $key = eval { Overnet::Core::Nostr->load_key(privkey => $secret) };
  return (undef, {
    code    => 'backend_unavailable',
    message => "$@",
  }) unless $key;

  return ($key, undef);
}

1;
