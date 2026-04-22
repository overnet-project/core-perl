package Overnet::Authority::Delegation;

use strict;
use warnings;
use Time::HiRes qw(time);
use Overnet::Core::Nostr;

our $VERSION = '0.001';

sub create_auth_event {
  my ($class, %args) = @_;
  my $key = _require_key($args{key});
  my $challenge = $args{challenge};
  my $scope = $args{scope};
  my $created_at = exists $args{created_at} ? $args{created_at} : int(time());

  return _invalid('challenge is required')
    unless defined $challenge && !ref($challenge) && length($challenge);
  return _invalid('scope is required')
    unless defined $scope && !ref($scope) && length($scope);
  return _invalid('created_at is required')
    unless defined $created_at && !ref($created_at);

  return $key->create_event_hash(
    kind       => 22242,
    created_at => $created_at + 0,
    content    => '',
    tags       => [
      [ 'relay', $scope ],
      [ 'challenge', $challenge ],
    ],
  );
}

sub verify_auth_event {
  my ($class, %args) = @_;
  my $challenge = $args{challenge};
  my $scope = $args{scope};
  my $event_hash = $args{event};

  return _invalid('challenge is required')
    unless defined $challenge && !ref($challenge) && length($challenge);
  return _invalid('scope is required')
    unless defined $scope && !ref($scope) && length($scope);

  my ($event, $error) = _coerce_signed_event($event_hash);
  return _invalid($error) unless $event;

  return _invalid('auth event requires kind 22242')
    unless $event->kind == 22242;

  my %tags = _first_tag_values($event->tags);
  return _invalid('auth event challenge does not match')
    unless defined $tags{challenge} && $tags{challenge} eq $challenge;
  return _invalid('auth event relay scope does not match')
    unless defined $tags{relay} && $tags{relay} eq $scope;

  return {
    valid    => 1,
    pubkey   => $event->pubkey,
    event_id => $event->id,
    event    => $event->to_hash,
  };
}

sub create_delegation_grant_event {
  my ($class, %args) = @_;
  my $key = _require_key($args{key});
  my $relay_url = $args{relay_url};
  my $scope = $args{scope};
  my $delegate_pubkey = $args{delegate_pubkey};
  my $session_id = $args{session_id};
  my $expires_at = $args{expires_at};
  my $kind = exists $args{kind} ? $args{kind} : 14142;
  my $nick = $args{nick};
  my $created_at = exists $args{created_at} ? $args{created_at} : int(time());

  return _invalid('relay_url is required')
    unless defined $relay_url && !ref($relay_url) && length($relay_url);
  return _invalid('scope is required')
    unless defined $scope && !ref($scope) && length($scope);
  return _invalid('delegate_pubkey is required')
    unless defined $delegate_pubkey && !ref($delegate_pubkey) && $delegate_pubkey =~ /\A[0-9a-f]{64}\z/;
  return _invalid('session_id is required')
    unless defined $session_id && !ref($session_id) && length($session_id);
  return _invalid('expires_at is required')
    unless defined $expires_at && !ref($expires_at) && $expires_at =~ /\A\d+\z/;
  return _invalid('kind must be a positive integer')
    unless defined $kind && !ref($kind) && $kind =~ /\A[1-9]\d*\z/;
  return _invalid('created_at is required')
    unless defined $created_at && !ref($created_at);
  return _invalid('nick must be a non-empty string')
    if defined $nick && (ref($nick) || !length($nick));

  return $key->create_event_hash(
    kind       => 0 + $kind,
    created_at => $created_at + 0,
    content    => '',
    tags       => [
      [ 'relay', $relay_url ],
      [ 'server', $scope ],
      [ 'delegate', $delegate_pubkey ],
      [ 'session', $session_id ],
      [ 'expires_at', "$expires_at" ],
      (defined $nick ? ([ 'nick', $nick ]) : ()),
    ],
  );
}

sub verify_delegation_grant {
  my ($class, %args) = @_;
  my $authority_pubkey = $args{authority_pubkey};
  my $relay_url = $args{relay_url};
  my $scope = $args{scope};
  my $delegate_pubkey = $args{delegate_pubkey};
  my $session_id = $args{session_id};
  my $expires_at = $args{expires_at};
  my $kind = exists $args{kind} ? $args{kind} : 14142;
  my $event_hash = $args{event};

  return _invalid('authority_pubkey is required')
    unless defined $authority_pubkey && !ref($authority_pubkey) && $authority_pubkey =~ /\A[0-9a-f]{64}\z/;
  return _invalid('relay_url is required')
    unless defined $relay_url && !ref($relay_url) && length($relay_url);
  return _invalid('scope is required')
    unless defined $scope && !ref($scope) && length($scope);
  return _invalid('delegate_pubkey is required')
    unless defined $delegate_pubkey && !ref($delegate_pubkey) && $delegate_pubkey =~ /\A[0-9a-f]{64}\z/;
  return _invalid('session_id is required')
    unless defined $session_id && !ref($session_id) && length($session_id);
  return _invalid('expires_at is required')
    unless defined $expires_at && !ref($expires_at) && $expires_at =~ /\A\d+\z/;
  return _invalid('kind must be a positive integer')
    unless defined $kind && !ref($kind) && $kind =~ /\A[1-9]\d*\z/;

  my ($event, $error) = _coerce_signed_event($event_hash);
  return _invalid($error) unless $event;

  return _invalid('delegation event uses the wrong event kind')
    unless $event->kind == $kind;
  return _invalid('delegation event pubkey does not match the authenticated user')
    unless $event->pubkey eq $authority_pubkey;

  my %tags = _first_tag_values($event->tags);
  return _invalid('delegation event relay does not match')
    unless defined $tags{relay} && $tags{relay} eq $relay_url;
  return _invalid('delegation event server scope does not match')
    unless defined $tags{server} && $tags{server} eq $scope;
  return _invalid('delegation event delegate pubkey does not match')
    unless defined $tags{delegate} && $tags{delegate} eq $delegate_pubkey;
  return _invalid('delegation event session does not match')
    unless defined $tags{session} && $tags{session} eq $session_id;
  return _invalid('delegation event expiration does not match')
    unless defined $tags{expires_at} && $tags{expires_at} =~ /\A\d+\z/ && $tags{expires_at} == $expires_at;

  return {
    valid    => 1,
    pubkey   => $event->pubkey,
    event_id => $event->id,
    event    => $event->to_hash,
  };
}

sub _coerce_signed_event {
  my ($event_hash) = @_;
  return (undef, 'event must be an object')
    unless ref($event_hash) eq 'HASH';

  my $event = Overnet::Core::Nostr->event_from_wire($event_hash);
  return (undef, 'event must be a valid signed Nostr event')
    unless $event && eval { $event->validate; 1 };

  return ($event, undef);
}

sub _first_tag_values {
  my ($tags) = @_;
  my %values;

  for my $tag (@{$tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
    next if exists $values{$tag->[0]};
    $values{$tag->[0]} = $tag->[1];
  }

  return %values;
}

sub _invalid {
  my ($reason) = @_;
  return {
    valid  => 0,
    reason => $reason,
  };
}

sub _require_key {
  my ($key) = @_;
  return $key
    if ref($key) && ref($key) eq 'Overnet::Core::Nostr::Key';
  die "key must be an Overnet::Core::Nostr::Key instance\n";
}

1;
