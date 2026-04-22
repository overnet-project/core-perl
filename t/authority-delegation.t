use strict;
use warnings;
use Test::More;

use lib 'lib';
use lib 'local/lib/perl5';

use Net::Nostr::Key;
use Overnet::Authority::Delegation;
use Overnet::Core::Nostr;

subtest 'create_auth_event builds a verifiable kind 22242 auth event' => sub {
  my $key = Overnet::Core::Nostr->generate_key;
  my $challenge = 'c' x 64;
  my $scope = 'irc://irc.example.test/overnet';
  my $created_at = 1_744_301_000;

  my $event = Overnet::Authority::Delegation->create_auth_event(
    key        => $key,
    challenge  => $challenge,
    scope      => $scope,
    created_at => $created_at,
  );

  is $event->{kind}, 22242, 'the auth event uses kind 22242';
  is $event->{created_at}, $created_at, 'the auth event preserves the requested timestamp';
  is $event->{content}, '', 'the auth event uses an empty content payload';
  is_deeply $event->{tags}, [
    [ relay => $scope ],
    [ challenge => $challenge ],
  ], 'the auth event includes the required relay scope and challenge tags';
  like $event->{id}, qr/\A[0-9a-f]{64}\z/, 'the auth event is signed';
  like $event->{sig}, qr/\A[0-9a-f]{128}\z/, 'the auth event includes a Schnorr signature';

  my $verification = Overnet::Authority::Delegation->verify_auth_event(
    challenge => $challenge,
    scope     => $scope,
    event     => $event,
  );

  ok $verification->{valid}, 'the generated auth event verifies';
  is $verification->{pubkey}, $key->pubkey_hex, 'the generated auth event preserves the signing pubkey';
};

subtest 'create_delegation_grant_event builds a verifiable kind 14142 delegation grant' => sub {
  my $key = Overnet::Core::Nostr->generate_key;
  my $relay_url = 'ws://127.0.0.1:7448';
  my $scope = 'irc://irc.example.test/overnet';
  my $delegate_pubkey = 'd' x 64;
  my $session_id = 'session-123';
  my $expires_at = 1_744_304_600;
  my $created_at = 1_744_301_100;

  my $event = Overnet::Authority::Delegation->create_delegation_grant_event(
    key             => $key,
    relay_url       => $relay_url,
    scope           => $scope,
    delegate_pubkey => $delegate_pubkey,
    session_id      => $session_id,
    expires_at      => $expires_at,
    created_at      => $created_at,
    nick            => 'alice',
  );

  is $event->{kind}, 14142, 'the delegation grant uses the default kind 14142';
  is $event->{created_at}, $created_at, 'the delegation grant preserves the requested timestamp';
  is $event->{content}, '', 'the delegation grant uses an empty content payload';
  is_deeply $event->{tags}, [
    [ relay => $relay_url ],
    [ server => $scope ],
    [ delegate => $delegate_pubkey ],
    [ session => $session_id ],
    [ expires_at => $expires_at ],
    [ nick => 'alice' ],
  ], 'the delegation grant includes the required relay, scope, delegate, session, and expiration tags';
  like $event->{id}, qr/\A[0-9a-f]{64}\z/, 'the delegation grant is signed';
  like $event->{sig}, qr/\A[0-9a-f]{128}\z/, 'the delegation grant includes a Schnorr signature';

  my $verification = Overnet::Authority::Delegation->verify_delegation_grant(
    authority_pubkey => $key->pubkey_hex,
    relay_url        => $relay_url,
    scope            => $scope,
    delegate_pubkey  => $delegate_pubkey,
    session_id       => $session_id,
    expires_at       => $expires_at,
    event            => $event,
  );

  ok $verification->{valid}, 'the generated delegation grant verifies';
  is $verification->{pubkey}, $key->pubkey_hex, 'the generated delegation grant preserves the signing pubkey';
};

subtest 'load_key accepts PEM text, raw hex, and nsec secrets' => sub {
  my $net_key = Net::Nostr::Key->new;

  my $pem_key = Overnet::Core::Nostr->load_key(
    privkey => $net_key->privkey_pem,
  );
  is $pem_key->pubkey_hex, $net_key->pubkey_hex, 'PEM key text loads correctly';

  my $hex_key = Overnet::Core::Nostr->load_key(
    privkey => $net_key->privkey_hex,
  );
  is $hex_key->pubkey_hex, $net_key->pubkey_hex, 'raw hex key text loads correctly';

  my $nsec_key = Overnet::Core::Nostr->load_key(
    privkey => $net_key->privkey_nsec,
  );
  is $nsec_key->pubkey_hex, $net_key->pubkey_hex, 'nsec key text loads correctly';
};

done_testing;
