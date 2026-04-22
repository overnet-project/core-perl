use strict;
use warnings;

use Test::More;

use Overnet::Auth::Agent;

subtest 'sessions.revoke drops one stored session so later renew fails' => sub {
  my $agent = Overnet::Auth::Agent->new(
    identities => [
      {
        identity_id => 'default',
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => '274722f14ff06e2a790322ae1cee2d28c9cb0ffcd18d78d3bc7cca3f19e9764d',
        },
      },
    ],
    sessions => [
      {
        session_handle => { id => 'sess-1' },
        identity_id    => 'default',
        program_id     => 'irc.bridge',
        service        => {
          locators => [ 'wss://relay.example.test/auth' ],
          service_identity => {
            scheme => 'nostr.pubkey',
            value  => '1111111111111111111111111111111111111111111111111111111111111111',
          },
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.delegate',
        renewable => 1,
        artifacts => [],
      },
    ],
  );

  my $revoke = $agent->dispatch({
    type   => 'request',
    id     => 'revoke-1',
    method => 'sessions.revoke',
    params => {
      session_handle => { id => 'sess-1' },
    },
  });

  is $revoke->{ok}, 1, 'revoke succeeds';

  my $renew = $agent->dispatch({
    type   => 'request',
    id     => 'renew-1',
    method => 'sessions.renew',
    params => {
      session_handle => { id => 'sess-1' },
      interactive    => 0,
    },
  });

  is $renew->{ok}, 0, 'renew fails after revoke';
  is $renew->{error}{code}, 'invalid_request', 'renew reports an unknown session handle';
};

done_testing;
