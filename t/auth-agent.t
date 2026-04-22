use strict;
use warnings;

use Test::More;

use Overnet::Auth::Agent;
use Overnet::Core::Nostr;

my $fixture_secret = '1111111111111111111111111111111111111111111111111111111111111111';
my $fixture_pubkey = '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa';

{
  package t::auth_agent::CountingBackend;

  sub new {
    my ($class, %args) = @_;
    return bless {
      calls  => 0,
      secret => $args{secret},
    }, $class;
  }

  sub load_signing_key {
    my ($self) = @_;
    $self->{calls}++;
    return (
      Overnet::Core::Nostr->load_key(privkey => $self->{secret}),
      undef,
    );
  }

  sub calls { $_[0]->{calls} }
}

subtest 'sessions.authorize uses the direct_secret backend type' => sub {
  my $agent = Overnet::Auth::Agent->new(
    identities => [
      {
        identity_id => 'default',
        backend_type => 'direct_secret',
        backend_config => {
          secret => $fixture_secret,
        },
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
  );

  my $response = $agent->dispatch({
    type   => 'request',
    id     => 'auth-direct-1',
    method => 'sessions.authorize',
    params => {
      program_id => 'irc.bridge',
      identity_id => 'default',
      service => {
        locators => [ 'irc://irc.example.test/overnet' ],
      },
      scope => 'irc://irc.example.test/overnet',
      action => 'session.authenticate',
      challenge => {
        type  => 'opaque',
        value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
      },
      artifacts => [
        {
          type => 'nostr.event',
          params => {
            kind => 22242,
            tags => [
              [ relay => 'irc://irc.example.test/overnet' ],
              [ challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f' ],
            ],
          },
        },
      ],
    },
  });

  is $response->{ok}, 1, 'authorize succeeds';
  is $response->{result}{artifacts}[0]{value}{pubkey}, $fixture_pubkey, 'authorize signs with the direct_secret backend identity';
};

subtest 'sessions.authorize uses the pass backend type' => sub {
  my @seen;
  my $agent = Overnet::Auth::Agent->new(
    identities => [
      {
        identity_id => 'default',
        backend_type => 'pass',
        backend_config => {
          entry => 'overnet-priv-key',
          command_runner => sub {
            @seen = @_;
            return ($fixture_secret . "\n", undef);
          },
        },
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
  );

  my $response = $agent->dispatch({
    type   => 'request',
    id     => 'auth-pass-1',
    method => 'sessions.authorize',
    params => {
      program_id => 'irc.bridge',
      identity_id => 'default',
      service => {
        locators => [ 'irc://irc.example.test/overnet' ],
      },
      scope => 'irc://irc.example.test/overnet',
      action => 'session.authenticate',
      challenge => {
        type  => 'opaque',
        value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
      },
      artifacts => [
        {
          type => 'nostr.event',
          params => {
            kind => 22242,
            tags => [
              [ relay => 'irc://irc.example.test/overnet' ],
              [ challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f' ],
            ],
          },
        },
      ],
    },
  });

  is $response->{ok}, 1, 'authorize succeeds';
  is_deeply \@seen, [ 'pass', 'show', 'overnet-priv-key' ], 'agent routed through the pass backend';
  is $response->{result}{artifacts}[0]{value}{pubkey}, $fixture_pubkey, 'authorize signs with the pass backend identity';
};

subtest 'sessions.authorize reports backend_unavailable for an unknown backend type' => sub {
  my $agent = Overnet::Auth::Agent->new(
    identities => [
      {
        identity_id  => 'default',
        backend_type => 'unknown-backend',
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
  );

  my $response = $agent->dispatch({
    type   => 'request',
    id     => 'auth-unknown-1',
    method => 'sessions.authorize',
    params => {
      program_id => 'irc.bridge',
      identity_id => 'default',
      service => {
        locators => [ 'irc://irc.example.test/overnet' ],
      },
      scope => 'irc://irc.example.test/overnet',
      action => 'session.authenticate',
      challenge => {
        type  => 'opaque',
        value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
      },
      artifacts => [
        {
          type => 'nostr.event',
          params => {
            kind => 22242,
            tags => [
              [ relay => 'irc://irc.example.test/overnet' ],
              [ challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f' ],
            ],
          },
        },
      ],
    },
  });

  is $response->{ok}, 0, 'authorize fails';
  is $response->{error}{code}, 'backend_unavailable', 'unknown backend type is reported as backend_unavailable';
};

subtest 'sessions.authorize honors an injected backend instance' => sub {
  my $backend = t::auth_agent::CountingBackend->new(secret => $fixture_secret);
  my $agent = Overnet::Auth::Agent->new(
    identities => [
      {
        identity_id => 'default',
        backend     => $backend,
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
  );

  my $response = $agent->dispatch({
    type   => 'request',
    id     => 'auth-object-1',
    method => 'sessions.authorize',
    params => {
      program_id => 'irc.bridge',
      identity_id => 'default',
      service => {
        locators => [ 'irc://irc.example.test/overnet' ],
      },
      scope => 'irc://irc.example.test/overnet',
      action => 'session.authenticate',
      challenge => {
        type  => 'opaque',
        value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
      },
      artifacts => [
        {
          type => 'nostr.event',
          params => {
            kind => 22242,
            tags => [
              [ relay => 'irc://irc.example.test/overnet' ],
              [ challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f' ],
            ],
          },
        },
      ],
    },
  });

  is $response->{ok}, 1, 'authorize succeeds';
  is $backend->calls, 1, 'the injected backend instance was used';
  is $response->{result}{artifacts}[0]{value}{pubkey}, $fixture_pubkey, 'authorize signs with the injected backend identity';
};

subtest 'sessions.authorize invokes the backend for each authorization request' => sub {
  my $backend = t::auth_agent::CountingBackend->new(secret => $fixture_secret);
  my $agent = Overnet::Auth::Agent->new(
    identities => [
      {
        identity_id => 'default',
        backend     => $backend,
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
  );

  for my $id (1, 2) {
    my $response = $agent->dispatch({
      type   => 'request',
      id     => "auth-repeat-$id",
      method => 'sessions.authorize',
      params => {
        program_id => 'irc.bridge',
        identity_id => 'default',
        service => {
          locators => [ 'irc://irc.example.test/overnet' ],
        },
        scope => 'irc://irc.example.test/overnet',
        action => 'session.authenticate',
        challenge => {
          type  => 'opaque',
          value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
        },
        artifacts => [
          {
            type => 'nostr.event',
            params => {
              kind => 22242,
              tags => [
                [ relay => 'irc://irc.example.test/overnet' ],
                [ challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f' ],
              ],
            },
          },
        ],
      },
    });

    is $response->{ok}, 1, "authorize $id succeeds";
  }

  is $backend->calls, 2, 'the backend was invoked for both authorization requests';
};

subtest 'sessions.renew propagates backend_unavailable when the identity backend fails' => sub {
  my $agent = Overnet::Auth::Agent->new(
    identities => [
      {
        identity_id => 'default',
        backend_type => 'pass',
        backend_config => {
          entry => 'overnet-priv-key',
          command_runner => sub {
            return (undef, 'pass show failed');
          },
        },
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
    policies => [
      {
        identity_id => 'default',
        program_id  => 'irc.bridge',
        scope       => 'irc://irc.example.test/overnet',
        action      => 'session.authenticate',
        locators    => [ 'irc://irc.example.test/overnet' ],
      },
    ],
    sessions => [
      {
        session_handle => { id => 'sess-1' },
        identity_id    => 'default',
        program_id     => 'irc.bridge',
        service        => {
          locators => [ 'irc://irc.example.test/overnet' ],
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.authenticate',
        renewable => 1,
        artifacts => [
          {
            type => 'nostr.event',
            params => {
              kind => 22242,
              tags => [
                [ relay => 'irc://irc.example.test/overnet' ],
                [ challenge => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f' ],
              ],
            },
          },
        ],
      },
    ],
  );

  my $renew = $agent->dispatch({
    type   => 'request',
    id     => 'renew-backend-1',
    method => 'sessions.renew',
    params => {
      session_handle => { id => 'sess-1' },
      challenge => {
        type  => 'opaque',
        value => '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f',
      },
      interactive => 0,
    },
  });

  is $renew->{ok}, 0, 'renew fails';
  is $renew->{error}{code}, 'backend_unavailable', 'renew surfaces the backend failure';
};

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

subtest 'sessions.revoke succeeds without consulting an unavailable backend' => sub {
  my $agent = Overnet::Auth::Agent->new(
    identities => [
      {
        identity_id  => 'default',
        backend_type => 'pass',
        backend_config => {
          entry => 'overnet-priv-key',
          command_runner => sub {
            return (undef, 'pass show failed');
          },
        },
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
    sessions => [
      {
        session_handle => { id => 'sess-1' },
        identity_id    => 'default',
        program_id     => 'irc.bridge',
        service        => {
          locators => [ 'irc://irc.example.test/overnet' ],
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.authenticate',
        renewable => 1,
        artifacts => [],
      },
    ],
  );

  my $revoke = $agent->dispatch({
    type   => 'request',
    id     => 'revoke-backend-1',
    method => 'sessions.revoke',
    params => {
      session_handle => { id => 'sess-1' },
    },
  });

  is $revoke->{ok}, 1, 'revoke succeeds';
  is_deeply $revoke->{result}, {}, 'revoke does not depend on backend availability';
};

done_testing;
