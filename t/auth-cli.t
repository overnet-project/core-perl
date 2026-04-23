use strict;
use warnings;

use File::Spec;
use FindBin;
use JSON::PP qw(decode_json);
use Test::More;

use Overnet::Auth::CLI;

{
  package t::auth_cli::FakeClient;

  sub new {
    my ($class, %args) = @_;
    return bless {
      responses => $args{responses} || {},
      calls     => [],
    }, $class;
  }

  sub identities_list {
    my ($self) = @_;
    push @{$self->{calls}}, {
      method => 'identities.list',
      params => {},
    };
    return $self->{responses}{'identities.list'};
  }

  sub policies_list {
    my ($self) = @_;
    push @{$self->{calls}}, {
      method => 'policies.list',
      params => {},
    };
    return $self->{responses}{'policies.list'};
  }

  sub policies_grant {
    my ($self, %params) = @_;
    push @{$self->{calls}}, {
      method => 'policies.grant',
      params => \%params,
    };
    return $self->{responses}{'policies.grant'};
  }

  sub policies_revoke {
    my ($self, %params) = @_;
    push @{$self->{calls}}, {
      method => 'policies.revoke',
      params => \%params,
    };
    return $self->{responses}{'policies.revoke'};
  }

  sub service_pins_list {
    my ($self) = @_;
    push @{$self->{calls}}, {
      method => 'service_pins.list',
      params => {},
    };
    return $self->{responses}{'service_pins.list'};
  }

  sub service_pins_set {
    my ($self, %params) = @_;
    push @{$self->{calls}}, {
      method => 'service_pins.set',
      params => \%params,
    };
    return $self->{responses}{'service_pins.set'};
  }

  sub service_pins_forget {
    my ($self, %params) = @_;
    push @{$self->{calls}}, {
      method => 'service_pins.forget',
      params => \%params,
    };
    return $self->{responses}{'service_pins.forget'};
  }

  sub sessions_list {
    my ($self) = @_;
    push @{$self->{calls}}, {
      method => 'sessions.list',
      params => {},
    };
    return $self->{responses}{'sessions.list'};
  }

  sub sessions_authorize {
    my ($self, %params) = @_;
    push @{$self->{calls}}, {
      method => 'sessions.authorize',
      params => \%params,
    };
    return $self->{responses}{'sessions.authorize'};
  }

  sub sessions_renew {
    my ($self, %params) = @_;
    push @{$self->{calls}}, {
      method => 'sessions.renew',
      params => \%params,
    };
    return $self->{responses}{'sessions.renew'};
  }

  sub sessions_revoke {
    my ($self, %params) = @_;
    push @{$self->{calls}}, {
      method => 'sessions.revoke',
      params => \%params,
    };
    return $self->{responses}{'sessions.revoke'};
  }

  sub calls {
    my ($self) = @_;
    return $self->{calls};
  }
}

my $script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-auth.pl');
my $libdir = File::Spec->catdir($FindBin::Bin, '..', 'lib');

subtest 'identities command prints the identity list result as JSON' => sub {
  my $client = t::auth_cli::FakeClient->new(
    responses => {
      'identities.list' => {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::PP::true,
        result => {
          identities => [
            {
              identity_id => 'default',
              public_identity => {
                scheme => 'nostr.pubkey',
                value  => ('a' x 64),
              },
            },
          ],
        },
      },
    },
  );

  my $result = Overnet::Auth::CLI->run(
    argv   => [ 'identities' ],
    client => $client,
  );

  is $result->{exit_code}, 0, 'identities exits successfully';
  is_deeply decode_json($result->{output}), {
    ok     => JSON::PP::true,
    result => {
      identities => [
        {
          identity_id => 'default',
          public_identity => {
            scheme => 'nostr.pubkey',
            value  => ('a' x 64),
          },
        },
      ],
    },
  }, 'identities prints the auth-agent result payload';
  is_deeply $client->calls, [
    {
      method => 'identities.list',
      params => {},
    },
  ], 'identities calls identities.list';
};

subtest 'authorize command builds the expected sessions.authorize request' => sub {
  my $artifact_file = File::Spec->catfile($FindBin::Bin, 'auth-cli-artifact.json');
  _write_file($artifact_file, <<'JSON');
{"type":"nostr.event","params":{"kind":22242,"tags":[["relay","irc://irc.example.test/overnet"],["challenge","abcd"]]} }
JSON

  my $client = t::auth_cli::FakeClient->new(
    responses => {
      'sessions.authorize' => {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::PP::true,
        result => {
          session_handle => { id => 'sess-1' },
        },
      },
    },
  );

  my $result = Overnet::Auth::CLI->run(
    argv => [
      'authorize',
      '--identity-id', 'default',
      '--program-id', 'irc.bridge',
      '--service-locator', 'irc://irc.example.test/overnet',
      '--scope', 'irc://irc.example.test/overnet',
      '--action', 'session.authenticate',
      '--challenge-type', 'opaque',
      '--challenge-value', 'abcd',
      '--artifact-file', $artifact_file,
      '--service-identity-scheme', 'nostr.pubkey',
      '--service-identity-value', ('b' x 64),
      '--service-identity-display', 'irc.example.test authority',
      '--no-interactive',
    ],
    client => $client,
  );

  is $result->{exit_code}, 0, 'authorize exits successfully';
  is_deeply decode_json($result->{output}), {
    ok     => JSON::PP::true,
    result => {
      session_handle => { id => 'sess-1' },
    },
  }, 'authorize prints the auth-agent result payload';
  is_deeply $client->calls, [
    {
      method => 'sessions.authorize',
      params => {
        identity_id => 'default',
        program_id  => 'irc.bridge',
        service     => {
          locators => [ 'irc://irc.example.test/overnet' ],
          service_identity => {
            scheme  => 'nostr.pubkey',
            value   => ('b' x 64),
            display => 'irc.example.test authority',
          },
        },
        scope       => 'irc://irc.example.test/overnet',
        action      => 'session.authenticate',
        interactive => JSON::PP::false,
        challenge   => {
          type  => 'opaque',
          value => 'abcd',
        },
        artifacts => [
          {
            type => 'nostr.event',
            params => {
              kind => 22242,
              tags => [
                [ 'relay', 'irc://irc.example.test/overnet' ],
                [ 'challenge', 'abcd' ],
              ],
            },
          },
        ],
      },
    },
  ], 'authorize maps CLI flags onto sessions.authorize';

  unlink $artifact_file or die "unlink $artifact_file failed: $!";
};

subtest 'policies and sessions commands print daemon-managed state as JSON' => sub {
  my $client = t::auth_cli::FakeClient->new(
    responses => {
      'policies.list' => {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::PP::true,
        result => {
          policies => [
            {
              policy_id   => 'policy-1',
              identity_id => 'default',
              program_id  => 'irc.bridge',
              locators    => [ 'irc://irc.example.test/overnet' ],
              scope       => 'irc://irc.example.test/overnet',
              action      => 'session.authenticate',
            },
          ],
        },
      },
      'sessions.list' => {
        type   => 'response',
        id     => 'auth-2',
        ok     => JSON::PP::true,
        result => {
          sessions => [
            {
              session_handle => { id => 'sess-1' },
              identity_id    => 'default',
              action         => 'session.authenticate',
            },
          ],
        },
      },
    },
  );

  my $policies = Overnet::Auth::CLI->run(
    argv   => [ 'policies' ],
    client => $client,
  );
  my $sessions = Overnet::Auth::CLI->run(
    argv   => [ 'sessions' ],
    client => $client,
  );

  is $policies->{exit_code}, 0, 'policies exits successfully';
  is $sessions->{exit_code}, 0, 'sessions exits successfully';
  is_deeply decode_json($policies->{output}), {
    ok     => JSON::PP::true,
    result => {
      policies => [
        {
          policy_id   => 'policy-1',
          identity_id => 'default',
          program_id  => 'irc.bridge',
          locators    => [ 'irc://irc.example.test/overnet' ],
          scope       => 'irc://irc.example.test/overnet',
          action      => 'session.authenticate',
        },
      ],
    },
  }, 'policies prints daemon-managed policy state';
  is_deeply decode_json($sessions->{output}), {
    ok     => JSON::PP::true,
    result => {
      sessions => [
        {
          session_handle => { id => 'sess-1' },
          identity_id    => 'default',
          action         => 'session.authenticate',
        },
      ],
    },
  }, 'sessions prints daemon-managed session state';
};

subtest 'policy-grant, policy-revoke, service-pins, service-pin-set, and service-pin-forget build the expected requests' => sub {
  my $client = t::auth_cli::FakeClient->new(
    responses => {
      'policies.grant' => {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::PP::true,
        result => {
          policy => { policy_id => 'policy-1' },
        },
      },
      'policies.revoke' => {
        type   => 'response',
        id     => 'auth-2',
        ok     => JSON::PP::true,
        result => {
          policy_id => 'policy-1',
        },
      },
      'service_pins.list' => {
        type   => 'response',
        id     => 'auth-3',
        ok     => JSON::PP::true,
        result => {
          service_pins => [],
        },
      },
      'service_pins.set' => {
        type   => 'response',
        id     => 'auth-4',
        ok     => JSON::PP::true,
        result => {
          locator => 'wss://relay.example.test/auth',
        },
      },
      'service_pins.forget' => {
        type   => 'response',
        id     => 'auth-5',
        ok     => JSON::PP::true,
        result => {
          locator => 'wss://relay.example.test/auth',
        },
      },
    },
  );

  my $grant = Overnet::Auth::CLI->run(
    argv => [
      'policy-grant',
      '--identity-id', 'default',
      '--program-id', 'irc.bridge',
      '--service-locator', 'wss://relay.example.test/auth',
      '--service-identity-scheme', 'nostr.pubkey',
      '--service-identity-value', ('b' x 64),
      '--scope', 'irc://irc.example.test/overnet',
      '--action', 'session.delegate',
    ],
    client => $client,
  );
  my $revoke = Overnet::Auth::CLI->run(
    argv   => [ 'policy-revoke', '--policy-id', 'policy-1' ],
    client => $client,
  );
  my $pins = Overnet::Auth::CLI->run(
    argv   => [ 'service-pins' ],
    client => $client,
  );
  my $set = Overnet::Auth::CLI->run(
    argv => [
      'service-pin-set',
      '--service-locator', 'wss://relay.example.test/auth',
      '--service-identity-scheme', 'nostr.pubkey',
      '--service-identity-value', ('c' x 64),
      '--service-identity-display', 'relay.example.test authority',
    ],
    client => $client,
  );
  my $forget = Overnet::Auth::CLI->run(
    argv   => [ 'service-pin-forget', '--service-locator', 'wss://relay.example.test/auth' ],
    client => $client,
  );

  is $grant->{exit_code}, 0, 'policy-grant exits successfully';
  is $revoke->{exit_code}, 0, 'policy-revoke exits successfully';
  is $pins->{exit_code}, 0, 'service-pins exits successfully';
  is $set->{exit_code}, 0, 'service-pin-set exits successfully';
  is $forget->{exit_code}, 0, 'service-pin-forget exits successfully';
  is_deeply $client->calls, [
    {
      method => 'policies.grant',
      params => {
        policy => {
          identity_id => 'default',
          program_id  => 'irc.bridge',
          service     => {
            locators => [ 'wss://relay.example.test/auth' ],
            service_identity => {
              scheme => 'nostr.pubkey',
              value  => ('b' x 64),
            },
          },
          scope  => 'irc://irc.example.test/overnet',
          action => 'session.delegate',
        },
      },
    },
    {
      method => 'policies.revoke',
      params => {
        policy_id => 'policy-1',
      },
    },
    {
      method => 'service_pins.list',
      params => {},
    },
    {
      method => 'service_pins.set',
      params => {
        locator => 'wss://relay.example.test/auth',
        service_identity => {
          scheme  => 'nostr.pubkey',
          value   => ('c' x 64),
          display => 'relay.example.test authority',
        },
      },
    },
    {
      method => 'service_pins.forget',
      params => {
        locator => 'wss://relay.example.test/auth',
      },
    },
  ], 'management commands map CLI flags to auth-agent methods';
};

subtest 'renew and revoke commands wrap session ids as session handles' => sub {
  my $client = t::auth_cli::FakeClient->new(
    responses => {
      'sessions.renew' => {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::PP::true,
        result => {
          session_handle => { id => 'sess-2' },
        },
      },
      'sessions.revoke' => {
        type   => 'response',
        id     => 'auth-2',
        ok     => JSON::PP::true,
        result => {
          revoked => JSON::PP::true,
        },
      },
    },
  );

  my $renew = Overnet::Auth::CLI->run(
    argv   => [ 'renew', '--session-id', 'sess-2', '--no-interactive' ],
    client => $client,
  );
  my $revoke = Overnet::Auth::CLI->run(
    argv   => [ 'revoke', '--session-id', 'sess-2' ],
    client => $client,
  );

  is $renew->{exit_code}, 0, 'renew exits successfully';
  is $revoke->{exit_code}, 0, 'revoke exits successfully';
  is_deeply $client->calls, [
    {
      method => 'sessions.renew',
      params => {
        session_handle => { id => 'sess-2' },
        interactive    => JSON::PP::false,
      },
    },
    {
      method => 'sessions.revoke',
      params => {
        session_handle => { id => 'sess-2' },
      },
    },
  ], 'renew and revoke wrap the session id as a session_handle object';
};

subtest 'client CLI script exists and prints help' => sub {
  ok -f $script, 'auth client script exists'
    or BAIL_OUT('auth client script is required');

  my $syntax = system($^X, "-I$libdir", '-c', $script);
  is $syntax >> 8, 0, 'auth client script has valid syntax';

  my $help = qx{$^X -I$libdir $script --help 2>&1};
  is $? >> 8, 0, '--help exits cleanly';
  like $help, qr/Usage:\s+overnet-auth\.pl identities/,
    '--help prints the command synopsis';
  like $help, qr/overnet-auth\.pl policies/,
    '--help lists policies';
  like $help, qr/overnet-auth\.pl service-pin-set/,
    '--help lists service pin management';
  like $help, qr/overnet-auth\.pl sessions/,
    '--help lists sessions';
};

done_testing;

sub _write_file {
  my ($path, $content) = @_;
  open my $fh, '>', $path
    or die "open $path failed: $!";
  print {$fh} $content
    or die "write $path failed: $!";
  close $fh
    or die "close $path failed: $!";
}
