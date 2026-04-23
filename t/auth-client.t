use strict;
use warnings;

use File::Spec;
use Socket qw(AF_UNIX PF_UNSPEC SOCK_STREAM);
use Test::More;

use Overnet::Auth::Agent;
use Overnet::Auth::Client;
use Overnet::Auth::Server;

my $fixture_secret = '1111111111111111111111111111111111111111111111111111111111111111';
my $fixture_pubkey = '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa';

subtest 'agent_info discovers the endpoint from OVERNET_AUTH_SOCK' => sub {
  _with_auth_server(
    agent       => Overnet::Auth::Agent->new,
    connections => 1,
    run         => sub {
      my (%args) = @_;
      local $ENV{OVERNET_AUTH_SOCK} = $args{endpoint};

      my $client = Overnet::Auth::Client->new(
        socket_factory => $args{socket_factory},
      );
      my $response = $client->agent_info;

      is $response->{ok}, 1, 'agent.info succeeds';
      is $response->{result}{protocol_version}, '0.1.0', 'protocol version is returned';
      ok scalar grep { $_ eq 'sessions.authorize' } @{$response->{result}{capabilities} || []},
        'capabilities include sessions.authorize';
    },
  );
};

subtest 'sessions_authorize returns a signed auth artifact through the socket client' => sub {
  _with_auth_server(
    agent => Overnet::Auth::Agent->new(
      identities => [
        {
          identity_id  => 'default',
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
    ),
    connections => 1,
    run         => sub {
      my (%args) = @_;

      my $client = Overnet::Auth::Client->new(
        endpoint        => $args{endpoint},
        socket_factory  => $args{socket_factory},
      );
      my $response = $client->sessions_authorize(
        program_id  => 'irc.bridge',
        identity_id => 'default',
        service     => {
          locators => [ 'irc://irc.example.test/overnet' ],
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.authenticate',
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
      );

      is $response->{ok}, 1, 'sessions.authorize succeeds';
      is $response->{result}{identity_id}, 'default', 'response identifies the selected identity';
      is $response->{result}{artifacts}[0]{value}{pubkey}, $fixture_pubkey,
        'the returned auth artifact is signed by the configured identity';
    },
  );
};

subtest 'sessions_authorize preserves structured error responses' => sub {
  _with_auth_server(
    agent => Overnet::Auth::Agent->new(
      identities => [
        {
          identity_id  => 'default',
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
    ),
    connections => 1,
    run         => sub {
      my (%args) = @_;

      my $client = Overnet::Auth::Client->new(
        endpoint       => $args{endpoint},
        socket_factory => $args{socket_factory},
      );
      my $response = $client->sessions_authorize(
        program_id   => 'irc.bridge',
        identity_id  => 'default',
        interactive  => 0,
        service      => {
          locators => [ 'irc://irc.example.test/overnet' ],
        },
        scope     => 'irc://irc.example.test/overnet',
        action    => 'session.authenticate',
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
      );

      is $response->{ok}, 0, 'sessions.authorize fails';
      is $response->{error}{code}, 'headless_unavailable', 'the auth-agent error response is preserved';
    },
  );
};

subtest 'client reports a missing auth-agent endpoint clearly' => sub {
  local $ENV{OVERNET_AUTH_SOCK};
  local $ENV{OVERNET_AUTH_ENDPOINT};

  my $error = eval {
    my $client = Overnet::Auth::Client->new;
    $client->agent_info;
    1;
  } ? undef : $@;

  like $error, qr/auth-agent endpoint is not configured/,
    'client refuses to run without a configured endpoint';
};

subtest 'endpoint falls back to OVERNET_AUTH_ENDPOINT when OVERNET_AUTH_SOCK is unset' => sub {
  local $ENV{OVERNET_AUTH_SOCK};
  local $ENV{OVERNET_AUTH_ENDPOINT} = '/tmp/overnet-auth.endpoint';

  my $client = Overnet::Auth::Client->new;
  is $client->endpoint, '/tmp/overnet-auth.endpoint',
    'endpoint discovery falls back to OVERNET_AUTH_ENDPOINT';
};

done_testing;

sub _with_auth_server {
  my (%args) = @_;
  my $endpoint = File::Spec->catfile('/virtual', 'auth.sock');
  my @children;

  my $result = eval {
    $args{run}->(
      endpoint => $endpoint,
      socket_factory => sub {
        my ($requested_endpoint) = @_;
        is $requested_endpoint, $endpoint, 'client requested the expected endpoint';
        socketpair(my $server_socket, my $client_socket, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
          or die "socketpair failed: $!";
        my $server = Overnet::Auth::Server->new(
          agent => $args{agent},
        );
        my $child = fork();
        die "fork failed: $!" unless defined $child;
        if (!$child) {
          close $client_socket or die "close client socket failed: $!";
          $server->serve_socket($server_socket);
          close $server_socket or die "close server socket failed: $!";
          exit 0;
        }
        close $server_socket or die "close server socket failed: $!";
        push @children, $child;
        return $client_socket;
      },
    );
    1;
  };
  my $error = $@;

  is scalar(@children), ($args{connections} || 1), 'expected auth-agent connections were opened';
  for my $child (@children) {
    waitpid($child, 0);
    is $? >> 8, 0, 'auth-agent server exits cleanly';
  }

  die $error unless $result;
}
