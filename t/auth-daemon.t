use strict;
use warnings;

use FindBin;
use File::Spec;
use File::Temp qw(tempdir);
use JSON::PP qw(encode_json);
use Socket qw(AF_UNIX PF_UNSPEC SOCK_STREAM);
use Test::More;

use Overnet::Auth::Client;
use Overnet::Auth::Daemon;

my $fixture_secret = '1111111111111111111111111111111111111111111111111111111111111111';
my $fixture_pubkey = '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa';
my $challenge = '6cf8a952df516a8e691c6138496516abe84ccfefa9678f518bb52f70b1ca966f';

{
  package t::auth_daemon::FakeListener;

  sub new {
    my ($class, %args) = @_;
    return bless {
      queue  => $args{queue} || [],
      closed => 0,
    }, $class;
  }

  sub accept {
    my ($self) = @_;
    return shift @{$self->{queue}};
  }

  sub close {
    my ($self) = @_;
    $self->{closed} = 1;
    return 1;
  }
}

subtest 'daemon serves multiple requests from the configured endpoint' => sub {
  my $dir = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  my $socket_path = File::Spec->catfile($dir, 'auth.sock');

  _write_config($config_file, $socket_path);
  my ($pid, $client) = _start_daemon(
    config_file     => $config_file,
    max_connections => 2,
    endpoint        => $socket_path,
  );

  my $info = $client->agent_info;
  is $info->{ok}, 1, 'agent.info succeeds through the daemon';

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
      value => $challenge,
    },
    artifacts => [
      {
        type => 'nostr.event',
        params => {
          kind => 22242,
          tags => [
            [ relay => 'irc://irc.example.test/overnet' ],
            [ challenge => $challenge ],
          ],
        },
      },
    ],
  );

  is $response->{ok}, 1, 'sessions.authorize succeeds through the daemon';
  is $response->{result}{artifacts}[0]{value}{pubkey}, $fixture_pubkey,
    'daemon-loaded identity signs the returned artifact';

  _wait_for_child($pid, 'daemon exits cleanly after serving the expected request count');
};

subtest 'endpoint argument overrides the configured daemon endpoint' => sub {
  my $dir = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  my $configured_socket = File::Spec->catfile($dir, 'configured.sock');
  my $override_socket = File::Spec->catfile($dir, 'override.sock');

  _write_config($config_file, $configured_socket);
  my ($pid, $client) = _start_daemon(
    config_file     => $config_file,
    endpoint        => $override_socket,
    max_connections => 1,
  );

  my $response = $client->agent_info;

  is $response->{ok}, 1, 'agent.info succeeds through the override socket';
  is $client->endpoint, $override_socket, 'client was pointed at the override endpoint';

  _wait_for_child($pid, 'daemon exits cleanly after serving the override socket');
};

subtest 'daemon rejects a pre-existing non-socket file at the endpoint path' => sub {
  my $dir = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  my $socket_path = File::Spec->catfile($dir, 'auth.sock');

  _write_config($config_file, $socket_path);
  open my $fh, '>', $socket_path or die "open $socket_path failed: $!";
  print {$fh} "not a socket\n" or die "write $socket_path failed: $!";
  close $fh or die "close $socket_path failed: $!";

  my $error = eval {
    my $daemon = Overnet::Auth::Daemon->new(
      config_file => $config_file,
    );
    $daemon->run;
    1;
  } ? undef : $@;

  like $error, qr/auth-agent endpoint path already exists and is not a socket/,
    'daemon refuses to unlink non-socket endpoint paths';
};

subtest 'daemon loads mutable state from the configured state file' => sub {
  my $dir = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  my $state_file = File::Spec->catfile($dir, 'auth-state.json');
  my $socket_path = File::Spec->catfile($dir, 'auth.sock');

  _write_config($config_file, $socket_path, state_file => $state_file, with_policies => 0);
  _write_state($state_file, {
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
    service_pins => {},
    sessions     => [],
  });

  my ($pid, $client) = _start_daemon(
    config_file     => $config_file,
    max_connections => 1,
    endpoint        => $socket_path,
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
      value => $challenge,
    },
    artifacts => [
      {
        type => 'nostr.event',
        params => {
          kind => 22242,
          tags => [
            [ relay => 'irc://irc.example.test/overnet' ],
            [ challenge => $challenge ],
          ],
        },
      },
    ],
  );

  is $response->{ok}, 1, 'headless authorization succeeds from persisted policy state';
  _wait_for_child($pid, 'daemon exits cleanly after loading persisted mutable state');
};

subtest 'daemon persists mutable session and service-pin state to the configured state file' => sub {
  my $dir = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  my $state_file = File::Spec->catfile($dir, 'auth-state.json');
  my $socket_path = File::Spec->catfile($dir, 'auth.sock');

  _write_config($config_file, $socket_path, state_file => $state_file, with_policies => 0);
  my ($pid, $client) = _start_daemon(
    config_file     => $config_file,
    max_connections => 1,
    endpoint        => $socket_path,
  );

  my $response = $client->sessions_authorize(
    program_id  => 'irc.bridge',
    identity_id => 'default',
    service     => {
      locators => [ 'wss://relay.example.test/auth' ],
      service_identity => {
        scheme => 'nostr.pubkey',
        value  => ('1' x 64),
      },
    },
    scope     => 'irc://irc.example.test/overnet',
    action    => 'session.authenticate',
    challenge => {
      type  => 'opaque',
      value => $challenge,
    },
    artifacts => [
      {
        type => 'nostr.event',
        params => {
          kind => 22242,
          tags => [
            [ relay => 'irc://irc.example.test/overnet' ],
            [ challenge => $challenge ],
          ],
        },
      },
    ],
  );

  is $response->{ok}, 1, 'authorization succeeds';
  _wait_for_child($pid, 'daemon exits cleanly after persisting mutable state');

  my $state = _read_json($state_file);
  is scalar(@{$state->{sessions} || []}), 1, 'persisted state includes the new session';
  is $state->{service_pins}{'wss://relay.example.test/auth'}{value}, ('1' x 64),
    'persisted state includes the first-contact service pin';
};

done_testing;

sub _start_daemon {
  my (%args) = @_;
  my @client_sockets;
  my @server_sockets;
  my $endpoint = defined($args{endpoint}) ? $args{endpoint} : _config_endpoint($args{config_file});

  for (1 .. ($args{max_connections} || 1)) {
    socketpair(my $server_socket, my $client_socket, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
      or die "socketpair failed: $!";
    push @server_sockets, $server_socket;
    push @client_sockets, $client_socket;
  }

  my $pid = fork();
  die "fork failed: $!" unless defined $pid;
  if (!$pid) {
    my $listener = t::auth_daemon::FakeListener->new(queue => \@server_sockets);
    my $daemon = Overnet::Auth::Daemon->new(%args);
    $daemon->{listen_factory} = sub { return $listener };
    $daemon->run;
    exit 0;
  }

  my $client = Overnet::Auth::Client->new(
    endpoint       => $endpoint,
    socket_factory => sub {
      my ($requested_endpoint) = @_;
      is $requested_endpoint, $endpoint, 'client requested the expected endpoint';
      return shift @client_sockets;
    },
  );

  return ($pid, $client);
}

sub _wait_for_child {
  my ($pid, $name) = @_;
  waitpid($pid, 0);
  is $? >> 8, 0, $name;
}

sub _config_endpoint {
  my ($path) = @_;
  open my $fh, '<', $path or die "open $path failed: $!";
  my $decoded = do { local $/; encode_json(JSON::PP::decode_json(<$fh>)) };
  close $fh or die "close $path failed: $!";
  my $config = JSON::PP::decode_json($decoded);
  return $config->{daemon}{endpoint};
}

sub _write_config {
  my ($path, $socket_path, %args) = @_;
  my @policies = $args{with_policies} || !exists($args{with_policies}) ? (
    {
      identity_id => 'default',
      program_id  => 'irc.bridge',
      locators    => [ 'irc://irc.example.test/overnet' ],
      scope       => 'irc://irc.example.test/overnet',
      action      => 'session.authenticate',
    },
  ) : ();

  open my $fh, '>', $path
    or die "open $path failed: $!";
  print {$fh} encode_json({
    daemon => {
      endpoint => $socket_path,
      (defined($args{state_file}) ? (state_file => $args{state_file}) : ()),
    },
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
    policies => \@policies,
  })
    or die "write $path failed: $!";
  close $fh
    or die "close $path failed: $!";
}

sub _write_state {
  my ($path, $value) = @_;
  open my $fh, '>', $path
    or die "open $path failed: $!";
  print {$fh} encode_json($value)
    or die "write $path failed: $!";
  close $fh
    or die "close $path failed: $!";
}

sub _read_json {
  my ($path) = @_;
  open my $fh, '<', $path
    or die "open $path failed: $!";
  my $value = JSON::PP::decode_json(do { local $/; <$fh> });
  close $fh
    or die "close $path failed: $!";
  return $value;
}
