use strict;
use warnings;
use Test::More;
use FindBin;
use File::Spec;

use Overnet::Program::Host;

my $happy_program = File::Spec->catfile($FindBin::Bin, 'program-fixtures', 'host-happy-program.pl');
my $invalid_program = File::Spec->catfile($FindBin::Bin, 'program-fixtures', 'host-invalid-program.pl');
my $silent_program = File::Spec->catfile($FindBin::Bin, 'program-fixtures', 'host-silent-program.pl');
my $truncated_program = File::Spec->catfile($FindBin::Bin, 'program-fixtures', 'host-truncated-program.pl');
my $version_mismatch_program = File::Spec->catfile($FindBin::Bin, 'program-fixtures', 'host-version-mismatch-program.pl');

sub _method_seen {
  my ($entries, $direction, $type, $method) = @_;
  for my $entry (@{$entries}) {
    next unless ($entry->{direction} || '') eq $direction;
    next unless ($entry->{message}{type} || '') eq $type;
    next unless ($entry->{message}{method} || '') eq $method;
    return 1;
  }
  return 0;
}

subtest 'host supervises a real child program over stdio' => sub {
  my $host = Overnet::Program::Host->new(
    command => [$^X, $happy_program],
    runtime_args => {
      config => {
        name => 'runtime-config',
      },
    },
    permissions => ['config.read', 'timers.write'],
    services    => {
      'config.get'      => {},
      'timers.schedule' => {},
    },
    startup_timeout_ms  => 500,
    shutdown_timeout_ms => 500,
  );

  $host->start;

  is $host->state, 'ready', 'host reaches ready state after handshake';
  ok defined $host->pid, 'host tracks child pid';
  is $host->instance->peer_program_id, 'fixture.host.program', 'host records child program identity';

  my $health_seen = $host->pump_until(
    timeout_ms => 500,
    condition  => sub {
      my ($current_host) = @_;
      for my $message (@{$current_host->observed_notifications}) {
        next unless ($message->{method} || '') eq 'program.health';
        return 1 if (($message->{params}{details}{timer_id} || '') eq 'fixture-timer');
      }
      return 0;
    },
  );
  ok $health_seen, 'host delivers runtime.timer_fired and observes program.health';

  my $observed = $host->observed_notifications;
  is scalar @{$observed}, 2, 'host records observed program notifications';
  is_deeply(
    [ map { $_->{method} } @{$observed} ],
    ['program.log', 'program.health'],
    'host preserves observed notification order',
  );

  my $transcript = $host->transcript;
  ok _method_seen($transcript, 'to_program', 'request', 'runtime.init'),
    'transcript includes runtime.init';
  ok _method_seen($transcript, 'from_program', 'request', 'config.get'),
    'transcript includes child config.get request';
  ok _method_seen($transcript, 'from_program', 'request', 'timers.schedule'),
    'transcript includes child timers.schedule request';
  ok _method_seen($transcript, 'to_program', 'notification', 'runtime.timer_fired'),
    'transcript includes runtime.timer_fired delivery';

  like $host->stderr_output, qr/fixture config: runtime-config/, 'host captures child stderr';

  my $shutdown = $host->request_shutdown(reason => 'test complete');
  is $shutdown->{state}, 'shutdown_complete', 'host completes runtime shutdown handshake';
  is $shutdown->{exit_code}, 0, 'child exits cleanly';
  ok $host->has_exited, 'host reaps child process';
  like $host->stderr_output, qr/fixture done/, 'host captures child shutdown stderr';

  $transcript = $host->transcript;
  ok _method_seen($transcript, 'to_program', 'request', 'runtime.shutdown'),
    'transcript includes runtime.shutdown';
};

subtest 'host surfaces child protocol framing errors' => sub {
  my $host = Overnet::Program::Host->new(
    command => [$^X, $invalid_program],
    startup_timeout_ms => 200,
  );

  my $error;
  eval {
    $host->start;
    1;
  } or $error = $@;

  like $error, qr/Protocol framing error: non-numeric length prefix/,
    'host reports protocol framing errors from child stdout';
};

subtest 'host treats truncated stdout frames as fatal protocol errors on eof' => sub {
  my $host = Overnet::Program::Host->new(
    command => [$^X, $truncated_program],
    startup_timeout_ms => 200,
  );

  my $error;
  eval {
    $host->start;
    1;
  } or $error = $@;

  like $error, qr/Protocol framing error: payload shorter than declared length/,
    'host validates buffered stdout frames at end of stream';
};

subtest 'host treats early stdout closure as fatal transport loss' => sub {
  my $host = Overnet::Program::Host->new(
    command => [$^X, $silent_program],
    startup_timeout_ms => 200,
  );

  my $error;
  eval {
    $host->start;
    1;
  } or $error = $@;

  like $error, qr/Protocol transport error: program stdout closed before orderly shutdown/,
    'host fails fast when the protocol stdout channel closes unexpectedly';
};

subtest 'host sends runtime.fatal on handshake version mismatch before terminating the session' => sub {
  my $host = Overnet::Program::Host->new(
    command => [$^X, $version_mismatch_program],
    supported_protocol_versions => ['0.1'],
    startup_timeout_ms => 200,
  );

  my $error;
  eval {
    $host->start;
    1;
  } or $error = $@;

  like $error, qr/protocol\.version_mismatch: No compatible protocol version/,
    'host surfaces the fatal handshake mismatch';
  ok _method_seen($host->transcript, 'to_program', 'notification', 'runtime.fatal'),
    'host transcript records runtime.fatal delivery';
};

done_testing;
