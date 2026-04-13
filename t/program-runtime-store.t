use strict;
use warnings;
use Test::More;
use JSON::PP qw(decode_json);
use File::Basename qw(dirname);
use File::Spec;

use Overnet::Program::Instance;
use Overnet::Program::Protocol;
use Overnet::Program::Runtime;
use Overnet::Program::Services;

sub _load_fixture_input {
  my ($name) = @_;

  my $path = File::Spec->catfile(dirname(__FILE__), 'fixtures', $name);
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $json = do { local $/; <$fh> };
  close $fh;

  return decode_json($json)->{input};
}

sub _ready_instance {
  my (%args) = @_;

  my $instance = Overnet::Program::Instance->new(%args);
  my $hello = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'store.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(id => $hello->{send}{id})
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_program_ready()
  );

  return $instance;
}

subtest 'services append and read event streams' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $first = $services->dispatch_request(
    'events.append',
    {
      stream => 'program.journal',
      event  => { step => 1, action => 'start' },
    },
    permissions => ['events.append'],
  );
  is $first->{stream}, 'program.journal', 'append returns stream name';
  is $first->{offset}, 0, 'first append gets offset 0';

  my $second = $services->dispatch_request(
    'events.append',
    {
      stream => 'program.journal',
      event  => { step => 2, action => 'finish' },
    },
    permissions => ['events.append'],
  );
  is $second->{offset}, 1, 'second append gets offset 1';

  my $read_all = $services->dispatch_request(
    'events.read',
    { stream => 'program.journal' },
    permissions => ['events.read'],
  );
  is $read_all->{stream}, 'program.journal', 'read returns stream name';
  is scalar @{$read_all->{entries}}, 2, 'read returns appended entries';
  is $read_all->{entries}[0]{offset}, 0, 'first entry offset returned';
  is $read_all->{entries}[1]{event}{action}, 'finish', 'second event payload returned';

  my $read_tail = $services->dispatch_request(
    'events.read',
    {
      stream       => 'program.journal',
      after_offset => 0,
      limit        => 1,
    },
    permissions => ['events.read'],
  );
  is scalar @{$read_tail->{entries}}, 1, 'after_offset and limit are applied';
  is $read_tail->{entries}[0]{offset}, 1, 'tail read starts after exclusive lower bound';
};

subtest 'services reject invalid event store params' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error;
  eval {
    $services->dispatch_request(
      'events.append',
      { event => { ok => 1 } },
      permissions => ['events.append'],
    );
    1;
  } or $error = $@;
  is ref($error), 'HASH', 'missing stream error is structured';
  is $error->{code}, 'protocol.invalid_params', 'missing stream is invalid params';

  $error = undef;
  eval {
    $services->dispatch_request(
      'events.append',
      { stream => 'program.journal', event => 'not-an-object' },
      permissions => ['events.append'],
    );
    1;
  } or $error = $@;
  is ref($error), 'HASH', 'non-object event error is structured';
  is $error->{code}, 'protocol.invalid_params', 'non-object appended event is invalid params';

  $error = undef;
  eval {
    $services->dispatch_request(
      'events.read',
      { stream => 'program.journal', limit => 'many' },
      permissions => ['events.read'],
    );
    1;
  } or $error = $@;
  is ref($error), 'HASH', 'invalid limit error is structured';
  is $error->{code}, 'protocol.invalid_params', 'invalid limit is invalid params';
};

subtest 'accepted emitted outputs are exposed through runtime event streams' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $event = _load_fixture_input('valid-native-event.json');
  my $state = _load_fixture_input('valid-state-event.json');
  my $capability = {
    name    => 'adapter.irc.presence',
    version => '1.0',
    details => { scope => 'channel' },
  };

  $services->dispatch_request(
    'overnet.emit_event',
    { event => $event },
    permissions => ['overnet.emit_event'],
  );
  $services->dispatch_request(
    'overnet.emit_state',
    { state => $state },
    permissions => ['overnet.emit_state'],
  );
  $services->dispatch_request(
    'overnet.emit_capabilities',
    { capabilities => [$capability] },
    permissions => ['overnet.emit_capabilities'],
  );

  my $event_stream = $runtime->emitted_stream_name('event');
  my $state_stream = $runtime->emitted_stream_name('state');
  my $capability_stream = $runtime->emitted_stream_name('capability');

  my $event_entries = $services->dispatch_request(
    'events.read',
    { stream => $event_stream },
    permissions => ['events.read'],
  );
  is scalar @{$event_entries->{entries}}, 1, 'accepted emitted event is available via events.read';
  is $event_entries->{entries}[0]{event}{id}, $event->{id}, 'accepted emitted event payload is stored';

  my $state_entries = $services->dispatch_request(
    'events.read',
    { stream => $state_stream },
    permissions => ['events.read'],
  );
  is scalar @{$state_entries->{entries}}, 1, 'accepted emitted state is available via events.read';
  is $state_entries->{entries}[0]{event}{id}, $state->{id}, 'accepted emitted state payload is stored';

  my $capability_entries = $services->dispatch_request(
    'events.read',
    { stream => $capability_stream },
    permissions => ['events.read'],
  );
  is scalar @{$capability_entries->{entries}}, 1, 'accepted emitted capability is available via events.read';
  is $capability_entries->{entries}[0]{event}{name}, $capability->{name}, 'accepted emitted capability payload is stored';
};

subtest 'instance can read emitted stream entries through protocol' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $instance = _ready_instance(
    supported_protocol_versions => ['0.1'],
    permissions                 => ['overnet.emit_event', 'events.read'],
    service_handler             => $services,
  );

  my $event = _load_fixture_input('valid-native-event.json');
  my $emit = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'emit-store-1',
      method => 'overnet.emit_event',
      params => { event => $event },
    )
  );
  ok $emit->{send}{ok}, 'emit_event succeeds before stream read';

  my $stream = $runtime->emitted_stream_name('event');
  my $read = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'emit-store-2',
      method => 'events.read',
      params => { stream => $stream },
    )
  );
  ok $read->{send}{ok}, 'events.read succeeds through instance';
  is $read->{send}{result}{entries}[0]{event}{id}, $event->{id}, 'protocol read returns emitted event payload';
};

done_testing;
