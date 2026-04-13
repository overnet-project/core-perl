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
      program_id                  => 'subscriptions.example',
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

subtest 'services open subscriptions and queue matching existing emitted outputs' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $event = _load_fixture_input('valid-native-event.json');
  my $state = _load_fixture_input('valid-state-event.json');

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

  my $opened = $services->dispatch_request(
    'subscriptions.open',
    {
      subscription_id => 'sub-1',
      query           => { overnet_et => 'chat.message' },
    },
    permissions => ['subscriptions.read'],
    session_id  => 'session-1',
  );
  is $opened->{subscription_id}, 'sub-1', 'subscription id returned';

  my $notifications = $runtime->drain_runtime_notifications('session-1');
  is scalar @{$notifications}, 1, 'matching existing item is queued';
  is $notifications->[0]{method}, 'runtime.subscription_event', 'runtime subscription notification is queued';
  is $notifications->[0]{params}{subscription_id}, 'sub-1', 'queued notification records subscription id';
  is $notifications->[0]{params}{item_type}, 'event', 'queued notification records item type';
  is $notifications->[0]{params}{data}{id}, $event->{id}, 'queued notification includes matched event payload';
};

subtest 'services reject invalid subscription params and duplicates' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error;
  eval {
    $services->dispatch_request(
      'subscriptions.open',
      {
        subscription_id => 'sub-1',
        query           => { unsupported => 'field' },
      },
      permissions => ['subscriptions.read'],
      session_id  => 'session-1',
    );
    1;
  } or $error = $@;
  is ref($error), 'HASH', 'unsupported query field error is structured';
  is $error->{code}, 'protocol.invalid_params', 'unsupported query field is invalid params';

  $services->dispatch_request(
    'subscriptions.open',
    {
      subscription_id => 'sub-1',
      query           => {},
    },
    permissions => ['subscriptions.read'],
    session_id  => 'session-1',
  );

  $error = undef;
  eval {
    $services->dispatch_request(
      'subscriptions.open',
      {
        subscription_id => 'sub-1',
        query           => {},
      },
      permissions => ['subscriptions.read'],
      session_id  => 'session-1',
    );
    1;
  } or $error = $@;
  is ref($error), 'HASH', 'duplicate subscription id error is structured';
  is $error->{code}, 'protocol.invalid_params', 'duplicate subscription id is invalid params';

  $error = undef;
  eval {
    $services->dispatch_request(
      'subscriptions.close',
      { subscription_id => 'missing' },
      permissions => ['subscriptions.read'],
      session_id  => 'session-1',
    );
    1;
  } or $error = $@;
  is ref($error), 'HASH', 'unknown close error is structured';
  is $error->{code}, 'protocol.invalid_params', 'unknown subscription close is invalid params';
};

subtest 'closing subscription stops future delivery and clears pending notifications' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $event = _load_fixture_input('valid-native-event.json');

  $services->dispatch_request(
    'subscriptions.open',
    {
      subscription_id => 'sub-close',
      query           => {},
    },
    permissions => ['subscriptions.read'],
    session_id  => 'session-close',
  );

  $services->dispatch_request(
    'overnet.emit_event',
    { event => $event },
    permissions => ['overnet.emit_event'],
  );

  is scalar @{$runtime->drain_runtime_notifications('other-session')}, 0, 'unrelated session has no notifications';

  $services->dispatch_request(
    'subscriptions.close',
    { subscription_id => 'sub-close' },
    permissions => ['subscriptions.read'],
    session_id  => 'session-close',
  );

  is scalar @{$runtime->drain_runtime_notifications('session-close')}, 0, 'closing clears pending notifications for that subscription';

  $services->dispatch_request(
    'overnet.emit_event',
    { event => $event },
    permissions => ['overnet.emit_event'],
  );

  is scalar @{$runtime->drain_runtime_notifications('session-close')}, 0, 'closed subscription receives no future notifications';
};

subtest 'empty-query subscriptions receive capability notifications' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $capability = {
    name    => 'adapter.irc.presence',
    version => '1.0',
    details => { scope => 'channel' },
  };

  $services->dispatch_request(
    'subscriptions.open',
    {
      subscription_id => 'sub-all',
      query           => {},
    },
    permissions => ['subscriptions.read'],
    session_id  => 'session-all',
  );
  $services->dispatch_request(
    'subscriptions.open',
    {
      subscription_id => 'sub-filtered',
      query           => { overnet_et => 'chat.message' },
    },
    permissions => ['subscriptions.read'],
    session_id  => 'session-filtered',
  );

  $services->dispatch_request(
    'overnet.emit_capabilities',
    { capabilities => [$capability] },
    permissions => ['overnet.emit_capabilities'],
  );

  my $all_notifications = $runtime->drain_runtime_notifications('session-all');
  is scalar @{$all_notifications}, 1, 'empty-query subscription receives capability notification';
  is $all_notifications->[0]{params}{item_type}, 'capability', 'notification records capability item type';
  is $all_notifications->[0]{params}{data}{name}, $capability->{name}, 'notification includes capability payload';

  is scalar @{$runtime->drain_runtime_notifications('session-filtered')}, 0,
    'field-filtered subscription does not receive capability notifications';
};

subtest 'instance drains runtime.subscription_event notifications' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $instance = _ready_instance(
    instance_id                 => 'instance-subscriptions',
    supported_protocol_versions => ['0.1'],
    permissions                 => ['subscriptions.read', 'overnet.emit_event', 'overnet.emit_capabilities'],
    service_handler             => $services,
  );

  my $opened = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'sub-open-1',
      method => 'subscriptions.open',
      params => {
        subscription_id => 'sub-1',
        query           => { overnet_et => 'chat.message' },
      },
    )
  );
  ok $opened->{send}{ok}, 'subscriptions.open succeeds through instance';

  my $event = _load_fixture_input('valid-native-event.json');
  my $emitted = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'sub-emit-1',
      method => 'overnet.emit_event',
      params => { event => $event },
    )
  );
  ok $emitted->{send}{ok}, 'emit_event succeeds through instance';

  my $notifications = $instance->drain_runtime_notifications;
  is scalar @{$notifications}, 1, 'instance drains one runtime notification';
  is $notifications->[0]{type}, 'notification', 'drained message is a notification';
  is $notifications->[0]{method}, 'runtime.subscription_event', 'drained method is runtime.subscription_event';
  is $notifications->[0]{params}{subscription_id}, 'sub-1', 'notification records subscription id';
  is $notifications->[0]{params}{item_type}, 'event', 'notification records item type';
  is $notifications->[0]{params}{data}{id}, $event->{id}, 'notification includes emitted event payload';

  my $closed = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'sub-close-1',
      method => 'subscriptions.close',
      params => { subscription_id => 'sub-1' },
    )
  );
  ok $closed->{send}{ok}, 'subscriptions.close succeeds through instance';

  $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'sub-emit-2',
      method => 'overnet.emit_event',
      params => { event => $event },
    )
  );
  is scalar @{$instance->drain_runtime_notifications}, 0, 'closed subscription produces no further notifications';

  my $reopened = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'sub-open-2',
      method => 'subscriptions.open',
      params => {
        subscription_id => 'sub-2',
        query           => {},
      },
    )
  );
  ok $reopened->{send}{ok}, 'empty-query subscription opens through instance';
  my $reopened_backlog = $instance->drain_runtime_notifications;
  is scalar @{$reopened_backlog}, 2, 'empty-query subscription replays existing accepted emitted items';

  my $capabilities = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'sub-emit-3',
      method => 'overnet.emit_capabilities',
      params => {
        capabilities => [
          {
            name    => 'adapter.irc.presence',
            version => '1.0',
          },
        ],
      },
    )
  );
  ok $capabilities->{send}{ok}, 'emit_capabilities succeeds through instance';

  my $capability_notifications = $instance->drain_runtime_notifications;
  is scalar @{$capability_notifications}, 1, 'instance drains one capability notification';
  is $capability_notifications->[0]{method}, 'runtime.subscription_event', 'capability notification method is runtime.subscription_event';
  is $capability_notifications->[0]{params}{subscription_id}, 'sub-2', 'capability notification records subscription id';
  is $capability_notifications->[0]{params}{item_type}, 'capability', 'capability notification records item type';
  is $capability_notifications->[0]{params}{data}{name}, 'adapter.irc.presence', 'capability notification includes payload';
};

done_testing;
