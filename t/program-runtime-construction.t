use strict;
use warnings;
use Test::More;

use Overnet::Program::AdapterRegistry;
use Overnet::Program::Runtime;
use Overnet::Program::SecretProvider;
use Overnet::Program::Store;

{
  package Local::ConstructorAdapter;

  sub new { bless {}, shift }
}

subtest 'runtime constructor protects reserved internal state' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    next_session_id       => 99,
    adapter_sessions      => 'bad',
    timers                => 'bad',
    emitted_items         => 'bad',
    subscriptions         => 'bad',
    secret_handles        => 'bad',
    runtime_notifications => 'bad',
    secrets               => { 'api-token' => 'top-secret' },
  );

  $runtime->register_adapter(
    adapter_id => 'constructor.adapter',
    adapter    => Local::ConstructorAdapter->new,
  );
  my $session = $runtime->open_adapter_session(
    adapter_id => 'constructor.adapter',
  );
  is $session->session_id, 'adapter-1', 'constructor does not allow next_session_id override';

  ok $runtime->schedule_timer(
    session_id => 'session-1',
    timer_id   => 'timer-1',
    delay_ms   => 0,
  ), 'constructor does not allow timers override';
  is scalar @{$runtime->drain_runtime_notifications('session-1')}, 1,
    'runtime notifications remain usable after constructor override attempt';

  my $issued = $runtime->issue_secret_handle(
    session_id => 'session-1',
    name       => 'api-token',
  );
  like $issued->{secret_handle}{id}, qr/\Ash_[0-9a-f]{64}\z/,
    'constructor does not allow secret handle table override';

  my $secret_provider = Overnet::Program::SecretProvider->new(
    secrets => { 'host-token' => 'top-secret' },
    random_bytes_cb => sub {
      my ($length) = @_;
      return 'Z' x $length;
    },
  );
  my $host_runtime = Overnet::Program::Runtime->new(
    secret_provider => $secret_provider,
  );
  isa_ok $host_runtime->secret_provider, 'Overnet::Program::SecretProvider',
    'runtime accepts an explicit secret provider';

  like(
    do {
      my $error;
      eval {
        Overnet::Program::Runtime->new(
          secret_provider => $secret_provider,
          secrets => { 'mixed' => 'nope' },
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/secrets cannot be supplied when secret_provider is provided/,
    'runtime rejects mixing explicit secret provider and inline secret args',
  );
};

subtest 'store constructor protects reserved storage internals' => sub {
  my $store = Overnet::Program::Store->new(
    streams   => 'bad',
    documents => 'bad',
  );

  my $appended = $store->append_event(
    stream => 'constructor.test',
    event  => { ok => 1 },
  );
  is $appended->{offset}, 0, 'append works with protected store internals';
  is $store->read_events(stream => 'constructor.test')->{entries}[0]{event}{ok}, 1,
    'read works with protected store internals';
  is $store->put_document(key => 'constructor.doc', value => { ok => 1 })->{key}, 'constructor.doc',
    'document put works with protected store internals';
  is $store->get_document(key => 'constructor.doc')->{value}{ok}, 1,
    'document get works with protected store internals';
};

subtest 'adapter registry constructor protects adapter table' => sub {
  my $registry = Overnet::Program::AdapterRegistry->new(
    adapters => 'bad',
  );

  ok $registry->register(
    adapter_id => 'constructor.registry',
    adapter    => Local::ConstructorAdapter->new,
  ), 'register works with protected registry internals';
  ok $registry->has('constructor.registry'), 'registry remains usable after constructor override attempt';
};

done_testing;
