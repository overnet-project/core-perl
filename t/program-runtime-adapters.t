use strict;
use warnings;
use Test::More;

use Overnet::Program::Runtime;
use Overnet::Program::Services;

{
  package Local::MockAdapter;

  sub new { bless {}, shift }

  sub map_input {
    my ($self, %args) = @_;
    return {
      events => [
        {
          kind    => 7800,
          adapter => 'mock',
          input   => $args{command},
        },
      ],
    };
  }

  sub derive {
    my ($self, %args) = @_;
    return {
      state => [
        {
          kind      => 37800,
          operation => $args{operation},
          input     => $args{input},
        },
      ],
    };
  }
}

{
  package Local::SessionConfigAdapter;

  sub new { bless {}, shift }

  sub map_input {
    my ($self, %args) = @_;
    return {
      valid => 1,
      event => {
        kind          => 7800,
        session_mode  => $args{session_config}{mode},
        command       => $args{command},
      },
    };
  }

  sub derive {
    my ($self, %args) = @_;
    return {
      valid => 1,
      event => {
        kind          => 37800,
        session_mode  => $args{session_config}{mode},
        operation     => $args{operation},
      },
    };
  }
}

subtest 'runtime registers adapters and opens sessions' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $adapter = Local::MockAdapter->new;

  ok $runtime->register_adapter(
    adapter_id => 'mock.adapter',
    adapter    => $adapter,
  ), 'adapter registered';

  my $session = $runtime->open_adapter_session(
    adapter_id => 'mock.adapter',
    config     => { mode => 'test' },
  );

  is $session->adapter_id, 'mock.adapter', 'session records adapter id';
  is_deeply $runtime->adapter_session_ids, [$session->session_id], 'runtime tracks session';
};

subtest 'runtime can instantiate adapters from class definitions' => sub {
  my $runtime = Overnet::Program::Runtime->new;

  ok $runtime->register_adapter_definition(
    adapter_id => 'mock.class',
    definition => {
      kind             => 'class',
      class            => 'Local::MockAdapter',
      constructor_args => {},
    },
  ), 'class adapter definition registered';

  my $session = $runtime->open_adapter_session(
    adapter_id => 'mock.class',
  );

  my $mapped = $session->map_input({ command => 'NOTICE' });
  is $mapped->{events}[0]{input}, 'NOTICE', 'class adapter was instantiated and used';
};

subtest 'runtime can load the real IRC adapter implementation path' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $irc_lib = '/home/_73/p/Overnet/overnet-adapter-irc/lib';

  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'real IRC adapter definition registered';

  my $session = $runtime->open_adapter_session(
    adapter_id => 'irc.real',
  );

  my $mapped = $session->map_input({
    command    => 'PRIVMSG',
    network    => 'irc.libera.chat',
    target     => '#overnet',
    nick       => 'alice',
    text       => 'Hello from runtime',
    created_at => 1744301000,
  });

  ok $mapped->{valid}, 'real adapter returned valid mapping result';
  is $mapped->{event}{kind}, 7800, 'real adapter returned mapped event';
};

subtest 'services normalize real IRC adapter outputs and support derive operations' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $irc_lib = '/home/_73/p/Overnet/overnet-adapter-irc/lib';

  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'real IRC adapter definition registered';

  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $opened = $services->dispatch_request(
    'adapters.open_session',
    { adapter_id => 'irc.real' },
    permissions => ['adapters.use'],
  );
  my $session_id = $opened->{adapter_session_id};

  my $mapped = $services->dispatch_request(
    'adapters.map_input',
    {
      adapter_session_id => $session_id,
      input              => {
        command    => 'PRIVMSG',
        network    => 'irc.libera.chat',
        target     => '#overnet',
        nick       => 'alice',
        text       => 'Hello from runtime',
        created_at => 1744301000,
      },
    },
    permissions => ['adapters.use'],
  );
  is $mapped->{events}[0]{kind}, 7800, 'real adapter event is normalized to events array';
  ok !exists $mapped->{valid}, 'adapter-local validity flag is not exposed through service result';
  ok !exists $mapped->{event}, 'adapter-local singular event shape is normalized';

  my $derived = $services->dispatch_request(
    'adapters.derive',
    {
      adapter_session_id => $session_id,
      operation          => 'channel_presence',
      input              => {
        network    => 'irc.libera.chat',
        target     => '#overnet',
        created_at => 1744300900,
        events     => [
          {
            command    => 'JOIN',
            network    => 'irc.libera.chat',
            target     => '#overnet',
            nick       => 'alice',
            created_at => 1744300870,
          },
        ],
      },
    },
    permissions => ['adapters.use'],
  );
  is $derived->{state}[0]{kind}, 37800, 'real adapter derived state is normalized to state array';
};

subtest 'services open, use, derive, and close adapter sessions' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  $runtime->register_adapter(
    adapter_id => 'mock.adapter',
    adapter    => Local::MockAdapter->new,
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $opened = $services->open_adapter_session(
    adapter_id => 'mock.adapter',
    config     => { source => 'example' },
  );
  my $session_id = $opened->{adapter_session_id};
  ok defined $session_id && length $session_id, 'session id returned';

  my $mapped = $services->map_input(
    adapter_session_id => $session_id,
    input              => { command => 'PRIVMSG' },
  );
  is $mapped->{events}[0]{input}, 'PRIVMSG', 'mapped adapter output returned';

  my $derived = $services->derive(
    adapter_session_id => $session_id,
    operation          => 'channel_presence',
    input              => { channel => '#overnet' },
  );
  is $derived->{state}[0]{operation}, 'channel_presence', 'derived adapter output returned';

  is_deeply $services->close_adapter_session(adapter_session_id => $session_id), {}, 'close returns empty result';
  is_deeply $runtime->adapter_session_ids, [], 'session removed after close';
};

subtest 'dispatch_request enforces adapters.use permission' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  $runtime->register_adapter(
    adapter_id => 'mock.adapter',
    adapter    => Local::MockAdapter->new,
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error;
  eval {
    $services->dispatch_request(
      'adapters.open_session',
      { adapter_id => 'mock.adapter', config => {} },
      permissions => [],
    );
    1;
  } or $error = $@;

  is ref($error), 'HASH', 'permission denial is structured';
  is $error->{code}, 'runtime.permission_denied', 'permission denial code returned';
  is $error->{details}{required_permission}, 'adapters.use', 'required permission is reported';
  is_deeply $runtime->adapter_session_ids, [], 'session is not opened without permission';

  my $opened = $services->dispatch_request(
    'adapters.open_session',
    { adapter_id => 'mock.adapter', config => {} },
    permissions => ['adapters.use'],
  );
  ok defined $opened->{adapter_session_id} && length $opened->{adapter_session_id},
    'dispatch_request succeeds when adapters.use is granted';
};

subtest 'dispatch_request reports unavailable services and invalid adapter params with structured errors' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  $runtime->register_adapter(
    adapter_id => 'mock.adapter',
    adapter    => Local::MockAdapter->new,
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error;
  eval {
    $services->dispatch_request(
      'config.get',
      {},
      permissions => ['config.read'],
    );
    1;
  } or $error = $@;
  is ref($error), 'HASH', 'unavailable service error is structured';
  is $error->{code}, 'runtime.service_unavailable', 'unimplemented service reports service_unavailable';

  $error = undef;
  eval {
    $services->dispatch_request(
      'adapters.map_input',
      { adapter_session_id => 'missing' },
      permissions => ['adapters.use'],
    );
    1;
  } or $error = $@;
  is ref($error), 'HASH', 'invalid adapter params error is structured';
  is $error->{code}, 'protocol.invalid_params', 'unknown adapter session is reported as invalid params';
};

subtest 'adapter session config is forwarded to adapter methods' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  $runtime->register_adapter(
    adapter_id => 'session.config',
    adapter    => Local::SessionConfigAdapter->new,
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $opened = $services->dispatch_request(
    'adapters.open_session',
    {
      adapter_id => 'session.config',
      config     => { mode => 'session-test' },
    },
    permissions => ['adapters.use'],
  );
  my $session_id = $opened->{adapter_session_id};

  my $mapped = $services->dispatch_request(
    'adapters.map_input',
    {
      adapter_session_id => $session_id,
      input              => { command => 'NOTICE' },
    },
    permissions => ['adapters.use'],
  );
  is $mapped->{events}[0]{session_mode}, 'session-test', 'session config is available during map_input';

  my $derived = $services->dispatch_request(
    'adapters.derive',
    {
      adapter_session_id => $session_id,
      operation          => 'derive-test',
      input              => {},
    },
    permissions => ['adapters.use'],
  );
  is $derived->{state}[0]{session_mode}, 'session-test', 'session config is available during derive';
};

subtest 'unknown adapters and sessions are rejected' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error;
  eval {
    $services->open_adapter_session(adapter_id => 'missing.adapter');
    1;
  } or $error = $@;
  is ref($error), 'HASH', 'unknown adapter error is structured';
  is $error->{code}, 'runtime.service_unavailable', 'unknown adapter is treated as unavailable runtime service';

  $error = undef;
  eval {
    $services->map_input(
      adapter_session_id => 'adapter-999',
      input              => {},
    );
    1;
  } or $error = $@;
  is ref($error), 'HASH', 'unknown session error is structured';
  is $error->{code}, 'protocol.invalid_params', 'unknown session is treated as invalid params';
};

done_testing;
