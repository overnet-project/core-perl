use strict;
use warnings;
use Test::More;

use Overnet::Program::Instance;
use Overnet::Program::Protocol;
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

subtest 'program.hello negotiates version and emits runtime.init' => sub {
  my $instance = Overnet::Program::Instance->new(
    instance_id                 => 'instance-42',
    runtime_program_id          => 'overnet.runtime',
    supported_protocol_versions => ['0.2', '0.1'],
    config                      => { mode => 'test' },
    permissions                 => ['config.read'],
    services                    => { config => { available => JSON::PP::true } },
  );

  my $result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
      program_version             => '1.0.0',
    )
  );

  is $instance->state, 'awaiting_init_response', 'state advanced after hello';
  is $instance->selected_protocol_version, '0.1', 'compatible version selected';
  is $instance->peer_program_id, 'irc.example', 'peer program id recorded';
  is $result->{send}{method}, 'runtime.init', 'runtime.init request emitted';
  is $result->{send}{params}{instance_id}, 'instance-42', 'instance id included';
  is $result->{send}{params}{program_id}, 'irc.example', 'runtime.init identifies the supervised program';
};

subtest 'runtime.init uses configured canonical program id when provided' => sub {
  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
    program_id                  => 'irc.canonical',
  );

  my $result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.asserted',
      supported_protocol_versions => ['0.1'],
    )
  );

  is $result->{send}{params}{program_id}, 'irc.canonical', 'configured canonical id is sent in runtime.init';
};

subtest 'successful init response moves session to awaiting_ready' => sub {
  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
  );

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );

  my $init_id = $hello_result->{send}{id};
  my $result = $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(
      id => $init_id,
    )
  );

  ok $result->{accepted}, 'init accepted';
  is $instance->state, 'awaiting_ready', 'state advanced to awaiting_ready';
};

subtest 'program.ready moves session to ready' => sub {
  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
  );

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(id => $hello_result->{send}{id})
  );

  my $result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_ready(
      params => { phase => 'done' },
    )
  );

  ok $result->{ready}, 'ready acknowledged';
  ok $instance->is_ready, 'instance is ready';
};

subtest 'request_shutdown emits runtime.shutdown and tracks state' => sub {
  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
  );

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(id => $hello_result->{send}{id})
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_program_ready()
  );

  my $result = $instance->request_shutdown(reason => 'operator-requested');
  is $instance->state, 'shutdown_requested', 'shutdown state recorded';
  is $result->{send}{method}, 'runtime.shutdown', 'runtime.shutdown emitted';

  my $shutdown_id = $result->{send}{id};
  my $shutdown_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(id => $shutdown_id)
  );

  ok $shutdown_result->{shutdown_complete}, 'shutdown completed';
  is $instance->state, 'shutdown_complete', 'session reached shutdown_complete';
};

subtest 'no compatible protocol version emits runtime.fatal and fails the session' => sub {
  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.2'],
  );

  my $result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );

  ok $result->{fatal}, 'hello mismatch produces a fatal runtime result';
  is $result->{send}{type}, 'notification', 'fatal result sends a notification';
  is $result->{send}{method}, 'runtime.fatal', 'fatal result uses runtime.fatal';
  is $result->{send}{params}{code}, 'protocol.version_mismatch', 'fatal code identifies version mismatch';
  is $result->{send}{params}{phase}, 'handshake', 'fatal notification identifies handshake phase';
  is $instance->state, 'failed', 'session enters failed state after version mismatch';
};

subtest 'unknown response ids are fatal protocol.unknown_request_id errors' => sub {
  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
  );

  my $hello = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );

  like(
    do {
      my $error;
      eval {
        $instance->process_program_message(
          Overnet::Program::Protocol::build_response_ok(id => 'unknown-init-id')
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/protocol\.unknown_request_id/,
    'unexpected runtime.init response id is a protocol.unknown_request_id error',
  );

  $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
  );
  $hello = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(id => $hello->{send}{id})
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_program_ready()
  );

  like(
    do {
      my $error;
      eval {
        $instance->process_program_message(
          Overnet::Program::Protocol::build_response_ok(id => 'unknown-ready-id')
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/protocol\.unknown_request_id/,
    'unexpected ready-state response id is a protocol.unknown_request_id error',
  );
};

subtest 'ready session dispatches adapter service requests through protocol' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  $runtime->register_adapter(
    adapter_id => 'mock.adapter',
    adapter    => Local::MockAdapter->new,
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
    permissions                 => ['adapters.use'],
    service_handler             => $services,
  );

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(id => $hello_result->{send}{id})
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_program_ready()
  );

  my $open = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'req-1',
      method => 'adapters.open_session',
      params => { adapter_id => 'mock.adapter', config => {} },
    )
  );
  is $open->{send}{type}, 'response', 'open_session yields response';
  ok $open->{send}{ok}, 'open_session succeeded';
  my $adapter_session_id = $open->{send}{result}{adapter_session_id};
  ok defined $adapter_session_id && length $adapter_session_id, 'adapter session id returned';

  my $mapped = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'req-2',
      method => 'adapters.map_input',
      params => {
        adapter_session_id => $adapter_session_id,
        input              => { command => 'NOTICE' },
      },
    )
  );
  ok $mapped->{send}{ok}, 'map_input succeeded';
  is $mapped->{send}{result}{events}[0]{input}, 'NOTICE', 'mapped output returned in response';

  my $closed = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'req-3',
      method => 'adapters.close_session',
      params => {
        adapter_session_id => $adapter_session_id,
      },
    )
  );
  ok $closed->{send}{ok}, 'close_session succeeded';
};

subtest 'ready session rejects adapter service requests without adapters.use' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  $runtime->register_adapter(
    adapter_id => 'mock.adapter',
    adapter    => Local::MockAdapter->new,
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
    permissions                 => ['config.read'],
    service_handler             => $services,
  );

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(id => $hello_result->{send}{id})
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_program_ready()
  );

  my $open = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'req-denied',
      method => 'adapters.open_session',
      params => { adapter_id => 'mock.adapter', config => {} },
    )
  );

  ok !$open->{send}{ok}, 'open_session is denied';
  is $open->{send}{error}{code}, 'runtime.permission_denied', 'permission error code returned';
  is $open->{send}{error}{details}{required_permission}, 'adapters.use', 'required permission is reported';
  is_deeply $runtime->adapter_session_ids, [], 'no adapter session is created';
};

subtest 'ready session rejects runtime-originated notifications from program' => sub {
  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
  );

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(id => $hello_result->{send}{id})
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_program_ready()
  );

  like(
    do {
      my $error;
      eval {
        $instance->process_program_message({
          type   => 'notification',
          method => 'runtime.timer_fired',
          params => {
            timer_id => 'timer-1',
            fired_at => 1744301000,
          },
        });
        1;
      } or $error = $@;
      $error;
    },
    qr/protocol\.unknown_method/,
    'runtime-originated notifications are rejected from the program side',
  );
};

subtest 'ready session returns protocol.unknown_method for runtime-only requests from program' => sub {
  my $runtime = Overnet::Program::Runtime->new;
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
    service_handler             => $services,
  );

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(id => $hello_result->{send}{id})
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_program_ready()
  );

  my $result = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'req-runtime-shutdown',
      method => 'runtime.shutdown',
      params => {},
    )
  );

  ok !$result->{send}{ok}, 'runtime-only request is rejected';
  is $result->{send}{error}{code}, 'protocol.unknown_method', 'wrong-direction request gets protocol.unknown_method';
};

subtest 'ready session reports unknown secret as invalid params' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'api-token' => 'top-secret',
    },
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
    permissions                 => ['secrets.read'],
    service_handler             => $services,
  );

  my $hello_result = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(id => $hello_result->{send}{id})
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_program_ready()
  );

  my $result = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'cfg-1',
      method => 'secrets.get',
      params => { name => 'missing-token' },
    )
  );

  ok !$result->{send}{ok}, 'secrets.get rejects unknown name';
  is $result->{send}{error}{code}, 'protocol.invalid_params', 'unknown secret is typed as invalid params';
};

subtest 'malformed program.hello is rejected as invalid params' => sub {
  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
  );

  like(
    do {
      my $error;
      eval {
        $instance->process_program_message({
          type   => 'notification',
          method => 'program.hello',
          params => {
            program_id => 'irc.example',
          },
        });
        1;
      } or $error = $@;
      $error;
    },
    qr/protocol\.invalid_params/,
    'malformed hello is rejected before version negotiation',
  );
};

done_testing;
