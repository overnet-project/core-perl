use strict;
use warnings;
use Test::More;
use JSON::PP ();

use Overnet::Program::Instance;
use Overnet::Program::Protocol;
use Overnet::Program::Runtime;
use Overnet::Program::SecretProvider;
use Overnet::Program::Services;

sub _structured_error (&) {
  my ($code) = @_;
  my $error;
  eval {
    $code->();
    1;
  } or $error = $@;
  return $error;
}

sub _random_bytes_cb {
  my $counter = 0;
  return sub {
    my ($length) = @_;
    $counter++;
    return chr(64 + $counter) x $length;
  };
}

subtest 'services issue opaque secret handles instead of raw values' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'api-token' => 'top-secret',
    },
    now_cb => sub { 1_700_000_000_000 },
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $result = $services->dispatch_request(
    'secrets.get',
    { name => 'api-token' },
    permissions => ['secrets.read'],
    session_id  => 'session-1',
    program_id  => 'secrets.program',
  );

  is $result->{name}, 'api-token', 'secrets.get returns the requested secret name';
  ok !exists $result->{value}, 'secrets.get does not expose the raw secret value';
  like $result->{secret_handle}{id}, qr/\Ash_[0-9a-f]{64}\z/, 'secret handle id is opaque';
  is $result->{secret_handle}{expires_at}, 1_700_000_300, 'secret handle expiry is returned';
};

subtest 'runtime resolves issued handles only inside the owning audience and before expiry' => sub {
  my $now = 1_700_000_000_000;
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'api-token' => 'top-secret',
    },
    now_cb               => sub { $now },
    secret_handle_ttl_ms => 1_000,
    random_bytes_cb      => _random_bytes_cb(),
  );

  my $issued = $runtime->issue_secret_handle(
    session_id => 'session-1',
    program_id => 'secrets.program',
    name       => 'api-token',
    purpose    => 'adapters.open_session:secure.adapter:server_password',
  );
  my $handle_id = $issued->{secret_handle}{id};

  my $resolved = $runtime->resolve_secret_handle(
    session_id  => 'session-1',
    program_id  => 'secrets.program',
    handle_id   => $handle_id,
    method      => 'adapters.open_session',
    adapter_id  => 'secure.adapter',
    secret_slot => 'server_password',
    purpose     => 'adapters.open_session:secure.adapter:server_password',
  );
  is_deeply(
    $resolved,
    {
      name  => 'api-token',
      value => 'top-secret',
    },
    'runtime can resolve the handle internally for the owning audience',
  );

  my $error = _structured_error {
    $runtime->resolve_secret_handle(
      session_id  => 'session-2',
      program_id  => 'secrets.program',
      handle_id   => $handle_id,
      method      => 'adapters.open_session',
      adapter_id  => 'secure.adapter',
      secret_slot => 'server_password',
      purpose     => 'adapters.open_session:secure.adapter:server_password',
    );
  };
  is ref($error), 'HASH', 'wrong-session resolution error is structured';
  is $error->{code}, 'protocol.invalid_params', 'wrong-session handle use is invalid params';
  is $error->{message}, 'Secret access denied or unavailable', 'wrong-session handle use is redacted';

  $error = _structured_error {
    $runtime->resolve_secret_handle(
      session_id  => 'session-1',
      program_id  => 'secrets.program',
      handle_id   => $handle_id,
      method      => 'adapters.open_session',
      adapter_id  => 'secure.adapter',
      secret_slot => 'server_password',
      purpose     => 'adapters.open_session:secure.adapter:sasl_password',
    );
  };
  is ref($error), 'HASH', 'wrong-purpose resolution error is structured';
  is $error->{code}, 'protocol.invalid_params', 'wrong-purpose handle use is invalid params';
  is $error->{message}, 'Secret access denied or unavailable', 'wrong-purpose handle use is redacted';

  $now += 1_001;
  $error = _structured_error {
    $runtime->resolve_secret_handle(
      session_id  => 'session-1',
      program_id  => 'secrets.program',
      handle_id   => $handle_id,
      method      => 'adapters.open_session',
      adapter_id  => 'secure.adapter',
      secret_slot => 'server_password',
      purpose     => 'adapters.open_session:secure.adapter:server_password',
    );
  };
  is ref($error), 'HASH', 'expired handle error is structured';
  is $error->{code}, 'protocol.invalid_params', 'expired handle is no longer resolvable';
};

subtest 'services reject invalid or unavailable secrets.get params without name enumeration' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'api-token' => 'top-secret',
    },
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error = _structured_error {
    $services->dispatch_request(
      'secrets.get',
      {},
      permissions => ['secrets.read'],
      session_id  => 'session-1',
      program_id  => 'secrets.program',
    );
  };
  is ref($error), 'HASH', 'missing name error is structured';
  is $error->{code}, 'protocol.invalid_params', 'missing name is invalid params';

  $error = _structured_error {
    $services->dispatch_request(
      'secrets.get',
      { name => 'missing-token' },
      permissions => ['secrets.read'],
      session_id  => 'session-1',
      program_id  => 'secrets.program',
    );
  };
  is ref($error), 'HASH', 'unknown secret name error is structured';
  is $error->{code}, 'protocol.invalid_params', 'unknown secret name is invalid params';
  is $error->{message}, 'Secret access denied or unavailable', 'unknown secret name error is redacted';
  is $error->{details}{param}, 'name', 'unknown secret name only identifies the request field';
};

subtest 'services enforce secrets.read permission' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'api-token' => 'top-secret',
    },
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);

  my $error = _structured_error {
    $services->dispatch_request(
      'secrets.get',
      { name => 'api-token' },
      permissions => [],
      session_id  => 'session-1',
      program_id  => 'secrets.program',
    );
  };
  is ref($error), 'HASH', 'permission error is structured';
  is $error->{code}, 'runtime.permission_denied', 'secrets.get requires permission';
  is $error->{details}{required_permission}, 'secrets.read', 'required permission is reported';
};

subtest 'secret-provider-backed secrets enforce per-secret ACLs and keep audit output redacted' => sub {
  my $secret_provider = Overnet::Program::SecretProvider->new(
    secrets => {
      'server-token' => 'top-secret',
    },
    secret_policies => {
      'server-token' => {
        allowed_program_ids  => ['allowed.program'],
        allowed_methods      => ['adapters.open_session'],
        allowed_adapter_ids  => ['secure.adapter'],
        allowed_secret_slots => ['server_password'],
        allowed_purposes     => ['adapters.open_session:secure.adapter:server_password'],
      },
    },
    now_cb          => sub { 1_700_000_000_000 },
    random_bytes_cb => _random_bytes_cb(),
  );
  my $runtime = Overnet::Program::Runtime->new(
    secret_provider => $secret_provider,
    now_cb => sub { 1_700_000_000_000 },
  );

  my $issued = $runtime->issue_secret_handle(
    session_id => 'session-1',
    program_id => 'allowed.program',
    name       => 'server-token',
    purpose    => 'adapters.open_session:secure.adapter:server_password',
  );

  my $resolved = $runtime->resolve_secret_handle(
    session_id  => 'session-1',
    program_id  => 'allowed.program',
    handle_id   => $issued->{secret_handle}{id},
    method      => 'adapters.open_session',
    adapter_id  => 'secure.adapter',
    secret_slot => 'server_password',
    purpose     => 'adapters.open_session:secure.adapter:server_password',
  );
  is $resolved->{value}, 'top-secret', 'secret-provider-backed runtime resolves an allowed handle';

  my $error = _structured_error {
    $runtime->issue_secret_handle(
      session_id => 'session-1',
      program_id => 'other.program',
      name       => 'server-token',
      purpose    => 'adapters.open_session:secure.adapter:server_password',
    );
  };
  is ref($error), 'HASH', 'policy denial is structured';
  is $error->{code}, 'protocol.invalid_params', 'policy denial uses invalid params';
  is $error->{message}, 'Secret access denied or unavailable', 'policy denial is redacted';

  my $audit_json = JSON::PP::encode_json($secret_provider->audit_events);
  unlike $audit_json, qr/top-secret/, 'audit log never includes plaintext secret material';
  unlike $audit_json, qr/\Q$issued->{secret_handle}{id}\E/, 'audit log never includes raw handle ids';
  like $audit_json, qr/secret_handle\.issue/, 'audit log records issue attempts';
  like $audit_json, qr/secret_handle\.resolve/, 'audit log records resolve attempts';
};

subtest 'rotation and session revocation invalidate previously issued handles' => sub {
  my $secret_provider = Overnet::Program::SecretProvider->new(
    secrets => {
      'api-token' => 'v1-secret',
    },
    now_cb          => sub { 1_700_000_000_000 },
    random_bytes_cb => _random_bytes_cb(),
  );
  my $runtime = Overnet::Program::Runtime->new(
    secret_provider => $secret_provider,
    now_cb => sub { 1_700_000_000_000 },
  );

  my $issued = $runtime->issue_secret_handle(
    session_id => 'session-1',
    program_id => 'rotate.program',
    name       => 'api-token',
  );
  my $handle_id = $issued->{secret_handle}{id};

  my $rotated = $runtime->rotate_secret(
    name  => 'api-token',
    value => 'v2-secret',
  );
  is $rotated->{revoked}, 1, 'rotating a secret revokes outstanding handles for that secret';

  my $error = _structured_error {
    $runtime->resolve_secret_handle(
      session_id => 'session-1',
      program_id => 'rotate.program',
      handle_id  => $handle_id,
    );
  };
  is ref($error), 'HASH', 'rotated handle error is structured';
  is $error->{code}, 'protocol.invalid_params', 'rotated handle can no longer be resolved';

  my $reissued = $runtime->issue_secret_handle(
    session_id => 'session-1',
    program_id => 'rotate.program',
    name       => 'api-token',
  );
  my $resolved = $runtime->resolve_secret_handle(
    session_id => 'session-1',
    program_id => 'rotate.program',
    handle_id  => $reissued->{secret_handle}{id},
  );
  is $resolved->{value}, 'v2-secret', 'reissued handles resolve the rotated secret value';

  is $runtime->revoke_secret_handles_for_session(session_id => 'session-1'), 1,
    'explicit session revocation removes outstanding handles';
  $error = _structured_error {
    $runtime->resolve_secret_handle(
      session_id => 'session-1',
      program_id => 'rotate.program',
      handle_id  => $reissued->{secret_handle}{id},
    );
  };
  is ref($error), 'HASH', 'revoked session handle error is structured';
  is $error->{code}, 'protocol.invalid_params', 'session-revoked handle is no longer resolvable';
};

subtest 'runtime validates secret constructor params' => sub {
  like(
    do {
      my $error;
      eval {
        Overnet::Program::Runtime->new(
          secrets => {
            'api-token' => {},
          },
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/secret api-token must be a string/,
    'runtime rejects non-string secret values',
  );

  like(
    do {
      my $error;
      eval {
        Overnet::Program::Runtime->new(
          secret_handle_ttl_ms => 0,
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/secret_handle_ttl_ms must be a positive integer/,
    'runtime rejects invalid secret handle ttl',
  );

  like(
    do {
      my $error;
      eval {
        Overnet::Program::Runtime->new(
          secret_policies => {
            'api-token' => {
              allowed_program_ids => [''],
            },
          },
        );
        1;
      } or $error = $@;
      $error;
    },
    qr/secret policy api-token\.allowed_program_ids must be an array of non-empty strings/,
    'runtime rejects invalid secret policy shapes',
  );
};

subtest 'instance issues secret handles through protocol without returning plaintext and revokes them on shutdown' => sub {
  my $runtime = Overnet::Program::Runtime->new(
    secrets => {
      'api-token' => 'top-secret',
    },
    now_cb          => sub { 1_700_000_000_000 },
    random_bytes_cb => _random_bytes_cb(),
  );
  my $services = Overnet::Program::Services->new(runtime => $runtime);
  my $instance = Overnet::Program::Instance->new(
    supported_protocol_versions => ['0.1'],
    permissions                 => ['secrets.read'],
    service_handler             => $services,
  );

  my $hello = $instance->process_program_message(
    Overnet::Program::Protocol::build_program_hello(
      program_id                  => 'secrets.example',
      supported_protocol_versions => ['0.1'],
    )
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(id => $hello->{send}{id})
  );
  $instance->process_program_message(
    Overnet::Program::Protocol::build_program_ready()
  );

  my $response = $instance->process_program_message(
    Overnet::Program::Protocol::build_request(
      id     => 'secret-1',
      method => 'secrets.get',
      params => { name => 'api-token' },
    )
  );

  ok $response->{send}{ok}, 'secrets.get succeeds through protocol';
  is $response->{send}{result}{name}, 'api-token', 'protocol response returns requested secret name';
  ok !exists $response->{send}{result}{value}, 'protocol response does not expose the secret plaintext';
  like $response->{send}{result}{secret_handle}{id}, qr/\Ash_[0-9a-f]{64}\z/, 'protocol response returns opaque handle';

  my $resolved = $runtime->resolve_secret_handle(
    session_id => 'instance-1',
    program_id => 'secrets.example',
    handle_id  => $response->{send}{result}{secret_handle}{id},
  );
  is $resolved->{value}, 'top-secret', 'runtime can resolve the protocol-issued handle internally';

  my $shutdown = $instance->request_shutdown(reason => 'done');
  $instance->process_program_message(
    Overnet::Program::Protocol::build_response_ok(id => $shutdown->{send}{id})
  );

  my $error = _structured_error {
    $runtime->resolve_secret_handle(
      session_id => 'instance-1',
      program_id => 'secrets.example',
      handle_id  => $response->{send}{result}{secret_handle}{id},
    );
  };
  is ref($error), 'HASH', 'shutdown-revoked handle error is structured';
  is $error->{code}, 'protocol.invalid_params', 'instance shutdown revokes outstanding secret handles';
};

done_testing;
