use strict;
use warnings;
use Test::More;

use Overnet::Program::Protocol;

sub dies_with (&) {
  my ($code) = @_;
  my $error;
  eval { $code->(); 1 } or $error = $@;
  return $error;
}

subtest 'encodes framed JSON messages' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame = $protocol->encode_message({
    type   => 'notification',
    method => 'program.hello',
    params => {
      program_id                  => 'irc.example',
      supported_protocol_versions => ['0.1'],
    },
  });

  like $frame, qr/\A\d+\n\{/, 'frame has length prefix and JSON payload';
  is $protocol->buffered_bytes, 0, 'encoding does not change decoder buffer';
};

subtest 'decodes a complete frame' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame = $protocol->encode_message({
    type   => 'notification',
    method => 'program.ready',
    params => {},
  });

  my $messages = $protocol->feed($frame);
  is scalar(@{$messages}), 1, 'one message decoded';
  is_deeply $messages->[0], {
    type   => 'notification',
    method => 'program.ready',
    params => {},
  }, 'decoded message matches original';
};

subtest 'handles partial frames across multiple chunks' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame = $protocol->encode_message({
    type   => 'request',
    id     => '1',
    method => 'runtime.init',
    params => {
      protocol_version => '0.1',
    },
  });

  my $mid = int(length($frame) / 2);
  my $first = substr($frame, 0, $mid);
  my $second = substr($frame, $mid);

  my $messages = $protocol->feed($first);
  is scalar(@{$messages}), 0, 'no message decoded from partial frame';
  ok $protocol->buffered_bytes > 0, 'partial bytes retained';

  $messages = $protocol->feed($second);
  is scalar(@{$messages}), 1, 'message decoded after second chunk';
  is $messages->[0]{method}, 'runtime.init', 'decoded expected request';
};

subtest 'decodes multiple frames from one chunk' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame_a = $protocol->encode_message({
    type   => 'notification',
    method => 'program.log',
    params => {
      level   => 'info',
      message => 'a',
    },
  });
  my $frame_b = $protocol->encode_message({
    type   => 'notification',
    method => 'program.health',
    params => {
      status => 'ready',
    },
  });

  my $messages = $protocol->feed($frame_a . $frame_b);
  is scalar(@{$messages}), 2, 'two messages decoded';
  is $messages->[0]{method}, 'program.log', 'first message preserved';
  is $messages->[1]{method}, 'program.health', 'second message preserved';
};

subtest 'rejects non-numeric length prefixes' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  like dies_with { $protocol->feed("abc\n{}") },
    qr/non-numeric length prefix/,
    'non-numeric prefix is rejected';
};

subtest 'rejects oversized frames' => sub {
  my $protocol = Overnet::Program::Protocol->new(max_frame_size => 10);
  my $frame = "11\n" . ('x' x 11);

  like dies_with { $protocol->feed($frame) },
    qr/frame exceeds maximum size/,
    'oversized frame is rejected';
};

subtest 'rejects invalid JSON payloads' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame = "4\nnope";

  like dies_with { $protocol->feed($frame) },
    qr/invalid JSON payload/,
    'invalid JSON payload is rejected';
};

subtest 'rejects truncated frames at end of stream' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame = "10\n{\"type\":1";

  is scalar(@{$protocol->feed($frame)}), 0, 'truncated frame remains buffered until stream end';
  like dies_with { $protocol->finish },
    qr/payload shorter than declared length|incomplete frame at end of stream/,
    'end-of-stream validation rejects truncated frame';
};

subtest 'rejects trailing bytes at end of stream after valid frames' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame = $protocol->encode_message({
    type   => 'notification',
    method => 'program.ready',
    params => {},
  });

  is scalar(@{$protocol->feed($frame . 'x')}), 1, 'valid frame is decoded before trailing bytes';
  like dies_with { $protocol->finish },
    qr/incomplete frame at end of stream|trailing payload bytes do not begin a valid next frame/,
    'end-of-stream validation rejects trailing garbage';
};

subtest 'rejects JSON payloads that are not objects' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame = "2\n[]";

  like dies_with { $protocol->feed($frame) },
    qr/payload must decode to a JSON object/,
    'non-object payload is rejected';
};

subtest 'encode_message rejects non-object messages' => sub {
  my $protocol = Overnet::Program::Protocol->new;

  like dies_with { $protocol->encode_message([]) },
    qr/hash reference/,
    'non-hash messages are rejected';
};

subtest 'validates baseline request messages' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message({
    type   => 'request',
    id     => '1',
    method => 'runtime.shutdown',
    params => { reason => 'test' },
  });

  ok $ok, 'request is valid';
  ok !defined $code, 'no error code';
  ok !defined $message, 'no error message';
};

subtest 'rejects unknown notification methods' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message({
    type   => 'notification',
    method => 'program.unknown',
    params => {},
  });

  ok !$ok, 'notification is invalid';
  is $code, 'protocol.unknown_method', 'returns protocol.unknown_method';
  like $message, qr/Unknown notification method/, 'error message is informative';
};

subtest 'validates runtime.fatal notifications' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    Overnet::Program::Protocol::build_runtime_fatal(
      code    => 'protocol.version_mismatch',
      message => 'No compatible protocol version',
      phase   => 'handshake',
      details => {
        runtime_supported_protocol_versions => ['0.1'],
      },
    )
  );

  ok $ok, 'runtime.fatal notification is valid';
  ok !defined $code, 'no error code';
  ok !defined $message, 'no error message';
};

subtest 'rejects malformed runtime.fatal notifications' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message({
    type   => 'notification',
    method => 'runtime.fatal',
    params => {
      code => 'protocol.version_mismatch',
    },
  });

  ok !$ok, 'runtime.fatal notification is invalid';
  is $code, 'protocol.invalid_params', 'runtime.fatal validation uses invalid params';
  like $message, qr/runtime\.fatal params\.message is required/, 'validation error identifies missing field';
};

subtest 'rejects malformed responses' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message({
    type  => 'response',
    id    => '1',
    ok    => JSON::PP::true,
    error => { code => 'x', message => 'y' },
  });

  ok !$ok, 'response is invalid';
  is $code, 'protocol.invalid_message', 'returns protocol.invalid_message';
  like $message, qr/must not include error/, 'error message is informative';
};

subtest 'rejects response ok values that are not booleans' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message({
    type  => 'response',
    id    => '1',
    ok    => '0',
    error => { code => 'x', message => 'y' },
  });

  ok !$ok, 'response is invalid';
  is $code, 'protocol.invalid_message', 'returns protocol.invalid_message';
  like $message, qr/ok field must be a boolean/, 'error message is informative';
};

subtest 'rejects malformed program.hello notifications' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message({
    type   => 'notification',
    method => 'program.hello',
    params => {
      program_id => 'irc.example',
    },
  });

  ok !$ok, 'notification is invalid';
  is $code, 'protocol.invalid_params', 'returns protocol.invalid_params';
  like $message, qr/supported_protocol_versions/, 'error message identifies missing field';
};

subtest 'builds baseline handshake messages' => sub {
  my $hello = Overnet::Program::Protocol::build_program_hello(
    program_id                  => 'irc.example',
    supported_protocol_versions => ['0.1'],
    program_version             => '1.2.3',
  );
  is $hello->{type}, 'notification', 'hello is notification';
  is $hello->{method}, 'program.hello', 'hello method is correct';

  my $init = Overnet::Program::Protocol::build_runtime_init(
    id               => 'init-1',
    protocol_version => '0.1',
    instance_id      => 'instance-1',
    program_id       => 'irc.example',
    config           => {},
    permissions      => ['config.read'],
    services         => {},
  );
  is $init->{type}, 'request', 'runtime.init is request';
  is $init->{method}, 'runtime.init', 'runtime.init method is correct';

  my $ready = Overnet::Program::Protocol::build_program_ready(
    params => { phase => 'startup-complete' },
  );
  is $ready->{method}, 'program.ready', 'program.ready method is correct';

  my $shutdown = Overnet::Program::Protocol::build_runtime_shutdown(
    id     => 'shutdown-1',
    reason => 'operator-requested',
  );
  is $shutdown->{method}, 'runtime.shutdown', 'runtime.shutdown method is correct';
};

subtest 'encodes request helper output as framed messages' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame = $protocol->encode_request(
    id     => 'cfg-1',
    method => 'config.get',
    params => {},
  );

  my $messages = $protocol->feed($frame);
  is scalar(@{$messages}), 1, 'one helper-built request decoded';
  is $messages->[0]{method}, 'config.get', 'helper-built request survives roundtrip';
};

done_testing;
