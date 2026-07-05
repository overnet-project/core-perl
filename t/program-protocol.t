use strictures 2;
use JSON ();
use Test2::V0;

use Overnet::Program::Protocol;

sub dies_with (&) {
  my ($code) = @_;
  my $error;
  eval { $code->(); 1 } or $error = $@;
  return $error;
}

subtest 'encodes framed JSON messages' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = $protocol->encode_message(
    {
      type   => 'notification',
      method => 'program.hello',
      params => {
        program_id                  => 'irc.example',
        supported_protocol_versions => ['0.1'],
      },
    }
  );

  like $frame, qr/\A\d+\n\{/mx, 'frame has length prefix and JSON payload';
  is $protocol->buffered_bytes, 0, 'encoding does not change decoder buffer';
};

subtest 'decodes a complete frame' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = $protocol->encode_message(
    {
      type   => 'notification',
      method => 'program.ready',
      params => {},
    }
  );

  my $messages = $protocol->feed($frame);
  is scalar(@{$messages}), 1, 'one message decoded';
  is $messages->[0],
    {
    type   => 'notification',
    method => 'program.ready',
    params => {},
    },
    'decoded message matches original';
};

subtest 'handles partial frames across multiple chunks' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = $protocol->encode_message(
    {
      type   => 'request',
      id     => '1',
      method => 'runtime.init',
      params => {
        protocol_version => '0.1',
      },
    }
  );

  my $mid    = int(length($frame) / 2);
  my $first  = substr($frame, 0, $mid);
  my $second = substr($frame, $mid);

  my $messages = $protocol->feed($first);
  is scalar(@{$messages}), 0, 'no message decoded from partial frame';
  ok $protocol->buffered_bytes > 0, 'partial bytes retained';

  $messages = $protocol->feed($second);
  is scalar(@{$messages}),   1,              'message decoded after second chunk';
  is $messages->[0]{method}, 'runtime.init', 'decoded expected request';
};

subtest 'decodes multiple frames from one chunk' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame_a  = $protocol->encode_message(
    {
      type   => 'notification',
      method => 'program.log',
      params => {
        level   => 'info',
        message => 'a',
      },
    }
  );
  my $frame_b = $protocol->encode_message(
    {
      type   => 'notification',
      method => 'program.health',
      params => {
        status => 'ready',
      },
    }
  );

  my $messages = $protocol->feed($frame_a . $frame_b);
  is scalar(@{$messages}),   2,                'two messages decoded';
  is $messages->[0]{method}, 'program.log',    'first message preserved';
  is $messages->[1]{method}, 'program.health', 'second message preserved';
};

subtest 'rejects non-numeric length prefixes' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  like dies_with { $protocol->feed("abc\n{}") }, qr/non-numeric\ length\ prefix/mx, 'non-numeric prefix is rejected';
};

subtest 'rejects oversized frames' => sub {
  my $protocol = Overnet::Program::Protocol->new(max_frame_size => 10);
  my $frame    = "11\n" . ('x' x 11);

  like dies_with { $protocol->feed($frame) }, qr/frame\ exceeds\ maximum\ size/mx, 'oversized frame is rejected';
};

subtest 'rejects an unterminated length prefix that exceeds the maximum' => sub {
  my $protocol = Overnet::Program::Protocol->new(max_frame_size => 1000);

  # A canonical length prefix for a <= 1000-byte frame is at most 4 digits.
  # A longer run of bytes with no newline can never begin a valid frame, so
  # it must be rejected rather than buffered without bound.
  like dies_with { $protocol->feed('1' x 4096) },
    qr/length\ prefix\ exceeds\ maximum\ size/mx,
    'an over-long unterminated length prefix is rejected instead of buffered without bound';
};

subtest 'retains a short partial length prefix awaiting its newline' => sub {
  my $protocol = Overnet::Program::Protocol->new(max_frame_size => 1000);

  my $messages = $protocol->feed('12');
  is scalar(@{$messages}), 0, 'no complete frame yet';
  ok $protocol->buffered_bytes > 0, 'a short in-progress length prefix is still retained';
};

subtest 'rejects invalid JSON payloads' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = "4\nnope";

  like dies_with { $protocol->feed($frame) }, qr/invalid\ JSON\ payload/mx, 'invalid JSON payload is rejected';
};

subtest 'rejects truncated frames at end of stream' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = "10\n{\"type\":1";

  is scalar(@{$protocol->feed($frame)}), 0, 'truncated frame remains buffered until stream end';
  like dies_with { $protocol->finish },
    qr/payload\ shorter\ than\ declared\ length|incomplete\ frame\ at\ end\ of\ stream/mx,
    'end-of-stream validation rejects truncated frame';
};

subtest 'rejects trailing bytes at end of stream after valid frames' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = $protocol->encode_message(
    {
      type   => 'notification',
      method => 'program.ready',
      params => {},
    }
  );

  is scalar(@{$protocol->feed($frame . 'x')}), 1, 'valid frame is decoded before trailing bytes';
  like dies_with { $protocol->finish },
    qr/incomplete\ frame\ at\ end\ of\ stream|trailing\ payload\ bytes\ do\ not\ begin\ a\ valid\ next\ frame/mx,
    'end-of-stream validation rejects trailing garbage';
};

subtest 'rejects JSON payloads that are not objects' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = "2\n[]";

  like dies_with { $protocol->feed($frame) },
    qr/payload\ must\ decode\ to\ a\ JSON\ object/mx,
    'non-object payload is rejected';
};

subtest 'encode_message rejects non-object messages' => sub {
  my $protocol = Overnet::Program::Protocol->new;

  like dies_with { $protocol->encode_message([]) }, qr/hash\ reference/mx, 'non-hash messages are rejected';
};

subtest 'constructor rejects invalid max_frame_size values' => sub {
  like dies_with { Overnet::Program::Protocol->new(max_frame_size => 'not-a-number') },
    qr/max_frame_size\ must\ be\ a\ positive\ integer/mx,
    'non-numeric max_frame_size is rejected at construction';

  like dies_with { Overnet::Program::Protocol->new(max_frame_size => 0) },
    qr/max_frame_size\ must\ be\ a\ positive\ integer/mx,
    'zero max_frame_size is rejected at construction';
};

subtest 'validates baseline request messages' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'request',
      id     => '1',
      method => 'runtime.shutdown',
      params => {reason => 'test'},
    }
  );

  ok $ok,               'request is valid';
  ok !defined $code,    'no error code';
  ok !defined $message, 'no error message';
};

subtest 'rejects unknown notification methods' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'notification',
      method => 'program.unknown',
      params => {},
    }
  );

  ok !$ok, 'notification is invalid';
  is $code, 'protocol.unknown_method', 'returns protocol.unknown_method';
  like $message, qr/Unknown\ notification\ method/mx, 'error message is informative';
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

  ok $ok,               'runtime.fatal notification is valid';
  ok !defined $code,    'no error code';
  ok !defined $message, 'no error message';
};

subtest 'rejects malformed runtime.fatal notifications' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'notification',
      method => 'runtime.fatal',
      params => {
        code => 'protocol.version_mismatch',
      },
    }
  );

  ok !$ok, 'runtime.fatal notification is invalid';
  is $code, 'protocol.invalid_params', 'runtime.fatal validation uses invalid params';
  like $message, qr/runtime\.fatal\ params\.message\ is\ required/mx, 'validation error identifies missing field';
};

subtest 'accepts baseline runtime.subscription_event item types' => sub {
  my $protocol = Overnet::Program::Protocol->new;

  for my $item_type (qw(event state capability)) {
    my ($ok, $code, $message) = $protocol->validate_message(
      {
        type   => 'notification',
        method => 'runtime.subscription_event',
        params => {
          subscription_id => 'sub-1',
          item_type       => $item_type,
          data            => {},
        },
      }
    );

    ok $ok, "runtime.subscription_event accepts item_type $item_type"
      or diag "code=$code message=$message";
  }
};

subtest 'accepts runtime.subscription_event private_message item type' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'notification',
      method => 'runtime.subscription_event',
      params => {
        subscription_id => 'sub-1',
        item_type       => 'private_message',
        data            => {
          transport    => {kind => 1059},
          private_type => 'chat.message',
          object_type  => 'chat.channel',
          object_id    => 'group:abc',
        },
      },
    }
  );

  ok $ok,               'private_message subscription event is valid';
  ok !defined $code,    'no error code';
  ok !defined $message, 'no error message';
};

subtest 'accepts runtime.subscription_event nostr.event item type' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'notification',
      method => 'runtime.subscription_event',
      params => {
        subscription_id => 'sub-1',
        item_type       => 'nostr.event',
        data            => {id => 'abc', kind => 1},
      },
    }
  );

  ok $ok,               'nostr.event subscription event is valid';
  ok !defined $code,    'no error code';
  ok !defined $message, 'no error message';
};

subtest 'rejects private_message subscription events missing required data' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'notification',
      method => 'runtime.subscription_event',
      params => {
        subscription_id => 'sub-1',
        item_type       => 'private_message',
        data            => {
          private_type => 'chat.message',
          object_type  => 'chat.channel',
          object_id    => 'group:abc',
        },
      },
    }
  );

  ok !$ok, 'private_message missing transport is invalid';
  is $code, 'protocol.invalid_params', 'uses invalid params code';
  like $message, qr/private_message\ data\.transport/mx, 'error identifies missing transport';
};

subtest 'rejects runtime.subscription_event with unknown item type' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'notification',
      method => 'runtime.subscription_event',
      params => {
        subscription_id => 'sub-1',
        item_type       => 'bogus',
        data            => {},
      },
    }
  );

  ok !$ok, 'unknown item_type is invalid';
  is $code, 'protocol.invalid_params', 'uses invalid params code';
  like $message, qr/item_type\ is\ invalid/mx, 'error identifies invalid item_type';
};

subtest 'rejects malformed responses' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type  => 'response',
      id    => '1',
      ok    => JSON::true,
      error => {code => 'x', message => 'y'},
    }
  );

  ok !$ok, 'response is invalid';
  is $code, 'protocol.invalid_message', 'returns protocol.invalid_message';
  like $message, qr/must\ not\ include\ error/mx, 'error message is informative';
};

subtest 'rejects response ok values that are not booleans' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type  => 'response',
      id    => '1',
      ok    => '0',
      error => {code => 'x', message => 'y'},
    }
  );

  ok !$ok, 'response is invalid';
  is $code, 'protocol.invalid_message', 'returns protocol.invalid_message';
  like $message, qr/ok\ field\ must\ be\ a\ boolean/mx, 'error message is informative';
};

subtest 'rejects malformed program.hello notifications' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my ($ok, $code, $message) = $protocol->validate_message(
    {
      type   => 'notification',
      method => 'program.hello',
      params => {
        program_id => 'irc.example',
      },
    }
  );

  ok !$ok, 'notification is invalid';
  is $code, 'protocol.invalid_params', 'returns protocol.invalid_params';
  like $message, qr/supported_protocol_versions/mx, 'error message identifies missing field';
};

subtest 'builds baseline handshake messages' => sub {
  my $hello = Overnet::Program::Protocol::build_program_hello(
    program_id                  => 'irc.example',
    supported_protocol_versions => ['0.1'],
    program_version             => '1.2.3',
  );
  is $hello->{type},   'notification',  'hello is notification';
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
  is $init->{type},   'request',      'runtime.init is request';
  is $init->{method}, 'runtime.init', 'runtime.init method is correct';

  my $ready = Overnet::Program::Protocol::build_program_ready(params => {phase => 'startup-complete'},);
  is $ready->{method}, 'program.ready', 'program.ready method is correct';

  my $shutdown = Overnet::Program::Protocol::build_runtime_shutdown(
    id     => 'shutdown-1',
    reason => 'operator-requested',
  );
  is $shutdown->{method}, 'runtime.shutdown', 'runtime.shutdown method is correct';
};

subtest 'encodes request helper output as framed messages' => sub {
  my $protocol = Overnet::Program::Protocol->new;
  my $frame    = $protocol->encode_request(
    id     => 'cfg-1',
    method => 'config.get',
    params => {},
  );

  my $messages = $protocol->feed($frame);
  is scalar(@{$messages}),   1,            'one helper-built request decoded';
  is $messages->[0]{method}, 'config.get', 'helper-built request survives roundtrip';
};

done_testing;
