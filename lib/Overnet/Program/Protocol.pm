package Overnet::Program::Protocol;

use strict;
use warnings;
use JSON::PP ();

our $VERSION = '0.001';
my $DEFAULT_MAX_FRAME_SIZE = 1024 * 1024;
my %VALID_MESSAGE_TYPES = map { $_ => 1 } qw(request response notification);
my %PROGRAM_NOTIFICATION_METHODS = map { $_ => 1 } qw(
  program.hello
  program.ready
  program.log
  program.health
);
my %RUNTIME_NOTIFICATION_METHODS = map { $_ => 1 } qw(
  runtime.fatal
  runtime.subscription_event
  runtime.timer_fired
);
my %RUNTIME_REQUEST_METHODS = map { $_ => 1 } qw(
  runtime.init
  runtime.shutdown
);
my %SERVICE_REQUEST_METHODS = map { $_ => 1 } qw(
  config.get
  config.describe
  secrets.get
  storage.put
  storage.get
  storage.delete
  storage.list
  events.append
  events.read
  subscriptions.open
  subscriptions.close
  timers.schedule
  timers.cancel
  adapters.open_session
  adapters.map_input
  adapters.derive
  adapters.close_session
  overnet.emit_event
  overnet.emit_state
  overnet.emit_private_message
  overnet.emit_capabilities
);
my %BASELINE_NOTIFICATION_METHODS = (
  %PROGRAM_NOTIFICATION_METHODS,
  %RUNTIME_NOTIFICATION_METHODS,
);
my %BASELINE_REQUEST_METHODS = (
  %RUNTIME_REQUEST_METHODS,
  %SERVICE_REQUEST_METHODS,
);

sub new {
  my ($class, %args) = @_;

  my $self = bless {
    max_frame_size => $args{max_frame_size} || $DEFAULT_MAX_FRAME_SIZE,
    _buffer        => '',
  }, $class;

  return $self;
}

sub max_frame_size {
  my ($self) = @_;
  return $self->{max_frame_size};
}

sub buffered_bytes {
  my ($self) = @_;
  return length $self->{_buffer};
}

sub is_program_notification_method {
  my ($class, $method) = @_;
  return defined $method && !ref($method) && $PROGRAM_NOTIFICATION_METHODS{$method} ? 1 : 0;
}

sub is_runtime_notification_method {
  my ($class, $method) = @_;
  return defined $method && !ref($method) && $RUNTIME_NOTIFICATION_METHODS{$method} ? 1 : 0;
}

sub is_runtime_request_method {
  my ($class, $method) = @_;
  return defined $method && !ref($method) && $RUNTIME_REQUEST_METHODS{$method} ? 1 : 0;
}

sub is_service_request_method {
  my ($class, $method) = @_;
  return defined $method && !ref($method) && $SERVICE_REQUEST_METHODS{$method} ? 1 : 0;
}

sub encode_message {
  my ($self, $message) = @_;
  _assert_message_object($message);

  my $json = JSON::PP->new->utf8->canonical->encode($message);
  my $length = length $json;

  if ($length > $self->{max_frame_size}) {
    die "Protocol frame exceeds maximum size\n";
  }

  return $length . "\n" . $json;
}

sub validate_message {
  my ($self, $message) = @_;
  _assert_message_object($message);

  my $type = $message->{type};
  return (0, 'protocol.invalid_message', 'Message type is required')
    unless defined $type && !ref($type) && length($type);
  return (0, 'protocol.unknown_message_type', "Unknown message type: $type")
    unless $VALID_MESSAGE_TYPES{$type};

  if ($type eq 'request') {
    return _validate_request($message);
  } elsif ($type eq 'response') {
    return _validate_response($message);
  } else {
    return _validate_notification($message);
  }
}

sub encode_request {
  my ($self, %args) = @_;
  my $message = build_request(%args);
  return $self->encode_message($message);
}

sub encode_response_ok {
  my ($self, %args) = @_;
  my $message = build_response_ok(%args);
  return $self->encode_message($message);
}

sub encode_response_error {
  my ($self, %args) = @_;
  my $message = build_response_error(%args);
  return $self->encode_message($message);
}

sub encode_notification {
  my ($self, %args) = @_;
  my $message = build_notification(%args);
  return $self->encode_message($message);
}

sub build_request {
  my (%args) = @_;
  _require_string_field(id => $args{id});
  _require_string_field(method => $args{method});
  _require_object_field_optional(params => $args{params});

  return {
    type   => 'request',
    id     => $args{id},
    method => $args{method},
    params => $args{params} || {},
  };
}

sub build_response_ok {
  my (%args) = @_;
  _require_string_field(id => $args{id});
  _require_object_field_optional(result => $args{result});

  return {
    type   => 'response',
    id     => $args{id},
    ok     => JSON::PP::true,
    result => $args{result} || {},
  };
}

sub build_response_error {
  my (%args) = @_;
  _require_string_field(id => $args{id});
  _require_string_field(code => $args{code});
  _require_string_field(message => $args{message});
  _require_object_field_optional(details => $args{details});

  my $error = {
    code    => $args{code},
    message => $args{message},
  };
  $error->{details} = $args{details} if defined $args{details};

  return {
    type  => 'response',
    id    => $args{id},
    ok    => JSON::PP::false,
    error => $error,
  };
}

sub build_notification {
  my (%args) = @_;
  _require_string_field(method => $args{method});
  _require_object_field_optional(params => $args{params});

  return {
    type   => 'notification',
    method => $args{method},
    params => $args{params} || {},
  };
}

sub build_program_hello {
  my (%args) = @_;
  _require_string_field(program_id => $args{program_id});
  _require_string_array_field(supported_protocol_versions => $args{supported_protocol_versions});
  _require_string_field_optional(program_version => $args{program_version});
  _require_object_field_optional(metadata => $args{metadata});

  my %params = (
    program_id                  => $args{program_id},
    supported_protocol_versions => $args{supported_protocol_versions},
  );
  $params{program_version} = $args{program_version} if defined $args{program_version};
  $params{metadata} = $args{metadata} if defined $args{metadata};

  return build_notification(
    method => 'program.hello',
    params => \%params,
  );
}

sub build_runtime_init {
  my (%args) = @_;
  _require_string_field(id => $args{id});
  _require_string_field(protocol_version => $args{protocol_version});
  _require_string_field(instance_id => $args{instance_id});
  _require_string_field(program_id => $args{program_id});
  _require_array_field(permissions => $args{permissions});
  _require_object_field(config => $args{config});
  _require_object_field(services => $args{services});

  return build_request(
    id     => $args{id},
    method => 'runtime.init',
    params => {
      protocol_version => $args{protocol_version},
      instance_id      => $args{instance_id},
      program_id       => $args{program_id},
      config           => $args{config},
      permissions      => $args{permissions},
      services         => $args{services},
    },
  );
}

sub build_program_ready {
  my (%args) = @_;
  _require_object_field_optional(params => $args{params});
  return build_notification(
    method => 'program.ready',
    params => $args{params} || {},
  );
}

sub build_runtime_fatal {
  my (%args) = @_;
  _require_string_field(code => $args{code});
  _require_string_field(message => $args{message});
  _require_string_field_optional(phase => $args{phase});
  _require_object_field_optional(details => $args{details});

  my %params = (
    code    => $args{code},
    message => $args{message},
  );
  $params{phase} = $args{phase} if defined $args{phase};
  $params{details} = $args{details} if defined $args{details};

  return build_notification(
    method => 'runtime.fatal',
    params => \%params,
  );
}

sub build_runtime_shutdown {
  my (%args) = @_;
  _require_string_field(id => $args{id});
  _require_string_field_optional(reason => $args{reason});

  my %params;
  $params{reason} = $args{reason} if defined $args{reason};

  return build_request(
    id     => $args{id},
    method => 'runtime.shutdown',
    params => \%params,
  );
}

sub feed {
  my ($self, $chunk) = @_;

  $self->{_buffer} .= $chunk if defined $chunk && length $chunk;

  my @messages;

  while (1) {
    my $newline_at = index($self->{_buffer}, "\n");
    last if $newline_at < 0;

    my $prefix = substr($self->{_buffer}, 0, $newline_at);
    if (!length $prefix) {
      die "Protocol framing error: missing length prefix\n";
    }

    if ($prefix !~ /\A\d+\z/) {
      die "Protocol framing error: non-numeric length prefix\n";
    }

    my $length = 0 + $prefix;
    if ($length > $self->{max_frame_size}) {
      die "Protocol framing error: frame exceeds maximum size\n";
    }

    my $header_length = $newline_at + 1;
    my $frame_length = $header_length + $length;
    last if length($self->{_buffer}) < $frame_length;

    my $payload = substr($self->{_buffer}, $header_length, $length);
    substr($self->{_buffer}, 0, $frame_length, '');

    my $message = _decode_payload($payload);
    push @messages, $message;
  }

  return \@messages;
}

sub finish {
  my ($self) = @_;

  return 1 unless length $self->{_buffer};

  my $newline_at = index($self->{_buffer}, "\n");
  if ($newline_at < 0) {
    die "Protocol framing error: incomplete frame at end of stream\n";
  }

  my $prefix = substr($self->{_buffer}, 0, $newline_at);
  if (!length $prefix) {
    die "Protocol framing error: missing length prefix\n";
  }

  if ($prefix !~ /\A\d+\z/) {
    die "Protocol framing error: non-numeric length prefix\n";
  }

  my $length = 0 + $prefix;
  if ($length > $self->{max_frame_size}) {
    die "Protocol framing error: frame exceeds maximum size\n";
  }

  my $header_length = $newline_at + 1;
  my $available_payload_bytes = length($self->{_buffer}) - $header_length;
  if ($available_payload_bytes < $length) {
    die "Protocol framing error: payload shorter than declared length\n";
  }

  die "Protocol framing error: trailing payload bytes do not begin a valid next frame\n";
}

sub _decode_payload {
  my ($payload) = @_;

  my $decoded;
  eval {
    $decoded = JSON::PP->new->utf8->decode($payload);
    1;
  } or do {
    my $err = $@ || 'unknown error';
    $err =~ s/\s+at \S+ line \d+.*\z//s;
    die "Protocol framing error: invalid JSON payload: $err\n";
  };

  if (ref($decoded) ne 'HASH') {
    die "Protocol framing error: payload must decode to a JSON object\n";
  }

  return $decoded;
}

sub _assert_message_object {
  my ($message) = @_;

  if (!defined $message || ref($message) ne 'HASH') {
    die "Protocol message must be a hash reference\n";
  }

  return 1;
}

sub _validate_request {
  my ($message) = @_;

  return (0, 'protocol.invalid_message', 'Request id is required')
    unless defined $message->{id} && !ref($message->{id}) && length($message->{id});
  return (0, 'protocol.invalid_message', 'Request method is required')
    unless defined $message->{method} && !ref($message->{method}) && length($message->{method});
  return (0, 'protocol.invalid_params', 'Request params must be an object')
    if exists $message->{params} && ref($message->{params}) ne 'HASH';
  return (0, 'protocol.unknown_method', "Unknown request method: $message->{method}")
    unless $BASELINE_REQUEST_METHODS{$message->{method}};

  if ($message->{method} eq 'runtime.init') {
    return _validate_runtime_init_request($message);
  }

  if ($message->{method} eq 'runtime.shutdown') {
    return _validate_runtime_shutdown_request($message);
  }

  return (1, undef, undef);
}

sub _validate_response {
  my ($message) = @_;

  return (0, 'protocol.invalid_message', 'Response id is required')
    unless defined $message->{id} && !ref($message->{id}) && length($message->{id});
  return (0, 'protocol.invalid_message', 'Response ok field is required')
    unless exists $message->{ok};

  my $ok = $message->{ok};
  return (0, 'protocol.invalid_message', 'Response ok field must be a boolean')
    unless JSON::PP::is_bool($ok);

  if ($ok) {
    return (0, 'protocol.invalid_params', 'Successful response result must be an object')
      if exists $message->{result} && ref($message->{result}) ne 'HASH';
    return (0, 'protocol.invalid_message', 'Successful response must not include error')
      if exists $message->{error};
  } else {
    return (0, 'protocol.invalid_message', 'Error response must include error object')
      unless ref($message->{error}) eq 'HASH';
    return (0, 'protocol.invalid_message', 'Error response code is required')
      unless defined $message->{error}{code} && !ref($message->{error}{code}) && length($message->{error}{code});
    return (0, 'protocol.invalid_message', 'Error response message is required')
      unless defined $message->{error}{message} && !ref($message->{error}{message}) && length($message->{error}{message});
    return (0, 'protocol.invalid_message', 'Error response details must be an object')
      if exists $message->{error}{details} && ref($message->{error}{details}) ne 'HASH';
  }

  return (1, undef, undef);
}

sub _validate_notification {
  my ($message) = @_;

  return (0, 'protocol.invalid_message', 'Notification method is required')
    unless defined $message->{method} && !ref($message->{method}) && length($message->{method});
  return (0, 'protocol.invalid_message', 'Notifications must not include id')
    if exists $message->{id};
  return (0, 'protocol.invalid_params', 'Notification params must be an object')
    if exists $message->{params} && ref($message->{params}) ne 'HASH';
  return (0, 'protocol.unknown_method', "Unknown notification method: $message->{method}")
    unless $BASELINE_NOTIFICATION_METHODS{$message->{method}};

  if ($message->{method} eq 'program.hello') {
    return _validate_program_hello_notification($message);
  }

  if ($message->{method} eq 'program.log') {
    return _validate_program_log_notification($message);
  }

  if ($message->{method} eq 'program.health') {
    return _validate_program_health_notification($message);
  }

  if ($message->{method} eq 'runtime.fatal') {
    return _validate_runtime_fatal_notification($message);
  }

  if ($message->{method} eq 'runtime.subscription_event') {
    return _validate_runtime_subscription_event_notification($message);
  }

  if ($message->{method} eq 'runtime.timer_fired') {
    return _validate_runtime_timer_fired_notification($message);
  }

  return (1, undef, undef);
}

sub _validate_program_hello_notification {
  my ($message) = @_;
  my $params = $message->{params} || {};

  return (0, 'protocol.invalid_params', 'program.hello params.program_id is required')
    unless _is_non_empty_string($params->{program_id});
  return (0, 'protocol.invalid_params', 'program.hello params.supported_protocol_versions must be an array of strings')
    unless _is_non_empty_string_array($params->{supported_protocol_versions});
  return (0, 'protocol.invalid_params', 'program.hello params.program_version must be a non-empty string')
    if exists $params->{program_version} && !_is_non_empty_string($params->{program_version});
  return (0, 'protocol.invalid_params', 'program.hello params.metadata must be an object')
    if exists $params->{metadata} && ref($params->{metadata}) ne 'HASH';

  return (1, undef, undef);
}

sub _validate_program_log_notification {
  my ($message) = @_;
  my $params = $message->{params} || {};

  return (0, 'protocol.invalid_params', 'program.log params.level is required')
    unless _is_non_empty_string($params->{level});
  return (0, 'protocol.invalid_params', 'program.log params.message is required')
    unless _is_non_empty_string($params->{message});
  return (0, 'protocol.invalid_params', 'program.log params.context must be an object')
    if exists $params->{context} && ref($params->{context}) ne 'HASH';

  return (1, undef, undef);
}

sub _validate_program_health_notification {
  my ($message) = @_;
  my $params = $message->{params} || {};

  return (0, 'protocol.invalid_params', 'program.health params.status is required')
    unless _is_non_empty_string($params->{status});
  return (0, 'protocol.invalid_params', 'program.health params.message must be a non-empty string')
    if exists $params->{message} && !_is_non_empty_string($params->{message});
  return (0, 'protocol.invalid_params', 'program.health params.details must be an object')
    if exists $params->{details} && ref($params->{details}) ne 'HASH';

  return (1, undef, undef);
}

sub _validate_runtime_fatal_notification {
  my ($message) = @_;
  my $params = $message->{params} || {};

  return (0, 'protocol.invalid_params', 'runtime.fatal params.code is required')
    unless _is_non_empty_string($params->{code});
  return (0, 'protocol.invalid_params', 'runtime.fatal params.message is required')
    unless _is_non_empty_string($params->{message});
  return (0, 'protocol.invalid_params', 'runtime.fatal params.phase must be a non-empty string')
    if exists $params->{phase} && !_is_non_empty_string($params->{phase});
  return (0, 'protocol.invalid_params', 'runtime.fatal params.details must be an object')
    if exists $params->{details} && ref($params->{details}) ne 'HASH';

  return (1, undef, undef);
}

sub _validate_runtime_subscription_event_notification {
  my ($message) = @_;
  my $params = $message->{params} || {};

  return (0, 'protocol.invalid_params', 'runtime.subscription_event params.subscription_id is required')
    unless _is_non_empty_string($params->{subscription_id});
  return (0, 'protocol.invalid_params', 'runtime.subscription_event params.item_type is required')
    unless _is_non_empty_string($params->{item_type});
  return (0, 'protocol.invalid_params', 'runtime.subscription_event params.item_type is invalid')
    unless $params->{item_type} eq 'event'
      || $params->{item_type} eq 'state'
      || $params->{item_type} eq 'capability';
  return (0, 'protocol.invalid_params', 'runtime.subscription_event params.data must be an object')
    unless ref($params->{data}) eq 'HASH';

  return (1, undef, undef);
}

sub _validate_runtime_timer_fired_notification {
  my ($message) = @_;
  my $params = $message->{params} || {};

  return (0, 'protocol.invalid_params', 'runtime.timer_fired params.timer_id is required')
    unless _is_non_empty_string($params->{timer_id});
  return (0, 'protocol.invalid_params', 'runtime.timer_fired params.fired_at must be an integer')
    unless _is_integer($params->{fired_at});
  return (0, 'protocol.invalid_params', 'runtime.timer_fired params.payload must be an object')
    if exists $params->{payload} && ref($params->{payload}) ne 'HASH';

  return (1, undef, undef);
}

sub _validate_runtime_init_request {
  my ($message) = @_;
  my $params = $message->{params} || {};

  return (0, 'protocol.invalid_params', 'runtime.init params.protocol_version is required')
    unless _is_non_empty_string($params->{protocol_version});
  return (0, 'protocol.invalid_params', 'runtime.init params.instance_id is required')
    unless _is_non_empty_string($params->{instance_id});
  return (0, 'protocol.invalid_params', 'runtime.init params.program_id is required')
    unless _is_non_empty_string($params->{program_id});
  return (0, 'protocol.invalid_params', 'runtime.init params.permissions must be an array of strings')
    unless ref($params->{permissions}) eq 'ARRAY'
      && !grep { !defined($_) || ref($_) || !length($_) } @{$params->{permissions}};
  return (0, 'protocol.invalid_params', 'runtime.init params.config must be an object')
    unless ref($params->{config}) eq 'HASH';
  return (0, 'protocol.invalid_params', 'runtime.init params.services must be an object')
    unless ref($params->{services}) eq 'HASH';

  return (1, undef, undef);
}

sub _validate_runtime_shutdown_request {
  my ($message) = @_;
  my $params = $message->{params} || {};

  return (0, 'protocol.invalid_params', 'runtime.shutdown params.reason must be a non-empty string')
    if exists $params->{reason} && !_is_non_empty_string($params->{reason});

  return (1, undef, undef);
}

sub _is_non_empty_string {
  my ($value) = @_;
  return defined $value && !ref($value) && length($value) ? 1 : 0;
}

sub _is_non_empty_string_array {
  my ($value) = @_;
  return 0 unless ref($value) eq 'ARRAY' && @{$value};

  for my $item (@{$value}) {
    return 0 unless _is_non_empty_string($item);
  }

  return 1;
}

sub _is_integer {
  my ($value) = @_;
  return defined $value && !ref($value) && $value =~ /\A-?\d+\z/ ? 1 : 0;
}

sub _require_string_field {
  my (%args) = @_;
  my ($name, $value) = each %args;
  die "$name is required\n" unless defined $value && !ref($value) && length($value);
}

sub _require_string_field_optional {
  my (%args) = @_;
  my ($name, $value) = each %args;
  return unless defined $value;
  die "$name must be a non-empty string\n" if ref($value) || !length($value);
}

sub _require_object_field {
  my (%args) = @_;
  my ($name, $value) = each %args;
  die "$name is required\n" unless defined $value;
  die "$name must be an object\n" if ref($value) ne 'HASH';
}

sub _require_object_field_optional {
  my (%args) = @_;
  my ($name, $value) = each %args;
  return unless defined $value;
  die "$name must be an object\n" if ref($value) ne 'HASH';
}

sub _require_array_field {
  my (%args) = @_;
  my ($name, $value) = each %args;
  die "$name is required\n" unless defined $value;
  die "$name must be an array\n" if ref($value) ne 'ARRAY';
}

sub _require_string_array_field {
  my (%args) = @_;
  my ($name, $value) = each %args;
  die "$name is required\n" unless defined $value;
  die "$name must be an array of strings\n" unless ref($value) eq 'ARRAY' && @{$value};
  for my $item (@{$value}) {
    die "$name must be an array of strings\n" if !defined($item) || ref($item) || !length($item);
  }
}

1;

=head1 NAME

Overnet::Program::Protocol - Overnet Program Protocol framing

=head1 DESCRIPTION

Framed JSON encoder/decoder for the Overnet Program Protocol baseline
transport.

=cut
