package Overnet::Program::Services;

use strict;
use warnings;
use Overnet::Program::Permissions;
use Overnet::Program::Runtime;

our $VERSION = '0.001';
my %SERVICE_METHODS = map { $_ => 1 } qw(
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
  overnet.emit_capabilities
);

sub new {
  my ($class, %args) = @_;

  my $runtime = $args{runtime};
  die "runtime is required\n"
    unless defined $runtime && ref($runtime) && $runtime->isa('Overnet::Program::Runtime');

  return bless {
    runtime => $runtime,
  }, $class;
}

sub runtime { $_[0]->{runtime} }

sub is_service_method {
  my ($class, $method) = @_;
  return defined $method && !ref($method) && $SERVICE_METHODS{$method} ? 1 : 0;
}

sub open_adapter_session {
  my ($self, %args) = @_;
  my $adapter_id = _require_string_param('adapter_id', $args{adapter_id});
  my $config = exists $args{config} ? $args{config} : {};

  _require_object_param('config', $config);
  _service_unavailable("Unknown adapter_id: $adapter_id", {
    method     => 'adapters.open_session',
    adapter_id => $adapter_id,
  }) unless $self->{runtime}->adapter_registry->has($adapter_id);

  my $session = $self->{runtime}->open_adapter_session(%args);
  return {
    adapter_session_id => $session->session_id,
  };
}

sub map_input {
  my ($self, %args) = @_;
  my $session_id = _require_string_param('adapter_session_id', $args{adapter_session_id});
  _require_present_param('input', \%args);
  my $input = $args{input};

  _require_object_param('input', $input);
  my $session = _require_adapter_session($self->{runtime}, $session_id);
  return _normalize_adapter_result(
    %{ _call_adapter(
      session => $session,
      method  => 'adapters.map_input',
      code    => sub { $session->map_input($input) },
    ) }
  );
}

sub derive {
  my ($self, %args) = @_;
  my $session_id = _require_string_param('adapter_session_id', $args{adapter_session_id});
  my $operation = _require_string_param('operation', $args{operation});
  _require_present_param('input', \%args);
  my $input = $args{input};

  _require_object_param('input', $input);
  my $session = _require_adapter_session($self->{runtime}, $session_id);
  return _normalize_adapter_result(
    %{ _call_adapter(
      session => $session,
      method  => 'adapters.derive',
      code    => sub {
        $session->derive(
          operation => $operation,
          input     => $input,
        );
      },
    ) }
  );
}

sub close_adapter_session {
  my ($self, %args) = @_;
  my $session_id = _require_string_param('adapter_session_id', $args{adapter_session_id});

  _require_adapter_session($self->{runtime}, $session_id);
  $self->{runtime}->close_adapter_session($session_id);
  return {};
}

sub append_event_entry {
  my ($self, %args) = @_;
  my $stream = _require_string_param('stream', $args{stream});
  _require_present_param('event', \%args);
  my $event = _require_object_param('event', $args{event});

  return $self->{runtime}->append_event(
    stream => $stream,
    event  => $event,
  );
}

sub read_event_entries {
  my ($self, %args) = @_;
  my $stream = _require_string_param('stream', $args{stream});
  my %read_args = (
    stream => $stream,
  );

  if (exists $args{after_offset}) {
    $read_args{after_offset} = _require_integer_param('after_offset', $args{after_offset});
  }
  if (exists $args{limit}) {
    $read_args{limit} = _require_non_negative_integer_param('limit', $args{limit});
  }

  return $self->{runtime}->read_events(%read_args);
}

sub open_subscription {
  my ($self, %args) = @_;
  my $session_id = _require_string_param('session_id', $args{session_id});
  my $subscription_id = _require_string_param('subscription_id', $args{subscription_id});
  _require_present_param('query', \%args);
  my $query = _require_object_param('query', $args{query});

  _validate_subscription_query($query);
  _invalid_params(
    "Duplicate subscription_id: $subscription_id",
    {
      param           => 'subscription_id',
      subscription_id => $subscription_id,
    },
  ) if $self->{runtime}->has_subscription(
    session_id      => $session_id,
    subscription_id => $subscription_id,
  );

  $self->{runtime}->open_subscription(
    session_id      => $session_id,
    subscription_id => $subscription_id,
    query           => $query,
  );

  return {
    subscription_id => $subscription_id,
  };
}

sub close_subscription {
  my ($self, %args) = @_;
  my $session_id = _require_string_param('session_id', $args{session_id});
  my $subscription_id = _require_string_param('subscription_id', $args{subscription_id});

  _invalid_params(
    "Unknown subscription_id: $subscription_id",
    {
      param           => 'subscription_id',
      subscription_id => $subscription_id,
    },
  ) unless $self->{runtime}->has_subscription(
    session_id      => $session_id,
    subscription_id => $subscription_id,
  );

  $self->{runtime}->close_subscription(
    session_id      => $session_id,
    subscription_id => $subscription_id,
  );

  return {};
}

sub schedule_timer {
  my ($self, %args) = @_;
  my $session_id = _require_string_param('session_id', $args{session_id});
  my $timer_id = _require_string_param('timer_id', $args{timer_id});

  my $has_at = exists $args{at};
  my $has_delay_ms = exists $args{delay_ms};
  _invalid_params(
    'Exactly one of at or delay_ms must be supplied',
    { param => 'at' },
  ) if ($has_at && $has_delay_ms) || (!$has_at && !$has_delay_ms);

  my %schedule_args = (
    session_id => $session_id,
    timer_id   => $timer_id,
  );
  if ($has_at) {
    $schedule_args{at} = _require_integer_param('at', $args{at});
  } else {
    $schedule_args{delay_ms} = _require_non_negative_integer_param('delay_ms', $args{delay_ms});
  }
  if (exists $args{repeat_ms}) {
    $schedule_args{repeat_ms} = _require_positive_integer_param('repeat_ms', $args{repeat_ms});
  }
  if (exists $args{payload}) {
    $schedule_args{payload} = _require_object_param('payload', $args{payload});
  }

  _invalid_params(
    "Duplicate timer_id: $timer_id",
    {
      param    => 'timer_id',
      timer_id => $timer_id,
    },
  ) if $self->{runtime}->has_timer(
    session_id => $session_id,
    timer_id   => $timer_id,
  );

  $self->{runtime}->schedule_timer(%schedule_args);
  return {
    timer_id => $timer_id,
  };
}

sub cancel_timer {
  my ($self, %args) = @_;
  my $session_id = _require_string_param('session_id', $args{session_id});
  my $timer_id = _require_string_param('timer_id', $args{timer_id});

  _invalid_params(
    "Unknown timer_id: $timer_id",
    {
      param    => 'timer_id',
      timer_id => $timer_id,
    },
  ) unless $self->{runtime}->has_timer(
    session_id => $session_id,
    timer_id   => $timer_id,
  );

  $self->{runtime}->cancel_timer(
    session_id => $session_id,
    timer_id   => $timer_id,
  );
  return {};
}

sub emit_event {
  my ($self, %args) = @_;
  _require_present_param('event', \%args);
  my $event = _require_object_param('event', $args{event});

  return $self->{runtime}->accept_emitted_item(
    method    => 'overnet.emit_event',
    item_type => 'event',
    candidate => $event,
  );
}

sub emit_state {
  my ($self, %args) = @_;
  _require_present_param('state', \%args);
  my $state = _require_object_param('state', $args{state});

  return $self->{runtime}->accept_emitted_item(
    method    => 'overnet.emit_state',
    item_type => 'state',
    candidate => $state,
  );
}

sub emit_capabilities {
  my ($self, %args) = @_;
  _require_present_param('capabilities', \%args);
  my $capabilities = _require_array_param('capabilities', $args{capabilities});

  return $self->{runtime}->accept_emitted_capabilities(
    method       => 'overnet.emit_capabilities',
    capabilities => $capabilities,
  );
}

sub dispatch_request {
  my ($self, $method, $params, %args) = @_;

  die "method is required\n"
    unless defined $method && !ref($method) && length($method);
  $params ||= {};
  die "params must be an object\n"
    if ref($params) ne 'HASH';

  _protocol_unknown_method("Unknown service method: $method", { method => $method })
    unless __PACKAGE__->is_service_method($method);

  Overnet::Program::Permissions->assert_method_allowed(
    method      => $method,
    permissions => $args{permissions},
  );

  my %dispatch = (
    'events.append'           => sub { $self->append_event_entry(%{$params}) },
    'events.read'             => sub { $self->read_event_entries(%{$params}) },
    'subscriptions.open'      => sub { $self->open_subscription(%{$params}, session_id => $args{session_id}) },
    'subscriptions.close'     => sub { $self->close_subscription(%{$params}, session_id => $args{session_id}) },
    'timers.schedule'         => sub { $self->schedule_timer(%{$params}, session_id => $args{session_id}) },
    'timers.cancel'           => sub { $self->cancel_timer(%{$params}, session_id => $args{session_id}) },
    'adapters.open_session'  => sub { $self->open_adapter_session(%{$params}) },
    'adapters.map_input'     => sub { $self->map_input(%{$params}) },
    'adapters.derive'        => sub { $self->derive(%{$params}) },
    'adapters.close_session' => sub { $self->close_adapter_session(%{$params}) },
    'overnet.emit_event'     => sub { $self->emit_event(%{$params}) },
    'overnet.emit_state'     => sub { $self->emit_state(%{$params}) },
    'overnet.emit_capabilities' => sub { $self->emit_capabilities(%{$params}) },
  );

  my $handler = $dispatch{$method}
    or _service_unavailable(
      "Runtime service method $method is not available",
      { method => $method },
    );

  return $handler->();
}

sub _call_adapter {
  my (%args) = @_;
  my $session = $args{session};
  my $method = $args{method};
  my $code = $args{code};

  my $result;
  my $error;
  eval {
    $result = $code->();
    1;
  } or $error = $@;

  if ($error) {
    die $error if ref($error) eq 'HASH';

    chomp $error;
    _service_unavailable(
      $error,
      {
        method     => $method,
        adapter_id => $session->adapter_id,
      },
    );
  }

  return {
    adapter_id => $session->adapter_id,
    method     => $method,
    result     => $result,
  };
}

sub _normalize_adapter_result {
  my (%args) = @_;
  my $result = $args{result};
  my $adapter_id = $args{adapter_id};
  my $method = $args{method};

  _service_unavailable(
    'Adapter result must be an object',
    {
      method     => $method,
      adapter_id => $adapter_id,
    },
  ) if ref($result) ne 'HASH';

  if (exists $result->{valid} && !$result->{valid}) {
    my $message = defined $result->{reason} && !ref($result->{reason}) && length($result->{reason})
      ? $result->{reason}
      : 'Adapter rejected request';
    _invalid_params(
      $message,
      {
        method     => $method,
        adapter_id => $adapter_id,
      },
    );
  }

  my %normalized;
  if (exists $result->{events}) {
    $normalized{events} = _normalized_result_array(
      name       => 'events',
      value      => $result->{events},
      adapter_id => $adapter_id,
      method     => $method,
    );
  }
  if (exists $result->{state}) {
    $normalized{state} = _normalized_result_array(
      name       => 'state',
      value      => $result->{state},
      adapter_id => $adapter_id,
      method     => $method,
    );
  }
  if (exists $result->{capabilities}) {
    $normalized{capabilities} = _normalized_result_array(
      name       => 'capabilities',
      value      => $result->{capabilities},
      adapter_id => $adapter_id,
      method     => $method,
    );
  }

  if (exists $result->{event}) {
    _service_unavailable(
      'Adapter event result must be an object',
      {
        method     => $method,
        adapter_id => $adapter_id,
      },
    ) if ref($result->{event}) ne 'HASH';

    if (($result->{event}{kind} || 0) == 37800) {
      $normalized{state} ||= [];
      push @{$normalized{state}}, $result->{event};
    } else {
      $normalized{events} ||= [];
      push @{$normalized{events}}, $result->{event};
    }
  }

  return \%normalized;
}

sub _normalized_result_array {
  my (%args) = @_;
  my $name = $args{name};
  my $value = $args{value};

  _service_unavailable(
    "Adapter $name result must be an array",
    {
      method     => $args{method},
      adapter_id => $args{adapter_id},
    },
  ) unless ref($value) eq 'ARRAY';

  for my $item (@{$value}) {
    _service_unavailable(
      "Adapter $name items must be objects",
      {
        method     => $args{method},
        adapter_id => $args{adapter_id},
      },
    ) unless ref($item) eq 'HASH';
  }

  return [ @{$value} ];
}

sub _require_adapter_session {
  my ($runtime, $session_id) = @_;
  my $session = $runtime->get_adapter_session($session_id);

  _invalid_params(
    "Unknown adapter_session_id: $session_id",
    {
      param              => 'adapter_session_id',
      adapter_session_id => $session_id,
    },
  ) unless defined $session;

  return $session;
}

sub _require_present_param {
  my ($name, $params) = @_;
  _invalid_params("$name is required", { param => $name })
    unless exists $params->{$name};
  return 1;
}

sub _require_string_param {
  my ($name, $value) = @_;
  _invalid_params("$name is required", { param => $name })
    unless defined $value && !ref($value) && length($value);
  return $value;
}

sub _require_object_param {
  my ($name, $value) = @_;
  _invalid_params("$name must be an object", { param => $name })
    if ref($value) ne 'HASH';
  return $value;
}

sub _require_array_param {
  my ($name, $value) = @_;
  _invalid_params("$name must be an array", { param => $name })
    if ref($value) ne 'ARRAY';
  return $value;
}

sub _require_integer_param {
  my ($name, $value) = @_;
  _invalid_params("$name must be an integer", { param => $name })
    unless defined $value && !ref($value) && $value =~ /\A-?\d+\z/;
  return 0 + $value;
}

sub _require_non_negative_integer_param {
  my ($name, $value) = @_;
  _invalid_params("$name must be a non-negative integer", { param => $name })
    unless defined $value && !ref($value) && $value =~ /\A\d+\z/;
  return 0 + $value;
}

sub _require_positive_integer_param {
  my ($name, $value) = @_;
  _invalid_params("$name must be a positive integer", { param => $name })
    unless defined $value && !ref($value) && $value =~ /\A[1-9]\d*\z/;
  return 0 + $value;
}

sub _validate_subscription_query {
  my ($query) = @_;
  my %allowed = map { $_ => 1 } qw(kind overnet_et overnet_ot overnet_oid);

  for my $field (sort keys %{$query}) {
    _invalid_params(
      "query contains unsupported field: $field",
      { param => "query.$field" },
    ) unless $allowed{$field};
  }

  if (exists $query->{kind}) {
    _invalid_params(
      'query.kind must be an integer',
      { param => 'query.kind' },
    ) unless defined $query->{kind} && !ref($query->{kind}) && $query->{kind} =~ /\A-?\d+\z/;
  }

  for my $field (qw(overnet_et overnet_ot overnet_oid)) {
    next unless exists $query->{$field};
    _invalid_params(
      "query.$field must be a non-empty string",
      { param => "query.$field" },
    ) unless defined $query->{$field} && !ref($query->{$field}) && length($query->{$field});
  }

  return 1;
}

sub _invalid_params {
  my ($message, $details) = @_;
  die {
    code    => 'protocol.invalid_params',
    message => $message,
    (defined $details ? (details => $details) : ()),
  };
}

sub _protocol_unknown_method {
  my ($message, $details) = @_;
  die {
    code    => 'protocol.unknown_method',
    message => $message,
    (defined $details ? (details => $details) : ()),
  };
}

sub _service_unavailable {
  my ($message, $details) = @_;
  die {
    code    => 'runtime.service_unavailable',
    message => $message,
    (defined $details ? (details => $details) : ()),
  };
}

1;

=head1 NAME

Overnet::Program::Services - Overnet Program Services scaffold

=head1 DESCRIPTION

Runtime-managed program services, including adapter-session access.

=cut
