package Overnet::Program::Runtime;

use strict;
use warnings;
use JSON::PP ();
use Net::Nostr::Event;
use Time::HiRes qw(time);
use Overnet::Core::PrivateMessaging ();
use Overnet::Core::Validator ();
use Overnet::Program::AdapterRegistry;
use Overnet::Program::AdapterSession;
use Overnet::Program::SecretProvider;
use Overnet::Program::Store;
use Overnet::Program::Subscription;
use Overnet::Program::Timer;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;
  my $adapter_registry = $args{adapter_registry} || Overnet::Program::AdapterRegistry->new;
  my $store = $args{store} || Overnet::Program::Store->new;
  my $now_cb = $args{now_cb} || sub { int(time() * 1000) };
  my $secret_provider = $args{secret_provider};
  my $config = exists $args{config} ? $args{config} : {};
  my $config_description = exists $args{config_description} ? $args{config_description} : {};

  die "adapter_registry must be an Overnet::Program::AdapterRegistry instance\n"
    unless ref($adapter_registry) && $adapter_registry->isa('Overnet::Program::AdapterRegistry');
  die "store must be an Overnet::Program::Store instance\n"
    unless ref($store) && $store->isa('Overnet::Program::Store');
  die "now_cb must be a code reference\n"
    unless ref($now_cb) eq 'CODE';
  die "config must be an object\n"
    unless ref($config) eq 'HASH';
  die "config_description must be an object\n"
    unless ref($config_description) eq 'HASH';

  die "host is reserved for process supervision; use secret_provider instead\n"
    if exists $args{host};

  if (defined $secret_provider) {
    die "secret_provider must be an Overnet::Program::SecretProvider instance\n"
      unless ref($secret_provider) && $secret_provider->isa('Overnet::Program::SecretProvider');
    for my $field (qw(secrets secret_policies secret_handle_ttl_ms random_bytes_cb)) {
      die "$field cannot be supplied when secret_provider is provided\n"
        if exists $args{$field};
    }
  } else {
    $secret_provider = Overnet::Program::SecretProvider->new(
      now_cb => $now_cb,
      (exists $args{secrets} ? (secrets => $args{secrets}) : ()),
      (exists $args{secret_policies} ? (secret_policies => $args{secret_policies}) : ()),
      (exists $args{secret_handle_ttl_ms} ? (secret_handle_ttl_ms => $args{secret_handle_ttl_ms}) : ()),
      (exists $args{random_bytes_cb} ? (random_bytes_cb => $args{random_bytes_cb}) : ()),
    );
  }

  _validate_config_description($config_description);

  return bless {
    adapter_registry => $adapter_registry,
    store            => $store,
    secret_provider  => $secret_provider,
    now_cb           => $now_cb,
    config           => _clone_json($config),
    config_description => _clone_json($config_description),
    next_session_id  => 1,
    adapter_sessions => {},
    timers           => {},
    emitted_items    => [],
    subscriptions    => {},
    runtime_notifications => {},
  }, $class;
}

sub adapter_registry { $_[0]->{adapter_registry} }
sub store { $_[0]->{store} }
sub secret_provider { $_[0]->{secret_provider} }
sub config { _clone_json($_[0]->{config}) }
sub describe_config { _clone_json($_[0]->{config_description}) }
sub has_secret {
  my ($self, %args) = @_;
  return $self->{secret_provider}->has_secret(%args);
}

sub issue_secret_handle {
  my ($self, %args) = @_;
  return $self->{secret_provider}->issue_secret_handle(%args);
}

sub resolve_secret_handle {
  my ($self, %args) = @_;
  return $self->{secret_provider}->resolve_secret_handle(%args);
}

sub revoke_secret_handle {
  my ($self, %args) = @_;
  return $self->{secret_provider}->revoke_secret_handle(%args);
}

sub revoke_secret_handles_for_session {
  my ($self, %args) = @_;
  return $self->{secret_provider}->revoke_secret_handles_for_session(%args);
}

sub rotate_secret {
  my ($self, %args) = @_;
  return $self->{secret_provider}->rotate_secret(%args);
}

sub secret_audit_events {
  my ($self) = @_;
  return $self->{secret_provider}->audit_events;
}
sub emitted_items { [ @{$_[0]->{emitted_items} || []} ] }

sub emitted_stream_name {
  my ($self, $item_type) = @_;

  die "item_type must be event, state, private_message, or capability\n"
    unless defined $item_type
      && !ref($item_type)
      && (
        $item_type eq 'event'
        || $item_type eq 'state'
        || $item_type eq 'private_message'
        || $item_type eq 'capability'
      );

  return "runtime.accepted.$item_type";
}

sub register_adapter {
  my ($self, %args) = @_;
  return $self->{adapter_registry}->register(%args);
}

sub register_adapter_definition {
  my ($self, %args) = @_;
  return $self->{adapter_registry}->register_definition(%args);
}

sub open_adapter_session {
  my ($self, %args) = @_;

  my $adapter_id = $args{adapter_id};
  my $config = $args{config} || {};
  my $secret_handles = exists $args{secret_handles} ? $args{secret_handles} : {};
  my $program_session_id = $args{session_id};
  my $program_id = $args{program_id};

  die "adapter_id is required\n"
    unless defined $adapter_id && !ref($adapter_id) && length($adapter_id);
  die "config must be an object\n"
    if ref($config) ne 'HASH';
  die "secret_handles must be an object\n"
    if ref($secret_handles) ne 'HASH';
  die "session_id is required when secret_handles are supplied\n"
    if keys(%{$secret_handles}) && (!defined $program_session_id || ref($program_session_id) || !length($program_session_id));
  die "program_id must be a non-empty string\n"
    if defined $program_id && (ref($program_id) || !length($program_id));

  my $adapter = $self->{adapter_registry}->build($adapter_id);
  die "Unknown adapter_id: $adapter_id\n"
    unless defined $adapter;

  if (keys %{$secret_handles}) {
    _require_adapter_secret_slot_support(
      adapter    => $adapter,
      adapter_id => $adapter_id,
      slots      => [ sort keys %{$secret_handles} ],
    );
  }

  my $session_id = 'adapter-' . $self->{next_session_id}++;
  my $session = Overnet::Program::AdapterSession->new(
    session_id          => $session_id,
    adapter_id          => $adapter_id,
    adapter             => $adapter,
    config              => $config,
    program_session_id  => $program_session_id,
    program_id          => $program_id,
  );

  my %resolved_secret_values;
  eval {
    if (keys %{$secret_handles}) {
      for my $slot (sort keys %{$secret_handles}) {
        my $handle = $secret_handles->{$slot};
        die {
          code    => 'protocol.invalid_params',
          message => "secret_handles.$slot must be a secret_handle object",
          details => {
            param => "secret_handles.$slot",
          },
        } unless ref($handle) eq 'HASH';
        die {
          code    => 'protocol.invalid_params',
          message => "secret_handles.$slot.id must be a non-empty string",
          details => {
            param => "secret_handles.$slot.id",
          },
        } unless defined $handle->{id} && !ref($handle->{id}) && length($handle->{id});

        my $resolved = $self->resolve_secret_handle(
          session_id => $program_session_id,
          handle_id  => $handle->{id},
          (defined $program_id ? (program_id => $program_id) : ()),
          method      => 'adapters.open_session',
          adapter_id  => $adapter_id,
          secret_slot => $slot,
          purpose     => "adapters.open_session:$adapter_id:$slot",
          error_param => "secret_handles.$slot",
        );
        $resolved_secret_values{$slot} = $resolved->{value};
      }
    }

    $session->open(secret_values => \%resolved_secret_values);
    1;
  } or do {
    my $error = $@;
    _clear_secret_values(\%resolved_secret_values);
    die $error if ref($error) eq 'HASH';

    chomp $error if !ref($error);
    die {
      code    => 'runtime.service_unavailable',
      message => $error,
      details => {
        method     => 'adapters.open_session',
        adapter_id => $adapter_id,
      },
    };
  };
  _clear_secret_values(\%resolved_secret_values);

  $self->{adapter_sessions}{$session_id} = $session;
  return $session;
}

sub get_adapter_session {
  my ($self, $session_id) = @_;
  return undef unless defined $session_id;
  return $self->{adapter_sessions}{$session_id};
}

sub close_adapter_session {
  my ($self, $session_id) = @_;
  die "adapter_session_id is required\n"
    unless defined $session_id && !ref($session_id) && length($session_id);

  my $session = $self->{adapter_sessions}{$session_id};
  die "Unknown adapter_session_id: $session_id\n"
    unless defined $session;

  $session->close;
  delete $self->{adapter_sessions}{$session_id};

  return 1;
}

sub adapter_session_ids {
  my ($self) = @_;
  return [ sort keys %{$self->{adapter_sessions}} ];
}

sub release_session_resources {
  my ($self, %args) = @_;
  my $session_id = _require_string_arg(session_id => $args{session_id});

  my %released = (
    adapter_sessions_closed => 0,
    subscriptions_closed    => 0,
    timers_canceled         => 0,
    notifications_cleared   => 0,
  );

  for my $adapter_session_id (sort keys %{$self->{adapter_sessions}}) {
    my $session = $self->{adapter_sessions}{$adapter_session_id};
    next unless defined $session;
    next unless defined $session->program_session_id;
    next unless $session->program_session_id eq $session_id;

    eval { $session->close; 1; };
    delete $self->{adapter_sessions}{$adapter_session_id};
    $released{adapter_sessions_closed}++;
  }

  if (exists $self->{subscriptions}{$session_id}) {
    $released{subscriptions_closed} = scalar keys %{$self->{subscriptions}{$session_id} || {}};
    delete $self->{subscriptions}{$session_id};
  }

  if (exists $self->{timers}{$session_id}) {
    $released{timers_canceled} = scalar keys %{$self->{timers}{$session_id} || {}};
    delete $self->{timers}{$session_id};
  }

  if (exists $self->{runtime_notifications}{$session_id}) {
    $released{notifications_cleared} = scalar @{$self->{runtime_notifications}{$session_id} || []};
    delete $self->{runtime_notifications}{$session_id};
  }

  return \%released;
}

sub append_event {
  my ($self, %args) = @_;
  return $self->{store}->append_event(%args);
}

sub read_events {
  my ($self, %args) = @_;
  return $self->{store}->read_events(%args);
}

sub has_document {
  my ($self, %args) = @_;
  return $self->{store}->has_document(%args);
}

sub put_document {
  my ($self, %args) = @_;
  return $self->{store}->put_document(%args);
}

sub get_document {
  my ($self, %args) = @_;
  return $self->{store}->get_document(%args);
}

sub delete_document {
  my ($self, %args) = @_;
  return $self->{store}->delete_document(%args);
}

sub list_documents {
  my ($self, %args) = @_;
  return $self->{store}->list_documents(%args);
}

sub has_subscription {
  my ($self, %args) = @_;
  my $session_id = $args{session_id};
  my $subscription_id = $args{subscription_id};

  return 0 unless defined $session_id && defined $subscription_id;
  return exists $self->{subscriptions}{$session_id}
    && exists $self->{subscriptions}{$session_id}{$subscription_id}
    ? 1
    : 0;
}

sub has_timer {
  my ($self, %args) = @_;
  my $session_id = $args{session_id};
  my $timer_id = $args{timer_id};

  return 0 unless defined $session_id && defined $timer_id;
  return exists $self->{timers}{$session_id}
    && exists $self->{timers}{$session_id}{$timer_id}
    ? 1
    : 0;
}

sub schedule_timer {
  my ($self, %args) = @_;
  my $session_id = _require_string_arg(session_id => $args{session_id});
  my $timer_id = _require_string_arg(timer_id => $args{timer_id});
  my $repeat_ms = $args{repeat_ms};
  my $payload = $args{payload};

  die "Duplicate timer_id: $timer_id\n"
    if $self->has_timer(
      session_id => $session_id,
      timer_id   => $timer_id,
    );
  die "repeat_ms must be a positive integer\n"
    if defined $repeat_ms && (ref($repeat_ms) || $repeat_ms !~ /\A[1-9]\d*\z/);
  die "payload must be an object\n"
    if defined $payload && ref($payload) ne 'HASH';

  my $due_at_ms;
  if (exists $args{at}) {
    my $at = $args{at};
    die "at must be an integer\n"
      unless defined $at && !ref($at) && $at =~ /\A-?\d+\z/;
    $due_at_ms = (0 + $at) * 1000;
  } else {
    my $delay_ms = $args{delay_ms};
    die "delay_ms must be a non-negative integer\n"
      unless defined $delay_ms && !ref($delay_ms) && $delay_ms =~ /\A\d+\z/;
    $due_at_ms = $self->_now_ms + (0 + $delay_ms);
  }

  my $timer = Overnet::Program::Timer->new(
    session_id => $session_id,
    timer_id   => $timer_id,
    due_at_ms  => $due_at_ms,
    (defined $repeat_ms ? (repeat_ms => $repeat_ms) : ()),
    (defined $payload ? (payload => $payload) : ()),
  );
  $self->{timers}{$session_id}{$timer_id} = $timer;

  return $timer;
}

sub cancel_timer {
  my ($self, %args) = @_;
  my $session_id = _require_string_arg(session_id => $args{session_id});
  my $timer_id = _require_string_arg(timer_id => $args{timer_id});

  my $timer = delete $self->{timers}{$session_id}{$timer_id};
  die "Unknown timer_id: $timer_id\n"
    unless defined $timer;
  delete $self->{timers}{$session_id}
    unless keys %{$self->{timers}{$session_id} || {}};

  my $queue = $self->{runtime_notifications}{$session_id} || [];
  @{$queue} = grep {
    !(
      ($_->{method} || '') eq 'runtime.timer_fired'
      && ref($_->{params}) eq 'HASH'
      && ($_->{params}{timer_id} || '') eq $timer_id
    )
  } @{$queue};

  return 1;
}

sub open_subscription {
  my ($self, %args) = @_;
  my $session_id = _require_string_arg(session_id => $args{session_id});
  my $subscription_id = _require_string_arg(subscription_id => $args{subscription_id});
  my $query = $args{query};

  die "query must be an object\n"
    unless ref($query) eq 'HASH';
  die "Duplicate subscription_id: $subscription_id\n"
    if $self->has_subscription(
      session_id      => $session_id,
      subscription_id => $subscription_id,
    );

  my $subscription = Overnet::Program::Subscription->new(
    session_id      => $session_id,
    subscription_id => $subscription_id,
    query           => $query,
  );
  $self->{subscriptions}{$session_id}{$subscription_id} = $subscription;

  for my $item (@{$self->{emitted_items}}) {
    my %notification_args = (
      session_id    => $session_id,
      subscription  => $subscription,
      item_type     => $item->{item_type},
      data          => $item->{data},
    );
    if ($item->{item_type} eq 'event' || $item->{item_type} eq 'state') {
      $notification_args{event} = _event_from_wire($item->{data});
    }
    $self->_queue_subscription_notification_if_match(
      %notification_args,
    );
  }

  return $subscription;
}

sub close_subscription {
  my ($self, %args) = @_;
  my $session_id = _require_string_arg(session_id => $args{session_id});
  my $subscription_id = _require_string_arg(subscription_id => $args{subscription_id});

  my $subscription = delete $self->{subscriptions}{$session_id}{$subscription_id};
  die "Unknown subscription_id: $subscription_id\n"
    unless defined $subscription;
  delete $self->{subscriptions}{$session_id}
    unless keys %{$self->{subscriptions}{$session_id} || {}};

  my $queue = $self->{runtime_notifications}{$session_id} || [];
  @{$queue} = grep {
    !(
      ($_->{method} || '') eq 'runtime.subscription_event'
      && ref($_->{params}) eq 'HASH'
      && ($_->{params}{subscription_id} || '') eq $subscription_id
    )
  } @{$queue};

  return 1;
}

sub drain_runtime_notifications {
  my ($self, $session_id) = @_;
  _require_string_arg(session_id => $session_id);
  $self->_queue_due_timer_notifications;

  my $notifications = delete $self->{runtime_notifications}{$session_id} || [];
  return _clone_json($notifications);
}

sub accept_emitted_private_message {
  my ($self, %args) = @_;

  my $method = $args{method};
  my $candidate = $args{candidate};

  die "method is required\n"
    unless defined $method && !ref($method) && length($method);
  die "candidate must be an object\n"
    unless ref($candidate) eq 'HASH';

  my $validation = Overnet::Core::PrivateMessaging::validate_transport($candidate);
  my @errors = @{$validation->{errors} || []};

  if (@errors || !$validation->{valid}) {
    die {
      code    => 'runtime.validation_failed',
      message => 'Candidate private message failed validation',
      details => {
        method    => $method,
        item_type => 'private_message',
        errors    => \@errors,
      },
    };
  }

  my $visible_transport = _clone_json($candidate->{transport});
  delete $visible_transport->{decrypted_rumor}
    if ref($visible_transport) eq 'HASH';
  my $stored = {
    transport    => $visible_transport,
    private_type => $validation->{private_type},
    object_type  => $validation->{object_type},
    object_id    => $validation->{object_id},
  };
  $stored->{decrypted_rumor} = _clone_json($validation->{decrypted_rumor})
    if ref($validation->{decrypted_rumor}) eq 'HASH';
  $stored->{sender_identity} = $validation->{sender_identity}
    if defined $validation->{sender_identity};

  $self->_record_emitted_item(
    item_type => 'private_message',
    data      => $stored,
  );

  my $result = {
    accepted => JSON::PP::true,
  };
  $result->{event_id} = $stored->{transport}{id}
    if defined $stored->{transport}{id};
  $result->{rumor_id} = $stored->{decrypted_rumor}{id}
    if ref($stored->{decrypted_rumor}) eq 'HASH' && defined $stored->{decrypted_rumor}{id};

  return $result;
}

sub accept_emitted_item {
  my ($self, %args) = @_;

  my $method = $args{method};
  my $item_type = $args{item_type};
  my $candidate = $args{candidate};

  die "method is required\n"
    unless defined $method && !ref($method) && length($method);
  die "item_type must be event or state\n"
    unless defined $item_type && ($item_type eq 'event' || $item_type eq 'state');
  die "candidate must be an object\n"
    unless ref($candidate) eq 'HASH';

  my $validation = Overnet::Core::Validator::validate($candidate, {});
  my $event = $validation->{event};
  my $kind = defined $event
    ? $event->kind
    : $candidate->{kind};
  my @errors;
  if (
    $item_type eq 'state'
    && defined $kind
    && !ref($kind)
    && $kind != 37800
  ) {
    push @errors, 'overnet.emit_state requires kind 37800';
  }
  if (
    $item_type eq 'event'
    && defined $kind
    && !ref($kind)
    && $kind == 37800
  ) {
    push @errors, 'overnet.emit_event does not accept kind 37800 state events';
  }
  push @errors, @{$validation->{errors} || []}
    unless $validation->{valid};

  if (@errors) {
    die {
      code    => 'runtime.validation_failed',
      message => "Candidate Overnet $item_type failed validation",
      details => {
        method    => $method,
        item_type => $item_type,
        errors    => \@errors,
      },
    };
  }

  my $stored = $event->to_hash;
  $self->_record_emitted_item(
    item_type => $item_type,
    data      => $stored,
    event     => $event,
  );

  my $result = {
    accepted => JSON::PP::true,
  };
  $result->{event_id} = $event->id;

  return $result;
}

sub accept_emitted_capabilities {
  my ($self, %args) = @_;

  my $method = $args{method};
  my $capabilities = $args{capabilities};

  die "method is required\n"
    unless defined $method && !ref($method) && length($method);
  die "capabilities must be an array\n"
    unless ref($capabilities) eq 'ARRAY';

  my @errors;
  my @stored;
  for my $index (0 .. $#{$capabilities}) {
    my $capability = $capabilities->[$index];
    my $path = "capabilities[$index]";

    if (ref($capability) ne 'HASH') {
      push @errors, "$path must be an object";
      next;
    }
    if (!defined $capability->{name} || ref($capability->{name}) || !length($capability->{name})) {
      push @errors, "$path.name must be a non-empty string";
    }
    if (!defined $capability->{version} || ref($capability->{version}) || !length($capability->{version})) {
      push @errors, "$path.version must be a non-empty string";
    }
    if (exists $capability->{details} && ref($capability->{details}) ne 'HASH') {
      push @errors, "$path.details must be an object";
    }

    push @stored, _clone_json($capability);
  }

  if (@errors) {
    die {
      code    => 'runtime.validation_failed',
      message => 'Candidate capability advertisements failed validation',
      details => {
        method    => $method,
        item_type => 'capability',
        errors    => \@errors,
      },
    };
  }

  for my $capability (@stored) {
    $self->_record_emitted_item(
      item_type => 'capability',
      data      => $capability,
    );
  }

  return {
    accepted => JSON::PP::true,
  };
}

sub _queue_subscription_notifications_for_item {
  my ($self, %args) = @_;
  my $item_type = $args{item_type};
  my $event = $args{event};
  my $data = $args{data};

  for my $session_id (sort keys %{$self->{subscriptions}}) {
    for my $subscription_id (sort keys %{$self->{subscriptions}{$session_id}}) {
      my $subscription = $self->{subscriptions}{$session_id}{$subscription_id};
      $self->_queue_subscription_notification_if_match(
        session_id   => $session_id,
        subscription => $subscription,
        item_type    => $item_type,
        event        => $event,
        data         => $data,
      );
    }
  }

  return 1;
}

sub _queue_subscription_notification_if_match {
  my ($self, %args) = @_;
  my $session_id = $args{session_id};
  my $subscription = $args{subscription};
  my $item_type = $args{item_type};
  my $event = $args{event};
  my $data = $args{data};

  return 0 unless ref($data) eq 'HASH';
  return 0 unless $subscription->matches(
    item_type => $item_type,
    event     => $event,
    data      => $data,
  );

  push @{$self->{runtime_notifications}{$session_id} ||= []}, {
    method => 'runtime.subscription_event',
    params => {
      subscription_id => $subscription->subscription_id,
      item_type       => $item_type,
      data            => _clone_json($data),
    },
  };

  return 1;
}

sub _record_emitted_item {
  my ($self, %args) = @_;
  my $item_type = $args{item_type};
  my $data = $args{data};

  push @{$self->{emitted_items}}, {
    item_type => $item_type,
    data      => _clone_json($data),
  };
  $self->append_event(
    stream => $self->emitted_stream_name($item_type),
    event  => $data,
  );
  $self->_queue_subscription_notifications_for_item(
    item_type => $item_type,
    data      => $data,
    (exists $args{event} ? (event => $args{event}) : ()),
  );

  return 1;
}

sub _event_from_wire {
  my ($input) = @_;
  return undef unless ref($input) eq 'HASH';

  my $event;
  eval {
    $event = Net::Nostr::Event->from_wire($input);
    1;
  } or return undef;

  return $event;
}

sub _now_ms {
  my ($self) = @_;
  my $now = $self->{now_cb}->();

  die "now_cb must return an integer millisecond timestamp\n"
    unless defined $now && !ref($now) && $now =~ /\A-?\d+\z/;

  return 0 + $now;
}

sub _clear_secret_values {
  my ($values) = @_;
  return 1 unless ref($values) eq 'HASH';

  for my $slot (keys %{$values}) {
    next unless defined $values->{$slot};
    $values->{$slot} = '';
    delete $values->{$slot};
  }

  return 1;
}

sub _require_adapter_secret_slot_support {
  my (%args) = @_;
  my $adapter = $args{adapter};
  my $adapter_id = $args{adapter_id};
  my $slots = $args{slots} || [];

  die {
    code    => 'runtime.service_unavailable',
    message => "Adapter $adapter_id does not declare secure secret input slots",
    details => {
      method     => 'adapters.open_session',
      adapter_id => $adapter_id,
    },
  } unless $adapter->can('supported_secret_slots');

  die {
    code    => 'runtime.service_unavailable',
    message => "Adapter $adapter_id does not support secure session opening",
    details => {
      method     => 'adapters.open_session',
      adapter_id => $adapter_id,
    },
  } unless $adapter->can('open_session');

  my $supported = $adapter->supported_secret_slots;
  die {
    code    => 'runtime.service_unavailable',
    message => "Adapter $adapter_id supported_secret_slots must return an array",
    details => {
      method     => 'adapters.open_session',
      adapter_id => $adapter_id,
    },
  } unless ref($supported) eq 'ARRAY';
  die {
    code    => 'runtime.service_unavailable',
    message => "Adapter $adapter_id supported_secret_slots must contain non-empty strings",
    details => {
      method     => 'adapters.open_session',
      adapter_id => $adapter_id,
    },
  } if grep { !defined($_) || ref($_) || !length($_) } @{$supported};

  my %supported = map { $_ => 1 } @{$supported};
  for my $slot (@{$slots}) {
    die {
      code    => 'protocol.invalid_params',
      message => "Unsupported secret handle slot: $slot",
      details => {
        param => "secret_handles.$slot",
      },
    } unless $supported{$slot};
  }

  return 1;
}

sub _queue_due_timer_notifications {
  my ($self) = @_;
  my $now_ms = $self->_now_ms;
  my $fired_at = int($now_ms / 1000);

  for my $session_id (sort keys %{$self->{timers}}) {
    my $timers = $self->{timers}{$session_id} || {};

    for my $timer_id (sort keys %{$timers}) {
      my $timer = $timers->{$timer_id};
      next unless defined $timer;

      next unless $timer->is_due($now_ms);

      push @{$self->{runtime_notifications}{$session_id} ||= []}, {
        method => 'runtime.timer_fired',
        params => $timer->build_notification_params(
          fired_at => $fired_at,
        ),
      };

      if ($timer->is_repeating) {
        $timer->advance_after_fire_until_after($now_ms);
        next;
      }

      delete $timers->{$timer_id};
    }

    delete $self->{timers}{$session_id}
      unless keys %{$timers};
  }

  return 1;
}

sub _require_string_arg {
  my ($name, $value) = @_;

  die "$name is required\n"
    unless defined $value && !ref($value) && length($value);

  return $value;
}

sub _validate_config_description {
  my ($description) = @_;

  die "config_description.schema must be an object\n"
    if exists $description->{schema}
      && ref($description->{schema}) ne 'HASH';
  die "config_description.schema_ref must be a non-empty string\n"
    if exists $description->{schema_ref}
      && (
        !defined $description->{schema_ref}
        || ref($description->{schema_ref})
        || !length($description->{schema_ref})
      );
  die "config_description.version must be a non-empty string\n"
    if exists $description->{version}
      && (
        !defined $description->{version}
        || ref($description->{version})
        || !length($description->{version})
      );

  return 1;
}

sub _clone_json {
  my ($value) = @_;
  return JSON::PP->new->utf8->canonical->decode(
    JSON::PP->new->utf8->canonical->encode($value)
  );
}

1;

=head1 NAME

Overnet::Program::Runtime - Overnet Program Runtime scaffold

=head1 DESCRIPTION

Runtime entry point including runtime-managed adapter registration and adapter
session lifecycle.

=cut
