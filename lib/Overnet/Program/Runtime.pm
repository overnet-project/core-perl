package Overnet::Program::Runtime;

use strict;
use warnings;
use JSON::PP ();
use Net::Nostr::Event;
use Time::HiRes qw(time);
use Overnet::Core::Validator ();
use Overnet::Program::AdapterRegistry;
use Overnet::Program::AdapterSession;
use Overnet::Program::Store;
use Overnet::Program::Subscription;
use Overnet::Program::Timer;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;
  my $adapter_registry = $args{adapter_registry} || Overnet::Program::AdapterRegistry->new;
  my $store = $args{store} || Overnet::Program::Store->new;
  my $now_cb = $args{now_cb} || sub { int(time() * 1000) };

  die "adapter_registry must be an Overnet::Program::AdapterRegistry instance\n"
    unless ref($adapter_registry) && $adapter_registry->isa('Overnet::Program::AdapterRegistry');
  die "store must be an Overnet::Program::Store instance\n"
    unless ref($store) && $store->isa('Overnet::Program::Store');
  die "now_cb must be a code reference\n"
    unless ref($now_cb) eq 'CODE';

  return bless {
    adapter_registry => $adapter_registry,
    store            => $store,
    now_cb           => $now_cb,
    next_session_id  => 1,
    adapter_sessions => {},
    timers           => {},
    emitted_items    => [],
    subscriptions    => {},
    runtime_notifications => {},
    %args,
  }, $class;
}

sub adapter_registry { $_[0]->{adapter_registry} }
sub store { $_[0]->{store} }
sub emitted_items { [ @{$_[0]->{emitted_items} || []} ] }

sub emitted_stream_name {
  my ($self, $item_type) = @_;

  die "item_type must be event, state, or capability\n"
    unless defined $item_type
      && !ref($item_type)
      && (
        $item_type eq 'event'
        || $item_type eq 'state'
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

  die "adapter_id is required\n"
    unless defined $adapter_id && !ref($adapter_id) && length($adapter_id);
  die "config must be an object\n"
    if ref($config) ne 'HASH';

  my $adapter = $self->{adapter_registry}->build($adapter_id);
  die "Unknown adapter_id: $adapter_id\n"
    unless defined $adapter;

  my $session_id = 'adapter-' . $self->{next_session_id}++;
  my $session = Overnet::Program::AdapterSession->new(
    session_id => $session_id,
    adapter_id => $adapter_id,
    adapter    => $adapter,
    config     => $config,
  );

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

  my $session = delete $self->{adapter_sessions}{$session_id};
  die "Unknown adapter_session_id: $session_id\n"
    unless defined $session;

  return 1;
}

sub adapter_session_ids {
  my ($self) = @_;
  return [ sort keys %{$self->{adapter_sessions}} ];
}

sub append_event {
  my ($self, %args) = @_;
  return $self->{store}->append_event(%args);
}

sub read_events {
  my ($self, %args) = @_;
  return $self->{store}->read_events(%args);
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

sub _queue_due_timer_notifications {
  my ($self) = @_;
  my $now_ms = $self->_now_ms;
  my $fired_at = int($now_ms / 1000);

  for my $session_id (sort keys %{$self->{timers}}) {
    my $timers = $self->{timers}{$session_id} || {};

    for my $timer_id (sort keys %{$timers}) {
      my $timer = $timers->{$timer_id};
      next unless defined $timer;

      while ($timer->is_due($now_ms)) {
        push @{$self->{runtime_notifications}{$session_id} ||= []}, {
          method => 'runtime.timer_fired',
          params => $timer->build_notification_params(
            fired_at => $fired_at,
          ),
        };

        if ($timer->is_repeating) {
          $timer->advance_after_fire;
          next;
        }

        delete $timers->{$timer_id};
        last;
      }
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
