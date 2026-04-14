package Overnet::Program::Host;

use strict;
use warnings;
use IO::Handle ();
use IO::Select;
use IPC::Open3 qw(open3);
use JSON::PP ();
use POSIX qw(WNOHANG);
use Symbol qw(gensym);
use Time::HiRes qw(time);
use Overnet::Program::Instance;
use Overnet::Program::Protocol;
use Overnet::Program::Runtime;
use Overnet::Program::Services;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;

  my $command = $args{command};
  my $runtime = $args{runtime};
  my $runtime_args = exists $args{runtime_args} ? $args{runtime_args} : {};
  my $service_handler = $args{service_handler};
  my $protocol = $args{protocol} || Overnet::Program::Protocol->new;
  my $poll_interval_ms = exists $args{poll_interval_ms} ? $args{poll_interval_ms} : 25;
  my $read_chunk_size = exists $args{read_chunk_size} ? $args{read_chunk_size} : 4096;
  my $startup_timeout_ms = exists $args{startup_timeout_ms} ? $args{startup_timeout_ms} : 1_000;
  my $shutdown_timeout_ms = exists $args{shutdown_timeout_ms} ? $args{shutdown_timeout_ms} : 1_000;

  die "command must be a non-empty array of strings\n"
    unless _is_string_array($command);
  die "runtime_args must be an object\n"
    unless ref($runtime_args) eq 'HASH';
  die "runtime_args cannot be supplied when runtime is provided\n"
    if defined $runtime && keys %{$runtime_args};
  die "protocol must be an Overnet::Program::Protocol instance\n"
    unless ref($protocol) && $protocol->isa('Overnet::Program::Protocol');
  die "poll_interval_ms must be a non-negative integer\n"
    unless _is_non_negative_integer($poll_interval_ms);
  die "read_chunk_size must be a positive integer\n"
    unless _is_positive_integer($read_chunk_size);
  die "startup_timeout_ms must be a non-negative integer\n"
    unless _is_non_negative_integer($startup_timeout_ms);
  die "shutdown_timeout_ms must be a non-negative integer\n"
    unless _is_non_negative_integer($shutdown_timeout_ms);

  if (defined $runtime) {
    die "runtime must be an Overnet::Program::Runtime instance\n"
      unless ref($runtime) && $runtime->isa('Overnet::Program::Runtime');
  } else {
    $runtime = Overnet::Program::Runtime->new(%{$runtime_args});
  }

  if (defined $service_handler) {
    die "service_handler must be an Overnet::Program::Services instance\n"
      unless ref($service_handler) && $service_handler->isa('Overnet::Program::Services');
    die "service_handler runtime must match runtime\n"
      unless $service_handler->runtime == $runtime;
  } else {
    $service_handler = Overnet::Program::Services->new(runtime => $runtime);
  }

  my %instance_args = (
    protocol        => $protocol,
    service_handler => $service_handler,
  );
  for my $field (qw(
    supported_protocol_versions
    program_id
    instance_id
    runtime_program_id
    permissions
    services
    config
  )) {
    $instance_args{$field} = $args{$field}
      if exists $args{$field};
  }

  my $instance = Overnet::Program::Instance->new(%instance_args);

  return bless {
    command             => [ @{$command} ],
    runtime             => $runtime,
    service_handler     => $service_handler,
    protocol            => $protocol,
    instance            => $instance,
    poll_interval_ms    => 0 + $poll_interval_ms,
    read_chunk_size     => 0 + $read_chunk_size,
    startup_timeout_ms  => 0 + $startup_timeout_ms,
    shutdown_timeout_ms => 0 + $shutdown_timeout_ms,
    transcript          => [],
    observed_notifications => [],
    stderr_output       => '',
  }, $class;
}

sub runtime { $_[0]->{runtime} }
sub service_handler { $_[0]->{service_handler} }
sub protocol { $_[0]->{protocol} }
sub instance { $_[0]->{instance} }
sub pid { $_[0]->{pid} }
sub state { $_[0]->{instance}->state }
sub wait_status { $_[0]->{wait_status} }
sub exit_code { $_[0]->{exit_code} }
sub exit_signal { $_[0]->{exit_signal} }
sub has_exited { defined $_[0]->{wait_status} ? 1 : 0 }
sub stderr_output { $_[0]->{stderr_output} }

sub transcript {
  my ($self) = @_;
  return _clone_json($self->{transcript});
}

sub observed_notifications {
  my ($self) = @_;
  return _clone_json($self->{observed_notifications});
}

sub start {
  my ($self, %args) = @_;
  my $timeout_ms = exists $args{timeout_ms}
    ? $args{timeout_ms}
    : $self->{startup_timeout_ms};

  die "host process already started\n"
    if defined $self->{pid} && !defined $self->{wait_status};

  $self->_spawn_child;
  my $ready = eval {
    $self->pump_until(
      timeout_ms => $timeout_ms,
      condition  => sub { $_[0]->instance->is_ready },
    );
  };
  if (!$ready) {
    my $error = $@;
    $self->_best_effort_terminate(signal => 'TERM', timeout_ms => 200);
    die $error if length $error;
    die "Program did not reach ready state within timeout\n";
  }

  return $self;
}

sub pump {
  my ($self, %args) = @_;
  my $timeout_ms = exists $args{timeout_ms}
    ? $args{timeout_ms}
    : $self->{poll_interval_ms};

  die "timeout_ms must be a non-negative integer\n"
    unless _is_non_negative_integer($timeout_ms);

  my $deadline = _now_ms() + $timeout_ms;
  my $progress = 0;

  while (1) {
    $progress += $self->_flush_runtime_notifications;

    my $remaining = $deadline - _now_ms();
    last if $remaining < 0;

    my $step_timeout = $remaining > $self->{poll_interval_ms}
      ? $self->{poll_interval_ms}
      : $remaining;
    $progress += $self->_poll_io(timeout_ms => $step_timeout);

    last if _now_ms() >= $deadline;
    last if defined $self->{wait_status} && !$self->_has_open_read_handles;
  }

  return $progress;
}

sub pump_until {
  my ($self, %args) = @_;
  my $condition = $args{condition};
  my $timeout_ms = exists $args{timeout_ms}
    ? $args{timeout_ms}
    : $self->{startup_timeout_ms};

  die "condition must be a code reference\n"
    unless ref($condition) eq 'CODE';
  die "timeout_ms must be a non-negative integer\n"
    unless _is_non_negative_integer($timeout_ms);

  my $deadline = _now_ms() + $timeout_ms;

  while (1) {
    return 1 if $condition->($self);

    my $remaining = $deadline - _now_ms();
    last if $remaining < 0;

    $self->_flush_runtime_notifications;
    return 1 if $condition->($self);

    my $step_timeout = $remaining > $self->{poll_interval_ms}
      ? $self->{poll_interval_ms}
      : $remaining;
    $self->_poll_io(timeout_ms => $step_timeout);

    return 1 if $condition->($self);
    last if defined $self->{wait_status} && !$self->_has_open_read_handles;
  }

  return $condition->($self) ? 1 : 0;
}

sub request_shutdown {
  my ($self, %args) = @_;
  my $timeout_ms = exists $args{timeout_ms}
    ? $args{timeout_ms}
    : $self->{shutdown_timeout_ms};

  my $request = $self->{instance}->request_shutdown(
    (exists $args{reason} ? (reason => $args{reason}) : ()),
  );
  $self->_send_message($request->{send});

  my $complete = eval {
    $self->pump_until(
      timeout_ms => $timeout_ms,
      condition  => sub {
        my $state = $_[0]->state;
        return $state eq 'shutdown_complete' || $state eq 'failed';
      },
    );
  };
  if (!$complete) {
    my $error = $@;
    $self->_best_effort_terminate(signal => 'TERM', timeout_ms => 200);
    die $error if length $error;
    die "Program did not complete runtime.shutdown within timeout\n";
  }

  $self->_close_child_stdin;

  my $exited = $self->pump_until(
    timeout_ms => $timeout_ms,
    condition  => sub { $_[0]->has_exited },
  );
  unless ($exited) {
    $self->_best_effort_terminate(signal => 'TERM', timeout_ms => 200);
    die "Program did not exit after runtime.shutdown\n";
  }

  return {
    state       => $self->state,
    wait_status => $self->wait_status,
    exit_code   => $self->exit_code,
    exit_signal => $self->exit_signal,
  };
}

sub terminate {
  my ($self, %args) = @_;
  my $signal = exists $args{signal} ? $args{signal} : 'TERM';
  my $timeout_ms = exists $args{timeout_ms} ? $args{timeout_ms} : 0;

  return 0 unless defined $self->{pid} && !defined $self->{wait_status};

  $self->_close_child_stdin;
  kill $signal, $self->{pid};

  return 1 if !$timeout_ms;
  return $self->pump_until(
    timeout_ms => $timeout_ms,
    condition  => sub { $_[0]->has_exited },
  );
}

sub DESTROY {
  my ($self) = @_;
  return unless defined $self->{pid} && !defined $self->{wait_status};
  $self->_best_effort_terminate(signal => 'TERM', timeout_ms => 100);
}

sub _spawn_child {
  my ($self) = @_;

  my $child_err = gensym();
  my ($child_in, $child_out);
  my $pid = open3($child_in, $child_out, $child_err, @{$self->{command}});

  binmode($child_in, ':raw');
  binmode($child_out, ':raw');
  binmode($child_err, ':raw');

  $child_in->autoflush(1);
  $child_out->autoflush(1);
  $child_err->autoflush(1);

  $self->{pid} = $pid;
  $self->{child_in} = $child_in;
  $self->{child_out} = $child_out;
  $self->{child_err} = $child_err;
  $self->{wait_status} = undef;
  $self->{exit_code} = undef;
  $self->{exit_signal} = undef;
  $self->{released_runtime_resources} = 0;
}

sub _poll_io {
  my ($self, %args) = @_;
  my $timeout_ms = exists $args{timeout_ms} ? $args{timeout_ms} : 0;

  $self->_reap_child;

  my @handles = grep { defined $_ } ($self->{child_out}, $self->{child_err});
  if (!@handles) {
    select undef, undef, undef, $timeout_ms / 1000 if $timeout_ms > 0;
    $self->_reap_child;
    return 0;
  }

  my $selector = IO::Select->new(@handles);
  my @ready = $selector->can_read($timeout_ms / 1000);
  my $progress = 0;

  for my $handle (@ready) {
    my $bytes = sysread($handle, my $chunk, $self->{read_chunk_size});
    if (!defined $bytes) {
      next if $!{EINTR};
      my $stream = $self->_stream_name_for_handle($handle);
      die "Failed to read $stream from child process: $!\n";
    }

    if ($bytes == 0) {
      $self->_handle_eof($handle);
      next;
    }

    $progress++;
    if ($self->_is_child_out($handle)) {
      $progress += $self->_process_stdout_chunk($chunk);
      next;
    }

    $self->{stderr_output} .= $chunk;
  }

  $self->_reap_child;
  return $progress;
}

sub _process_stdout_chunk {
  my ($self, $chunk) = @_;
  my $messages = eval { $self->{protocol}->feed($chunk) };
  if (!$messages) {
    my $error = $@ || "Unknown protocol framing error\n";
    die $error;
  }

  my $progress = 0;
  for my $message (@{$messages}) {
    $progress++;
    push @{$self->{transcript}}, {
      direction => 'from_program',
      message   => _clone_json($message),
    };

    my $result = eval { $self->{instance}->process_program_message($message) };
    if (!$result) {
      my $error = $@ || "Unknown program protocol error\n";
      die $error;
    }

    if ($message->{type} eq 'notification' && ($result->{observed} || '') =~ /\Aprogram\.(?:log|health)\z/) {
      push @{$self->{observed_notifications}}, _clone_json($message);
    }

    if (defined $result->{send}) {
      $self->_send_message($result->{send});
    }

    $progress += $self->_flush_runtime_notifications;

    if ($result->{fatal}) {
      my $error = $result->{error} || {};
      my $code = (ref($error) eq 'HASH' && defined $error->{code} && !ref($error->{code}))
        ? $error->{code}
        : 'runtime.fatal';
      my $message_text = (ref($error) eq 'HASH' && defined $error->{message} && !ref($error->{message}))
        ? $error->{message}
        : 'Fatal runtime error';
      die "$code: $message_text\n";
    }
  }

  return $progress;
}

sub _send_message {
  my ($self, $message) = @_;
  die "child stdin is not available\n"
    unless defined $self->{child_in};

  my $frame = $self->{protocol}->encode_message($message);
  my $offset = 0;
  while ($offset < length $frame) {
    my $written = syswrite($self->{child_in}, $frame, length($frame) - $offset, $offset);
    if (!defined $written) {
      next if $!{EINTR};
      die "Failed to write protocol frame to child process: $!\n";
    }
    $offset += $written;
  }

  push @{$self->{transcript}}, {
    direction => 'to_program',
    message   => _clone_json($message),
  };

  return 1;
}

sub _flush_runtime_notifications {
  my ($self) = @_;
  return 0 unless $self->{instance}->is_ready;
  return 0 unless defined $self->{child_in};

  my $notifications = $self->{instance}->drain_runtime_notifications;
  for my $message (@{$notifications}) {
    $self->_send_message($message);
  }

  return scalar @{$notifications};
}

sub _close_child_stdin {
  my ($self) = @_;
  return unless defined $self->{child_in};
  close delete $self->{child_in};
}

sub _handle_eof {
  my ($self, $handle) = @_;

  if ($self->_is_child_out($handle)) {
    $self->{protocol}->finish;
    close delete $self->{child_out};
    die "Protocol transport error: program stdout closed before orderly shutdown\n"
      unless $self->state eq 'shutdown_complete';
    return;
  }

  if ($self->_is_child_err($handle)) {
    close delete $self->{child_err};
    return;
  }
}

sub _reap_child {
  my ($self) = @_;
  return unless defined $self->{pid};
  return if defined $self->{wait_status};

  my $result = waitpid($self->{pid}, WNOHANG);
  return unless $result == $self->{pid};

  my $wait_status = $?;
  $self->{wait_status} = $wait_status;
  $self->{exit_code} = ($wait_status & 127) ? undef : ($wait_status >> 8);
  $self->{exit_signal} = $wait_status & 127;
  $self->_release_runtime_resources;
}

sub _release_runtime_resources {
  my ($self) = @_;
  return if $self->{released_runtime_resources};
  return unless defined $self->{runtime};
  return unless defined $self->{instance};

  my $instance_id = $self->{instance}->instance_id;
  return unless defined $instance_id && length $instance_id;

  $self->{runtime}->release_session_resources(
    session_id => $instance_id,
  );
  $self->{released_runtime_resources} = 1;
}

sub _has_open_read_handles {
  my ($self) = @_;
  return (defined $self->{child_out} || defined $self->{child_err}) ? 1 : 0;
}

sub _is_child_out {
  my ($self, $handle) = @_;
  return defined $self->{child_out}
    && defined $handle
    && defined fileno($self->{child_out})
    && defined fileno($handle)
    && fileno($self->{child_out}) == fileno($handle)
      ? 1
      : 0;
}

sub _is_child_err {
  my ($self, $handle) = @_;
  return defined $self->{child_err}
    && defined $handle
    && defined fileno($self->{child_err})
    && defined fileno($handle)
    && fileno($self->{child_err}) == fileno($handle)
      ? 1
      : 0;
}

sub _stream_name_for_handle {
  my ($self, $handle) = @_;
  return 'stdout' if $self->_is_child_out($handle);
  return 'stderr' if $self->_is_child_err($handle);
  return 'unknown stream';
}

sub _best_effort_terminate {
  my ($self, %args) = @_;
  eval {
    $self->terminate(%args);
    1;
  } or do {
    return 0;
  };
  return 1;
}

sub _is_string_array {
  my ($value) = @_;
  return 0 unless ref($value) eq 'ARRAY' && @{$value};
  for my $item (@{$value}) {
    return 0 unless defined $item && !ref($item) && length($item);
  }
  return 1;
}

sub _is_non_negative_integer {
  my ($value) = @_;
  return defined $value && !ref($value) && $value =~ /\A(?:0|[1-9]\d*)\z/ ? 1 : 0;
}

sub _is_positive_integer {
  my ($value) = @_;
  return defined $value && !ref($value) && $value =~ /\A[1-9]\d*\z/ ? 1 : 0;
}

sub _clone_json {
  my ($value) = @_;
  return JSON::PP->new->canonical->decode(
    JSON::PP->new->canonical->encode($value)
  );
}

sub _now_ms {
  return int(time() * 1000);
}

1;

=head1 NAME

Overnet::Program::Host - Supervised process host for Overnet programs

=head1 DESCRIPTION

Spawns a program process, drives the framed program runtime protocol over
stdin/stdout, captures stderr, and routes messages through
L<Overnet::Program::Instance>.

=cut
