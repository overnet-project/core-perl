package Overnet::Program::Instance;

use strict;
use warnings;
use Overnet::Program::Protocol;
use Overnet::Program::Services;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;

  my $protocol = $args{protocol} || Overnet::Program::Protocol->new;
  my $supported_protocol_versions = $args{supported_protocol_versions} || ['0.1'];
  my $program_id = $args{program_id};
  my $instance_id = $args{instance_id} || 'instance-1';
  my $runtime_program_id = $args{runtime_program_id} || 'overnet.runtime';
  my $service_handler = $args{service_handler};
  my $config = exists $args{config}
    ? $args{config}
    : (
      defined $service_handler
        ? $service_handler->runtime->config
        : {}
    );

  die "protocol must be an Overnet::Program::Protocol instance\n"
    unless ref($protocol) && $protocol->isa('Overnet::Program::Protocol');
  die "supported_protocol_versions must be a non-empty array\n"
    unless ref($supported_protocol_versions) eq 'ARRAY' && @{$supported_protocol_versions};
  die "instance_id is required\n"
    unless defined $instance_id && length $instance_id;
  die "runtime_program_id is required\n"
    unless defined $runtime_program_id && length $runtime_program_id;
  if (defined $service_handler) {
    die "service_handler must be an Overnet::Program::Services instance\n"
      unless ref($service_handler) && $service_handler->isa('Overnet::Program::Services');
  }
  die "config must be an object\n"
    unless ref($config) eq 'HASH';

  return bless {
    protocol                    => $protocol,
    supported_protocol_versions => [ @{$supported_protocol_versions} ],
    program_id                  => $program_id,
    instance_id                 => $instance_id,
    runtime_program_id          => $runtime_program_id,
    config                      => $config,
    permissions                 => $args{permissions} || [],
    services                    => $args{services} || {},
    service_handler             => $service_handler,
    state                       => 'awaiting_hello',
    next_request_id             => 1,
    inflight                    => {},
  }, $class;
}

sub state { $_[0]->{state} }
sub instance_id { $_[0]->{instance_id} }
sub is_ready { $_[0]->{state} eq 'ready' ? 1 : 0 }
sub selected_protocol_version { $_[0]->{selected_protocol_version} }
sub peer_program_id { $_[0]->{peer_program_id} }
sub inflight_request_ids { [ sort keys %{$_[0]->{inflight}} ] }

sub drain_runtime_notifications {
  my ($self) = @_;

  die "Runtime notifications can only be drained from ready state\n"
    unless $self->{state} eq 'ready';

  my $handler = $self->{service_handler}
    or return [];
  my $runtime = $handler->runtime;
  return [] unless defined $runtime;

  my $notifications = $runtime->drain_runtime_notifications($self->{instance_id});
  return [
    map {
      Overnet::Program::Protocol::build_notification(
        method => $_->{method},
        params => $_->{params} || {},
      )
    } @{$notifications}
  ];
}

sub process_program_message {
  my ($self, $message) = @_;

  my ($ok, $code, $error) = $self->{protocol}->validate_message($message);
  die "$code: $error\n" unless $ok;

  my $state = $self->{state};

  if ($state eq 'awaiting_hello') {
    return $self->_handle_program_hello($message);
  }

  if ($state eq 'awaiting_init_response') {
    return $self->_handle_init_response($message);
  }

  if ($state eq 'awaiting_ready') {
    return $self->_handle_ready_phase($message);
  }

  if ($state eq 'ready') {
    return $self->_handle_ready_message($message);
  }

  if ($state eq 'shutdown_requested') {
    return $self->_handle_shutdown_response($message);
  }

  die "Cannot process messages in state $state\n";
}

sub request_shutdown {
  my ($self, %args) = @_;

  die "Shutdown can only be requested from ready state\n"
    unless $self->{state} eq 'ready';

  my $id = $self->_allocate_request_id;
  my $request = Overnet::Program::Protocol::build_runtime_shutdown(
    id     => $id,
    reason => $args{reason},
  );

  $self->{inflight}{$id} = 'runtime.shutdown';
  $self->{state} = 'shutdown_requested';

  return {
    send => $request,
  };
}

sub _handle_program_hello {
  my ($self, $message) = @_;

  die "Expected notification in awaiting_hello state\n"
    unless $message->{type} eq 'notification';
  die "Expected program.hello notification\n"
    unless $message->{method} eq 'program.hello';

  my $params = $message->{params} || {};
  my $selected = $self->_select_protocol_version($params->{supported_protocol_versions});
  unless (defined $selected) {
    $self->{state} = 'failed';
    return {
      send => Overnet::Program::Protocol::build_runtime_fatal(
        code    => 'protocol.version_mismatch',
        message => 'No compatible protocol version',
        phase   => 'handshake',
        details => {
          runtime_supported_protocol_versions => [ @{$self->{supported_protocol_versions}} ],
          program_supported_protocol_versions => [ @{$params->{supported_protocol_versions} || []} ],
        },
      ),
      fatal => 1,
      error => {
        code    => 'protocol.version_mismatch',
        message => 'No compatible protocol version',
      },
    };
  }

  $self->{selected_protocol_version} = $selected;
  $self->{peer_program_id} = $params->{program_id};
  $self->{peer_program_version} = $params->{program_version}
    if defined $params->{program_version};
  $self->{peer_metadata} = $params->{metadata}
    if defined $params->{metadata};

  my $id = $self->_allocate_request_id;
  my $known_program_id = defined $self->{program_id} && length $self->{program_id}
    ? $self->{program_id}
    : $self->{peer_program_id};
  my $request = Overnet::Program::Protocol::build_runtime_init(
    id               => $id,
    protocol_version => $selected,
    instance_id      => $self->{instance_id},
    program_id       => $known_program_id,
    config           => $self->{config},
    permissions      => $self->{permissions},
    services         => $self->{services},
  );

  $self->{inflight}{$id} = 'runtime.init';
  $self->{state} = 'awaiting_init_response';

  return {
    send => $request,
  };
}

sub _handle_init_response {
  my ($self, $message) = @_;

  die "Expected response while awaiting runtime.init response\n"
    unless $message->{type} eq 'response';

  my $method = delete $self->{inflight}{$message->{id}}
    or die "protocol.unknown_request_id: Unexpected response id while awaiting runtime.init response\n";
  die "Expected runtime.init response\n"
    unless $method eq 'runtime.init';

  if ($message->{ok}) {
    $self->{state} = 'awaiting_ready';
    return { accepted => 1 };
  }

  $self->{state} = 'failed';
  return {
    rejected => 1,
    error    => $message->{error},
  };
}

sub _handle_ready_phase {
  my ($self, $message) = @_;

  die "Expected notification while awaiting program.ready\n"
    unless $message->{type} eq 'notification';

  if ($message->{method} eq 'program.ready') {
    $self->{state} = 'ready';
    return { ready => 1 };
  }

  if ($message->{method} eq 'program.log' || $message->{method} eq 'program.health') {
    return { observed => $message->{method} };
  }

  die "Unexpected notification while awaiting program.ready\n";
}

sub _handle_ready_message {
  my ($self, $message) = @_;

  if ($message->{type} eq 'notification') {
    return { observed => $message->{method} }
      if $message->{method} eq 'program.log' || $message->{method} eq 'program.health';

    die "protocol.unknown_method: Unexpected notification in ready state: $message->{method}\n";
  }

  if ($message->{type} eq 'request') {
    return $self->_handle_service_request($message);
  }

  if ($message->{type} eq 'response') {
    my $method = delete $self->{inflight}{$message->{id}}
      or die "protocol.unknown_request_id: Unexpected response id in ready state\n";
    return {
      response_to => $method,
      ok          => $message->{ok} ? 1 : 0,
      ($message->{ok} ? () : (error => $message->{error})),
    };
  }

  die "Unexpected message type in ready state\n";
}

sub _handle_service_request {
  my ($self, $message) = @_;

  unless (Overnet::Program::Services->is_service_method($message->{method})) {
    return {
      send => Overnet::Program::Protocol::build_response_error(
        id      => $message->{id},
        code    => 'protocol.unknown_method',
        message => "Unknown request method in this context: $message->{method}",
      ),
    };
  }

  my $handler = $self->{service_handler}
    or return {
      send => Overnet::Program::Protocol::build_response_error(
        id      => $message->{id},
        code    => 'runtime.service_unavailable',
        message => 'No service handler configured for request processing',
      ),
    };

  my $result;
  my $error;
  eval {
    $result = $handler->dispatch_request(
      $message->{method},
      $message->{params} || {},
      permissions => $self->{permissions},
      session_id  => $self->{instance_id},
      program_id  => $self->_known_program_id,
    );
    1;
  } or $error = $@;

  if ($error) {
    if (ref($error) eq 'HASH' && defined $error->{code} && defined $error->{message}) {
      my %response = (
        id      => $message->{id},
        code    => $error->{code},
        message => $error->{message},
      );
      $response{details} = $error->{details}
        if defined $error->{details};

      return {
        send => Overnet::Program::Protocol::build_response_error(%response),
      };
    }

    chomp $error if !ref($error);
    return {
      send => Overnet::Program::Protocol::build_response_error(
        id      => $message->{id},
        code    => 'program.operation_failed',
        message => $error,
      ),
    };
  }

  return {
    send => Overnet::Program::Protocol::build_response_ok(
      id     => $message->{id},
      result => $result || {},
    ),
  };
}

sub _handle_shutdown_response {
  my ($self, $message) = @_;

  die "Expected response while awaiting runtime.shutdown response\n"
    unless $message->{type} eq 'response';

  my $method = delete $self->{inflight}{$message->{id}}
    or die "protocol.unknown_request_id: Unexpected response id while awaiting runtime.shutdown response\n";
  die "Expected runtime.shutdown response\n"
    unless $method eq 'runtime.shutdown';

  if ($message->{ok}) {
    $self->_revoke_secret_handles;
    $self->{state} = 'shutdown_complete';
    return { shutdown_complete => 1 };
  }

  $self->_revoke_secret_handles;
  $self->{state} = 'failed';
  return {
    shutdown_rejected => 1,
    error             => $message->{error},
  };
}

sub _allocate_request_id {
  my ($self) = @_;
  my $id = 'runtime-' . $self->{next_request_id}++;
  return $id;
}

sub _select_protocol_version {
  my ($self, $peer_versions) = @_;
  return undef unless ref($peer_versions) eq 'ARRAY' && @{$peer_versions};

  my %peer = map { $_ => 1 } @{$peer_versions};
  for my $version (@{$self->{supported_protocol_versions}}) {
    return $version if $peer{$version};
  }

  return undef;
}

sub _known_program_id {
  my ($self) = @_;
  return $self->{program_id}
    if defined $self->{program_id} && length $self->{program_id};
  return $self->{peer_program_id};
}

sub _revoke_secret_handles {
  my ($self) = @_;
  my $handler = $self->{service_handler}
    or return 0;
  my $runtime = $handler->runtime
    or return 0;

  return $runtime->revoke_secret_handles_for_session(
    session_id => $self->{instance_id},
  );
}

1;

=head1 NAME

Overnet::Program::Instance - Overnet program runtime session state

=head1 DESCRIPTION

Session-oriented state machine for one supervised Overnet program instance.

=cut
