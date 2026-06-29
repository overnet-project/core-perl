package Overnet::Auth::Client;

use strictures 2;
use Carp    qw(croak);
use English qw(-no_match_vars);

use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);

use Overnet::Program::Protocol;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;

  return bless {
    endpoint        => $args{endpoint},
    protocol        => $args{protocol} || Overnet::Program::Protocol->new,
    next_request_id => 1,
    socket_factory  => $args{socket_factory},
  }, $class;
}

sub endpoint {
  my ($self) = @_;
  if ( defined $self->{endpoint}
    && !ref($self->{endpoint})
    && length($self->{endpoint})) {
    return $self->{endpoint};
  }
  if ( defined $ENV{OVERNET_AUTH_SOCK}
    && !ref($ENV{OVERNET_AUTH_SOCK})
    && length($ENV{OVERNET_AUTH_SOCK})) {
    return $ENV{OVERNET_AUTH_SOCK};
  }
  if ( defined $ENV{OVERNET_AUTH_ENDPOINT}
    && !ref($ENV{OVERNET_AUTH_ENDPOINT})
    && length($ENV{OVERNET_AUTH_ENDPOINT})) {
    return $ENV{OVERNET_AUTH_ENDPOINT};
  }
  return;
}

sub request {
  my ($self, %args) = @_;
  my $method = $args{method};
  my $params = $args{params} || {};

  if (!(defined $method && !ref($method) && length($method))) {
    croak "method is required\n";
  }
  if (!(ref($params) eq 'HASH')) {
    croak "params must be an object\n";
  }

  my $id =
       defined($args{id})
    && !ref($args{id})
    && length($args{id})
    ? $args{id}
    : 'auth-' . $self->{next_request_id}++;
  my $request = Overnet::Program::Protocol::build_request(
    id     => $id,
    method => $method,
    params => $params,
  );

  my $socket = $self->_connect_socket;
  my $frame  = $self->{protocol}->encode_message($request);
  _write_all($socket, $frame);

  my $response = $self->_read_response($socket, $id);
  close $socket
    or croak "close auth-agent socket failed: $OS_ERROR";

  return $response;
}

sub agent_info {
  my ($self) = @_;
  return $self->request(
    method => 'agent.info',
    params => {},
  );
}

sub identities_list {
  my ($self) = @_;
  return $self->request(
    method => 'identities.list',
    params => {},
  );
}

sub policies_list {
  my ($self) = @_;
  return $self->request(
    method => 'policies.list',
    params => {},
  );
}

sub policies_grant {
  my ($self, %params) = @_;
  return $self->request(
    method => 'policies.grant',
    params => \%params,
  );
}

sub policies_revoke {
  my ($self, %params) = @_;
  return $self->request(
    method => 'policies.revoke',
    params => \%params,
  );
}

sub service_pins_list {
  my ($self) = @_;
  return $self->request(
    method => 'service_pins.list',
    params => {},
  );
}

sub service_pins_set {
  my ($self, %params) = @_;
  return $self->request(
    method => 'service_pins.set',
    params => \%params,
  );
}

sub service_pins_forget {
  my ($self, %params) = @_;
  return $self->request(
    method => 'service_pins.forget',
    params => \%params,
  );
}

sub sessions_list {
  my ($self) = @_;
  return $self->request(
    method => 'sessions.list',
    params => {},
  );
}

sub sessions_authorize {
  my ($self, %params) = @_;
  return $self->request(
    method => 'sessions.authorize',
    params => \%params,
  );
}

sub sessions_renew {
  my ($self, %params) = @_;
  return $self->request(
    method => 'sessions.renew',
    params => \%params,
  );
}

sub sessions_revoke {
  my ($self, %params) = @_;
  return $self->request(
    method => 'sessions.revoke',
    params => \%params,
  );
}

sub _connect_socket {
  my ($self) = @_;
  my $factory = $self->{socket_factory};
  if (ref($factory) eq 'CODE') {
    my $socket = $factory->($self->endpoint);
    if (!($socket)) {
      croak "socket_factory did not return a socket\n";
    }
    return $socket;
  }

  my $endpoint = $self->endpoint;
  if (!(defined $endpoint && !ref($endpoint) && length($endpoint))) {
    croak "auth-agent endpoint is not configured\n";
  }

  my $socket = IO::Socket::UNIX->new(
    Type => SOCK_STREAM,
    Peer => $endpoint,
  );
  if (!($socket)) {
    croak "connect to auth-agent endpoint $endpoint failed: $OS_ERROR";
  }

  return $socket;
}

sub _read_response {
  my ($self, $socket, $expected_id) = @_;
  my $reader = Overnet::Program::Protocol->new(max_frame_size => $self->{protocol}->max_frame_size,);

  while (1) {
    my $chunk = q{};
    my $read  = sysread($socket, $chunk, 4096);
    if (!(defined $read)) {
      croak "read from auth-agent endpoint failed: $OS_ERROR";
    }

    if ($read == 0) {
      $reader->finish;
      croak "auth-agent closed the connection before sending a response\n";
    }

    my $messages = $reader->feed($chunk);
    if (!(@{$messages})) {
      next;
    }

    my $response = $messages->[0];
    my ($ok, $code, $message) =
      $self->{protocol}->validate_message($response);
    if (!($ok)) {
      croak "$code: $message\n";
    }
    if (!((($response->{id} || q{}) eq $expected_id))) {
      croak "auth-agent response id does not match request id\n";
    }

    return $response;
  }
  return;
}

sub _write_all {
  my ($socket, $bytes) = @_;
  my $offset = 0;

  while ($offset < length($bytes)) {
    my $written = syswrite($socket, $bytes, length($bytes) - $offset, $offset);
    if (!(defined $written)) {
      croak "write to auth-agent endpoint failed: $OS_ERROR";
    }
    $offset += $written;
  }

  return 1;
}

1;

=head1 NAME

Overnet::Auth::Client - Overnet Perl module

=head1 VERSION

Version 0.001.

=head1 SYNOPSIS

  use Overnet::Auth::Client;

=head1 DESCRIPTION

This module is part of the Overnet Perl implementation.

=head1 SUBROUTINES/METHODS

=head2 new

Public API entry point.

=head2 endpoint

Public API entry point.

=head2 request

Public API entry point.

=head2 agent_info

Public API entry point.

=head2 identities_list

Public API entry point.

=head2 policies_list

Public API entry point.

=head2 policies_grant

Public API entry point.

=head2 policies_revoke

Public API entry point.

=head2 service_pins_list

Public API entry point.

=head2 service_pins_set

Public API entry point.

=head2 service_pins_forget

Public API entry point.

=head2 sessions_list

Public API entry point.

=head2 sessions_authorize

Public API entry point.

=head2 sessions_renew

Public API entry point.

=head2 sessions_revoke

Public API entry point.

=head1 DIAGNOSTICS

This module reports errors through normal Perl exceptions or structured return values.

=head1 CONFIGURATION AND ENVIRONMENT

No module-specific environment configuration is required.

=head1 DEPENDENCIES

See the distribution metadata for runtime dependencies.

=head1 INCOMPATIBILITIES

No known incompatibilities are documented.

=head1 BUGS AND LIMITATIONS

No known bugs are documented.

=head1 AUTHOR

Overnet Project.

=head1 LICENSE AND COPYRIGHT

See the project license.

=cut
