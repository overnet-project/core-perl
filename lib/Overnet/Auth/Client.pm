package Overnet::Auth::Client;

use strict;
use warnings;

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
  return $self->{endpoint}
    if defined $self->{endpoint} && !ref($self->{endpoint}) && length($self->{endpoint});
  return $ENV{OVERNET_AUTH_SOCK}
    if defined $ENV{OVERNET_AUTH_SOCK} && !ref($ENV{OVERNET_AUTH_SOCK}) && length($ENV{OVERNET_AUTH_SOCK});
  return $ENV{OVERNET_AUTH_ENDPOINT}
    if defined $ENV{OVERNET_AUTH_ENDPOINT} && !ref($ENV{OVERNET_AUTH_ENDPOINT}) && length($ENV{OVERNET_AUTH_ENDPOINT});
  return undef;
}

sub request {
  my ($self, %args) = @_;
  my $method = $args{method};
  my $params = $args{params} || {};

  die "method is required\n"
    unless defined $method && !ref($method) && length($method);
  die "params must be an object\n"
    unless ref($params) eq 'HASH';

  my $id = defined($args{id}) && !ref($args{id}) && length($args{id})
    ? $args{id}
    : 'auth-' . $self->{next_request_id}++;
  my $request = Overnet::Program::Protocol::build_request(
    id     => $id,
    method => $method,
    params => $params,
  );

  my $socket = $self->_connect_socket;
  my $frame = $self->{protocol}->encode_message($request);
  _write_all($socket, $frame);

  my $response = $self->_read_response($socket, $id);
  close $socket
    or die "close auth-agent socket failed: $!";

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
    die "socket_factory did not return a socket\n"
      unless $socket;
    return $socket;
  }

  my $endpoint = $self->endpoint;
  die "auth-agent endpoint is not configured\n"
    unless defined $endpoint && !ref($endpoint) && length($endpoint);

  my $socket = IO::Socket::UNIX->new(
    Type => SOCK_STREAM,
    Peer => $endpoint,
  );
  die "connect to auth-agent endpoint $endpoint failed: $!"
    unless $socket;

  return $socket;
}

sub _read_response {
  my ($self, $socket, $expected_id) = @_;
  my $reader = Overnet::Program::Protocol->new(
    max_frame_size => $self->{protocol}->max_frame_size,
  );

  while (1) {
    my $chunk = '';
    my $read = sysread($socket, $chunk, 4096);
    die "read from auth-agent endpoint failed: $!"
      unless defined $read;

    if ($read == 0) {
      $reader->finish;
      die "auth-agent closed the connection before sending a response\n";
    }

    my $messages = $reader->feed($chunk);
    next unless @{$messages};

    my $response = $messages->[0];
    my ($ok, $code, $message) = $self->{protocol}->validate_message($response);
    die "$code: $message\n"
      unless $ok;
    die "auth-agent response id does not match request id\n"
      unless (($response->{id} || '') eq $expected_id);

    return $response;
  }
}

sub _write_all {
  my ($socket, $bytes) = @_;
  my $offset = 0;

  while ($offset < length($bytes)) {
    my $written = syswrite($socket, $bytes, length($bytes) - $offset, $offset);
    die "write to auth-agent endpoint failed: $!"
      unless defined $written;
    $offset += $written;
  }

  return 1;
}

1;
