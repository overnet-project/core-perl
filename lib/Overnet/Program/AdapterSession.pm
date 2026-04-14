package Overnet::Program::AdapterSession;

use strict;
use warnings;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;

  my $session_id = $args{session_id};
  my $adapter_id = $args{adapter_id};
  my $adapter = $args{adapter};
  my $config = $args{config} || {};
  my $program_session_id = $args{program_session_id};
  my $program_id = $args{program_id};

  die "session_id is required\n"
    unless defined $session_id && !ref($session_id) && length($session_id);
  die "adapter_id is required\n"
    unless defined $adapter_id && !ref($adapter_id) && length($adapter_id);
  die "adapter is required\n"
    unless defined $adapter && ref($adapter);
  die "config must be an object\n"
    if ref($config) ne 'HASH';
  die "program_session_id must be a non-empty string\n"
    if defined $program_session_id && (ref($program_session_id) || !length($program_session_id));
  die "program_id must be a non-empty string\n"
    if defined $program_id && (ref($program_id) || !length($program_id));

  return bless {
    session_id         => $session_id,
    adapter_id         => $adapter_id,
    adapter            => $adapter,
    config             => $config,
    program_session_id => $program_session_id,
    program_id         => $program_id,
  }, $class;
}

sub session_id { $_[0]->{session_id} }
sub adapter_id { $_[0]->{adapter_id} }
sub config { $_[0]->{config} }
sub program_session_id { $_[0]->{program_session_id} }
sub program_id { $_[0]->{program_id} }

sub open {
  my ($self, %args) = @_;
  my $secret_values = $args{secret_values} || {};

  die "secret_values must be an object\n"
    if ref($secret_values) ne 'HASH';
  return 1
    unless $self->{adapter}->can('open_session');

  return $self->{adapter}->open_session(
    adapter_session_id => $self->{session_id},
    adapter_id         => $self->{adapter_id},
    session_config     => $self->{config},
    secret_values      => $secret_values,
    (defined $self->{program_session_id} ? (program_session_id => $self->{program_session_id}) : ()),
    (defined $self->{program_id} ? (program_id => $self->{program_id}) : ()),
  );
}

sub map_input {
  my ($self, $input) = @_;
  die "adapter does not support map_input\n"
    unless $self->{adapter}->can('map_input');
  return $self->{adapter}->map_input(
    %{$input || {}},
    session_config    => $self->{config},
    adapter_session_id => $self->{session_id},
    (defined $self->{program_session_id} ? (program_session_id => $self->{program_session_id}) : ()),
    (defined $self->{program_id} ? (program_id => $self->{program_id}) : ()),
  );
}

sub derive {
  my ($self, %args) = @_;
  my $operation = $args{operation};
  my $input = $args{input} || {};

  die "operation is required\n"
    unless defined $operation && !ref($operation) && length($operation);
  die "input must be an object\n"
    if ref($input) ne 'HASH';
  if ($self->{adapter}->can('derive')) {
    return $self->{adapter}->derive(
      operation         => $operation,
      input             => $input,
      session_config    => $self->{config},
      adapter_session_id => $self->{session_id},
      (defined $self->{program_session_id} ? (program_session_id => $self->{program_session_id}) : ()),
      (defined $self->{program_id} ? (program_id => $self->{program_id}) : ()),
    );
  }

  my $operation_method = 'derive_' . $operation;
  if ($self->{adapter}->can($operation_method)) {
    return $self->{adapter}->$operation_method(
      %{$input},
      session_config    => $self->{config},
      adapter_session_id => $self->{session_id},
      (defined $self->{program_session_id} ? (program_session_id => $self->{program_session_id}) : ()),
      (defined $self->{program_id} ? (program_id => $self->{program_id}) : ()),
    );
  }

  die "adapter does not support derive\n";
}

sub close {
  my ($self) = @_;
  return 1
    unless $self->{adapter}->can('close_session');

  return $self->{adapter}->close_session(
    adapter_session_id => $self->{session_id},
    adapter_id         => $self->{adapter_id},
    session_config     => $self->{config},
    (defined $self->{program_session_id} ? (program_session_id => $self->{program_session_id}) : ()),
    (defined $self->{program_id} ? (program_id => $self->{program_id}) : ()),
  );
}

1;

=head1 NAME

Overnet::Program::AdapterSession - Runtime-managed adapter session

=head1 DESCRIPTION

Represents one runtime-managed session against a registered adapter
implementation.

=cut
