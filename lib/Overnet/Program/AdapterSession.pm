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

  die "session_id is required\n"
    unless defined $session_id && !ref($session_id) && length($session_id);
  die "adapter_id is required\n"
    unless defined $adapter_id && !ref($adapter_id) && length($adapter_id);
  die "adapter is required\n"
    unless defined $adapter && ref($adapter);
  die "config must be an object\n"
    if ref($config) ne 'HASH';

  return bless {
    session_id => $session_id,
    adapter_id => $adapter_id,
    adapter    => $adapter,
    config     => $config,
  }, $class;
}

sub session_id { $_[0]->{session_id} }
sub adapter_id { $_[0]->{adapter_id} }
sub config { $_[0]->{config} }

sub map_input {
  my ($self, $input) = @_;
  die "adapter does not support map_input\n"
    unless $self->{adapter}->can('map_input');
  return $self->{adapter}->map_input(
    %{$input || {}},
    session_config => $self->{config},
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
      operation      => $operation,
      input          => $input,
      session_config => $self->{config},
    );
  }

  my $operation_method = 'derive_' . $operation;
  if ($self->{adapter}->can($operation_method)) {
    return $self->{adapter}->$operation_method(
      %{$input},
      session_config => $self->{config},
    );
  }

  die "adapter does not support derive\n";
}

1;

=head1 NAME

Overnet::Program::AdapterSession - Runtime-managed adapter session

=head1 DESCRIPTION

Represents one runtime-managed session against a registered adapter
implementation.

=cut
