package Overnet::Program::AdapterRegistry;

use strict;
use warnings;
use Overnet::Program::AdapterFactory;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;
  my $adapter_factory = $args{adapter_factory} || Overnet::Program::AdapterFactory->new;

  die "adapter_factory must be an Overnet::Program::AdapterFactory instance\n"
    unless ref($adapter_factory) && $adapter_factory->isa('Overnet::Program::AdapterFactory');

  my $self = bless {
    %args,
    adapters        => {},
    adapter_factory => $adapter_factory,
  }, $class;
  return $self;
}

sub register {
  my ($self, %args) = @_;

  my $adapter_id = $args{adapter_id};
  my $adapter = $args{adapter};

  die "adapter_id is required\n"
    unless defined $adapter_id && !ref($adapter_id) && length($adapter_id);
  die "adapter is required\n"
    unless defined $adapter && ref($adapter);

  $self->{adapters}{$adapter_id} = $adapter;
  return 1;
}

sub register_definition {
  my ($self, %args) = @_;

  my $adapter_id = $args{adapter_id};
  my $definition = $args{definition};

  die "adapter_id is required\n"
    unless defined $adapter_id && !ref($adapter_id) && length($adapter_id);
  die "definition is required\n"
    unless defined $definition && ref($definition) eq 'HASH';

  $self->{adapters}{$adapter_id} = $definition;
  return 1;
}

sub get {
  my ($self, $adapter_id) = @_;
  return undef unless defined $adapter_id;
  return $self->{adapters}{$adapter_id};
}

sub build {
  my ($self, $adapter_id) = @_;
  my $entry = $self->get($adapter_id);
  return undef unless defined $entry;

  if (ref($entry) eq 'HASH' && exists $entry->{kind}) {
    return $self->{adapter_factory}->build(definition => $entry);
  }

  return $entry;
}

sub has {
  my ($self, $adapter_id) = @_;
  return defined $self->get($adapter_id) ? 1 : 0;
}

sub adapter_ids {
  my ($self) = @_;
  return [ sort keys %{$self->{adapters}} ];
}

1;

=head1 NAME

Overnet::Program::AdapterRegistry - Runtime-managed adapter registry

=head1 DESCRIPTION

Registers adapter implementations by adapter id for use by the Overnet Program
Runtime, including direct objects and runtime-instantiated adapter definitions.

=cut
