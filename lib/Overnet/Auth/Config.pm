package Overnet::Auth::Config;

use strict;
use warnings;

use JSON::PP ();

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;
  my $config = exists $args{config} ? $args{config} : {};

  die "auth config must be an object\n"
    unless ref($config) eq 'HASH';
  die "auth config daemon section must be an object\n"
    if exists($config->{daemon}) && ref($config->{daemon}) ne 'HASH';
  my $daemon = ref($config->{daemon}) eq 'HASH' ? $config->{daemon} : {};
  die "auth config daemon.state_file must be a string\n"
    if exists($daemon->{state_file})
       && (ref($daemon->{state_file}) || !length($daemon->{state_file}));
  die "auth config identities must be an array\n"
    if exists($config->{identities}) && ref($config->{identities}) ne 'ARRAY';
  die "auth config policies must be an array\n"
    if exists($config->{policies}) && ref($config->{policies}) ne 'ARRAY';
  die "auth config service_pins must be an object\n"
    if exists($config->{service_pins}) && ref($config->{service_pins}) ne 'HASH';
  die "auth config sessions must be an array\n"
    if exists($config->{sessions}) && ref($config->{sessions}) ne 'ARRAY';

  return bless {
    config => _clone($config),
  }, $class;
}

sub load_file {
  my ($class, %args) = @_;
  my $path = $args{path};

  die "path is required\n"
    unless defined $path && !ref($path) && length($path);

  open my $fh, '<', $path
    or die "open $path failed: $!";
  my $json = do { local $/; <$fh> };
  close $fh
    or die "close $path failed: $!";

  my $decoded = eval { JSON::PP->new->utf8->decode($json) };
  die "auth config file $path is not valid JSON: $@"
    unless defined $decoded;
  die "auth config must decode to an object\n"
    unless ref($decoded) eq 'HASH';

  return $class->new(config => $decoded);
}

sub endpoint {
  my ($self) = @_;
  my $daemon = $self->{config}{daemon} || {};
  return $daemon->{endpoint};
}

sub socket_mode {
  my ($self) = @_;
  my $daemon = $self->{config}{daemon} || {};
  return $daemon->{socket_mode};
}

sub state_file {
  my ($self) = @_;
  my $daemon = $self->{config}{daemon} || {};
  return $daemon->{state_file};
}

sub agent_args {
  my ($self, %args) = @_;
  my $state = exists($args{state}) ? $args{state} : $self->mutable_state;

  die "auth mutable state must be an object\n"
    unless ref($state) eq 'HASH';
  die "auth mutable state policies must be an array\n"
    if exists($state->{policies}) && ref($state->{policies}) ne 'ARRAY';
  die "auth mutable state service_pins must be an object\n"
    if exists($state->{service_pins}) && ref($state->{service_pins}) ne 'HASH';
  die "auth mutable state sessions must be an array\n"
    if exists($state->{sessions}) && ref($state->{sessions}) ne 'ARRAY';

  return {
    identities   => $self->identities,
    policies     => _clone($state->{policies} || []),
    service_pins => _clone($state->{service_pins} || {}),
    sessions     => _clone($state->{sessions} || []),
  };
}

sub identities {
  my ($self) = @_;
  my $config = $self->{config};
  return _clone($config->{identities} || []);
}

sub mutable_state {
  my ($self) = @_;
  my $config = $self->{config};

  return {
    policies     => _clone($config->{policies} || []),
    service_pins => _clone($config->{service_pins} || {}),
    sessions     => _clone($config->{sessions} || []),
  };
}

sub _clone {
  my ($value) = @_;
  return undef unless defined $value;
  return $value unless ref($value);

  if (ref($value) eq 'HASH') {
    return {
      map { $_ => _clone($value->{$_}) }
      keys %{$value}
    };
  }

  if (ref($value) eq 'ARRAY') {
    return [ map { _clone($_) } @{$value} ];
  }

  return "$value";
}

1;
