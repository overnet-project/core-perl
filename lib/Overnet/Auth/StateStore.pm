package Overnet::Auth::StateStore;

use strict;
use warnings;

use File::Basename qw(dirname);
use File::Path qw(make_path);
use JSON::PP ();

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;
  my $path = $args{path};

  die "path is required\n"
    unless defined $path && !ref($path) && length($path);

  return bless {
    path => $path,
  }, $class;
}

sub path {
  my ($self) = @_;
  return $self->{path};
}

sub load_state {
  my ($self) = @_;
  my $path = $self->{path};

  return undef unless -e $path;

  open my $fh, '<', $path
    or die "open $path failed: $!";
  my $json = do { local $/; <$fh> };
  close $fh
    or die "close $path failed: $!";

  my $decoded = eval { JSON::PP->new->utf8->decode($json) };
  die "auth state file $path is not valid JSON: $@"
    unless defined $decoded;

  return _normalize_state($decoded);
}

sub save_state {
  my ($self, %args) = @_;
  my $state = _normalize_state($args{state});
  my $path = $self->{path};
  my $parent = dirname($path);
  my $tmp = $path . '.tmp.' . $$;

  make_path($parent)
    unless -d $parent;

  my $json = JSON::PP->new->utf8->canonical->pretty->encode($state);

  open my $fh, '>', $tmp
    or die "open $tmp failed: $!";
  print {$fh} $json
    or die "write $tmp failed: $!";
  close $fh
    or die "close $tmp failed: $!";

  rename $tmp, $path
    or die "rename $tmp to $path failed: $!";

  return 1;
}

sub _normalize_state {
  my ($state) = @_;

  die "auth state must decode to an object\n"
    unless ref($state) eq 'HASH';
  die "auth state policies must be an array\n"
    if exists($state->{policies}) && ref($state->{policies}) ne 'ARRAY';
  die "auth state service_pins must be an object\n"
    if exists($state->{service_pins}) && ref($state->{service_pins}) ne 'HASH';
  die "auth state sessions must be an array\n"
    if exists($state->{sessions}) && ref($state->{sessions}) ne 'ARRAY';

  return {
    policies     => _clone($state->{policies} || []),
    service_pins => _clone($state->{service_pins} || {}),
    sessions     => _clone($state->{sessions} || []),
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
