package Overnet::Program::AdapterFactory;

use strict;
use warnings;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;
  return bless \%args, $class;
}

sub build {
  my ($self, %args) = @_;

  my $definition = $args{definition};
  die "definition is required\n"
    unless defined $definition && ref($definition) eq 'HASH';

  my $kind = $definition->{kind} || 'object';

  if ($kind eq 'object') {
    my $adapter = $definition->{adapter};
    die "definition.adapter is required for object adapters\n"
      unless defined $adapter && ref($adapter);
    return $adapter;
  }

  if ($kind eq 'class') {
    my $class = $definition->{class};
    my $constructor_args = $definition->{constructor_args} || {};
    my $lib_dirs = $definition->{lib_dirs} || [];

    die "definition.class is required for class adapters\n"
      unless defined $class && !ref($class) && length($class);
    die "definition.constructor_args must be an object\n"
      if ref($constructor_args) ne 'HASH';
    die "definition.lib_dirs must be an array\n"
      if ref($lib_dirs) ne 'ARRAY';

    unless ($class->can('new')) {
      local @INC = (@{$lib_dirs}, @INC);
      eval "require $class; 1"
        or die "Unable to load adapter class $class: $@";
    }

    my $adapter = $class->new(%{$constructor_args});
    die "Adapter class $class did not return an object from new()\n"
      unless defined $adapter && ref($adapter);

    return $adapter;
  }

  die "Unsupported adapter definition kind: $kind\n";
}

1;

=head1 NAME

Overnet::Program::AdapterFactory - Runtime adapter instantiation

=head1 DESCRIPTION

Builds runtime-managed adapter instances from adapter definitions.

=cut
