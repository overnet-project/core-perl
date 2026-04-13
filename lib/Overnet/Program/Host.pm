package Overnet::Program::Host;

use strict;
use warnings;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;
  return bless \%args, $class;
}

1;

=head1 NAME

Overnet::Program::Host - Runtime host scaffold for Overnet programs

=head1 DESCRIPTION

Scaffold module for supervising Overnet program instances.

=cut
