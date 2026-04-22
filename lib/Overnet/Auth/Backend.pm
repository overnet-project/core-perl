package Overnet::Auth::Backend;

use strict;
use warnings;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;
  return bless { %args }, $class;
}

sub backend_type {
  die "backend_type must be implemented by " . ref($_[0]) . "\n";
}

sub load_signing_key {
  die "load_signing_key must be implemented by " . ref($_[0]) . "\n";
}

1;
