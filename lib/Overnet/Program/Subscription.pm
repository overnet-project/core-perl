package Overnet::Program::Subscription;

use strict;
use warnings;
use Net::Nostr::Event;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;

  my $session_id = $args{session_id};
  my $subscription_id = $args{subscription_id};
  my $query = $args{query} || {};

  die "session_id is required\n"
    unless defined $session_id && !ref($session_id) && length($session_id);
  die "subscription_id is required\n"
    unless defined $subscription_id && !ref($subscription_id) && length($subscription_id);
  die "query must be an object\n"
    unless ref($query) eq 'HASH';

  return bless {
    session_id      => $session_id,
    subscription_id => $subscription_id,
    query           => { %{$query} },
  }, $class;
}

sub session_id { $_[0]->{session_id} }
sub subscription_id { $_[0]->{subscription_id} }
sub query { { %{$_[0]->{query}} } }

sub matches {
  my ($self, %args) = @_;
  my $item_type = $args{item_type};
  my $event = $args{event};
  my $query = $self->{query};

  return 0 unless defined $item_type && !ref($item_type);
  return 0 if $item_type ne 'event' && $item_type ne 'state' && keys %{$query};

  return 1 unless keys %{$query};
  return 0 unless defined $event && ref($event) && $event->isa('Net::Nostr::Event');

  if (exists $query->{kind} && $event->kind != $query->{kind}) {
    return 0;
  }

  my %tag_values = _first_tag_values($event->tags);
  for my $field (qw(overnet_et overnet_ot overnet_oid)) {
    next unless exists $query->{$field};
    return 0 unless defined $tag_values{$field} && $tag_values{$field} eq $query->{$field};
  }

  return 1;
}

sub _first_tag_values {
  my ($tags) = @_;
  my %values;

  for my $tag (@{$tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
    next if exists $values{$tag->[0]};
    $values{$tag->[0]} = $tag->[1];
  }

  return %values;
}

1;

=head1 NAME

Overnet::Program::Subscription - Overnet program subscription scaffold

=head1 DESCRIPTION

Runtime-managed session-scoped subscription object with baseline Overnet query
matching.

=cut
