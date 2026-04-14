package Overnet::Program::Timer;

use strict;
use warnings;
use JSON::PP ();

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;

  my $session_id = $args{session_id};
  my $timer_id = $args{timer_id};
  my $due_at_ms = $args{due_at_ms};
  my $repeat_ms = $args{repeat_ms};
  my $payload = $args{payload};

  die "session_id is required\n"
    unless defined $session_id && !ref($session_id) && length($session_id);
  die "timer_id is required\n"
    unless defined $timer_id && !ref($timer_id) && length($timer_id);
  die "due_at_ms must be an integer\n"
    unless defined $due_at_ms && !ref($due_at_ms) && $due_at_ms =~ /\A-?\d+\z/;
  die "repeat_ms must be a positive integer\n"
    if defined $repeat_ms && (ref($repeat_ms) || $repeat_ms !~ /\A[1-9]\d*\z/);
  die "payload must be an object\n"
    if defined $payload && ref($payload) ne 'HASH';

  return bless {
    session_id => $session_id,
    timer_id   => $timer_id,
    due_at_ms  => 0 + $due_at_ms,
    (defined $repeat_ms ? (repeat_ms => 0 + $repeat_ms) : ()),
    (defined $payload ? (payload => _clone_json($payload)) : ()),
  }, $class;
}

sub session_id { $_[0]->{session_id} }
sub timer_id { $_[0]->{timer_id} }
sub due_at_ms { $_[0]->{due_at_ms} }
sub repeat_ms { $_[0]->{repeat_ms} }
sub payload { exists $_[0]->{payload} ? _clone_json($_[0]->{payload}) : undef }

sub is_due {
  my ($self, $now_ms) = @_;

  die "now_ms must be an integer\n"
    unless defined $now_ms && !ref($now_ms) && $now_ms =~ /\A-?\d+\z/;

  return $self->{due_at_ms} <= $now_ms ? 1 : 0;
}

sub is_repeating {
  my ($self) = @_;
  return defined $self->{repeat_ms} ? 1 : 0;
}

sub advance_after_fire {
  my ($self) = @_;

  die "Timer is not repeating\n"
    unless $self->is_repeating;

  $self->{due_at_ms} += $self->{repeat_ms};
  return $self->{due_at_ms};
}

sub advance_after_fire_until_after {
  my ($self, $now_ms) = @_;

  die "Timer is not repeating\n"
    unless $self->is_repeating;
  die "now_ms must be an integer\n"
    unless defined $now_ms && !ref($now_ms) && $now_ms =~ /\A-?\d+\z/;

  $self->advance_after_fire;
  while ($self->{due_at_ms} <= $now_ms) {
    $self->{due_at_ms} += $self->{repeat_ms};
  }

  return $self->{due_at_ms};
}

sub build_notification_params {
  my ($self, %args) = @_;
  my $fired_at = $args{fired_at};

  die "fired_at must be an integer\n"
    unless defined $fired_at && !ref($fired_at) && $fired_at =~ /\A-?\d+\z/;

  my %params = (
    timer_id => $self->{timer_id},
    fired_at => 0 + $fired_at,
  );
  $params{payload} = _clone_json($self->{payload})
    if exists $self->{payload};

  return \%params;
}

sub _clone_json {
  my ($value) = @_;
  return JSON::PP->new->utf8->canonical->decode(
    JSON::PP->new->utf8->canonical->encode($value)
  );
}

1;

=head1 NAME

Overnet::Program::Timer - Overnet program timer scaffold

=head1 DESCRIPTION

Runtime-managed timer object for scheduled notifications.

=cut
