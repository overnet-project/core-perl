package Overnet::Auth::Server;

use strict;
use warnings;

use Overnet::Program::Protocol;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;
  die "agent is required\n"
    unless ref($args{agent}) && $args{agent}->can('dispatch');

  return bless {
    agent    => $args{agent},
    protocol => $args{protocol} || Overnet::Program::Protocol->new,
  }, $class;
}

sub serve_socket {
  my ($self, $socket) = @_;
  die "socket is required\n"
    unless $socket;

  my $reader = Overnet::Program::Protocol->new(
    max_frame_size => $self->{protocol}->max_frame_size,
  );

  while (1) {
    my $chunk = '';
    my $read = sysread($socket, $chunk, 4096);
    die "read from auth-agent socket failed: $!"
      unless defined $read;
    last if $read == 0;

    my $messages = $reader->feed($chunk);
    for my $message (@{$messages}) {
      my $response = $self->{agent}->dispatch($message);
      my $frame = $self->{protocol}->encode_message($response);
      _write_all($socket, $frame);
      return 1;
    }
  }

  $reader->finish;
  return 1;
}

sub _write_all {
  my ($socket, $bytes) = @_;
  my $offset = 0;

  while ($offset < length($bytes)) {
    my $written = syswrite($socket, $bytes, length($bytes) - $offset, $offset);
    die "write to auth-agent socket failed: $!"
      unless defined $written;
    $offset += $written;
  }

  return 1;
}

1;
