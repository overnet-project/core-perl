package Overnet::Auth::Daemon;

use strict;
use warnings;

use File::Basename qw(dirname);
use File::Path qw(make_path);
use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);

use Overnet::Auth::Agent;
use Overnet::Auth::Config;
use Overnet::Auth::Server;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;

  my $config = $args{config};
  $config = Overnet::Auth::Config->load_file(path => $args{config_file})
    if !defined($config) && defined($args{config_file});
  $config = Overnet::Auth::Config->new(config => {})
    unless defined $config;

  die "config must be an Overnet::Auth::Config\n"
    unless ref($config) && $config->isa('Overnet::Auth::Config');

  my $endpoint = defined($args{endpoint}) && !ref($args{endpoint}) && length($args{endpoint})
    ? $args{endpoint}
    : $config->endpoint;
  die "auth-agent endpoint is required\n"
    unless defined $endpoint && !ref($endpoint) && length($endpoint);

  my $socket_mode = exists($args{socket_mode})
    ? $args{socket_mode}
    : $config->socket_mode;
  $socket_mode = 0600
    unless defined $socket_mode;

  my $agent = $args{agent} || Overnet::Auth::Agent->new(%{$config->agent_args});
  die "agent must support dispatch\n"
    unless ref($agent) && $agent->can('dispatch');

  my $server = $args{server} || Overnet::Auth::Server->new(agent => $agent);

  return bless {
    config          => $config,
    endpoint        => $endpoint,
    socket_mode     => $socket_mode,
    max_connections => $args{max_connections},
    server          => $server,
    listen_factory  => $args{listen_factory},
    listen_socket   => undef,
  }, $class;
}

sub endpoint {
  my ($self) = @_;
  return $self->{endpoint};
}

sub run {
  my ($self) = @_;
  my $socket = $self->_listen_socket;
  my $served = 0;

  while (1) {
    last if defined($self->{max_connections}) && $served >= $self->{max_connections};

    my $client = $socket->accept;
    die "accept on auth-agent endpoint failed: $!"
      unless $client;

    eval {
      $self->{server}->serve_socket($client);
      1;
    } or do {
      my $error = $@ || 'unknown auth-agent socket failure';
      close $client;
      $self->_teardown_socket;
      die $error;
    };

    close $client
      or die "close auth-agent client socket failed: $!";
    $served++;
  }

  $self->_teardown_socket;
  return 1;
}

sub _listen_socket {
  my ($self) = @_;
  return $self->{listen_socket}
    if $self->{listen_socket};

  my $endpoint = $self->{endpoint};
  my $parent = dirname($endpoint);
  make_path($parent)
    unless -d $parent;

  if (-e $endpoint) {
    die "auth-agent endpoint path already exists and is not a socket\n"
      unless -S $endpoint;
    unlink $endpoint
      or die "unlink stale auth-agent socket $endpoint failed: $!";
  }

  my $socket;
  if (ref($self->{listen_factory}) eq 'CODE') {
    $socket = $self->{listen_factory}->($endpoint);
  }
  else {
    $socket = IO::Socket::UNIX->new(
      Type   => SOCK_STREAM,
      Local  => $endpoint,
      Listen => 5,
    );
  }
  die "listen on auth-agent endpoint $endpoint failed: $!"
    unless $socket;

  if (-S $endpoint) {
    chmod $self->{socket_mode}, $endpoint
      or die "chmod auth-agent endpoint $endpoint failed: $!";
  }

  $self->{listen_socket} = $socket;
  return $socket;
}

sub _teardown_socket {
  my ($self) = @_;
  my $socket = delete $self->{listen_socket};
  if ($socket) {
    if (ref($socket) && $socket->can('close')) {
      $socket->close
        or die "close auth-agent listener socket failed\n";
    }
    else {
      close $socket
        or die "close auth-agent listener socket failed: $!";
    }
  }

  my $endpoint = $self->{endpoint};
  unlink $endpoint
    or die "unlink auth-agent endpoint $endpoint failed: $!"
    if defined($endpoint) && -S $endpoint;

  return 1;
}

1;
