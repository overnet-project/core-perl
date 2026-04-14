package Overnet::Program::Store;

use strict;
use warnings;
use JSON::PP ();

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;
  return bless {
    %args,
    streams   => {},
    documents => {},
  }, $class;
}

sub has_document {
  my ($self, %args) = @_;
  my $key = $args{key};

  die "key is required\n"
    unless defined $key && !ref($key) && length($key);

  return exists $self->{documents}{$key} ? 1 : 0;
}

sub put_document {
  my ($self, %args) = @_;
  my $key = $args{key};
  my $value = $args{value};

  die "key is required\n"
    unless defined $key && !ref($key) && length($key);
  die "value must be an object\n"
    unless ref($value) eq 'HASH';

  $self->{documents}{$key} = _clone_json_object($value);
  return {
    key => $key,
  };
}

sub get_document {
  my ($self, %args) = @_;
  my $key = $args{key};

  die "key is required\n"
    unless defined $key && !ref($key) && length($key);
  die "Unknown key: $key\n"
    unless exists $self->{documents}{$key};

  return {
    key   => $key,
    value => _clone_json_object($self->{documents}{$key}),
  };
}

sub delete_document {
  my ($self, %args) = @_;
  my $key = $args{key};

  die "key is required\n"
    unless defined $key && !ref($key) && length($key);
  die "Unknown key: $key\n"
    unless exists $self->{documents}{$key};

  delete $self->{documents}{$key};
  return {};
}

sub list_documents {
  my ($self, %args) = @_;
  my $prefix = $args{prefix};

  die "prefix must be a string\n"
    if defined $prefix && ref($prefix);

  my @keys = sort keys %{$self->{documents}};
  if (defined $prefix) {
    @keys = grep { index($_, $prefix) == 0 } @keys;
  }

  return {
    keys => \@keys,
  };
}

sub append_event {
  my ($self, %args) = @_;
  my $stream = $args{stream};
  my $event = $args{event};

  die "stream is required\n"
    unless defined $stream && !ref($stream) && length($stream);
  die "event must be an object\n"
    unless ref($event) eq 'HASH';

  my $stored_event = _clone_json_object($event);
  my $entries = $self->{streams}{$stream} ||= [];
  my $offset = scalar @{$entries};

  push @{$entries}, {
    offset => $offset,
    event  => $stored_event,
  };

  return {
    stream => $stream,
    offset => $offset,
  };
}

sub read_events {
  my ($self, %args) = @_;
  my $stream = $args{stream};
  my $after_offset = $args{after_offset};
  my $limit = $args{limit};

  die "stream is required\n"
    unless defined $stream && !ref($stream) && length($stream);
  die "after_offset must be an integer\n"
    if defined $after_offset && (ref($after_offset) || $after_offset !~ /\A-?\d+\z/);
  die "limit must be a non-negative integer\n"
    if defined $limit && (ref($limit) || $limit !~ /\A\d+\z/);

  my @entries = @{$self->{streams}{$stream} || []};
  @entries = grep { $_->{offset} > $after_offset } @entries
    if defined $after_offset;
  @entries = splice(@entries, 0, $limit)
    if defined $limit;

  return {
    stream  => $stream,
    entries => [
      map {
        {
          offset => $_->{offset},
          event  => _clone_json_object($_->{event}),
        }
      } @entries
    ],
  };
}

sub _clone_json_object {
  my ($value) = @_;
  return JSON::PP->new->utf8->canonical->decode(
    JSON::PP->new->utf8->canonical->encode($value)
  );
}

1;

=head1 NAME

Overnet::Program::Store - Overnet program storage scaffold

=head1 DESCRIPTION

Runtime-managed in-memory append-only event storage used by baseline program
runtime services, including exact-key document storage.

=cut
