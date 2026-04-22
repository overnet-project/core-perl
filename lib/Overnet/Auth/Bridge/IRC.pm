package Overnet::Auth::Bridge::IRC;

use strict;
use warnings;

use JSON::PP qw(encode_json decode_json);
use MIME::Base64 qw(encode_base64 decode_base64);

our $VERSION = '0.001';

sub encode_artifact {
  my ($class, %args) = @_;
  my $artifact = $args{artifact};
  my $command = $args{command};
  my $encoding = $args{encoding};

  die "artifact must be an object\n"
    unless ref($artifact) eq 'HASH';
  die "command is required\n"
    unless defined $command && !ref($command) && length($command);
  die "encoding is required\n"
    unless defined $encoding && !ref($encoding) && length($encoding);
  die "artifact must be a nostr.event\n"
    unless (($artifact->{type} || '') eq 'nostr.event')
        && (($artifact->{format} || '') eq 'nostr.event')
        && ref($artifact->{value}) eq 'HASH';
  die "unsupported IRC artifact encoding: $encoding\n"
    unless $encoding eq 'base64-json';

  return {
    command  => $command,
    encoding => $encoding,
    payload  => encode_base64(encode_json($artifact->{value}), ''),
  };
}

sub decode_artifact {
  my ($class, %args) = @_;
  my $encoding = $args{encoding};
  my $payload = $args{payload};

  die "encoding is required\n"
    unless defined $encoding && !ref($encoding) && length($encoding);
  die "payload is required\n"
    unless defined $payload && !ref($payload) && length($payload);
  die "unsupported IRC artifact encoding: $encoding\n"
    unless $encoding eq 'base64-json';

  return {
    type   => 'nostr.event',
    format => 'nostr.event',
    value  => decode_json(decode_base64($payload)),
  };
}

1;
