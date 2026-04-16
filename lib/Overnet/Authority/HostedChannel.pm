package Overnet::Authority::HostedChannel;

use strict;
use warnings;
use Net::Nostr::Group ();

sub irc_casefold {
  my ($value) = @_;
  return undef unless defined $value && !ref($value);

  my $folded = $value;
  $folded =~ tr/A-Z[]\\^/a-z{}|~/;
  return $folded;
}

sub irc_user_mask {
  my (%args) = @_;
  for my $field (qw(nick user host)) {
    return undef
      unless defined $args{$field} && !ref($args{$field}) && length($args{$field});
  }

  return join('',
    $args{nick},
    '!',
    $args{user},
    '@',
    $args{host},
  );
}

sub irc_mask_matches {
  my (%args) = @_;
  my $mask = $args{mask};
  my $value = $args{value};
  return 0 unless defined $mask && !ref($mask) && length($mask);
  return 0 unless defined $value && !ref($value) && length($value);

  my $folded_mask = irc_casefold($mask);
  my $folded_value = irc_casefold($value);
  return 0 unless defined $folded_mask && defined $folded_value;

  my $pattern = quotemeta($folded_mask);
  $pattern =~ s/\\\*/.*/g;
  $pattern =~ s/\\\?/./g;

  return $folded_value =~ /\A$pattern\z/ ? 1 : 0;
}

sub authoritative_group_id {
  my (%args) = @_;
  my $network = $args{network};
  my $channel = $args{channel};

  return undef unless defined $network && !ref($network) && length($network);
  return undef unless _is_channel_name($channel);

  my $folded_channel = irc_casefold($channel);
  return undef unless defined $folded_channel && length($folded_channel);

  my $group_id = join(
    '-',
    'irc',
    unpack('H*', $network),
    unpack('H*', $folded_channel),
  );
  return Net::Nostr::Group->validate_group_id($group_id)
    ? $group_id
    : undef;
}

sub channel_name_from_group_id {
  my (%args) = @_;
  my $network = $args{network};
  my $group_id = $args{group_id};

  return undef unless defined $network && !ref($network) && length($network);
  return undef unless defined $group_id && !ref($group_id) && length($group_id);
  return undef unless $group_id =~ /\Airc-([0-9a-f]+)-([0-9a-f]+)\z/;

  my ($network_hex, $channel_hex) = ($1, $2);
  my $decoded_network = pack('H*', $network_hex);
  return undef unless $decoded_network eq $network;

  my $channel = pack('H*', $channel_hex);
  return undef unless _is_channel_name($channel);

  return $channel;
}

sub resolve_nip29_group_binding {
  my (%args) = @_;
  my $session_config = ref($args{session_config}) eq 'HASH'
    ? $args{session_config}
    : {};
  my $network = $args{network};
  my $target = $args{target};

  return (undef, undef, 'authoritative NIP-29 mapping requires session_config.group_host')
    unless defined $session_config->{group_host} && !ref($session_config->{group_host}) && length($session_config->{group_host});
  return (undef, undef, 'authoritative NIP-29 mapping requires a channel target')
    unless _is_channel_name($target);

  my $binding;
  if (ref($session_config->{channel_groups}) eq 'HASH') {
    if (exists $session_config->{channel_groups}{$target}) {
      $binding = $session_config->{channel_groups}{$target};
    } else {
      my $target_key = irc_casefold($target);
      for my $configured_channel (keys %{$session_config->{channel_groups}}) {
        next unless defined irc_casefold($configured_channel);
        next unless irc_casefold($configured_channel) eq $target_key;
        $binding = $session_config->{channel_groups}{$configured_channel};
        last;
      }
    }
  }

  my $group_id = ref($binding) eq 'HASH'
    ? $binding->{group_id}
    : $binding;
  $group_id = authoritative_group_id(
    network => $network,
    channel => $target,
  ) unless defined $group_id && length($group_id);

  return (undef, undef, "authoritative NIP-29 binding for $target requires group_id")
    unless defined $group_id && length($group_id);
  return (undef, undef, "authoritative NIP-29 binding for $target uses an invalid group_id")
    unless Net::Nostr::Group->validate_group_id($group_id);

  return ($session_config->{group_host}, $group_id, undef);
}

sub channel_name_from_group_event {
  my (%args) = @_;
  my $network = $args{network};
  my $event = $args{event};

  return undef unless defined $network && !ref($network) && length($network);
  my $tags = _event_tags($event);
  return undef unless ref($tags) eq 'ARRAY';

  my %first = _first_tag_values($tags);
  my $channel = channel_name_from_group_id(
    network  => $network,
    group_id => $first{d} || $first{h},
  );
  return undef unless defined $channel;

  if (defined $first{name} && _is_channel_name($first{name})) {
    my $named = irc_casefold($first{name});
    my $folded = irc_casefold($channel);
    return $first{name}
      if defined $named && defined $folded && $named eq $folded;
  }

  return $channel;
}

sub _event_tags {
  my ($event) = @_;
  return undef unless defined $event;

  return $event->{tags}
    if ref($event) eq 'HASH' && ref($event->{tags}) eq 'ARRAY';
  return $event->tags
    if ref($event) && $event->can('tags');
  return undef;
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

sub _is_channel_name {
  my ($value) = @_;
  return defined $value
    && !ref($value)
    && $value =~ /\A[#&][^\x00\x07\r\n ,:]+\z/
      ? 1
      : 0;
}

1;
