package Overnet::Core::PrivateMessaging;

use strict;
use warnings;

use JSON::PP ();
use Net::Nostr::GiftWrap;

my %VALID_PRIVATE_TYPES = map { $_ => 1 } qw(chat.dm_message chat.dm_notice);
my $JSON = JSON::PP->new->utf8->canonical;

sub validate_transport {
  my ($input) = @_;
  my @errors;

  if (ref($input) ne 'HASH') {
    return _result(errors => ['Private messaging input must be a hash object']);
  }

  if ($input->{relay_carried_private_intent} && ref($input->{event}) eq 'HASH') {
    return _validate_relay_carried_private_intent_event($input);
  }

  my $transport = $input->{transport};
  if (ref($transport) ne 'HASH') {
    push @errors, 'Private messaging transport must be a hash object';
    return _result(errors => \@errors);
  }

  my $visible_kind = $transport->{kind};
  if (!defined $visible_kind || ref($visible_kind) || $visible_kind !~ /\A\d+\z/) {
    push @errors, 'Private messaging transport kind must be an integer';
  } elsif ($visible_kind != 1059) {
    push @errors, 'Relay-carried private direct messages must use kind 1059 gift wrap events';
  }

  my $rumor_data = $transport->{decrypted_rumor};
  my $normalized_rumor;
  my ($private_type, $object_type, $object_id, $sender_identity);

  if (ref($rumor_data) eq 'HASH') {
    my ($payload, $payload_error) = _normalize_payload($rumor_data->{content});
    push @errors, $payload_error if defined $payload_error;

    my $rumor_event;
    if (!@errors) {
      my %rumor_args = (
        pubkey     => $rumor_data->{pubkey},
        created_at => $rumor_data->{created_at},
        kind       => $rumor_data->{kind},
        tags       => $rumor_data->{tags},
        content    => $JSON->encode($payload),
      );

      eval { $rumor_event = Net::Nostr::GiftWrap->create_rumor(%rumor_args) };
      if ($@) {
        (my $err = $@) =~ s/ at .+ line \d+.*//s;
        push @errors, "Invalid NIP-17 rumor: $err";
      }
    }

    if ($rumor_event) {
      push @errors, 'Relay-carried private direct messages must use kind 14 rumors'
        unless $rumor_event->kind == 14;

      my @recipient_tags = grep { ref($_) eq 'ARRAY' && @{$_} >= 2 && $_->[0] eq 'p' } @{$rumor_event->tags};
      push @errors, 'Relay-carried one-to-one private direct messages require exactly one rumor p tag'
        unless @recipient_tags == 1;
    }

    if (defined $payload) {
      push @errors, _validate_payload($payload);
      $private_type = $payload->{private_type};
      $object_type = $payload->{object_type};
      $object_id = $payload->{object_id};
      $sender_identity = ref($payload->{provenance}) eq 'HASH'
        ? $payload->{provenance}{external_identity}
        : undef;

      if (ref($input->{source}) eq 'HASH' && ($input->{source}{protocol} // '') eq 'irc') {
        push @errors, _validate_irc_decrypted_binding(
          source  => $input->{source},
          payload => $payload,
        );
      }
    }

    if ($rumor_event && !@errors) {
      $normalized_rumor = {
        id         => $rumor_event->id,
        pubkey     => $rumor_event->pubkey,
        created_at => $rumor_event->created_at,
        kind       => $rumor_event->kind,
        tags       => $rumor_event->tags,
        content    => $payload,
      };
    }
  } else {
    if (!defined $input->{private_type} || !defined $input->{object_type} || !defined $input->{object_id}) {
      push @errors, 'Opaque private-message transport requires private_type, object_type, and object_id metadata';
      return _result(errors => \@errors);
    }

    $private_type = $input->{private_type};
    $object_type = $input->{object_type};
    $object_id = $input->{object_id};
    $sender_identity = $input->{sender_identity};

    push @errors, _validate_opaque_metadata(
      private_type    => $private_type,
      object_type     => $object_type,
      object_id       => $object_id,
      sender_identity => $sender_identity,
    );

    my @recipient_tags = grep {
      ref($_) eq 'ARRAY' && @{$_} >= 2 && $_->[0] eq 'p'
    } @{$transport->{tags} || []};
    push @errors, 'Opaque private direct messages require exactly one visible transport p tag'
      unless @recipient_tags == 1;

    if (ref($input->{source}) eq 'HASH' && ($input->{source}{protocol} // '') eq 'irc') {
      push @errors, _validate_irc_opaque_binding(
        source          => $input->{source},
        private_type    => $private_type,
        object_type     => $object_type,
        object_id       => $object_id,
        sender_identity => $sender_identity,
      );
    }
  }

  return _result(
    errors          => \@errors,
    visible_kind    => $visible_kind,
    decrypted_rumor => $normalized_rumor,
    private_type    => $private_type,
    object_type     => $object_type,
    object_id       => $object_id,
    sender_identity => $sender_identity,
  );
}

sub _validate_relay_carried_private_intent_event {
  my ($input) = @_;
  my @errors;
  my $event = $input->{event};
  my $kind = $event->{kind};

  if (defined $kind && !ref($kind) && $kind =~ /\A\d+\z/ && $kind == 7800) {
    my %tag_values;
    for my $tag (@{$event->{tags} || []}) {
      next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
      $tag_values{$tag->[0]} = $tag->[1];
    }

    if (($tag_values{overnet_ot} // '') eq 'chat.dm'
        && (($tag_values{overnet_et} // '') eq 'chat.dm_message'
          || ($tag_values{overnet_et} // '') eq 'chat.dm_notice')) {
      push @errors, 'Relay-carried private direct messages must use NIP-17 rather than public Overnet core events';
    }
  }

  push @errors, 'Relay-carried private direct messages must use NIP-17 rather than public Overnet core events'
    unless @errors;

  return _result(errors => \@errors);
}

sub _normalize_payload {
  my ($content) = @_;

  if (ref($content) eq 'HASH') {
    return ($content, undef);
  }

  if (!defined $content || ref($content)) {
    return (undef, 'Decrypted rumor content must be a JSON object or JSON object string');
  }

  my $decoded;
  eval { $decoded = $JSON->decode($content) };
  if ($@ || ref($decoded) ne 'HASH') {
    return (undef, 'Decrypted rumor content must decode to a JSON object');
  }

  return ($decoded, undef);
}

sub _validate_payload {
  my ($payload) = @_;
  my @errors;

  if (!_is_non_empty_string($payload->{overnet_v})) {
    push @errors, 'Private-message payload overnet_v must be a non-empty string';
  }

  if (!defined $payload->{private_type} || !$VALID_PRIVATE_TYPES{$payload->{private_type}}) {
    push @errors, 'Private-message payload private_type must be chat.dm_message or chat.dm_notice';
  }

  if (($payload->{object_type} // '') ne 'chat.dm') {
    push @errors, 'Private-message payload object_type must be chat.dm';
  }

  if (!_is_non_empty_string($payload->{object_id})) {
    push @errors, 'Private-message payload object_id must be a non-empty string';
  }

  push @errors, _validate_provenance($payload->{provenance});

  if (ref($payload->{body}) ne 'HASH') {
    push @errors, 'Private-message payload body must be an object';
  } elsif (!exists $payload->{body}{text} || !defined $payload->{body}{text} || ref($payload->{body}{text})) {
    push @errors, 'Private-message payload body.text must be a string';
  }

  return @errors;
}

sub _validate_irc_decrypted_binding {
  my (%args) = @_;
  my $source = $args{source};
  my $payload = $args{payload};
  my @errors;

  my $network = $source->{network};
  push @errors, 'IRC private-message binding requires a non-empty source.network string'
    unless _is_non_empty_string($network);

  my $line = $source->{line};
  if (!_is_non_empty_string($line)) {
    push @errors, 'IRC private-message binding requires a non-empty source.line string';
    return @errors;
  }

  my $parsed = _parse_irc_direct_message_line($line);
  if (!$parsed) {
    push @errors, 'IRC private-message binding source.line must contain a direct-message PRIVMSG or NOTICE';
    return @errors;
  }
  my $command = $parsed->{command};
  my $target = $parsed->{target};

  if ($target =~ /\A[#&+!]/) {
    push @errors, 'IRC private-message binding source.line must target a nick, not a channel';
    return @errors;
  }

  if ($command eq 'PRIVMSG') {
    push @errors, 'IRC private-message binding must use private_type chat.dm_message for PRIVMSG'
      unless ($payload->{private_type} // '') eq 'chat.dm_message';
  } elsif ($command eq 'NOTICE') {
    push @errors, 'IRC private-message binding must use private_type chat.dm_notice for NOTICE'
      unless ($payload->{private_type} // '') eq 'chat.dm_notice';
  } else {
    push @errors, 'IRC private-message binding source.line must use PRIVMSG or NOTICE';
  }

  my $expected_object_id = "irc:$network:dm:$target";
  push @errors, "IRC private-message binding object_id must be $expected_object_id"
    unless ($payload->{object_id} // '') eq $expected_object_id;

  if (ref($payload->{provenance}) ne 'HASH' || ($payload->{provenance}{protocol} // '') ne 'irc') {
    push @errors, 'IRC private-message binding provenance.protocol must be irc';
  } elsif (defined($payload->{provenance}{external_identity})
      && ($payload->{provenance}{external_identity} // '') ne ($parsed->{sender} // '')) {
    push @errors, 'IRC private-message binding provenance.external_identity must match the IRC sender nick';
  }

  return @errors;
}

sub _validate_irc_opaque_binding {
  my (%args) = @_;
  my $source = $args{source};
  my @errors;

  my $network = $source->{network};
  push @errors, 'IRC private-message binding requires a non-empty source.network string'
    unless _is_non_empty_string($network);

  my $line = $source->{line};
  if (!_is_non_empty_string($line)) {
    push @errors, 'IRC private-message binding requires a non-empty source.line string';
    return @errors;
  }

  my $parsed = _parse_irc_direct_message_line($line);
  if (!$parsed) {
    push @errors, 'IRC private-message binding source.line must contain a direct-message PRIVMSG or NOTICE';
    return @errors;
  }

  if ($parsed->{target} =~ /\A[#&+!]/) {
    push @errors, 'IRC private-message binding source.line must target a nick, not a channel';
    return @errors;
  }

  push @errors, 'Opaque IRC private-message binding source.line must carry an overnet-e2ee-v1 transport body'
    unless $line =~ /\s:\+overnet-e2ee-v1\s+\S/;

  if ($parsed->{command} eq 'PRIVMSG') {
    push @errors, 'IRC private-message binding must use private_type chat.dm_message for PRIVMSG'
      unless ($args{private_type} // '') eq 'chat.dm_message';
  } elsif ($parsed->{command} eq 'NOTICE') {
    push @errors, 'IRC private-message binding must use private_type chat.dm_notice for NOTICE'
      unless ($args{private_type} // '') eq 'chat.dm_notice';
  } else {
    push @errors, 'IRC private-message binding source.line must use PRIVMSG or NOTICE';
  }

  push @errors, 'Opaque private-message binding object_type must be chat.dm'
    unless ($args{object_type} // '') eq 'chat.dm';

  my $expected_object_id = "irc:$network:dm:$parsed->{target}";
  push @errors, "IRC private-message binding object_id must be $expected_object_id"
    unless ($args{object_id} // '') eq $expected_object_id;

  push @errors, 'Opaque IRC private-message binding requires sender_identity'
    unless _is_non_empty_string($args{sender_identity});
  push @errors, 'Opaque IRC private-message binding sender_identity must match the IRC sender nick'
    if _is_non_empty_string($args{sender_identity})
      && ($args{sender_identity} // '') ne ($parsed->{sender} // '');

  return @errors;
}

sub _validate_opaque_metadata {
  my (%args) = @_;
  my @errors;

  if (!defined $args{private_type} || !$VALID_PRIVATE_TYPES{$args{private_type}}) {
    push @errors, 'Opaque private-message private_type must be chat.dm_message or chat.dm_notice';
  }

  if (($args{object_type} // '') ne 'chat.dm') {
    push @errors, 'Opaque private-message object_type must be chat.dm';
  }

  if (!_is_non_empty_string($args{object_id})) {
    push @errors, 'Opaque private-message object_id must be a non-empty string';
  }

  if (exists $args{sender_identity} && defined $args{sender_identity} && !_is_non_empty_string($args{sender_identity})) {
    push @errors, 'Opaque private-message sender_identity must be a non-empty string when present';
  }

  return @errors;
}

sub _parse_irc_direct_message_line {
  my ($line) = @_;
  return undef unless _is_non_empty_string($line);

  my ($sender, $command, $target) = $line =~ /\A:([^\s!]+)(?:![^\s]+)?\s+([A-Z]+)\s+([^\s]+)\s+:/;
  return undef unless defined $sender && defined $command && defined $target;

  return {
    sender  => $sender,
    command => $command,
    target  => $target,
  };
}

sub _validate_provenance {
  my ($provenance) = @_;
  my @errors;

  if (ref($provenance) ne 'HASH') {
    push @errors, 'Private-message payload provenance must be an object';
    return @errors;
  }

  my $ptype = $provenance->{type};
  if (!defined $ptype || ($ptype ne 'native' && $ptype ne 'adapted')) {
    push @errors, "Private-message payload provenance type must be 'native' or 'adapted'";
    return @errors;
  }

  if ($ptype eq 'adapted') {
    if (!_is_non_empty_string($provenance->{protocol})) {
      push @errors, 'Adapted private-message provenance protocol must be a non-empty string';
    }

    if (!_is_non_empty_string($provenance->{origin})) {
      push @errors, 'Adapted private-message provenance origin must be a non-empty string';
    }

    if (!_is_string_array($provenance->{limitations})) {
      push @errors, 'Adapted private-message provenance limitations must be an array of strings';
    }

    my $has_identity = _is_non_empty_string($provenance->{external_identity});
    my $has_scope = _is_non_empty_string($provenance->{external_scope});
    push @errors, 'Adapted private-message provenance must include external_identity or external_scope'
      unless $has_identity || $has_scope;
  }

  return @errors;
}

sub _is_non_empty_string {
  my ($value) = @_;
  return defined $value && !ref($value) && length $value;
}

sub _is_string_array {
  my ($value) = @_;
  return 0 unless ref($value) eq 'ARRAY';
  for my $item (@{$value}) {
    return 0 if !defined $item || ref($item);
  }
  return 1;
}

sub _result {
  my (%args) = @_;
  my $errors = $args{errors} || [];

  return @{$errors}
    ? {
        valid  => 0,
        errors => $errors,
        reason => $errors->[0],
      }
    : {
        valid           => 1,
        errors          => [],
        visible_kind    => $args{visible_kind},
        decrypted_rumor => $args{decrypted_rumor},
        private_type    => $args{private_type},
        object_type     => $args{object_type},
        object_id       => $args{object_id},
        sender_identity => $args{sender_identity},
      };
}

1;
