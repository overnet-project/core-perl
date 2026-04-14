package Overnet::Core::Validator;

use strict;
use warnings;
use JSON::PP ();
use Net::Nostr::Event;

my %VALID_KINDS = (7800 => 1, 37800 => 1, 7801 => 1);
my %SINGULAR_TAGS = map { $_ => 1 } qw(overnet_v overnet_et overnet_ot overnet_oid overnet_delegate);
my $JSON = JSON::PP->new->utf8;

sub validate {
  my ($input, $context) = @_;
  my @errors;

  # Parse and validate basic Nostr event structure
  my $event;
  eval { $event = Net::Nostr::Event->from_wire($input) };
  if ($@) {
    (my $err = $@) =~ s/ at .+ line \d+.*//s;
    # Can't proceed without a parseable event
    return _result(
      errors => ["Invalid Nostr event: $err"],
    );
  }

  # Overnet kind check
  my $kind = $event->kind;
  push @errors, "Kind $kind is not a recognized Overnet kind (must be 7800, 37800, or 7801)"
    unless $VALID_KINDS{$kind};

  # Required tags
  my $tags = $event->tags;
  my %tag_values;
  my %tag_counts;
  for my $tag (@$tags) {
    next unless @$tag >= 2;
    $tag_counts{$tag->[0]}++;
    $tag_values{$tag->[0]} = $tag->[1];
  }

  for my $tag_name (sort keys %SINGULAR_TAGS) {
    if (($tag_counts{$tag_name} // 0) > 1) {
      push @errors, "Duplicate $tag_name tag";
    }
  }

  push @errors, "Missing required overnet_v tag"
    unless defined $tag_values{overnet_v};

  push @errors, "Missing required overnet_et tag"
    unless defined $tag_values{overnet_et};

  push @errors, "Missing required overnet_ot tag"
    unless defined $tag_values{overnet_ot};

  push @errors, "Missing required overnet_oid tag"
    unless defined $tag_values{overnet_oid};

  # Kind 37800 requires d tag matching overnet_oid
  if ($kind == 37800) {
    my $d_tag = $event->d_tag;

    if (($tag_counts{d} // 0) > 1) {
      push @errors, "Duplicate d tag";
    }

    if ($d_tag eq '') {
      push @errors, "Kind 37800 requires a d tag set to the object identifier";
    } elsif (defined $tag_values{overnet_oid} && $d_tag ne $tag_values{overnet_oid}) {
      push @errors, "Kind 37800 d tag must match overnet_oid";
    }
  }

  if ($kind == 7801) {
    my $can_check_removal_authorization = 1;

    if (defined $tag_values{overnet_et} && $tag_values{overnet_et} ne 'core.removal') {
      push @errors, "Kind 7801 must use overnet_et value core.removal";
      $can_check_removal_authorization = 0;
    }

    if (($tag_counts{e} // 0) > 1) {
      push @errors, "Duplicate e tag";
      $can_check_removal_authorization = 0;
    }

    if (!defined $tag_values{e}) {
      push @errors, "Kind 7801 requires an e tag identifying the event being tombstoned";
      $can_check_removal_authorization = 0;
    }

    if (($tag_counts{overnet_delegate} // 0) > 1) {
      push @errors, "Duplicate overnet_delegate tag";
      $can_check_removal_authorization = 0;
    }

    $context->{_can_check_removal_authorization} = $can_check_removal_authorization
      if ref $context eq 'HASH';
  }

  # Parse content — further content checks depend on successful parse
  my $content;
  eval { $content = $JSON->decode($event->content) };
  if ($@ || ref $content ne 'HASH') {
    push @errors, "Content must be a JSON object";
  } else {
    # Provenance
    my $provenance = $content->{provenance};
    if (!defined $provenance || ref $provenance ne 'HASH') {
      push @errors, "Missing required provenance field in content";
    } else {
      my $ptype = $provenance->{type};
      if (!defined $ptype || ($ptype ne 'native' && $ptype ne 'adapted')) {
        push @errors, "Provenance type must be 'native' or 'adapted'";
      } elsif ($ptype eq 'adapted') {
        if (!defined $provenance->{protocol}) {
          push @errors, "Adapted provenance missing required protocol field";
        } elsif (!_is_non_empty_string($provenance->{protocol})) {
          push @errors, "Adapted provenance protocol must be a non-empty string";
        }

        if (!defined $provenance->{origin}) {
          push @errors, "Adapted provenance missing required origin field";
        } elsif (!_is_non_empty_string($provenance->{origin})) {
          push @errors, "Adapted provenance origin must be a non-empty string";
        }

        if (!defined $provenance->{limitations}) {
          push @errors, "Adapted provenance missing required limitations field";
        } elsif (!_is_string_array($provenance->{limitations})) {
          push @errors, "Adapted provenance limitations must be an array of strings";
        }

        my $has_identity = 0;
        if (exists $provenance->{external_identity}) {
          if (_is_non_empty_string($provenance->{external_identity})) {
            $has_identity = 1;
          } else {
            push @errors, "Adapted provenance external_identity must be a non-empty string";
          }
        }

        my $has_scope = 0;
        if (exists $provenance->{external_scope}) {
          if (_is_non_empty_string($provenance->{external_scope})) {
            $has_scope = 1;
          } else {
            push @errors, "Adapted provenance external_scope must be a non-empty string";
          }
        }

        push @errors, "Adapted provenance must include external_identity or external_scope"
          unless $has_identity || $has_scope;
      }
    }

    my $body = $content->{body};
    if (!defined $body) {
      push @errors, "Missing required body field in content";
    } elsif (ref $body ne 'HASH') {
      push @errors, "Body field must be a JSON object";
    } elsif ($kind == 7801 && keys %{$body}) {
      push @errors, "Kind 7801 body must be an empty JSON object";
      $context->{_can_check_removal_authorization} = 0
        if ref $context eq 'HASH';
    }

    if (defined $tag_values{overnet_et} && $tag_values{overnet_et} eq 'core.delegation') {
      push @errors, "Core delegation events must use kind 7800"
        unless $kind == 7800;

      if (!defined $provenance || ref $provenance ne 'HASH' || ($provenance->{type} // '') ne 'native') {
        push @errors, "Core delegation events must use native provenance";
      }

      if (!defined $body || ref $body ne 'HASH') {
        # body shape errors already reported above
      } else {
        if (!defined $body->{action} || $body->{action} ne 'remove') {
          push @errors, "Core delegation action must be remove";
        }

        if (!defined $body->{delegate_pubkey}) {
          push @errors, "Core delegation missing required delegate_pubkey field";
        } elsif ($body->{delegate_pubkey} !~ /\A[0-9a-f]{64}\z/) {
          push @errors, "Core delegation delegate_pubkey must be 64-char lowercase hex";
        }

        if (defined $body->{expires_at}) {
          if (ref $body->{expires_at} || $body->{expires_at} !~ /\A\d+\z/) {
            push @errors, "Core delegation expires_at must be an integer timestamp";
          }
        }
      }
    }
  }

  if ($kind == 7801) {
    my $can_check_removal_authorization =
      !ref($context) || ref($context) ne 'HASH'
        ? 1
        : ($context->{_can_check_removal_authorization} // 1);

    if ($can_check_removal_authorization) {
      my $target_input = ref($context) eq 'HASH' ? $context->{target_event} : undef;
      if (!defined $target_input) {
        push @errors, "Kind 7801 requires target event context for authorization";
      } else {
        my $target_event;
        eval { $target_event = Net::Nostr::Event->from_wire($target_input) };
        if ($@) {
          (my $err = $@) =~ s/ at .+ line \d+.*//s;
          push @errors, "Invalid removal target event: $err";
        } elsif ($tag_values{e} ne $target_event->id) {
          push @errors, "Kind 7801 target event context does not match e tag";
        } elsif (!defined $tag_values{overnet_delegate}) {
          if ($event->pubkey ne $target_event->pubkey) {
            push @errors, "Kind 7801 removal must be authored by the same pubkey as the target event";
          }
        } else {
          my $delegation_input = ref($context) eq 'HASH' ? $context->{delegation_event} : undef;
          if (!defined $delegation_input) {
            push @errors, "Delegated removal requires delegation event context";
          } else {
            my $delegation_event;
            eval { $delegation_event = Net::Nostr::Event->from_wire($delegation_input) };
            if ($@) {
              (my $err = $@) =~ s/ at .+ line \d+.*//s;
              push @errors, "Invalid delegation event: $err";
            } elsif ($tag_values{overnet_delegate} ne $delegation_event->id) {
              push @errors, "Delegated removal delegation context does not match overnet_delegate tag";
            } else {
              _validate_delegated_removal(
                event            => $event,
                tag_values       => \%tag_values,
                target_event     => $target_event,
                delegation_event => $delegation_event,
                errors           => \@errors,
              );
            }
          }
        }
      }
    }
  }

  # Nostr crypto validation: id hash + signature
  eval { $event->validate() };
  if ($@) {
    (my $err = $@) =~ s/ at .+ line \d+.*//s;
    push @errors, "Nostr validation failed: $err";
  }

  return _result(
    event  => $event,
    errors => \@errors,
  );
}

sub _validate_delegated_removal {
  my %args = @_;
  my $event = $args{event};
  my $tag_values = $args{tag_values};
  my $target_event = $args{target_event};
  my $delegation_event = $args{delegation_event};
  my $errors = $args{errors};

  my %delegation_tags;
  for my $tag (@{$delegation_event->tags // []}) {
    next unless ref $tag eq 'ARRAY' && @$tag >= 2;
    $delegation_tags{$tag->[0]} = $tag->[1];
  }

  if (($delegation_tags{overnet_et} // '') ne 'core.delegation') {
    push @{$errors}, "Delegated removal requires a core.delegation event";
    return;
  }

  if (($delegation_tags{overnet_ot} // '') ne ($tag_values->{overnet_ot} // '')
      || ($delegation_tags{overnet_oid} // '') ne ($tag_values->{overnet_oid} // '')) {
    push @{$errors}, "Delegation object scope does not match removal object";
    return;
  }

  if ($delegation_event->pubkey ne $target_event->pubkey) {
    push @{$errors}, "Delegation must be authored by the same pubkey as the target event";
    return;
  }

  my $content;
  eval { $content = $JSON->decode($delegation_event->content) };
  if ($@ || ref $content ne 'HASH' || ref($content->{body}) ne 'HASH') {
    push @{$errors}, "Invalid delegation event content";
    return;
  }

  my $body = $content->{body};
  if (($body->{action} // '') ne 'remove') {
    push @{$errors}, "Delegation action must be remove";
    return;
  }

  if (($body->{delegate_pubkey} // '') ne $event->pubkey) {
    push @{$errors}, "Delegation delegate_pubkey does not authorize this removal pubkey";
    return;
  }

  if (defined $body->{expires_at} && $body->{expires_at} < $event->created_at) {
    push @{$errors}, "Delegation is expired at removal event timestamp";
  }
}

sub _result {
  my (%args) = @_;
  my $event = $args{event};
  my $errors = $args{errors} || [];
  return @{$errors}
    ? { valid => 0, errors => $errors, reason => $errors->[0], (defined $event ? (event => $event) : ()) }
    : { valid => 1, errors => [], (defined $event ? (event => $event) : ()) };
}

sub _is_non_empty_string {
  my ($value) = @_;
  return defined $value && !ref($value) && length($value) ? 1 : 0;
}

sub _is_string_array {
  my ($value) = @_;
  return 0 unless ref($value) eq 'ARRAY';

  for my $item (@{$value}) {
    return 0 unless _is_non_empty_string($item);
  }

  return 1;
}

1;
