#!/usr/bin/env perl
#
# Generates t/fixtures/ from overnet-spec/fixtures/core/.
#
# Valid fixtures are re-signed with real keys so the validator can do
# full Nostr crypto verification.  Invalid fixtures are copied as-is
# since they fail Overnet structural checks before crypto is reached.
#
use strict;
use warnings;
use JSON::PP;
use File::Basename;
use File::Spec;
use File::Path qw(make_path);

use Net::Nostr::Key;
use Net::Nostr::Event;

my $json = JSON::PP->new->utf8->pretty->canonical;

my $script_dir = dirname(__FILE__);
my $out_dir    = File::Spec->catdir($script_dir, 'fixtures');
my $spec_dir   = File::Spec->catdir($script_dir, '..', '..', 'overnet-spec', 'fixtures', 'core');

die "Spec fixtures not found at $spec_dir\n" unless -d $spec_dir;
make_path($out_dir);

# Three keys: one for native events, one for the adapter identity, and one delegate
my $native_key  = Net::Nostr::Key->new;
my $adapter_key = Net::Nostr::Key->new;
my $delegate_key = Net::Nostr::Key->new;

opendir my $dh, $spec_dir or die "Can't open $spec_dir: $!";
my @files = sort grep { /\.json$/ } readdir $dh;
closedir $dh;

# Precompute the generated native event so removal fixtures can reference it.
my $native_event = _generate_native_event(
  $json,
  File::Spec->catfile($spec_dir, 'valid-native-event.json'),
  $native_key,
);

my $delegation_event = _generate_delegation_event(
  $json,
  File::Spec->catfile($spec_dir, 'valid-delegation-event.json'),
  $native_key,
  $delegate_key,
);

for my $file (@files) {
  my $path = File::Spec->catfile($spec_dir, $file);
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $raw = do { local $/; <$fh> };
  close $fh;

  my $fixture = $json->decode($raw);

  if ($fixture->{expected}{overnet_valid}) {
    my $input = $fixture->{input};
    my $is_adapted = $input->{content} =~ /"type"\s*:\s*"adapted"/;
    my $is_delegated_removal = ref($fixture->{context}) eq 'HASH' && $fixture->{context}{delegation_fixture};
    my $is_delegation_event = _tag_value($input->{tags}, 'overnet_et') && _tag_value($input->{tags}, 'overnet_et') eq 'core.delegation';
    my $key =
      $is_delegated_removal ? $delegate_key
      : $is_adapted         ? $adapter_key
      :                      $native_key;
    my $pubkey = $key->pubkey_hex;

    # For kind 37800, update d tag and overnet_oid to match the new pubkey
    my @tags = @{$input->{tags}};
    if ($input->{kind} == 37800) {
      @tags = map {
        $_->[0] eq 'd'           ? ['d', $pubkey]
        : $_->[0] eq 'overnet_oid' ? ['overnet_oid', $pubkey]
        : $_
      } @tags;
    }

    # For removal events, reference the native event we generated
    if ($input->{kind} == 7801 && defined $native_event) {
      @tags = map {
        $_->[0] eq 'e' ? ['e', $native_event->id] : $_
      } @tags;
    }

    if ($is_delegated_removal && defined $delegation_event) {
      @tags = map {
        $_->[0] eq 'overnet_delegate' ? ['overnet_delegate', $delegation_event->id] : $_
      } @tags;
    }

    my $content = $input->{content};
    if ($is_delegation_event) {
      my $content_obj = $json->decode($content);
      $content_obj->{body}{delegate_pubkey} = $delegate_key->pubkey_hex;
      $content = $json->encode($content_obj);
    }

    my $event = $key->create_event(
      kind       => $input->{kind},
      content    => $content,
      tags       => \@tags,
      created_at => $input->{created_at},
    );

    $fixture->{input} = _event_hash($event);
  }

  if (ref $fixture->{context} eq 'HASH' && $fixture->{context}{target_fixture}) {
    if ($fixture->{context}{target_fixture} eq 'valid-native-event') {
      $fixture->{context}{target_event} = _event_hash($native_event);

      if ($fixture->{context}{match_target_e}) {
        my @tags = @{$fixture->{input}{tags}};
        @tags = map {
          $_->[0] eq 'e' ? ['e', $native_event->id] : $_
        } @tags;
        $fixture->{input}{tags} = \@tags;
        delete $fixture->{context}{match_target_e};
      }

      delete $fixture->{context}{target_fixture};
    } else {
      die "Unsupported target_fixture '$fixture->{context}{target_fixture}' in $file\n";
    }
  }

  if (ref $fixture->{context} eq 'HASH' && $fixture->{context}{delegation_fixture}) {
    if ($fixture->{context}{delegation_fixture} eq 'valid-delegation-event') {
      $fixture->{context}{delegation_event} = _event_hash($delegation_event);

      if ($fixture->{context}{match_delegation_ref}) {
        my @tags = @{$fixture->{input}{tags}};
        @tags = map {
          $_->[0] eq 'overnet_delegate' ? ['overnet_delegate', $delegation_event->id] : $_
        } @tags;
        $fixture->{input}{tags} = \@tags;
        delete $fixture->{context}{match_delegation_ref};
      }

      delete $fixture->{context}{delegation_fixture};
    } else {
      die "Unsupported delegation_fixture '$fixture->{context}{delegation_fixture}' in $file\n";
    }
  }

  if (ref $fixture->{context} eq 'HASH' && $fixture->{context}{use_delegate_pubkey}) {
    $fixture->{input}{pubkey} = $delegate_key->pubkey_hex;
    delete $fixture->{context}{use_delegate_pubkey};
  }

  my $out_path = File::Spec->catfile($out_dir, $file);
  open my $ofh, '>', $out_path or die "Can't write $out_path: $!";
  print $ofh $json->encode($fixture);
  close $ofh;
}

print "Generated " . scalar(@files) . " fixtures in $out_dir\n";

# Ensure numeric types survive JSON encoding
sub _event_hash {
  my ($event) = @_;
  return {
    id         => $event->id,
    pubkey     => $event->pubkey,
    created_at => $event->created_at + 0,
    kind       => $event->kind + 0,
    tags       => $event->tags,
    content    => $event->content,
    sig        => $event->sig,
  };
}

sub _generate_native_event {
  my ($json, $path, $key) = @_;
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $raw = do { local $/; <$fh> };
  close $fh;

  my $fixture = $json->decode($raw);
  my $input = $fixture->{input};

  return $key->create_event(
    kind       => $input->{kind},
    content    => $input->{content},
    tags       => $input->{tags},
    created_at => $input->{created_at},
  );
}

sub _generate_delegation_event {
  my ($json, $path, $key, $delegate_key) = @_;
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $raw = do { local $/; <$fh> };
  close $fh;

  my $fixture = $json->decode($raw);
  my $input = $fixture->{input};
  my $content = $json->decode($input->{content});
  $content->{body}{delegate_pubkey} = $delegate_key->pubkey_hex;

  return $key->create_event(
    kind       => $input->{kind},
    content    => $json->encode($content),
    tags       => $input->{tags},
    created_at => $input->{created_at},
  );
}

sub _tag_value {
  my ($tags, $name) = @_;
  for my $tag (@{$tags // []}) {
    next unless ref $tag eq 'ARRAY' && @$tag >= 2;
    return $tag->[1] if $tag->[0] eq $name;
  }
  return;
}
