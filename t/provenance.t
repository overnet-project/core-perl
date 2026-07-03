use strictures 2;

use Test2::V0;

use Overnet::Core::Provenance;

my $ADAPTER = 'a1b2c3d4' x 8;
my $FORGER  = 'f0' x 32;
my $OTHER   = 'c0' x 32;

sub adapted_event {
  my (%args) = @_;
  return {
    pubkey     => $args{pubkey},
    created_at => $args{created_at} // 1_744_300_860,
    provenance => {
      type     => 'adapted',
      protocol => $args{protocol} // 'irc',
      origin   => $args{origin}   // 'irc.libera.chat/#overnet',
    },
  };
}

sub authority_record {
  my (%args) = @_;
  return {body => {protocol => 'irc', origin => 'irc.libera.chat', origin_match => 'prefix', %args}};
}

sub outcome {
  my ($event, $records, $options) = @_;
  return Overnet::Core::Provenance::verify_event($event, $records, $options)->{outcome};
}

# Native data is not subject to verification.
is outcome({pubkey => $ADAPTER, provenance => {type => 'native'}}, []), 'not_applicable',
  'native provenance is not applicable';

# No records at all, or only non-applicable records, is the permissionless default.
is outcome(adapted_event(pubkey => $FORGER), []), 'unverified', 'no records yields unverified';
is outcome(adapted_event(pubkey => $FORGER), [authority_record(protocol => 'email', pubkeys => [$ADAPTER])]),
  'unverified', 'a record for another protocol does not apply';

# A trusted record binding the signing key makes it authoritative.
is outcome(adapted_event(pubkey => $ADAPTER), [authority_record(pubkeys => [$ADAPTER])]), 'authoritative',
  'listed pubkey is authoritative';

# A trusted record that excludes the signing key marks it forged.
is outcome(adapted_event(pubkey => $FORGER), [authority_record(pubkeys => [$ADAPTER])]), 'forged',
  'unlisted pubkey is forged';

# Revocation via an empty pubkey list forges a previously authoritative key.
is outcome(adapted_event(pubkey => $ADAPTER), [authority_record(pubkeys => [])]), 'forged',
  'empty pubkey list forges every key';

# Prefix matching must not cross an origin boundary.
is outcome(
  adapted_event(pubkey => $ADAPTER, origin => 'irc.libera.chatnet/#x'),
  [authority_record(pubkeys => [$ADAPTER])],
  ),
  'unverified', 'prefix match respects the separator boundary';

# An exact record does not cover a channel-scoped origin.
is outcome(adapted_event(pubkey => $FORGER), [authority_record(origin_match => 'exact', pubkeys => [$ADAPTER])],),
  'unverified', 'exact network record does not cover a channel origin';

# The only applicable record being out of its window is unresolvable.
is outcome(adapted_event(pubkey => $ADAPTER), [authority_record(not_after => 1_744_200_000, pubkeys => [$ADAPTER])],),
  'unresolvable', 'out-of-window record is unresolvable';

# Two applicable in-effect records that disagree cannot be reconciled.
is outcome(
  adapted_event(pubkey => $ADAPTER),
  [authority_record(pubkeys => [$ADAPTER]), authority_record(pubkeys => [$OTHER])],
  ),
  'unresolvable', 'conflicting records are unresolvable';

# A malformed applicable record cannot yield a determination on its own.
is outcome(adapted_event(pubkey => $ADAPTER), [authority_record(pubkeys => 'not-an-array')]), 'unresolvable',
  'malformed applicable record is unresolvable';

# A custom origin separator is honored.
is outcome(
  {
    pubkey     => $ADAPTER,
    created_at => 1_744_300_860,
    provenance => {type => 'adapted', protocol => 'email', origin => 'lists.example.org::dev'},
  },
  [{body => {protocol => 'email', origin => 'lists.example.org', origin_match => 'prefix', pubkeys => [$ADAPTER]}}],
  {origin_separator => q{::}},
  ),
  'authoritative', 'custom origin separator is honored';

# A well-formed record from wire content (JSON string) is decoded.
is outcome(
  {
    pubkey     => $ADAPTER,
    created_at => 1_744_300_860,
    content    =>
      '{"provenance":{"type":"adapted","protocol":"irc","origin":"irc.libera.chat/#overnet"},"body":{"text":"hi"}}',
  },
  [
    {
      content =>
"{\"provenance\":{\"type\":\"native\"},\"body\":{\"protocol\":\"irc\",\"origin\":\"irc.libera.chat\",\"origin_match\":\"prefix\",\"pubkeys\":[\"$ADAPTER\"]}}",
    }
  ],
  ),
  'authoritative', 'wire content is decoded for event and record';

done_testing;
