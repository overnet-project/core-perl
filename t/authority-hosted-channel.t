use strictures 2;
use Test2::V0;

use Overnet::Authority::HostedChannel;

subtest 'deterministic authoritative group ids are reversible' => sub {
  my $group_id = Overnet::Authority::HostedChannel::authoritative_group_id(
    network => 'irc.example.test',
    channel => '#Fresh',
  );

  is $group_id, 'irc-6972632e6578616d706c652e74657374-236672657368',
    'the deterministic hosted-channel group id encodes the IRC network and folded channel';
  is Overnet::Authority::HostedChannel::channel_name_from_group_id(
    network  => 'irc.example.test',
    group_id => $group_id,
    ),
    '#fresh',
    'the deterministic hosted-channel group id decodes back to the folded channel name';
};

subtest 'authoritative discovery prefers the channel name tag when it matches the deterministic binding' => sub {
  my $channel = Overnet::Authority::HostedChannel::channel_name_from_group_event(
    network => 'irc.example.test',
    event   => {
      kind => 39000,
      tags => [['d', 'irc-6972632e6578616d706c652e74657374-236672657368'], ['name', '#Fresh'],],
    },
  );

  is $channel, '#Fresh', 'authoritative discovery preserves the presentational channel spelling from metadata';
};

subtest 'hosted-channel helper detects tombstoned metadata events' => sub {
  ok Overnet::Authority::HostedChannel::group_event_is_tombstoned(
    event => {
      kind => 9002,
      tags => [['h', 'irc-6972632e6578616d706c652e74657374-236672657368'], ['status', 'tombstoned'],],
    },
    ),
    'the helper detects the profile tombstone status tag';

  ok !Overnet::Authority::HostedChannel::group_event_is_tombstoned(
    event => {
      kind => 39000,
      tags => [['d', 'irc-6972632e6578616d706c652e74657374-236672657368'], ['name', '#Fresh'],],
    },
    ),
    'the helper ignores ordinary hosted-channel metadata';
};

subtest 'IRC mask helpers build and match presentational user masks' => sub {
  is Overnet::Authority::HostedChannel::irc_user_mask(
    nick => 'Bob',
    user => 'bob',
    host => '127.0.0.1',
    ),
    'Bob!bob@127.0.0.1',
    'the helper renders a standard IRC nick!user@host mask';

  ok Overnet::Authority::HostedChannel::irc_mask_matches(
    mask  => 'bob!*@127.0.0.1',
    value => 'Bob!bob@127.0.0.1',
    ),
    'IRC mask matching uses RFC1459-style case folding and wildcards';

  ok !Overnet::Authority::HostedChannel::irc_mask_matches(
    mask  => 'alice!*@127.0.0.1',
    value => 'Bob!bob@127.0.0.1',
    ),
    'non-matching IRC masks are rejected';
};

subtest 'mask helpers reject unusable inputs' => sub {
  is Overnet::Authority::HostedChannel::irc_casefold(undef), undef, 'casefold rejects undef';
  is Overnet::Authority::HostedChannel::irc_casefold([]),    undef, 'casefold rejects references';

  is Overnet::Authority::HostedChannel::irc_user_mask(user => 'bob', host => 'h'), undef,
    'user masks require a nick';
  is Overnet::Authority::HostedChannel::irc_user_mask(nick => 'Bob', user => q{}, host => 'h'), undef,
    'user masks require a non-empty user';

  ok !Overnet::Authority::HostedChannel::irc_mask_matches(value => 'Bob!bob@h'), 'matching requires a mask';
  ok !Overnet::Authority::HostedChannel::irc_mask_matches(mask => 'a!*@*', value => []),
    'matching requires a scalar value';
  ok Overnet::Authority::HostedChannel::irc_mask_matches(mask => 'b?b!*@*', value => 'Bob!bob@h'),
    'single-character wildcards match';
};

subtest 'authoritative group id derivation rejects invalid scopes' => sub {
  is Overnet::Authority::HostedChannel::authoritative_group_id(channel => '#x'), undef,
    'a network is required';
  is Overnet::Authority::HostedChannel::authoritative_group_id(network => 'net', channel => 'nochan'),
    undef, 'a channel name is required';
};

subtest 'group id decoding rejects foreign and malformed ids' => sub {
  my $decode = sub {
    return Overnet::Authority::HostedChannel::channel_name_from_group_id(@_);
  };
  is $decode->(group_id => 'irc-61-2361'), undef, 'a network is required';
  is $decode->(network => 'a', group_id => undef),            undef, 'a group id is required';
  is $decode->(network => 'a', group_id => 'not-irc-shaped'), undef, 'non-IRC group ids are refused';
  is $decode->(network => 'a', group_id => 'irc-62-2361'),    undef, 'foreign-network group ids are refused';
  is $decode->(network => 'a', group_id => 'irc-61-61'),      undef,
    'group ids that decode to non-channel names are refused';
  is $decode->(network => 'a', group_id => 'irc-61-2361'), '#a', 'well-formed group ids decode';
};

subtest 'NIP-29 group binding resolution' => sub {
  my $resolve = sub {
    my ($host, $group_id, $error) = Overnet::Authority::HostedChannel::resolve_nip29_group_binding(@_);
    return {host => $host, group_id => $group_id, error => $error};
  };

  like $resolve->(network => 'a', target => '#x')->{error},
    qr/requires session_config[.]group_host/, 'a group host is required';
  like $resolve->(session_config => {group_host => 'g'}, network => 'a', target => 'nope')->{error},
    qr/requires a channel target/, 'a channel target is required';

  my $exact = $resolve->(
    session_config => {group_host => 'g', channel_groups => {'#x' => {group_id => 'irc-61-2378'}}},
    network        => 'a',
    target         => '#x',
  );
  is $exact->{group_id}, 'irc-61-2378', 'exact channel bindings resolve';
  is $exact->{host},     'g',           'the configured group host is returned';

  my $folded = $resolve->(
    session_config => {group_host => 'g', channel_groups => {'#other' => 'x', '#FOO' => 'irc-61-23666f6f'}},
    network        => 'a',
    target         => '#foo',
  );
  is $folded->{group_id}, 'irc-61-23666f6f', 'casefolded channel bindings resolve';

  my $fallback = $resolve->(
    session_config => {group_host => 'g', channel_groups => {'#x' => {}}},
    network        => 'a',
    target         => '#x',
  );
  is $fallback->{group_id},
    Overnet::Authority::HostedChannel::authoritative_group_id(network => 'a', channel => '#x'),
    'bindings without a group id fall back to the deterministic id';

  like $resolve->(
    session_config => {group_host => 'g'},
    network        => undef,
    target         => '#x',
  )->{error}, qr/requires group_id/, 'an underivable group id is an error';

  like $resolve->(
    session_config => {group_host => 'g', channel_groups => {'#x' => {group_id => ['not-a-string']}}},
    network        => 'a',
    target         => '#x',
  )->{error}, qr/uses an invalid group_id/, 'non-string configured group ids are refused';
};

subtest 'group event helpers tolerate malformed events' => sub {
  my $from_event = sub {
    return Overnet::Authority::HostedChannel::channel_name_from_group_event(@_);
  };
  is $from_event->(event => {tags => []}), undef, 'a network is required';
  is $from_event->(network => 'a', event => 'junk'), undef, 'non-event inputs are refused';

  {

    package t::hosted_channel::NoTagsObject;

    sub new { my ($class) = @_; return bless {}, $class }
  }
  is $from_event->(network => 'a', event => t::hosted_channel::NoTagsObject->new), undef,
    'objects without a tags accessor are refused';
  is $from_event->(network => 'a', event => {tags => [['x', 'y']]}), undef,
    'events without group id tags are refused';
  is $from_event->(network => 'a', event => {tags => [['h', 'irc-61-2361'], ['h', 'other'], 'junk']}),
    '#a', 'h tags resolve and only the first tag value counts';
  is $from_event->(network => 'a', event => {tags => [['d', 'irc-61-2361'], ['name', '#unrelated']]}),
    '#a', 'name tags that do not fold to the decoded channel are ignored';

  {

    package t::hosted_channel::TagObject;

    sub new  { my ($class, $tags) = @_; return bless {tags => $tags}, $class }
    sub tags { my ($self) = @_; return $self->{tags} }
  }
  is $from_event->(network => 'a', event => t::hosted_channel::TagObject->new([['d', 'irc-61-2361']])),
    '#a', 'objects with a tags accessor resolve';

  ok !Overnet::Authority::HostedChannel::group_event_is_tombstoned(event => undef),
    'missing events are not tombstoned';
  ok !Overnet::Authority::HostedChannel::group_event_is_tombstoned(
    event => {tags => [['short'], ['status', 'active']]},
    ),
    'non-tombstone status tags are ignored';
};

done_testing;
