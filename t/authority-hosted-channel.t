use strict;
use warnings;
use Test::More;

use lib 'lib';
use lib 'local/lib/perl5';

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
  ), '#fresh', 'the deterministic hosted-channel group id decodes back to the folded channel name';
};

subtest 'authoritative discovery prefers the channel name tag when it matches the deterministic binding' => sub {
  my $channel = Overnet::Authority::HostedChannel::channel_name_from_group_event(
    network => 'irc.example.test',
    event   => {
      kind => 39000,
      tags => [
        [ 'd', 'irc-6972632e6578616d706c652e74657374-236672657368' ],
        [ 'name', '#Fresh' ],
      ],
    },
  );

  is $channel, '#Fresh',
    'authoritative discovery preserves the presentational channel spelling from metadata';
};

subtest 'hosted-channel helper detects tombstoned metadata events' => sub {
  ok Overnet::Authority::HostedChannel::group_event_is_tombstoned(
    event => {
      kind => 9002,
      tags => [
        [ 'h', 'irc-6972632e6578616d706c652e74657374-236672657368' ],
        [ 'status', 'tombstoned' ],
      ],
    },
  ), 'the helper detects the profile tombstone status tag';

  ok !Overnet::Authority::HostedChannel::group_event_is_tombstoned(
    event => {
      kind => 39000,
      tags => [
        [ 'd', 'irc-6972632e6578616d706c652e74657374-236672657368' ],
        [ 'name', '#Fresh' ],
      ],
    },
  ), 'the helper ignores ordinary hosted-channel metadata';
};

subtest 'IRC mask helpers build and match presentational user masks' => sub {
  is Overnet::Authority::HostedChannel::irc_user_mask(
    nick => 'Bob',
    user => 'bob',
    host => '127.0.0.1',
  ), 'Bob!bob@127.0.0.1', 'the helper renders a standard IRC nick!user@host mask';

  ok Overnet::Authority::HostedChannel::irc_mask_matches(
    mask  => 'bob!*@127.0.0.1',
    value => 'Bob!bob@127.0.0.1',
  ), 'IRC mask matching uses RFC1459-style case folding and wildcards';

  ok !Overnet::Authority::HostedChannel::irc_mask_matches(
    mask  => 'alice!*@127.0.0.1',
    value => 'Bob!bob@127.0.0.1',
  ), 'non-matching IRC masks are rejected';
};

done_testing;
