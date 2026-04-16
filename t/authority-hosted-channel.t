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

done_testing;
