package Overnet::Test::SpecConformance;

use strict;
use warnings;

use Exporter qw(import);
use File::Basename qw(dirname);
use File::Spec;
use JSON::PP qw(decode_json);
use Overnet::Core::Nostr;
use Test::More;

our @EXPORT_OK = qw(
  run_core_validator_conformance
  run_private_messaging_conformance
  run_irc_adapter_map_conformance
  run_irc_adapter_derived_presence_conformance
  run_irc_adapter_authoritative_conformance
  run_irc_server_conformance
);

sub run_core_validator_conformance {
  require Overnet::Core::Validator;
  my $fixtures_dir = File::Spec->catdir(dirname(__FILE__), '..', '..', '..', 't', 'fixtures');
  opendir my $dh, $fixtures_dir or die "Can't open $fixtures_dir: $!";
  my @files = sort grep { /\.json\z/ } readdir $dh;
  closedir $dh;

  for my $file (@files) {
    my $fixture = _load_fixture(File::Spec->catfile($fixtures_dir, $file));
    my $expected = $fixture->{expected} || {};

    subtest "$file - " . ($fixture->{description} || $file) => sub {
      my $result = Overnet::Core::Validator::validate(
        $fixture->{input},
        $fixture->{context},
      );

      is(
        $result->{valid},
        $expected->{overnet_valid},
        "valid = $expected->{overnet_valid}",
      );

      if (!$expected->{overnet_valid} && $expected->{reason}) {
        my $found = grep { /\Q$expected->{reason}\E/i } @{$result->{errors} || []};
        ok($found, "errors contain: $expected->{reason}");
      }
    };
  }
}

sub run_private_messaging_conformance {
  require Overnet::Core::PrivateMessaging;

  _run_fixture_family(
    family => 'private-messaging',
    runner => sub {
      my ($fixture) = @_;
      my $expected = $fixture->{expected} || {};
      my $result = Overnet::Core::PrivateMessaging::validate_transport($fixture->{input});

      is(
        $result->{valid},
        $expected->{private_transport_valid},
        "valid = $expected->{private_transport_valid}",
      );

      if (!$expected->{private_transport_valid} && $expected->{reason}) {
        my $found = grep { /\Q$expected->{reason}\E/i } @{$result->{errors} || []};
        ok($found, "errors contain: $expected->{reason}");
      }

      _assertions($result, $expected->{assertions});
    },
  );
}

sub run_irc_adapter_map_conformance {
  require Overnet::Adapter::IRC;

  my $adapter = Overnet::Adapter::IRC->new;
  _run_fixture_family(
    family => 'irc',
    runner => sub {
      my ($fixture) = @_;
      my $expected = $fixture->{expected} || {};
      my $result = $adapter->map_input(%{$fixture->{input} || {}});

      is(
        $result->{valid},
        $expected->{overnet_valid},
        "valid = $expected->{overnet_valid}",
      );

      if ($expected->{overnet_valid}) {
        my $got_event = { %{$result->{event} || {}} };
        my $expected_event = { %{$expected->{event} || {}} };
        my $got_content = delete $got_event->{content};
        my $expected_content = delete $expected_event->{content};

        is_deeply($got_event, $expected_event, 'mapped event envelope matches fixture');
        is_deeply(
          decode_json($got_content),
          decode_json($expected_content),
          'mapped event content matches fixture semantically',
        );
      } else {
        is($result->{reason}, $expected->{reason}, 'reason matches fixture');
      }
    },
  );
}

sub run_irc_adapter_derived_presence_conformance {
  require Overnet::Adapter::IRC;

  my $adapter = Overnet::Adapter::IRC->new;
  _run_fixture_family(
    family => 'irc-derived',
    runner => sub {
      my ($fixture) = @_;
      my $expected = $fixture->{expected} || {};
      my $result = $adapter->derive_channel_presence(%{$fixture->{input} || {}});

      is(
        $result->{valid},
        $expected->{overnet_valid},
        "valid = $expected->{overnet_valid}",
      );

      if ($expected->{overnet_valid}) {
        my $got_event = { %{$result->{event} || {}} };
        my $expected_event = { %{$expected->{event} || {}} };
        my $got_content = delete $got_event->{content};
        my $expected_content = delete $expected_event->{content};

        is_deeply($got_event, $expected_event, 'derived event envelope matches fixture');
        is_deeply(
          decode_json($got_content),
          decode_json($expected_content),
          'derived event content matches fixture semantically',
        );
      } else {
        is($result->{reason}, $expected->{reason}, 'reason matches fixture');
      }
    },
  );
}

sub run_irc_adapter_authoritative_conformance {
  require Overnet::Adapter::IRC;

  my $adapter = Overnet::Adapter::IRC->new;
  _run_fixture_family(
    family => 'irc-authoritative',
    runner => sub {
      my ($fixture) = @_;
      my $input = $fixture->{input} || {};
      my $expected = $fixture->{expected} || {};
      my $result;

      if (defined($input->{command}) && length($input->{command})) {
        $result = $adapter->map_input(%{$input});
      } else {
        my %derive_input = %{_expanded_authoritative_input($input)};
        my $operation = delete $derive_input{operation};
        my $session_config = delete $derive_input{session_config};
        $result = $adapter->derive(
          operation      => $operation,
          session_config => $session_config,
          input          => \%derive_input,
        );
      }

      is(
        $result->{valid},
        exists($expected->{valid}) ? $expected->{valid} : 1,
        'result validity matches fixture',
      );
      _assertions($result, $expected->{assertions});
    },
  );
}

sub run_irc_server_conformance {
  _run_fixture_family(
    family => 'irc-server',
    runner => \&_run_irc_server_fixture,
  );
  _run_fixture_family(
    family => 'irc-server-authoritative',
    runner => \&_run_irc_server_fixture,
  );
}

sub _run_fixture_family {
  my (%args) = @_;
  my $family = $args{family};
  my $runner = $args{runner};

  for my $path (_fixture_files($family)) {
    my $fixture = _load_fixture($path);
    my $name = (File::Spec->splitpath($path))[2];
    my $description = $fixture->{description} || $name;

    subtest "$name - $description" => sub {
      $runner->($fixture, $path);
    };
  }
}

sub _run_irc_server_fixture {
  my ($fixture) = @_;
  my $input = $fixture->{input} || {};
  my $expected = $fixture->{expected} || {};
  my ($server, $client_id) = _build_irc_server_harness($input);
  my $client = $server->{clients}{$client_id};

  if (ref($input->{account_update}) eq 'HASH') {
    require Overnet::Program::IRC::Command::Auth;

    my $target_nick = $input->{account_update}{nick};
    $target_nick = $client->{nick}
      unless defined($target_nick) && !ref($target_nick) && length($target_nick);
    my $target_client = $server->_client_for_current_nick($target_nick);
    die "No fixture client found for account_update nick $target_nick\n"
      unless ref($target_client) eq 'HASH';

    Overnet::Program::IRC::Command::Auth::set_authoritative_account(
      $server,
      $target_client,
      (
        exists($input->{account_update}{account})
          ? (account => $input->{account_update}{account})
          : ()
      ),
    );
  }

  if (ref($input->{client}{received_lines}) eq 'ARRAY') {
    for my $line (@{$input->{client}{received_lines}}) {
      $server->_handle_client_line($client_id, $line);
    }
  }

  if (ref($input->{commands}) eq 'ARRAY') {
    for my $line (@{$input->{commands}}) {
      $server->_handle_client_line($client_id, $line);
    }
  }

  if (defined($input->{line}) && !ref($input->{line})) {
    $server->_handle_client_line($client_id, $input->{line});
  }

  my $render_result;
  if (ref($input->{item}) eq 'HASH') {
    my %item = %{$input->{item}};
    if (($item{item_type} || '') ne 'private_message' && ref($item{data}) eq 'HASH') {
      $item{data} = _coerce_fixture_wire_event($item{data});
    }
    $render_result = $server->_render_subscription_item(%item);
  } elsif (($input->{client}{registered} || 0)
      && !ref($input->{client})
      && 0) {
    # unreachable guard to keep the linter quiet
  }

  if (!defined($input->{line})
      && !ref($input->{item})
      && !ref($input->{client}{received_lines})
      && !ref($input->{commands})
      && ($input->{client}{registered} || 0)
      && defined($input->{client}{nick})
      && ref($expected->{lines}) eq 'ARRAY'
      && @{$expected->{lines}}) {
    my $nick = $input->{client}{nick};
    my $lines = Overnet::Program::IRC::Renderer::registration_prelude_lines(
      server_name    => $server->{config}{server_name},
      nick           => $nick,
      isupport_tokens => $server->_isupport_tokens,
    );
    push @{$server->{_spec_lines}{$client_id}}, @{$lines};
  }

  my $lines = $server->{_spec_lines}{$client_id} || [];
  if (ref($render_result) eq 'HASH' && defined($render_result->{line})) {
    $lines = [ @{$lines}, $render_result->{line} ];
  }

  if (ref($expected->{lines}) eq 'ARRAY') {
    ok(
      _contains_lines_in_order($lines, $expected->{lines}),
      'rendered lines contain the expected sequence',
    );
  }

  if (ref($expected->{decorated_lines}) eq 'ARRAY') {
    my @decorated;
    if (ref($render_result) eq 'HASH' && defined($render_result->{line})) {
      push @decorated, $server->_decorate_outbound_line_for_client($client, $render_result->{line});
    }
    ok(
      _contains_lines_in_order(\@decorated, $expected->{decorated_lines}),
      'decorated rendered lines contain the expected sequence',
    );
  }

  if (exists $expected->{registered}) {
    is($client->{registered} ? 1 : 0, $expected->{registered} ? 1 : 0, 'registered state matches fixture');
  }

  if (exists $expected->{nick}) {
    is($client->{nick}, $expected->{nick}, 'client nick matches fixture');
  }

  if (ref($expected->{joined_channels}) eq 'ARRAY') {
    is_deeply(
      [ sort values %{$client->{joined_channels} || {}} ],
      $expected->{joined_channels},
      'joined channels match fixture',
    );
  }

  if (exists $expected->{channel_object_id}) {
    my $event = $server->{_spec_last_emitted_event}
      || (
        ref($server->{_spec_last_map_result}{events}) eq 'ARRAY'
          ? $server->{_spec_last_map_result}{events}[0]
          : undef
      )
      || {};
    my $tags = _first_tag_values($event->{tags});
    is($tags->{overnet_oid}, $expected->{channel_object_id}, 'mapped channel object id matches fixture');
  }

  if (exists $expected->{mapped_overnet_et}) {
    my $event = $server->{_spec_last_emitted_event}
      || (
        ref($server->{_spec_last_map_result}{events}) eq 'ARRAY'
          ? $server->{_spec_last_map_result}{events}[0]
          : undef
      )
      || {};
    my $tags = _first_tag_values($event->{tags});
    is($tags->{overnet_et}, $expected->{mapped_overnet_et}, 'mapped overnet_et matches fixture');
    is($tags->{overnet_ot}, $expected->{mapped_overnet_ot}, 'mapped overnet_ot matches fixture');
    is($tags->{overnet_oid}, $expected->{mapped_overnet_oid}, 'mapped overnet_oid matches fixture');
  }

  if (exists $expected->{rendered}) {
    is((ref($render_result) eq 'HASH') ? 1 : 0, $expected->{rendered} ? 1 : 0, 'rendered flag matches fixture');
  }
}

sub _build_irc_server_harness {
  my ($input) = @_;
  require Overnet::Program::IRC::Server;
  require Overnet::Program::IRC::Renderer;
  require Overnet::Adapter::IRC;

  my $server = Overnet::Program::IRC::Server->new;
  bless $server, 'Overnet::Test::SpecConformance::IRCServerHarness';

  my $server_view = $input->{server_view} || {};
  my $client_spec = $input->{client} || {};
  my $adapter_config = ref($server_view->{adapter_config}) eq 'HASH'
    ? { %{$server_view->{adapter_config}} }
    : {};

  $server->{config} = {
    network       => $server_view->{network} || 'local',
    server_name   => $server_view->{server_name} || 'overnet.irc.local',
    adapter_config => $adapter_config,
    use_server_capabilities => $server_view->{use_server_capabilities} ? 1 : 0,
    supported_capabilities => ref($server_view->{supported_capabilities}) eq 'ARRAY'
      ? [ @{$server_view->{supported_capabilities}} ]
      : [],
  };
  $server->{adapter_session_id} = 'spec-fixture';
  $server->{_spec_adapter} = Overnet::Adapter::IRC->new;
  $server->{_spec_lines} = {};
  $server->{_spec_emits} = [];
  $server->{_spec_authoritative_channels} = {};

  my $client_id = 1;
  my $client = {
    id              => $client_id,
    registered      => $client_spec->{registered} ? 1 : 0,
    nick            => defined($client_spec->{nick})
      ? $client_spec->{nick}
      : ($client_spec->{registered} ? 'fixture-user' : undef),
    username        => $client_spec->{username},
    realname        => $client_spec->{realname},
    joined_channels => {},
    capabilities    => {},
    socket          => undef,
    peerhost        => $client_spec->{peerhost} || '127.0.0.1',
    peerport        => $client_spec->{peerport} || 6667,
  };
  $client->{authority_pubkey} = $client_spec->{authority_pubkey}
    if defined($client_spec->{authority_pubkey}) && !ref($client_spec->{authority_pubkey});
  if (ref($client_spec->{capabilities}) eq 'ARRAY') {
    $client->{capabilities}{$_} = 1 for @{$client_spec->{capabilities}};
  }
  $client->{e2ee_pubkey} = ('b' x 64)
    if $client->{capabilities}{'overnet-e2ee'};
  $server->{clients}{$client_id} = $client;
  if (defined($client->{nick}) && length($client->{nick})) {
    $server->{nick_to_client_id}{$server->_nick_key($client->{nick})} = $client_id;
  }

  my $next_client_id = 2;
  for my $nick (@{$server_view->{current_nicks} || []}) {
    _ensure_stub_client_for_nick($server, \$next_client_id, $nick);
  }

  for my $known (@{$input->{known_nicks} || []}) {
    if (ref($known) eq 'HASH') {
      _ensure_stub_client_for_nick(
        $server,
        \$next_client_id,
        $known->{nick},
        username => $known->{username},
        realname => $known->{realname},
        host     => $known->{host},
        authority_pubkey => $known->{authority_pubkey},
      );
      next;
    }

    _ensure_stub_client_for_nick($server, \$next_client_id, $known);
  }

  for my $entry (@{$input->{channels} || []}) {
    next unless ref($entry) eq 'HASH';
    my $channel = $entry->{channel};
    next unless defined $channel && !ref($channel) && length($channel);
    my $state = $server->_channel_state($channel);
    $state->{topic_text} = $entry->{topic}
      if defined $entry->{topic} && !ref($entry->{topic});
    for my $nick (@{$entry->{visible_nicks} || []}) {
      _ensure_stub_client_for_nick($server, \$next_client_id, $nick);
      $server->_add_visible_nick($channel, $nick);
    }
  }

  for my $channel (sort keys %{$server_view->{channel_members} || {}}) {
    my $state = $server->_channel_state($channel);
    for my $nick (@{$server_view->{channel_members}{$channel} || []}) {
      _ensure_stub_client_for_nick($server, \$next_client_id, $nick);
      $server->_add_visible_nick($channel, $nick);
      my $nick_key = $server->_nick_key($nick);
      next unless defined $nick_key;
      my $member_id = $server->{nick_to_client_id}{$nick_key};
      if (defined $member_id) {
        $state->{members}{$member_id} = 1;
        $server->{clients}{$member_id}{joined_channels}{$server->_channel_key($channel)} = $channel;
      }
    }
  }

  for my $entry (@{$input->{visible_channel_members} || []}) {
    next unless ref($entry) eq 'HASH';
    next unless defined($entry->{channel}) && !ref($entry->{channel}) && length($entry->{channel});
    next unless defined($entry->{nick}) && !ref($entry->{nick}) && length($entry->{nick});

    my $channel = $entry->{channel};
    my $state = $server->_channel_state($channel);
    _ensure_stub_client_for_nick(
      $server,
      \$next_client_id,
      $entry->{nick},
      username => $entry->{username},
      realname => $entry->{realname},
      host     => $entry->{host},
      authority_pubkey => $entry->{authority_pubkey},
    );
    $server->_add_visible_nick($channel, $entry->{nick});
    my $nick_key = $server->_nick_key($entry->{nick});
    next unless defined $nick_key;
    my $member_id = $server->{nick_to_client_id}{$nick_key};
    if (defined $member_id) {
      $state->{members}{$member_id} = 1;
      $server->{clients}{$member_id}{joined_channels}{$server->_channel_key($channel)} = $channel;
    }
  }

  for my $entry (@{$input->{channel_topics} || []}) {
    next unless ref($entry) eq 'HASH';
    next unless defined($entry->{channel}) && !ref($entry->{channel}) && length($entry->{channel});
    my $state = $server->_channel_state($entry->{channel});
    $state->{topic_text} = $entry->{topic};
    $state->{topic_line} = sprintf(
      ':%s TOPIC %s :%s',
      ($entry->{actor_nick} || 'server'),
      $entry->{channel},
      ($entry->{topic} || ''),
    );
  }

  for my $channel (sort keys %{$server_view->{channel_topic} || {}}) {
    my $item = $server_view->{channel_topic}{$channel};
    next unless ref($item) eq 'HASH';
    next unless (($item->{item_type} || '') eq 'state');
    next unless ref($item->{data}) eq 'HASH';

    my $event_hash = _coerce_fixture_wire_event($item->{data});
    my $content = eval { decode_json($event_hash->{content}) };
    next unless ref($content) eq 'HASH';
    next unless ref($content->{body}) eq 'HASH';
    next unless defined($content->{body}{topic}) && !ref($content->{body}{topic});

    my $nick = ref($content->{provenance}) eq 'HASH'
      ? $content->{provenance}{external_identity}
      : undef;
    $nick = 'server' unless defined($nick) && !ref($nick) && length($nick);

    my $state = $server->_channel_state($channel);
    $state->{topic_text} = $content->{body}{topic};
    $state->{topic_line} = sprintf(
      ':%s TOPIC %s :%s',
      $nick,
      $channel,
      $content->{body}{topic},
    );
  }

  for my $channel (@{$client_spec->{joined_channels} || []}) {
    $server->_add_client_to_channel($client_id, $channel);
  }

  while (scalar(grep { $server->{clients}{$_}{registered} } keys %{$server->{clients}}) < ($server_view->{registered_users} || 0)) {
    _ensure_stub_client_for_nick($server, \$next_client_id, 'fixture-reg-' . $next_client_id);
  }

  while (scalar(keys %{$server->{clients}}) < ($server_view->{connected_clients} || 0)) {
    my $id = $next_client_id++;
    $server->{clients}{$id} = {
      id              => $id,
      registered      => 0,
      joined_channels => {},
      capabilities    => {},
      socket          => undef,
      peerhost        => '127.0.0.1',
      peerport        => 6667 + $id,
    };
  }

  while (scalar(keys %{$server->{channels}}) < ($server_view->{channels} || 0)) {
    my $channel = '#fixture' . scalar(keys %{$server->{channels}});
    $server->_channel_state($channel);
  }

  for my $channel (sort keys %{$input->{authoritative_channels} || {}}) {
    my $scenario = $input->{authoritative_channels}{$channel} || {};
    next unless ref($scenario) eq 'HASH';
    my $canonical = $server->_canonical_channel_name($channel);
    my $events = _build_authoritative_events(
      session_config => $adapter_config,
      network        => $server->{config}{network},
      target         => $channel,
      scenario       => $scenario->{scenario} || {},
    );
    $server->{_spec_authoritative_channels}{$canonical} = {
      events => $events,
    };
    if (!exists($scenario->{discovered}) || $scenario->{discovered}) {
      $server->{authoritative_discovered_channels}{$canonical} = {
        channel_name => $canonical,
      };
    }
  }

  return ($server, $client_id);
}

sub _ensure_stub_client_for_nick {
  my ($server, $next_client_id_ref, $nick, %opts) = @_;
  return unless defined $nick && !ref($nick) && length($nick);
  my $nick_key = $server->_nick_key($nick);
  return unless defined $nick_key;
  if (exists $server->{nick_to_client_id}{$nick_key}) {
    my $client_id = $server->{nick_to_client_id}{$nick_key};
    my $client = $server->{clients}{$client_id};
    if (ref($client) eq 'HASH') {
      $client->{username} = $opts{username} if defined $opts{username};
      $client->{realname} = $opts{realname} if defined $opts{realname};
      $client->{peerhost} = $opts{host} if defined $opts{host};
      $client->{authority_pubkey} = $opts{authority_pubkey} if defined $opts{authority_pubkey};
    }
    return;
  }

  my $id = $$next_client_id_ref;
  $$next_client_id_ref++;
  $server->{clients}{$id} = {
    id              => $id,
    registered      => 1,
    nick            => $nick,
    username        => defined($opts{username}) ? $opts{username} : lc($nick),
    realname        => defined($opts{realname}) ? $opts{realname} : $nick,
    joined_channels => {},
    capabilities    => {},
    socket          => undef,
    peerhost        => defined($opts{host}) ? $opts{host} : '127.0.0.1',
    peerport        => 6667 + $id,
    (defined($opts{authority_pubkey}) ? (authority_pubkey => $opts{authority_pubkey}) : ()),
  };
  $server->{nick_to_client_id}{$nick_key} = $id;
}

sub _expanded_authoritative_input {
  my ($input) = @_;
  my %expanded = %{$input || {}};
  my $nested_input = delete $expanded{input};
  if (ref($nested_input) eq 'HASH') {
    my %inner = %{$nested_input};
    if (ref($inner{authoritative_scenario}) eq 'HASH') {
      $inner{authoritative_events} = _build_authoritative_events(
        session_config => $expanded{session_config},
        network        => $inner{network},
        target         => $inner{target},
        scenario       => $inner{authoritative_scenario},
      );
      delete $inner{authoritative_scenario};
    }
    $expanded{input} = \%inner;
  }
  return \%expanded if ref($expanded{input}) eq 'HASH';

  if (ref($expanded{authoritative_scenario}) eq 'HASH') {
    $expanded{authoritative_events} = _build_authoritative_events(
      session_config => $expanded{session_config},
      network        => $expanded{network},
      target         => $expanded{target},
      scenario       => $expanded{authoritative_scenario},
    );
    delete $expanded{authoritative_scenario};
  }

  return \%expanded;
}

sub _build_authoritative_events {
  my (%args) = @_;
  require Overnet::Authority::HostedChannel;
  require Net::Nostr::Event;
  require Net::Nostr::Group;

  my $scenario = $args{scenario} || {};
  return [] unless ref($scenario) eq 'HASH';
  my $events = $scenario->{events} || [];
  die "authoritative_scenario.events must be an array\n"
    unless ref($events) eq 'ARRAY';

  my (undef, $group_id, $error) = Overnet::Authority::HostedChannel::resolve_nip29_group_binding(
    network        => $args{network},
    session_config => $args{session_config},
    target         => $args{target},
  );
  die "$error\n" if defined $error;

  my @built;
  for my $spec (@{$events}) {
    die "authoritative_scenario event must be an object\n"
      unless ref($spec) eq 'HASH';
    push @built, _build_authoritative_event_hash(
      group_id => $group_id,
      spec     => $spec,
    );
  }

  return \@built;
}

sub _build_authoritative_event_hash {
  my (%args) = @_;
  require Net::Nostr::Event;
  require Net::Nostr::Group;

  my $group_id = $args{group_id};
  my $spec = $args{spec};
  my $type = $spec->{type} || '';
  my $pubkey = $spec->{pubkey} || ('f' x 64);
  my $created_at = $spec->{created_at} || 0;
  my $event_hash;

  if ($type eq 'metadata') {
    my $event = Net::Nostr::Group->metadata(
      pubkey     => $pubkey,
      group_id   => $group_id,
      created_at => $created_at,
      (defined($spec->{name}) ? (name => $spec->{name}) : ()),
      ($spec->{closed} ? (closed => 1) : ()),
      ($spec->{private} ? (private => 1) : ()),
      ($spec->{restricted} ? (restricted => 1) : ()),
      ($spec->{hidden} ? (hidden => 1) : ()),
    );
    $event_hash = $event->to_hash;
    _apply_metadata_tags($event_hash, $spec);
  } elsif ($type eq 'metadata_edit') {
    my $event = Net::Nostr::Group->edit_metadata(
      pubkey     => $pubkey,
      group_id   => $group_id,
      created_at => $created_at,
      (defined($spec->{name}) ? (name => $spec->{name}) : ()),
      ($spec->{closed} ? (closed => 1) : ()),
      ($spec->{private} ? (private => 1) : ()),
      ($spec->{restricted} ? (restricted => 1) : ()),
      ($spec->{hidden} ? (hidden => 1) : ()),
    );
    $event_hash = $event->to_hash;
    _apply_metadata_tags($event_hash, $spec);
  } elsif ($type eq 'admins') {
    my $event = Net::Nostr::Group->admins(
      pubkey     => $pubkey,
      group_id   => $group_id,
      created_at => $created_at,
      members    => $spec->{members} || [],
    );
    $event_hash = $event->to_hash;
  } elsif ($type eq 'members') {
    my $event = Net::Nostr::Group->members(
      pubkey     => $pubkey,
      group_id   => $group_id,
      created_at => $created_at,
      members    => $spec->{members} || [],
    );
    $event_hash = $event->to_hash;
  } elsif ($type eq 'roles') {
    my @roles = map {
      ref($_) eq 'HASH' ? $_ : { name => $_ }
    } @{$spec->{roles} || []};
    my $event = Net::Nostr::Group->roles(
      pubkey     => $pubkey,
      group_id   => $group_id,
      created_at => $created_at,
      roles      => \@roles,
    );
    $event_hash = $event->to_hash;
  } elsif ($type eq 'put_user') {
    my $event = Net::Nostr::Group->put_user(
      pubkey     => $pubkey,
      group_id   => $group_id,
      target     => $spec->{target_pubkey},
      created_at => $created_at,
      roles      => $spec->{roles} || [],
    );
    $event_hash = $event->to_hash;
  } elsif ($type eq 'remove_user') {
    my $event = Net::Nostr::Group->remove_user(
      pubkey     => $pubkey,
      group_id   => $group_id,
      target     => $spec->{target_pubkey},
      created_at => $created_at,
      reason     => $spec->{reason} || '',
    );
    $event_hash = $event->to_hash;
  } elsif ($type eq 'invite') {
    my $event = Net::Nostr::Group->create_invite(
      pubkey     => $pubkey,
      group_id   => $group_id,
      code       => $spec->{code},
      created_at => $created_at,
      reason     => $spec->{reason} || '',
    );
    $event_hash = $event->to_hash;
    push @{$event_hash->{tags}}, [ 'p', $spec->{target_pubkey} ]
      if defined $spec->{target_pubkey};
  } elsif ($type eq 'join') {
    my $event = Net::Nostr::Group->join_request(
      pubkey     => $pubkey,
      group_id   => $group_id,
      created_at => $created_at,
      (defined($spec->{code}) ? (code => $spec->{code}) : ()),
      reason     => $spec->{reason} || '',
    );
    $event_hash = $event->to_hash;
    push @{$event_hash->{tags}}, [ 'overnet_irc_mask', $spec->{actor_mask} ]
      if defined $spec->{actor_mask};
  } elsif ($type eq 'part') {
    my $event = Net::Nostr::Group->leave_request(
      pubkey     => $pubkey,
      group_id   => $group_id,
      created_at => $created_at,
      reason     => $spec->{reason} || '',
    );
    $event_hash = $event->to_hash;
  } else {
    die "Unsupported authoritative_scenario event type: $type\n";
  }

  if (defined($spec->{actor_pubkey})) {
    push @{$event_hash->{tags}},
      [ 'overnet_actor', $spec->{actor_pubkey} ],
      [ 'overnet_authority', $spec->{authority_event_id} ],
      [ 'overnet_sequence', 0 + $spec->{authority_sequence} ];
  }

  return $event_hash;
}

sub _apply_metadata_tags {
  my ($event_hash, $spec) = @_;
  push @{$event_hash->{tags}}, [ 'mode', 'moderated' ]
    if $spec->{moderated};
  push @{$event_hash->{tags}}, [ 'mode', 'topic-restricted' ]
    if $spec->{topic_restricted};
  push @{$event_hash->{tags}}, map { [ 'ban', $_ ] } @{$spec->{ban_masks} || []};
  push @{$event_hash->{tags}}, map { [ 'except', $_ ] } @{$spec->{except_masks} || []};
  push @{$event_hash->{tags}}, map { [ 'invite-except', $_ ] } @{$spec->{invite_exception_masks} || []};
  push @{$event_hash->{tags}}, [ 'key', $spec->{key} ]
    if exists $spec->{key};
  push @{$event_hash->{tags}}, [ 'limit', 0 + $spec->{user_limit} ]
    if exists $spec->{user_limit};
  push @{$event_hash->{tags}}, [ 'topic', $spec->{topic} ]
    if exists $spec->{topic};
  push @{$event_hash->{tags}}, [ 'status', 'tombstoned' ]
    if $spec->{tombstoned};
}

sub _coerce_fixture_wire_event {
  my ($event_hash) = @_;
  return undef unless ref($event_hash) eq 'HASH';

  my $parsed = Overnet::Core::Nostr->event_from_wire($event_hash);
  return { %{$event_hash} } if $parsed;

  my %unsigned = %{$event_hash};
  delete @unsigned{qw(id pubkey sig)};
  my $key = Overnet::Core::Nostr->generate_key;
  return $key->sign_event_hash(event => \%unsigned);
}

sub _fixture_files {
  my ($family) = @_;
  my $dir = _fixture_dir($family);
  return () unless -d $dir;

  opendir my $dh, $dir or die "Can't open $dir: $!";
  my @files = sort grep { /\.json\z/ } readdir $dh;
  closedir $dh;
  return map { File::Spec->catfile($dir, $_) } @files;
}

sub _fixture_dir {
  my ($family) = @_;
  return File::Spec->catdir(_spec_root(), 'fixtures', $family);
}

sub _spec_root {
  return File::Spec->catdir(dirname(__FILE__), '..', '..', '..', '..', 'overnet-spec');
}

sub _load_fixture {
  my ($path) = @_;
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $json = do { local $/; <$fh> };
  close $fh;
  return decode_json($json);
}

sub _assertions {
  my ($root, $assertions) = @_;
  return unless ref($assertions) eq 'ARRAY';

  for my $assertion (@{$assertions}) {
    my $path = $assertion->{path};
    my $value = _path_get($root, $path);

    if (exists $assertion->{equals}) {
      is_deeply($value, $assertion->{equals}, "$path equals expected value");
      next;
    }

    fail("Unsupported assertion shape for path $path");
  }
}

sub _path_get {
  my ($root, $path) = @_;
  return $root unless defined $path && length $path;

  my @parts = split /\./, $path;
  my $value = $root;
  for my $part (@parts) {
    return undef unless defined $value;

    if (ref($value) eq 'HASH') {
      $value = $value->{$part};
      next;
    }

    if (ref($value) eq 'ARRAY' && $part =~ /\A\d+\z/) {
      $value = $value->[$part];
      next;
    }

    return undef;
  }

  return $value;
}

sub _contains_lines_in_order {
  my ($got, $expected) = @_;
  return 0 unless ref($got) eq 'ARRAY' && ref($expected) eq 'ARRAY';
  return 1 unless @{$expected};

  my $cursor = 0;
  for my $line (@{$got}) {
    next unless defined $line && defined $expected->[$cursor];
    if (_line_matches($line, $expected->[$cursor])) {
      $cursor++;
      return 1 if $cursor >= @{$expected};
    }
  }

  return 0;
}

sub _line_matches {
  my ($got, $expected) = @_;
  return 0 unless defined $got && defined $expected;
  return 1 if $got eq $expected;

  if (index($expected, '<base64_json_transport>') >= 0) {
    my $pattern = quotemeta($expected);
    $pattern =~ s/\\<base64_json_transport\\>/\\S+/g;
    return $got =~ /\A$pattern\z/ ? 1 : 0;
  }

  return 0;
}

sub _first_tag_values {
  my ($tags) = @_;
  my %values;

  for my $tag (@{$tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag} >= 2;
    next if exists $values{$tag->[0]};
    $values{$tag->[0]} = $tag->[1];
  }

  return \%values;
}

package Overnet::Test::SpecConformance::IRCServerHarness;

use strict;
use warnings;

our @ISA = ('Overnet::Program::IRC::Server');

sub _supported_capabilities {
  my ($self) = @_;
  return $self->SUPER::_supported_capabilities()
    if $self->{config}{use_server_capabilities};
  return @{$self->{config}{supported_capabilities} || []};
}

sub _send_client_line {
  my ($self, $client_id, $line) = @_;
  my $client = $self->{clients}{$client_id};
  $line = $self->_decorate_outbound_line_for_client($client, $line)
    if ref($client) eq 'HASH';
  push @{$self->{_spec_lines}{$client_id}}, $line;
  return 1;
}

sub _send_message { return 1 }
sub _log { return 1 }
sub _health { return 1 }
sub _ensure_client_dm_subscription { return 1 }
sub _ensure_channel_subscription { return 1 }
sub _close_channel_subscription { return 1 }
sub _close_client_dm_subscription { return 1 }
sub _ensure_authoritative_discovery_subscription { return 1 }
sub _refresh_authoritative_discovery_cache { return 1 }
sub _ensure_authoritative_channel_subscription { return 1 }

sub _sign_candidate_event {
  my ($self, $candidate) = @_;
  return {
    %{$candidate},
    id     => ('0' x 64),
    pubkey => ('1' x 64),
    sig    => ('2' x 128),
  };
}

sub _request {
  my ($self, %args) = @_;
  my $method = $args{method};
  my $params = $args{params} || {};

  if ($method eq 'adapters.map_input') {
    my $result = $self->{_spec_adapter}->map_input(
      %{$params->{input} || {}},
      session_config => $self->{config}{adapter_config},
    );
    my $normalized = _normalize_adapter_result_for_harness($result);
    $self->{_spec_last_map_result} = $normalized;
    return $normalized;
  }

  if ($method eq 'adapters.derive') {
    return _normalize_adapter_result_for_harness($self->{_spec_adapter}->derive(
      operation      => $params->{operation},
      session_config => $self->{config}{adapter_config},
      input          => $params->{input},
    ));
  }

  if ($method eq 'overnet.emit_event') {
    $self->{_spec_last_emitted_event} = $params->{event};
    push @{$self->{_spec_emits}}, { method => $method, params => $params };
    return {};
  }

  if ($method eq 'overnet.emit_state' || $method eq 'overnet.emit_private_message' || $method eq 'overnet.emit_capabilities') {
    push @{$self->{_spec_emits}}, { method => $method, params => $params };
    return {};
  }

  if ($method eq 'subscriptions.open' || $method eq 'subscriptions.close' || $method eq 'nostr.open_subscription' || $method eq 'nostr.close_subscription') {
    return {};
  }

  if ($method eq 'nostr.read_subscription_snapshot' || $method eq 'nostr.query_events') {
    return { events => [] };
  }

  if ($method eq 'nostr.publish_event') {
    return { accepted => JSON::PP::true };
  }

  return {};
}

sub _normalize_adapter_result_for_harness {
  my ($result) = @_;
  return {} unless ref($result) eq 'HASH';
  return $result if exists $result->{events}
    || exists $result->{state}
    || exists $result->{view}
    || exists $result->{admission}
    || exists $result->{permission}
    || exists $result->{capabilities};

  my %normalized;
  if (exists $result->{event}) {
    if (($result->{event}{kind} || 0) == 37800) {
      $normalized{state} = [ $result->{event} ];
    } else {
      $normalized{events} = [ $result->{event} ];
    }
  }
  if (exists $result->{events}) {
    $normalized{events} = $result->{events};
  }
  return {
    %{$result},
    %normalized,
  };
}

sub _read_authoritative_nip29_events {
  my ($self, $channel, %args) = @_;
  my $canonical = $self->_canonical_channel_name($channel);
  my $entry = $self->{_spec_authoritative_channels}{$canonical} || {};
  return [ @{$entry->{events} || []} ];
}

sub _refresh_authoritative_nip29_channel_cache {
  my ($self, $channel, %args) = @_;
  my $canonical = $self->_canonical_channel_name($channel);
  my $events = $self->_read_authoritative_nip29_events($canonical, %args);
  $self->{authoritative_channel_cache}{$canonical} = {
    events => $events,
    view   => $self->_derive_authoritative_channel_view_from_events($canonical, $events),
  };
  return $events;
}

1;
