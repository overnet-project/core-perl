use strict;
use warnings;
use Test::More;
use JSON::PP qw(decode_json encode_json);
use File::Spec;
use File::Temp qw(tempdir);
use FindBin;
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL qw(SSL_VERIFY_NONE);
use IO::Socket::SSL::Utils qw(CERT_create PEM_cert2file PEM_key2file);
use Time::HiRes qw(time);

use Net::Nostr::Event;
use Net::Nostr::Key;
use Overnet::Program::Host;
use Overnet::Program::Runtime;

my $program_path = File::Spec->catfile($FindBin::Bin, '..', '..', 'overnet-program-irc', 'bin', 'overnet-irc-server.pl');
my $irc_lib = File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-adapter-irc', 'lib');
my $spec_irc_dir = File::Spec->catdir($FindBin::Bin, '..', '..', 'overnet-spec', 'fixtures', 'irc');

sub _load_irc_fixture {
  my ($name) = @_;
  my $path = File::Spec->catfile($spec_irc_dir, $name);
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $json = do { local $/; <$fh> };
  close $fh;
  return decode_json($json);
}

sub _method_count {
  my ($entries, $direction, $type, $method) = @_;
  my $count = 0;

  for my $entry (@{$entries}) {
    next unless ($entry->{direction} || '') eq $direction;
    next unless ($entry->{message}{type} || '') eq $type;
    next unless ($entry->{message}{method} || '') eq $method;
    $count++;
  }

  return $count;
}

sub _request_count_matching {
  my ($entries, $direction, $method, $predicate) = @_;
  my $count = 0;

  for my $entry (@{$entries}) {
    next unless ($entry->{direction} || '') eq $direction;
    next unless ($entry->{message}{type} || '') eq 'request';
    next unless ($entry->{message}{method} || '') eq $method;
    next if $predicate && !$predicate->($entry->{message}{params} || {});
    $count++;
  }

  return $count;
}

sub _wait_for_ready_details {
  my ($host) = @_;

  my $ready = $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      my ($current_host) = @_;
      for my $notification (@{$current_host->observed_notifications}) {
        next unless ($notification->{method} || '') eq 'program.health';
        next unless ($notification->{params}{status} || '') eq 'ready';
        next unless ref($notification->{params}{details}) eq 'HASH';
        return 1 if defined $notification->{params}{details}{listen_port};
      }
      return 0;
    },
  );
  return undef unless $ready;

  for my $notification (@{$host->observed_notifications}) {
    next unless ($notification->{method} || '') eq 'program.health';
    next unless ($notification->{params}{status} || '') eq 'ready';
    next unless ref($notification->{params}{details}) eq 'HASH';
    return $notification->{params}{details};
  }

  return undef;
}

sub _wait_for_dm_subscription_count {
  my ($host, $count) = @_;

  return $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      _request_count_matching(
        $_[0]->transcript,
        'from_program',
        'subscriptions.open',
        sub { (($_[0]{subscription_id} || '') =~ /\Adm:/) ? 1 : 0 },
      ) >= $count;
    },
  );
}

sub _connect_irc_client {
  my ($port) = @_;

  my $socket = IO::Socket::INET->new(
    PeerHost => '127.0.0.1',
    PeerPort => $port,
    Proto    => 'tcp',
    Timeout  => 1,
  ) or die "Can't connect fake IRC client to 127.0.0.1:$port: $!";

  binmode($socket, ':raw');
  $socket->autoflush(1);
  return {
    socket      => $socket,
    read_buffer => '',
  };
}

sub _connect_irc_client_tls {
  my ($port) = @_;

  my $socket = IO::Socket::SSL->new(
    PeerHost        => '127.0.0.1',
    PeerPort        => $port,
    SSL_verify_mode => SSL_VERIFY_NONE,
    Timeout         => 1,
  ) or die "Can't connect fake TLS IRC client to 127.0.0.1:$port: " . IO::Socket::SSL::errstr();

  binmode($socket, ':raw');
  $socket->autoflush(1);
  return {
    socket      => $socket,
    read_buffer => '',
  };
}

sub _read_client_line {
  my ($client, $timeout_ms) = @_;
  my (undef, $caller_file, $caller_line) = caller;

  while ($client->{read_buffer} !~ /\n/) {
    my $selector = IO::Select->new($client->{socket});
    my @ready = $selector->can_read($timeout_ms / 1000);
    die "Timed out waiting for IRC client line at $caller_file line $caller_line\n"
      unless @ready;

    my $bytes = sysread($client->{socket}, my $chunk, 4096);
    die "IRC client disconnected before sending a line at $caller_file line $caller_line\n"
      unless defined $bytes && $bytes > 0;
    $client->{read_buffer} .= $chunk;
  }

  $client->{read_buffer} =~ s/\A([^\n]*\n)//;
  my $line = $1;
  $line =~ s/\r?\n\z//;
  return $line;
}

sub _read_client_lines {
  my ($client, $count, $timeout_ms) = @_;
  my @lines;

  for (1 .. $count) {
    push @lines, _read_client_line($client, $timeout_ms);
  }

  return @lines;
}

sub _assert_registration_prelude {
  my (%args) = @_;
  my $client = $args{client};
  my $nick = $args{nick};
  my $network = $args{network};
  my $server_name = $args{server_name} || 'overnet.irc.local';

  is_deeply [
    _read_client_lines($client, 3, 1_000),
  ], [
    sprintf(':%s 001 %s :Welcome to Overnet IRC', $server_name, $nick),
    sprintf(':%s 005 %s CASEMAPPING=rfc1459 CHANTYPES=#& NETWORK=%s :are supported by this server', $server_name, $nick, $network),
    sprintf(':%s 422 %s :MOTD File is missing', $server_name, $nick),
  ], "$nick receives the minimal registration prelude";
}

sub _read_client_line_optional {
  my ($client, $timeout_ms) = @_;
  my (undef, $caller_file, $caller_line) = caller;

  while ($client->{read_buffer} !~ /\n/) {
    my $selector = IO::Select->new($client->{socket});
    my @ready = $selector->can_read($timeout_ms / 1000);
    return undef unless @ready;

    my $bytes = sysread($client->{socket}, my $chunk, 4096);
    die "IRC client disconnected unexpectedly at $caller_file line $caller_line\n"
      unless defined $bytes && $bytes > 0;
    $client->{read_buffer} .= $chunk;
  }

  $client->{read_buffer} =~ s/\A([^\n]*\n)//;
  my $line = $1;
  $line =~ s/\r?\n\z//;
  return $line;
}

sub _write_client_line {
  my ($client, $line) = @_;

  my $payload = $line . "\r\n";
  my $offset = 0;
  while ($offset < length $payload) {
    my $written = syswrite($client->{socket}, $payload, length($payload) - $offset, $offset);
    die "Failed to write fake IRC client line: $!\n"
      unless defined $written;
    $offset += $written;
  }
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

sub _find_emitted_item {
  my ($items, %args) = @_;

  for my $item (@{$items}) {
    next if defined $args{item_type} && ($item->{item_type} || '') ne $args{item_type};
    next unless ref($item->{data}) eq 'HASH';

    my %tags = _first_tag_values($item->{data}{tags});
    next if defined $args{overnet_et} && ($tags{overnet_et} || '') ne $args{overnet_et};
    next if defined $args{overnet_ot} && ($tags{overnet_ot} || '') ne $args{overnet_ot};
    next if defined $args{overnet_oid} && ($tags{overnet_oid} || '') ne $args{overnet_oid};

    return $item;
  }

  return undef;
}

sub _count_emitted_items {
  my ($items, %args) = @_;
  my $count = 0;

  for my $item (@{$items}) {
    next if defined $args{item_type} && ($item->{item_type} || '') ne $args{item_type};
    next unless ref($item->{data}) eq 'HASH';

    my %tags = _first_tag_values($item->{data}{tags});
    next if defined $args{overnet_et} && ($tags{overnet_et} || '') ne $args{overnet_et};
    next if defined $args{overnet_ot} && ($tags{overnet_ot} || '') ne $args{overnet_ot};
    next if defined $args{overnet_oid} && ($tags{overnet_oid} || '') ne $args{overnet_oid};

    $count++;
  }

  return $count;
}

sub _assert_signed_emitted_matches_fixture {
  my ($item, $expected, $key, $label, $time_window, $content_override) = @_;
  my $data = $item->{data};
  my $expected_content = defined $content_override
    ? $content_override
    : decode_json($expected->{content});

  like $data->{id}, qr/\A[0-9a-f]{64}\z/, "$label has a signed event id";
  like $data->{sig}, qr/\A[0-9a-f]{128}\z/, "$label has a Schnorr signature";
  is $data->{pubkey}, $key->pubkey_hex, "$label is signed by the configured key";
  is $data->{kind}, $expected->{kind}, "$label kind matches fixture";
  cmp_ok $data->{created_at}, '>=', $time_window->{min}, "$label created_at is not before send time";
  cmp_ok $data->{created_at}, '<=', $time_window->{max}, "$label created_at is within the send window";
  is_deeply $data->{tags}, $expected->{tags}, "$label tags match fixture";
  is_deeply decode_json($data->{content}), $expected_content,
    "$label content matches fixture semantically";

  my $event = Net::Nostr::Event->from_wire($data);
  ok eval { $event->validate; 1 }, "$label validates as a signed Nostr event";
}

subtest 'IRC server program enforces nick uniqueness and emits 433 for collisions' => sub {
  my $privmsg = _load_irc_fixture('valid-channel-privmsg.json');
  my $network_object_id = 'irc:' . $privmsg->{input}{network};

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-test-key.pem');
  my $key = Net::Nostr::Key->new;
  $key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.real',
      network          => $privmsg->{input}{network},
      listen_host      => '127.0.0.1',
      listen_port      => 0,
      server_name      => 'overnet.irc.local',
      signing_key_file => $key_path,
      adapter_config   => {},
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real IRC adapter for nick-collision coverage';

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'      => {},
      'adapters.map_input'         => {},
      'adapters.close_session'     => {},
      'subscriptions.open'         => {},
      'subscriptions.close'        => {},
      'overnet.emit_event'         => {},
      'overnet.emit_state'         => {},
      'overnet.emit_capabilities'  => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'nick-collision server reaches ready state';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'nick-collision server publishes ready health details';
  ok defined $ready_details->{listen_port} && $ready_details->{listen_port} > 0,
    'nick-collision server exposes the bound listen port';

  my $alice = _connect_irc_client($ready_details->{listen_port});
  my $bob   = _connect_irc_client($ready_details->{listen_port});
  my $carol = _connect_irc_client($ready_details->{listen_port});
  my $dave  = _connect_irc_client($ready_details->{listen_port});
  my $erin  = _connect_irc_client($ready_details->{listen_port});
  my $frank = _connect_irc_client($ready_details->{listen_port});

  _write_client_line($alice, 'NICK alice');
  _write_client_line($bob, 'NICK alice');
  is _read_client_line($bob, 1_000), ':overnet.irc.local 433 * alice :Nickname is already in use',
    'unregistered nick collision returns 433 with * target';

  _write_client_line($alice, 'USER alice 0 * :Alice Example');
  _assert_registration_prelude(
    client  => $alice,
    nick    => 'alice',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'alice registration completes the first DM subscription open';

  _write_client_line($bob, 'NICK bob');
  _write_client_line($bob, 'USER bob 0 * :Bob Example');
  _assert_registration_prelude(
    client  => $bob,
    nick    => 'bob',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 2),
    'bob registration completes the second DM subscription open';

  _write_client_line($bob, 'NICK alice');
  is _read_client_line($bob, 1_000), ':overnet.irc.local 433 bob alice :Nickname is already in use',
    'registered nick collision returns 433 with the current nick target';

  _write_client_line($alice, 'NICK alice_');
  is _read_client_line($alice, 1_000), ':alice NICK :alice_',
    'successful nick change is rendered back to the client';
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'irc.nick',
        overnet_ot  => 'irc.network',
        overnet_oid => $network_object_id,
      );
    },
  ), 'successful nick change is emitted through the runtime';

  _write_client_line($carol, 'NICK alice');
  _write_client_line($carol, 'USER carol 0 * :Carol Example');
  _assert_registration_prelude(
    client  => $carol,
    nick    => 'alice',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 3),
    'carol registration completes its DM subscription open';

  _write_client_line($bob, 'QUIT :bye');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      _request_count_matching(
        $_[0]->transcript,
        'from_program',
        'subscriptions.close',
        sub { (($_[0]{subscription_id} || '') =~ /\Adm:/) ? 1 : 0 },
      ) >= 2;
    },
  ), 'bob quit completes its DM subscription close';
  my $bob_closed = eval {
    _read_client_line($bob, 500);
    '';
  };
  like $@, qr/IRC client disconnected before sending a line/,
    'server closes the client connection after QUIT';

  _write_client_line($dave, 'NICK bob');
  _write_client_line($dave, 'USER dave 0 * :Dave Example');
  _assert_registration_prelude(
    client  => $dave,
    nick    => 'bob',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 5),
    'dave registration completes its DM subscription open';

  _write_client_line($erin, 'NICK erin');
  close $erin->{socket};
  ok $host->pump(timeout_ms => 200) >= 0,
    'server continues running after an unregistered client disconnects';
  _write_client_line($frank, 'NICK erin');
  _write_client_line($frank, 'USER frank 0 * :Frank Example');
  _assert_registration_prelude(
    client  => $frank,
    nick    => 'erin',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 6),
    'frank registration completes its DM subscription open';

  is _method_count($host->transcript, 'from_program', 'request', 'adapters.map_input'), 1,
    'only the successful registered nick change reaches adapter mapping';

  my $shutdown = $host->request_shutdown(reason => 'nick collision test complete');
  is $shutdown->{state}, 'shutdown_complete', 'nick-collision server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'nick-collision server exits cleanly';

  close $alice->{socket};
  close $carol->{socket};
  close $dave->{socket};
  close $frank->{socket};
};

subtest 'IRC server program supports a minimal IRC client compatibility slice' => sub {
  my $privmsg = _load_irc_fixture('valid-channel-privmsg.json');
  my $network = $privmsg->{input}{network};
  my $channel_object_id = 'irc:' . $network . ':#OverNet';

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-test-key.pem');
  my $key = Net::Nostr::Key->new;
  $key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.real',
      network          => $network,
      listen_host      => '127.0.0.1',
      listen_port      => 0,
      server_name      => 'overnet.irc.local',
      signing_key_file => $key_path,
      adapter_config   => {},
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real IRC adapter for compatibility coverage';

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'      => {},
      'adapters.map_input'         => {},
      'adapters.close_session'     => {},
      'subscriptions.open'         => {},
      'subscriptions.close'        => {},
      'overnet.emit_event'         => {},
      'overnet.emit_state'         => {},
      'overnet.emit_capabilities'  => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'compatibility server reaches ready state';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'compatibility server publishes ready health details';
  ok defined $ready_details->{listen_port} && $ready_details->{listen_port} > 0,
    'compatibility server exposes the bound listen port';

  my $alice = _connect_irc_client($ready_details->{listen_port});
  my $bob   = _connect_irc_client($ready_details->{listen_port});

  _write_client_line($alice, 'CAP LS 302');
  is _read_client_line($alice, 1_000), ':overnet.irc.local CAP * LS :',
    'CAP LS returns an empty capability advertisement';

  _write_client_line($alice, 'CAP REQ :multi-prefix sasl');
  is _read_client_line($alice, 1_000), ':overnet.irc.local CAP * NAK :multi-prefix sasl',
    'CAP REQ returns NAK for unsupported capabilities';

  _write_client_line($alice, 'CAP END');
  is _read_client_line_optional($alice, 200), undef,
    'CAP END does not emit any compatibility reply';

  _write_client_line($alice, 'JOIN #overnet');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 451 * :You have not registered',
    'pre-registration JOIN returns 451';

  _write_client_line($alice, 'MODE #overnet');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 451 * :You have not registered',
    'pre-registration MODE returns 451';

  _write_client_line($alice, 'USERHOST Alice');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 451 * :You have not registered',
    'pre-registration USERHOST returns 451';

  _write_client_line($alice, 'WHO #overnet');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 451 * :You have not registered',
    'pre-registration WHO returns 451';

  _write_client_line($alice, 'WHOIS Alice');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 451 * :You have not registered',
    'pre-registration WHOIS returns 451';

  _write_client_line($alice, 'LUSERS');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 451 * :You have not registered',
    'pre-registration LUSERS returns 451';

  _write_client_line($alice, 'LIST');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 451 * :You have not registered',
    'pre-registration LIST returns 451';

  _write_client_line($alice, 'NICK');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 431 * :No nickname given',
    'bare NICK returns 431';

  _write_client_line($alice, 'USER alice 0 *');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 461 * USER :Not enough parameters',
    'short USER returns 461';

  _write_client_line($alice, 'NICK Alice');
  _write_client_line($alice, 'USER alice 0 * :Alice Example');
  _assert_registration_prelude(
    client  => $alice,
    nick    => 'Alice',
    network => $network,
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'alice registration completes its DM subscription open';

  _write_client_line($alice, 'LUSERS');
  is_deeply [
    _read_client_lines($alice, 5, 1_000),
  ], [
    ':overnet.irc.local 251 Alice :There are 1 users and 0 services on 1 server',
    ':overnet.irc.local 252 Alice 0 :operator(s) online',
    ':overnet.irc.local 253 Alice 0 :unknown connection(s)',
    ':overnet.irc.local 254 Alice 0 :channels formed',
    ':overnet.irc.local 255 Alice :I have 2 clients and 1 server',
  ], 'LUSERS returns the minimal reply set';

  _write_client_line($alice, 'USERHOST');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 461 Alice USERHOST :Not enough parameters',
    'USERHOST without a nick returns 461';

  _write_client_line($alice, 'WHO');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 461 Alice WHO :Not enough parameters',
    'WHO without a target returns 461';

  _write_client_line($alice, 'WHOIS');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 461 Alice WHOIS :Not enough parameters',
    'WHOIS without a nick returns 461';

  _write_client_line($alice, 'TOPIC');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 461 Alice TOPIC :Not enough parameters',
    'TOPIC without a target returns 461';

  _write_client_line($alice, 'USERHOST aLiCe');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 302 Alice :Alice=+alice@127.0.0.1',
    'USERHOST uses folded nick lookup and returns a minimal 302 reply';

  _write_client_line($alice, 'WHOIS aLiCe');
  is_deeply [
    _read_client_lines($alice, 3, 1_000),
  ], [
    ':overnet.irc.local 311 Alice Alice alice 127.0.0.1 * :Alice Example',
    ':overnet.irc.local 312 Alice Alice overnet.irc.local :Overnet IRC',
    ':overnet.irc.local 318 Alice Alice :End of /WHOIS list.',
  ], 'WHOIS uses folded nick lookup and returns minimal WHOIS replies';

  _write_client_line($alice, 'FROB');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 421 Alice FROB :Unknown command',
    'unknown registered commands return 421';

  _write_client_line($alice, 'PART #Elsewhere');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 442 Alice #Elsewhere :You\'re not on that channel',
    'PART on an unjoined channel returns 442';

  _write_client_line($alice, 'MODE');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 461 Alice MODE :Not enough parameters',
    'MODE without a target returns 461';

  _write_client_line($alice, 'MODE aLiCe');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 221 Alice +',
    'self MODE query uses folded nick lookup and returns a minimal user mode reply';

  _write_client_line($alice, 'MODE #Elsewhere');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 442 Alice #Elsewhere :You\'re not on that channel',
    'MODE on an unjoined channel returns 442';

  _write_client_line($alice, 'WHO #Elsewhere');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 442 Alice #Elsewhere :You\'re not on that channel',
    'WHO on an unjoined channel returns 442';

  _write_client_line($alice, 'TOPIC #Elsewhere');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 442 Alice #Elsewhere :You\'re not on that channel',
    'TOPIC query on an unjoined channel returns 442';

  _write_client_line($alice, 'JOIN alice');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 403 Alice alice :No such channel',
    'JOIN on a non-channel target returns 403';

  _write_client_line($alice, 'PRIVMSG MissingNick :hello');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 401 Alice MissingNick :No such nick/channel',
    'PRIVMSG to a missing nick returns 401';

  _write_client_line($alice, 'WHOIS MissingNick');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 401 Alice MissingNick :No such nick/channel',
    'WHOIS for a missing nick returns 401';

  _write_client_line($bob, 'NICK aLICE');
  is _read_client_line($bob, 1_000), ':overnet.irc.local 433 * aLICE :Nickname is already in use',
    'nick uniqueness uses RFC1459-style case-folding';

  _write_client_line($alice, 'JOIN #OverNet');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.join',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'case-folded JOIN is emitted on the canonical channel object';
  is_deeply [
    _read_client_lines($alice, 3, 1_000),
  ], [
    ':Alice JOIN #OverNet',
    ':overnet.irc.local 353 Alice = #OverNet :Alice',
    ':overnet.irc.local 366 Alice #OverNet :End of /NAMES list.',
  ], 'join preserves the first presentational channel spelling and returns bootstrap lines';

  _write_client_line($alice, 'MODE #oVERnEt');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 324 Alice #OverNet +n',
    'MODE query uses folded channel lookup and canonical channel spelling';

  _write_client_line($alice, 'NAMES #oVERnEt');
  is_deeply [
    _read_client_lines($alice, 2, 1_000),
  ], [
    ':overnet.irc.local 353 Alice = #OverNet :Alice',
    ':overnet.irc.local 366 Alice #OverNet :End of /NAMES list.',
  ], 'explicit NAMES uses the canonical channel spelling after case-folded lookup';

  _write_client_line($alice, 'TOPIC #oVERnEt');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 331 Alice #OverNet :No topic is set',
    'TOPIC query returns 331 when no topic is known';

  _write_client_line($alice, 'WHO #oVERnEt');
  is_deeply [
    _read_client_lines($alice, 2, 1_000),
  ], [
    ':overnet.irc.local 352 Alice #OverNet alice 127.0.0.1 overnet.irc.local Alice H :0 Alice Example',
    ':overnet.irc.local 315 Alice #OverNet :End of /WHO list.',
  ], 'WHO query uses folded channel lookup and returns minimal WHO replies';

  _write_client_line($alice, 'PRIVMSG #oVERnEt :Casefolded hello');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.message',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'case-folded channel PRIVMSG is emitted on the canonical channel object';
  is _read_client_line($alice, 1_000), ':Alice PRIVMSG #OverNet :Casefolded hello',
    'case-folded channel PRIVMSG renders back using the canonical channel spelling';

  _write_client_line($alice, 'TOPIC #oVERnEt :Compatibility topic');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'state',
        overnet_et  => 'chat.topic',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'TOPIC set in compatibility coverage is emitted through the runtime';
  is _read_client_line($alice, 1_000), ':Alice TOPIC #OverNet :Compatibility topic',
    'TOPIC set renders back through the subscription path';

  _write_client_line($alice, 'TOPIC #oVERnEt');
  is _read_client_line($alice, 1_000), ':overnet.irc.local 332 Alice #OverNet :Compatibility topic',
    'TOPIC query returns 332 when a topic is known';

  _write_client_line($alice, 'LIST');
  is_deeply [
    _read_client_lines($alice, 3, 1_000),
  ], [
    ':overnet.irc.local 321 Alice Channel :Users Name',
    ':overnet.irc.local 322 Alice #OverNet 1 :Compatibility topic',
    ':overnet.irc.local 323 Alice :End of /LIST',
  ], 'LIST returns the current exposed channel state';

  my $shutdown = $host->request_shutdown(reason => 'compatibility test complete');
  is $shutdown->{state}, 'shutdown_complete', 'compatibility server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'compatibility server exits cleanly';

  close $alice->{socket};
  close $bob->{socket};
};

subtest 'IRC server program accepts clients, emits Overnet output, and fans channel items back out' => sub {
  my $join = _load_irc_fixture('valid-channel-join.json');
  my $privmsg = _load_irc_fixture('valid-channel-privmsg.json');
  my $part = _load_irc_fixture('valid-channel-part.json');
  my $quit = _load_irc_fixture('valid-channel-quit.json');
  my $nick = _load_irc_fixture('valid-network-nick.json');
  my $topic = _load_irc_fixture('valid-channel-topic.json');
  my $channel_object_id = 'irc:' . $privmsg->{input}{network} . ':' . $privmsg->{input}{target};
  my $network_object_id = 'irc:' . $privmsg->{input}{network};

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-test-key.pem');
  my $key = Net::Nostr::Key->new;
  $key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.real',
      network          => $privmsg->{input}{network},
      listen_host      => '127.0.0.1',
      listen_port      => 0,
      server_name      => 'overnet.irc.local',
      signing_key_file => $key_path,
      adapter_config   => {},
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real IRC adapter for the program';

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'      => {},
      'adapters.map_input'         => {},
      'adapters.close_session'     => {},
      'subscriptions.open'         => {},
      'subscriptions.close'        => {},
      'overnet.emit_event'         => {},
      'overnet.emit_state'         => {},
      'overnet.emit_capabilities'  => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'program reaches ready state under Host supervision';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'program publishes ready health details';
  is $ready_details->{server_name}, 'overnet.irc.local', 'ready health exposes configured server name';
  ok defined $ready_details->{listen_port} && $ready_details->{listen_port} > 0,
    'ready health exposes the bound listen port';

  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub { scalar(@{$runtime->adapter_session_ids}) == 1 },
  ), 'program opens a long-lived IRC adapter session after startup';

  my $alice = _connect_irc_client($ready_details->{listen_port});
  my $bob = _connect_irc_client($ready_details->{listen_port});

  _write_client_line($alice, 'NICK alice');
  _write_client_line($alice, 'USER alice 0 * :Alice Example');
  _assert_registration_prelude(
    client  => $alice,
    nick    => 'alice',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'alice registration completes the first DM subscription open';

  _write_client_line($bob, 'NICK bob');
  _write_client_line($bob, 'USER bob 0 * :Bob Example');
  _assert_registration_prelude(
    client  => $bob,
    nick    => 'bob',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 2),
    'bob registration completes the second DM subscription open';

  _write_client_line($alice, 'JOIN #overnet');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type  => 'event',
        overnet_et => 'chat.join',
        overnet_ot => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'alice join is emitted through the runtime';
  is_deeply [
    _read_client_lines($alice, 3, 1_000)
  ], [
    ':alice JOIN #overnet',
    ':overnet.irc.local 353 alice = #overnet :alice',
    ':overnet.irc.local 366 alice #overnet :End of /NAMES list.',
  ], 'alice receives JOIN plus the minimal NAMES bootstrap';

  my $privmsg_window = {
    min => int(time()) - 1,
    max => int(time()) + 5,
  };
  _write_client_line($alice, 'PRIVMSG #overnet :Hello from IRC!');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type  => 'event',
        overnet_et => 'chat.message',
        overnet_ot => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'alice channel message is emitted through the runtime';
  is _read_client_line($alice, 1_000), ':alice PRIVMSG #overnet :Hello from IRC!',
    'alice receives the subscription-driven PRIVMSG render';
  is _read_client_line_optional($bob, 200), undef,
    'bob does not receive channel renders before joining the channel';

  _write_client_line($bob, 'JOIN #overnet');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      _count_emitted_items(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.join',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      ) >= 2;
    },
  ), 'bob join is emitted through the runtime';
  is _read_client_line($alice, 1_000), ':bob JOIN #overnet',
    'joined clients receive later join lines';
  is_deeply [
    _read_client_lines($bob, 3, 1_000)
  ], [
    ':bob JOIN #overnet',
    ':overnet.irc.local 353 bob = #overnet :alice bob',
    ':overnet.irc.local 366 bob #overnet :End of /NAMES list.',
  ], 'joining client receives its own join line plus NAMES bootstrap';

  my $topic_window = {
    min => int(time()) - 1,
    max => int(time()) + 5,
  };
  _write_client_line($bob, 'TOPIC #overnet :Overnet discussion and implementation');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type  => 'state',
        overnet_et => 'chat.topic',
        overnet_ot => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'bob topic update is emitted through the runtime';
  is _read_client_line($alice, 1_000), ':bob TOPIC #overnet :Overnet discussion and implementation',
    'alice receives subscription-driven TOPIC fanout';
  is _read_client_line($bob, 1_000), ':bob TOPIC #overnet :Overnet discussion and implementation',
    'bob receives subscription-driven TOPIC fanout';

  my $carol = _connect_irc_client($ready_details->{listen_port});
  _write_client_line($carol, 'NICK carol');
  _write_client_line($carol, 'USER carol 0 * :Carol Example');
  _assert_registration_prelude(
    client  => $carol,
    nick    => 'carol',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 3),
    'carol registration completes its DM subscription open';

  _write_client_line($carol, 'JOIN #overnet');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      _count_emitted_items(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.join',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      ) >= 3;
    },
  ), 'carol join is emitted through the runtime';
  is _read_client_line($alice, 1_000), ':carol JOIN #overnet',
    'existing joined clients receive carol join lines';
  is _read_client_line($bob, 1_000), ':carol JOIN #overnet',
    'all joined clients receive carol join lines';
  is_deeply [
    _read_client_lines($carol, 4, 1_000)
  ], [
    ':carol JOIN #overnet',
    ':bob TOPIC #overnet :Overnet discussion and implementation',
    ':overnet.irc.local 353 carol = #overnet :alice bob carol',
    ':overnet.irc.local 366 carol #overnet :End of /NAMES list.',
  ], 'carol receives join, topic replay, and NAMES bootstrap';

  my $nick_window = {
    min => int(time()) - 1,
    max => int(time()) + 5,
  };
  _write_client_line($alice, 'NICK alice_');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'irc.nick',
        overnet_ot  => 'irc.network',
        overnet_oid => $network_object_id,
      );
    },
  ), 'alice nick change is emitted through the runtime';
  is _read_client_line($alice, 1_000), ':alice NICK :alice_',
    'alice receives her own NICK line';
  is _read_client_line($bob, 1_000), ':alice NICK :alice_',
    'bob receives alice nick change';
  is _read_client_line($carol, 1_000), ':alice NICK :alice_',
    'carol receives alice nick change';

  _write_client_line($alice, 'PART #overnet :bye');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.part',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'alice part is emitted through the runtime';
  is _read_client_line($alice, 1_000), ':alice_ PART #overnet :bye',
    'alice receives her own PART line';
  is _read_client_line($bob, 1_000), ':alice_ PART #overnet :bye',
    'remaining channel members receive PART lines';
  is _read_client_line($carol, 1_000), ':alice_ PART #overnet :bye',
    'all remaining channel members receive PART lines';

  _write_client_line($bob, 'NOTICE #overnet :Only Bob now');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type  => 'event',
        overnet_et => 'chat.notice',
        overnet_ot => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'bob notice is emitted through the runtime';
  is _read_client_line($bob, 1_000), ':bob NOTICE #overnet :Only Bob now',
    'bob receives subscription-driven NOTICE fanout';
  is _read_client_line($carol, 1_000), ':bob NOTICE #overnet :Only Bob now',
    'carol receives subscription-driven NOTICE fanout';
  is _read_client_line_optional($alice, 200), undef,
    'alice no longer receives renders after parting the channel';

  my $quit_window = {
    min => int(time()) - 1,
    max => int(time()) + 5,
  };
  _write_client_line($bob, 'QUIT :gone');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.quit',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'bob quit is emitted through the runtime';
  is _read_client_line($carol, 1_000), ':bob QUIT :gone',
    'remaining shared channel members receive QUIT lines';
  is _read_client_line_optional($alice, 200), undef,
    'parted clients do not receive later QUIT lines';
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      _request_count_matching(
        $_[0]->transcript,
        'from_program',
        'subscriptions.close',
        sub { (($_[0]{subscription_id} || '') =~ /\Adm:/) ? 1 : 0 },
      ) >= 2;
    },
  ), 'bob quit completes its DM subscription close before later client input';

  _write_client_line($carol, 'PART #overnet :done');
  is _read_client_line($carol, 1_000), ':carol PART #overnet :done',
    'carol receives her own final PART line';
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      _method_count($_[0]->transcript, 'from_program', 'request', 'subscriptions.close') >= 1
        && _count_emitted_items(
          $_[0]->runtime->emitted_items,
          item_type   => 'event',
          overnet_et  => 'chat.part',
          overnet_ot  => 'chat.channel',
          overnet_oid => $channel_object_id,
        ) >= 2;
    },
  ), 'program completes the final PART emit flow and closes the runtime subscription';

  my $emitted = $runtime->emitted_items;
  is _count_emitted_items(
    $emitted,
    item_type   => 'event',
    overnet_et  => 'chat.join',
    overnet_ot  => 'chat.channel',
    overnet_oid => $channel_object_id,
  ), 3, 'runtime recorded three channel join events';
  my $message_item = _find_emitted_item(
    $emitted,
    item_type   => 'event',
    overnet_et  => 'chat.message',
    overnet_ot  => 'chat.channel',
    overnet_oid => $channel_object_id,
  );
  ok $message_item, 'runtime recorded the channel message event';
  _assert_signed_emitted_matches_fixture(
    $message_item,
    $privmsg->{expected}{event},
    $key,
    'mapped channel PRIVMSG event',
    $privmsg_window,
  );

  my $topic_item = _find_emitted_item(
    $emitted,
    item_type   => 'state',
    overnet_et  => 'chat.topic',
    overnet_ot  => 'chat.channel',
    overnet_oid => $channel_object_id,
  );
  ok $topic_item, 'runtime recorded the channel topic state';
  my $topic_expected_content = decode_json($topic->{expected}{event}{content});
  $topic_expected_content->{provenance}{external_identity} = 'bob';
  _assert_signed_emitted_matches_fixture(
    $topic_item,
    $topic->{expected}{event},
    $key,
    'mapped channel TOPIC state',
    $topic_window,
    $topic_expected_content,
  );

  my $notice_item = _find_emitted_item(
    $emitted,
    item_type   => 'event',
    overnet_et  => 'chat.notice',
    overnet_ot  => 'chat.channel',
    overnet_oid => $channel_object_id,
  );
  ok $notice_item, 'runtime recorded the channel notice event';
  my $notice_event = Net::Nostr::Event->from_wire($notice_item->{data});
  ok eval { $notice_event->validate; 1 }, 'mapped channel notice validates as a signed Nostr event';

  my $nick_item = _find_emitted_item(
    $emitted,
    item_type   => 'event',
    overnet_et  => 'irc.nick',
    overnet_ot  => 'irc.network',
    overnet_oid => $network_object_id,
  );
  ok $nick_item, 'runtime recorded the network nick event';
  _assert_signed_emitted_matches_fixture(
    $nick_item,
    $nick->{expected}{event},
    $key,
    'mapped network NICK event',
    $nick_window,
  );

  my $part_item = _find_emitted_item(
    $emitted,
    item_type   => 'event',
    overnet_et  => 'chat.part',
    overnet_ot  => 'chat.channel',
    overnet_oid => $channel_object_id,
  );
  ok $part_item, 'runtime recorded the channel part event';
  my $part_expected_content = decode_json($part->{expected}{event}{content});
  $part_expected_content->{provenance}{external_identity} = 'alice_';
  _assert_signed_emitted_matches_fixture(
    $part_item,
    $part->{expected}{event},
    $key,
    'mapped channel PART event',
    {
      min => int(time()) - 10,
      max => int(time()) + 5,
    },
    $part_expected_content,
  );

  my $quit_item = _find_emitted_item(
    $emitted,
    item_type   => 'event',
    overnet_et  => 'chat.quit',
    overnet_ot  => 'chat.channel',
    overnet_oid => $channel_object_id,
  );
  ok $quit_item, 'runtime recorded the channel quit event';
  my $quit_expected_content = decode_json($quit->{expected}{event}{content});
  $quit_expected_content->{provenance}{external_identity} = 'bob';
  $quit_expected_content->{body}{reason} = 'gone';
  _assert_signed_emitted_matches_fixture(
    $quit_item,
    $quit->{expected}{event},
    $key,
    'mapped channel QUIT event',
    $quit_window,
    $quit_expected_content,
  );

  my $transcript = $host->transcript;
  is _request_count_matching(
    $transcript,
    'from_program',
    'subscriptions.open',
    sub { (($_[0]{subscription_id} || '') =~ /\Achannel:/) ? 1 : 0 },
  ), 1, 'program opens one shared channel subscription';
  is _request_count_matching(
    $transcript,
    'from_program',
    'subscriptions.close',
    sub { (($_[0]{subscription_id} || '') =~ /\Achannel:/) ? 1 : 0 },
  ), 1, 'program closes one shared channel subscription when the channel becomes empty';
  ok _method_count($transcript, 'to_program', 'notification', 'runtime.subscription_event') >= 6,
    'runtime delivers subscription events back to the program';
  ok _method_count($transcript, 'from_program', 'request', 'adapters.map_input') >= 9,
    'program maps client IRC commands through the adapter service';
  ok _method_count($transcript, 'from_program', 'request', 'overnet.emit_event') >= 8,
    'program emits event candidates through the runtime';
  ok _method_count($transcript, 'from_program', 'request', 'overnet.emit_state') >= 1,
    'program emits state candidates through the runtime';

  my $shutdown = $host->request_shutdown(reason => 'test complete');
  is $shutdown->{state}, 'shutdown_complete', 'program handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'program exits cleanly';
  is scalar @{$runtime->adapter_session_ids}, 0, 'runtime releases the long-lived adapter session on process exit';

  close $alice->{socket};
  close $bob->{socket};
  close $carol->{socket};
};

subtest 'IRC server program routes direct messages through directional chat.dm objects' => sub {
  my $dm_privmsg = _load_irc_fixture('valid-dm-privmsg.json');
  my $dm_notice = _load_irc_fixture('valid-dm-notice.json');
  my $network = $dm_privmsg->{input}{network};
  my $bob_dm_object_id = 'irc:' . $network . ':dm:bob';
  my $alice_dm_object_id = 'irc:' . $network . ':dm:alice';

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-test-key.pem');
  my $key = Net::Nostr::Key->new;
  $key->save_privkey($key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.real',
      network          => $network,
      listen_host      => '127.0.0.1',
      listen_port      => 0,
      server_name      => 'overnet.irc.local',
      signing_key_file => $key_path,
      adapter_config   => {},
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real IRC adapter for direct-message coverage';

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'      => {},
      'adapters.map_input'         => {},
      'adapters.close_session'     => {},
      'subscriptions.open'         => {},
      'subscriptions.close'        => {},
      'overnet.emit_event'         => {},
      'overnet.emit_state'         => {},
      'overnet.emit_capabilities'  => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'direct-message server reaches ready state';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'direct-message server publishes ready health details';
  ok defined $ready_details->{listen_port} && $ready_details->{listen_port} > 0,
    'direct-message server exposes the bound listen port';

  my $alice = _connect_irc_client($ready_details->{listen_port});
  my $bob = _connect_irc_client($ready_details->{listen_port});

  _write_client_line($alice, 'NICK alice');
  _write_client_line($alice, 'USER alice 0 * :Alice Example');
  _assert_registration_prelude(
    client  => $alice,
    nick    => 'alice',
    network => $dm_privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'alice DM subscription opens after registration';

  _write_client_line($bob, 'NICK bob');
  _write_client_line($bob, 'USER bob 0 * :Bob Example');
  _assert_registration_prelude(
    client  => $bob,
    nick    => 'bob',
    network => $dm_privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 2),
    'program opens one DM subscription per registered nick';

  my $dm_message_window = {
    min => int(time()) - 1,
    max => int(time()) + 5,
  };
  _write_client_line($alice, 'PRIVMSG bob :hello in private');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.dm_message',
        overnet_ot  => 'chat.dm',
        overnet_oid => $bob_dm_object_id,
      );
    },
  ), 'alice direct-message PRIVMSG is emitted through the runtime';
  $host->pump(timeout_ms => 100);
  is _read_client_line($bob, 1_000), ':alice PRIVMSG bob :hello in private',
    'bob receives the direct-message PRIVMSG fanout';
  is _read_client_line_optional($alice, 200), undef,
    'sender does not receive a synthetic DM echo';

  my $dm_notice_window = {
    min => int(time()) - 1,
    max => int(time()) + 5,
  };
  _write_client_line($bob, 'NOTICE alice :private notice');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.dm_notice',
        overnet_ot  => 'chat.dm',
        overnet_oid => $alice_dm_object_id,
      );
    },
  ), 'bob direct-message NOTICE is emitted through the runtime';
  $host->pump(timeout_ms => 100);
  is _read_client_line($alice, 1_000), ':bob NOTICE alice :private notice',
    'alice receives the direct-message NOTICE fanout';
  is _read_client_line_optional($bob, 200), undef,
    'NOTICE sender does not receive a synthetic DM echo';

  my $dm_message_item = _find_emitted_item(
    $runtime->emitted_items,
    item_type   => 'event',
    overnet_et  => 'chat.dm_message',
    overnet_ot  => 'chat.dm',
    overnet_oid => $bob_dm_object_id,
  );
  ok $dm_message_item, 'runtime recorded the direct-message PRIVMSG event';
  my $dm_message_expected = {
    %{$dm_privmsg->{expected}{event}},
    tags => [
      ['overnet_v',  '0.1.0'],
      ['overnet_et', 'chat.dm_message'],
      ['overnet_ot', 'chat.dm'],
      ['overnet_oid', $bob_dm_object_id],
    ],
  };
  my $dm_message_content = decode_json($dm_privmsg->{expected}{event}{content});
  $dm_message_content->{provenance}{origin} = $network . '/bob';
  $dm_message_content->{provenance}{external_identity} = 'alice';
  $dm_message_content->{body}{text} = 'hello in private';
  _assert_signed_emitted_matches_fixture(
    $dm_message_item,
    $dm_message_expected,
    $key,
    'mapped direct-message PRIVMSG event',
    $dm_message_window,
    $dm_message_content,
  );

  my $dm_notice_item = _find_emitted_item(
    $runtime->emitted_items,
    item_type   => 'event',
    overnet_et  => 'chat.dm_notice',
    overnet_ot  => 'chat.dm',
    overnet_oid => $alice_dm_object_id,
  );
  ok $dm_notice_item, 'runtime recorded the direct-message NOTICE event';
  my $dm_notice_expected = {
    %{$dm_notice->{expected}{event}},
    tags => [
      ['overnet_v',  '0.1.0'],
      ['overnet_et', 'chat.dm_notice'],
      ['overnet_ot', 'chat.dm'],
      ['overnet_oid', $alice_dm_object_id],
    ],
  };
  my $dm_notice_content = decode_json($dm_notice->{expected}{event}{content});
  $dm_notice_content->{provenance}{origin} = $network . '/alice';
  $dm_notice_content->{provenance}{external_identity} = 'bob';
  $dm_notice_content->{body}{text} = 'private notice';
  _assert_signed_emitted_matches_fixture(
    $dm_notice_item,
    $dm_notice_expected,
    $key,
    'mapped direct-message NOTICE event',
    $dm_notice_window,
    $dm_notice_content,
  );

  my $shutdown = $host->request_shutdown(reason => 'direct message test complete');
  is $shutdown->{state}, 'shutdown_complete', 'direct-message server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'direct-message server exits cleanly';
  is _request_count_matching(
    $host->transcript,
    'from_program',
    'subscriptions.open',
    sub { (($_[0]{subscription_id} || '') =~ /\Adm:/) ? 1 : 0 },
  ), 2, 'program opens exactly two DM subscriptions for the two registered clients';

  close $alice->{socket};
  close $bob->{socket};
};

subtest 'IRC server program accepts TLS clients using the baseline tls config shape' => sub {
  my $privmsg = _load_irc_fixture('valid-channel-privmsg.json');
  my $channel_object_id = 'irc:' . $privmsg->{input}{network} . ':' . $privmsg->{input}{target};

  my $tmpdir = tempdir(CLEANUP => 1);
  my $key_path = File::Spec->catfile($tmpdir, 'irc-server-test-key.pem');
  my $tls_cert_path = File::Spec->catfile($tmpdir, 'irc-server-cert.pem');
  my $tls_key_path = File::Spec->catfile($tmpdir, 'irc-server-key.pem');

  my $event_key = Net::Nostr::Key->new;
  $event_key->save_privkey($key_path);

  my ($cert, $tls_key) = CERT_create(
    subject => {
      commonName => 'localhost',
    },
    subjectAltNames => [
      [ DNS => 'localhost' ],
      [ IP  => '127.0.0.1' ],
    ],
  );
  PEM_cert2file($cert, $tls_cert_path);
  PEM_key2file($tls_key, $tls_key_path);

  my $runtime = Overnet::Program::Runtime->new(
    config => {
      adapter_id       => 'irc.real',
      network          => $privmsg->{input}{network},
      listen_host      => '127.0.0.1',
      listen_port      => 0,
      server_name      => 'overnet.irc.local',
      signing_key_file => $key_path,
      adapter_config   => {},
      tls              => {
        enabled          => JSON::PP::true,
        cert_chain_file  => $tls_cert_path,
        private_key_file => $tls_key_path,
        min_version      => 'TLSv1.2',
      },
    },
  );
  ok $runtime->register_adapter_definition(
    adapter_id => 'irc.real',
    definition => {
      kind             => 'class',
      class            => 'Overnet::Adapter::IRC',
      lib_dirs         => [$irc_lib],
      constructor_args => {},
    },
  ), 'runtime can register the real IRC adapter for the TLS server program';

  my $host = Overnet::Program::Host->new(
    command     => [$^X, $program_path],
    runtime     => $runtime,
    program_id  => 'overnet.program.irc_server',
    permissions => [
      'adapters.use',
      'subscriptions.read',
      'overnet.emit_event',
      'overnet.emit_state',
      'overnet.emit_capabilities',
    ],
    services => {
      'adapters.open_session'      => {},
      'adapters.map_input'         => {},
      'adapters.close_session'     => {},
      'subscriptions.open'         => {},
      'subscriptions.close'        => {},
      'overnet.emit_event'         => {},
      'overnet.emit_state'         => {},
      'overnet.emit_capabilities'  => {},
    },
    startup_timeout_ms  => 1_000,
    shutdown_timeout_ms => 1_000,
  );

  $host->start;
  is $host->state, 'ready', 'TLS-enabled server reaches ready state';

  my $ready_details = _wait_for_ready_details($host);
  ok $ready_details, 'TLS-enabled server publishes ready health details';
  ok defined $ready_details->{listen_port} && $ready_details->{listen_port} > 0,
    'TLS-enabled server exposes the bound listen port';

  my $client = _connect_irc_client_tls($ready_details->{listen_port});

  _write_client_line($client, 'NICK alice');
  _write_client_line($client, 'USER alice 0 * :Alice TLS');
  _assert_registration_prelude(
    client  => $client,
    nick    => 'alice',
    network => $privmsg->{input}{network},
  );
  ok _wait_for_dm_subscription_count($host, 1),
    'TLS client registration completes its DM subscription open';

  _write_client_line($client, 'JOIN #overnet');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.join',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'TLS client join is emitted through the runtime';
  is_deeply [
    _read_client_lines($client, 3, 1_000)
  ], [
    ':alice JOIN #overnet',
    ':overnet.irc.local 353 alice = #overnet :alice',
    ':overnet.irc.local 366 alice #overnet :End of /NAMES list.',
  ], 'TLS client receives join plus the minimal NAMES bootstrap';

  my $time_window = {
    min => int(time()) - 1,
    max => int(time()) + 5,
  };
  _write_client_line($client, 'PRIVMSG #overnet :Hello from TLS!');
  ok $host->pump_until(
    timeout_ms => 1_000,
    condition  => sub {
      defined _find_emitted_item(
        $_[0]->runtime->emitted_items,
        item_type   => 'event',
        overnet_et  => 'chat.message',
        overnet_ot  => 'chat.channel',
        overnet_oid => $channel_object_id,
      );
    },
  ), 'TLS client channel message is emitted through the runtime';
  is _read_client_line($client, 1_000), ':alice PRIVMSG #overnet :Hello from TLS!',
    'TLS client receives subscription-driven PRIVMSG render';

  my $message_item = _find_emitted_item(
    $runtime->emitted_items,
    item_type   => 'event',
    overnet_et  => 'chat.message',
    overnet_ot  => 'chat.channel',
    overnet_oid => $channel_object_id,
  );
  ok $message_item, 'runtime recorded the TLS client channel message';
  like $message_item->{data}{id}, qr/\A[0-9a-f]{64}\z/, 'TLS message is signed as a Nostr event';
  cmp_ok $message_item->{data}{created_at}, '>=', $time_window->{min}, 'TLS message created_at is recent';
  cmp_ok $message_item->{data}{created_at}, '<=', $time_window->{max}, 'TLS message created_at stays within the test window';

  is _request_count_matching(
    $host->transcript,
    'from_program',
    'subscriptions.open',
    sub { (($_[0]{subscription_id} || '') =~ /\Achannel:/) ? 1 : 0 },
  ), 1, 'TLS server opens one shared channel subscription';

  my $shutdown = $host->request_shutdown(reason => 'tls test complete');
  is $shutdown->{state}, 'shutdown_complete', 'TLS server handles runtime shutdown';
  is $shutdown->{exit_code}, 0, 'TLS server exits cleanly';

  close $client->{socket};
};

done_testing;
