package Overnet::Core::Nostr;

use strict;
use warnings;

use AnyEvent;
use Digest::SHA qw(sha256_hex);
use JSON::PP ();
use Net::Nostr::DirectMessage;
use Net::Nostr::Client;
use Net::Nostr::Event;
use Net::Nostr::Filter;
use Net::Nostr::Key;

my $JSON = JSON::PP->new->utf8->canonical;

sub load_key {
  my ($class, %args) = @_;
  die "privkey is required\n"
    unless defined $args{privkey} && !ref($args{privkey}) && length($args{privkey});

  my $key = Net::Nostr::Key->new(privkey => $args{privkey});
  return bless { key => $key }, 'Overnet::Core::Nostr::Key';
}

sub generate_key {
  my ($class) = @_;
  my $key = Net::Nostr::Key->new;
  return bless { key => $key }, 'Overnet::Core::Nostr::Key';
}

sub event_from_wire {
  my ($class, $input) = @_;
  my $event = eval { Net::Nostr::Event->from_wire($input) };
  return undef unless $event;
  return bless { event => $event }, 'Overnet::Core::Nostr::Event';
}

sub wrap_private_message {
  my ($class, %args) = @_;
  my $sender_key = _require_key_wrapper($args{sender_key});
  my $payload = $args{payload};
  my $recipient_pubkeys = $args{recipient_pubkeys};

  die "payload must be an object\n"
    unless ref($payload) eq 'HASH';
  die "recipient_pubkeys must be a non-empty array\n"
    unless ref($recipient_pubkeys) eq 'ARRAY' && @{$recipient_pubkeys};
  die "recipient_pubkeys must contain non-empty strings\n"
    if grep { !defined($_) || ref($_) || !length($_) } @{$recipient_pubkeys};

  my $rumor = Net::Nostr::DirectMessage->create(
    sender_pubkey => $sender_key->{key}->pubkey_hex,
    content       => $JSON->encode($payload),
    recipients    => [ @{$recipient_pubkeys} ],
  );
  my ($wrap) = Net::Nostr::DirectMessage->wrap_for_recipients(
    rumor       => $rumor,
    sender_key  => $sender_key->{key},
    skip_sender => $args{skip_sender} ? 1 : 0,
  );

  return {
    transport       => bless({ event => $wrap }, 'Overnet::Core::Nostr::Event'),
    decrypted_rumor => bless({ event => $rumor }, 'Overnet::Core::Nostr::Event'),
  };
}

sub sign_event_hash {
  my ($class, %args) = @_;
  my $key = _require_key_wrapper($args{key});
  my $event_hash = $args{event};

  die "event must be an object\n"
    unless ref($event_hash) eq 'HASH';
  die "event kind is required\n"
    unless defined $event_hash->{kind} && !ref($event_hash->{kind});
  die "event created_at is required\n"
    unless defined $event_hash->{created_at} && !ref($event_hash->{created_at});
  die "event tags must be an array\n"
    unless ref($event_hash->{tags}) eq 'ARRAY';
  die "event content must be a string\n"
    if defined($event_hash->{content}) && ref($event_hash->{content});

  my $expected_pubkey = $key->{key}->pubkey_hex;
  if (defined $event_hash->{pubkey}) {
    die "event pubkey does not match the signing key\n"
      unless !ref($event_hash->{pubkey}) && $event_hash->{pubkey} eq $expected_pubkey;
  }

  my $event = $key->{key}->create_event(
    kind       => $event_hash->{kind},
    created_at => $event_hash->{created_at},
    tags       => [ @{$event_hash->{tags}} ],
    content    => defined $event_hash->{content} ? $event_hash->{content} : '',
  );
  return bless { event => $event }, 'Overnet::Core::Nostr::Event';
}

sub publish_event {
  my ($class, %args) = @_;
  my $relay_url = $args{relay_url};
  my $event = _coerce_signed_event($args{event});
  my $timeout_ms = exists $args{timeout_ms} ? $args{timeout_ms} : 5_000;

  die "relay_url is required\n"
    unless defined $relay_url && !ref($relay_url) && length($relay_url);
  die "timeout_ms must be a positive integer\n"
    unless defined $timeout_ms && !ref($timeout_ms) && $timeout_ms =~ /\A[1-9]\d*\z/;

  my $client = Net::Nostr::Client->new;
  my $cv = AnyEvent->condvar;
  my $done = 0;
  my $timer = AnyEvent->timer(
    after => $timeout_ms / 1000,
    cb    => sub {
      return if $done;
      $done = 1;
      $cv->send({
        accepted => 0,
        message  => 'publish timed out',
      });
    },
  );

  $client->on(ok => sub {
    my ($event_id, $accepted, $message) = @_;
    return if $done;
    return unless $event_id eq $event->id;
    $done = 1;
    undef $timer;
    $cv->send({
      accepted => $accepted ? 1 : 0,
      message  => $message,
    });
  });

  $client->connect($relay_url);
  $client->publish($event->{event});
  my $result = $cv->recv;
  $client->disconnect;

  return {
    %{$result || {}},
    event_id => $event->id,
  };
}

sub query_events {
  my ($class, %args) = @_;
  my $relay_url = $args{relay_url};
  my $filters = $args{filters};
  my $timeout_ms = exists $args{timeout_ms} ? $args{timeout_ms} : 5_000;

  die "relay_url is required\n"
    unless defined $relay_url && !ref($relay_url) && length($relay_url);
  die "filters must be a non-empty array\n"
    unless ref($filters) eq 'ARRAY' && @{$filters};
  die "timeout_ms must be a positive integer\n"
    unless defined $timeout_ms && !ref($timeout_ms) && $timeout_ms =~ /\A[1-9]\d*\z/;

  my @filters = map {
    ref($_) eq 'Net::Nostr::Filter'
      ? $_
      : Net::Nostr::Filter->new(%{$_})
  } @{$filters};

  my $client = Net::Nostr::Client->new;
  my $cv = AnyEvent->condvar;
  my $done = 0;
  my @events;
  my %seen_ids;
  my $subscription_id = sha256_hex(join ':', time(), rand(), $$, $relay_url);
  my $timer = AnyEvent->timer(
    after => $timeout_ms / 1000,
    cb    => sub {
      return if $done;
      $done = 1;
      $cv->send([ @events ]);
    },
  );

  $client->on(event => sub {
    my ($sub_id, $event) = @_;
    return if $done;
    return unless $sub_id eq $subscription_id;
    return if $seen_ids{$event->id}++;
    push @events, $event;
  });

  $client->on(eose => sub {
    my ($sub_id) = @_;
    return if $done;
    return unless $sub_id eq $subscription_id;
    $done = 1;
    undef $timer;
    $cv->send([ @events ]);
  });

  $client->on(closed => sub {
    my ($sub_id) = @_;
    return if $done;
    return unless $sub_id eq $subscription_id;
    $done = 1;
    undef $timer;
    $cv->send([ @events ]);
  });

  $client->connect($relay_url);
  $client->subscribe($subscription_id, @filters);
  my $events = $cv->recv;
  $client->close($subscription_id) if $client->is_connected;
  $client->disconnect;

  return [
    map { $_->to_hash }
    @{$events || []}
  ];
}

sub _require_key_wrapper {
  my ($key) = @_;
  die "key must be an Overnet::Core::Nostr::Key instance\n"
    unless ref($key) && ref($key) eq 'Overnet::Core::Nostr::Key';
  return $key;
}

sub _coerce_signed_event {
  my ($input) = @_;
  return $input
    if ref($input) && ref($input) eq 'Overnet::Core::Nostr::Event';
  die "event must be an object\n"
    unless ref($input) eq 'HASH';

  my $event = Net::Nostr::Event->from_wire($input);
  return bless { event => $event }, 'Overnet::Core::Nostr::Event';
}

package Overnet::Core::Nostr::Key;

use strict;
use warnings;

sub pubkey_hex {
  my ($self) = @_;
  return $self->{key}->pubkey_hex;
}

sub create_event_hash {
  my ($self, %args) = @_;
  my $event = $self->{key}->create_event(
    kind       => $args{kind},
    created_at => $args{created_at},
    tags       => $args{tags},
    content    => $args{content},
  );
  return $event->to_hash;
}

sub sign_event_hash {
  my ($self, %args) = @_;
  return Overnet::Core::Nostr->sign_event_hash(
    key   => $self,
    event => $args{event},
  )->to_hash;
}

sub save_privkey {
  my ($self, $path) = @_;
  return $self->{key}->save_privkey($path);
}

package Overnet::Core::Nostr::Event;

use strict;
use warnings;

sub id         { $_[0]{event}->id }
sub kind       { $_[0]{event}->kind }
sub pubkey     { $_[0]{event}->pubkey }
sub created_at { $_[0]{event}->created_at }
sub content    { $_[0]{event}->content }
sub tags       { $_[0]{event}->tags }

sub to_hash {
  my ($self) = @_;
  return $self->{event}->to_hash;
}

sub validate {
  my ($self) = @_;
  return $self->{event}->validate;
}

1;
