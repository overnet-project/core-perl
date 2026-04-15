package Overnet::Core::Nostr;

use strict;
use warnings;

use JSON::PP ();
use Net::Nostr::DirectMessage;
use Net::Nostr::Event;
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

sub _require_key_wrapper {
  my ($key) = @_;
  die "key must be an Overnet::Core::Nostr::Key instance\n"
    unless ref($key) && ref($key) eq 'Overnet::Core::Nostr::Key';
  return $key;
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
