requires 'Net::Nostr';
requires 'Class::Tiny';
requires 'JSON::Schema::Modern';

on 'test' => sub {
  requires 'AnyEvent::WebSocket::Client';
};
