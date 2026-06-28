requires 'strictures', '2';
requires 'Net::Nostr';
requires 'Class::Tiny';
requires 'JSON';
requires 'JSON::Schema::Modern';

on 'test' => sub {
  requires 'AnyEvent::WebSocket::Client';
};
