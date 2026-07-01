requires 'perl', '5.040';
requires 'strictures', '2';
requires 'Net::Nostr';
requires 'Moo';
requires 'JSON';
requires 'JSON::Schema::Modern';

on 'test' => sub {
  requires 'AnyEvent::WebSocket::Client';
};
