use strict;
use warnings;
use Test::More;
use JSON::PP ();

use IO::Socket::SSL qw(SSL_VERIFY_NONE);
use Overnet::Program::TLSConfig;

sub exception (&);

subtest 'normalize accepts enabled server TLS config with implicit mode' => sub {
  my $tls = Overnet::Program::TLSConfig->normalize(
    tls => {
      enabled          => JSON::PP::true,
      cert_chain_file  => '/tmp/server-cert.pem',
      private_key_file => '/tmp/server-key.pem',
      min_version      => 'TLSv1.2',
    },
    implicit_mode => 'server',
  );

  is_deeply $tls, {
    enabled          => 1,
    mode             => 'server',
    cert_chain_file  => '/tmp/server-cert.pem',
    private_key_file => '/tmp/server-key.pem',
    min_version      => 'TLSv1.2',
  }, 'server TLS config normalizes to baseline shape';
};

subtest 'normalize rejects invalid baseline TLS shapes' => sub {
  like(
    exception {
      Overnet::Program::TLSConfig->normalize(
        tls => {
          cert_chain_file  => '/tmp/server-cert.pem',
          private_key_file => '/tmp/server-key.pem',
        },
        implicit_mode => 'server',
      );
    },
    qr/tls\.enabled is required/,
    'enabled is required when tls is present',
  );

  like(
    exception {
      Overnet::Program::TLSConfig->normalize(
        tls => {
          enabled => JSON::PP::true,
          mode    => 'server',
        },
      );
    },
    qr/tls\.cert_chain_file is required/,
    'server mode requires a cert chain file',
  );

  like(
    exception {
      Overnet::Program::TLSConfig->normalize(
        tls => {
          enabled          => JSON::PP::true,
          mode             => 'server',
          cert_chain_file  => '/tmp/server-cert.pem',
          private_key_file => '/tmp/server-key.pem',
          min_version      => 'TLSv1.1',
        },
      );
    },
    qr/tls\.min_version must be TLSv1\.2 or TLSv1\.3/,
    'min_version is restricted to the baseline secure values',
  );
};

subtest 'server_start_args maps baseline TLS config to IO::Socket::SSL arguments' => sub {
  my $tls = Overnet::Program::TLSConfig->normalize(
    tls => {
      enabled          => 1,
      cert_chain_file  => '/tmp/server-cert.pem',
      private_key_file => '/tmp/server-key.pem',
      verify_peer      => 0,
      min_version      => 'TLSv1.2',
    },
    implicit_mode => 'server',
  );

  my $args = Overnet::Program::TLSConfig->server_start_args($tls);

  is $args->{SSL_server}, 1, 'SSL_server is enabled';
  is $args->{SSL_startHandshake}, 1, 'server TLS does an immediate handshake';
  is $args->{SSL_cert_file}, '/tmp/server-cert.pem', 'cert chain file is mapped';
  is $args->{SSL_key_file}, '/tmp/server-key.pem', 'key file is mapped';
  is $args->{SSL_verify_mode}, SSL_VERIFY_NONE, 'verify mode defaults to none when verify_peer is false';
  is $args->{SSL_version}, 'SSLv23:!SSLv3:!SSLv2:!TLSv1:!TLSv1_1', 'TLSv1.2 minimum maps to the expected SSL version string';
};

sub exception (&) {
  my ($code) = @_;
  my $error;
  eval { $code->(); 1 } or $error = $@;
  return $error;
}

done_testing;
