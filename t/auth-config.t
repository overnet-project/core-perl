use strictures 2;

use FindBin;
use File::Spec;
use File::Temp qw(tempdir);
use JSON       ();
use Test::More;

use Overnet::Auth::Config;

my $fixture_secret = '1111111111111111111111111111111111111111111111111111111111111111';
my $fixture_pubkey = '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa';

subtest 'load_file returns endpoint and agent config from JSON' => sub {
  my $dir         = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  my $socket_path = File::Spec->catfile($dir, 'auth.sock');
  my $state_file  = File::Spec->catfile($dir, 'auth-state.json');

  _write_json(
    $config_file,
    {
      daemon => {
        endpoint   => $socket_path,
        state_file => $state_file,
      },
      identities => [
        {
          identity_id    => 'default',
          backend_type   => 'direct_secret',
          backend_config => {
            secret => $fixture_secret,
          },
          public_identity => {
            scheme => 'nostr.pubkey',
            value  => $fixture_pubkey,
          },
        },
      ],
      policies => [
        {
          identity_id => 'default',
          program_id  => 'irc.bridge',
          locators    => ['irc://irc.example.test/overnet'],
          scope       => 'irc://irc.example.test/overnet',
          action      => 'session.authenticate',
        },
      ],
    },
  );

  my $config = Overnet::Auth::Config->load_file(path => $config_file);

  is $config->endpoint,   $socket_path, 'config exposes the daemon endpoint';
  is $config->state_file, $state_file,  'config exposes the daemon state file';
  is_deeply $config->agent_args,
    {
    identities => [
      {
        identity_id    => 'default',
        backend_type   => 'direct_secret',
        backend_config => {
          secret => $fixture_secret,
        },
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
    policies => [
      {
        identity_id => 'default',
        program_id  => 'irc.bridge',
        locators    => ['irc://irc.example.test/overnet'],
        scope       => 'irc://irc.example.test/overnet',
        action      => 'session.authenticate',
      },
    ],
    service_pins                 => {},
    sessions                     => [],
    allow_unattended_autoapprove => 0,
    },
    'config exposes the agent constructor args and defaults to fail-closed approval';
};

subtest 'agent_args carries an explicit unattended-autoapprove opt-in from config' => sub {
  my $config = Overnet::Auth::Config->new(
    config => {
      allow_unattended_autoapprove => JSON::true,
      identities                   => [
        {
          identity_id     => 'default',
          public_identity => {
            scheme => 'nostr.pubkey',
            value  => $fixture_pubkey,
          },
        },
      ],
    },
  );

  is $config->agent_args->{allow_unattended_autoapprove}, 1,
    'a truthy config opt-in becomes a normalized boolean in agent_args';

  my $default = Overnet::Auth::Config->new(config => {});
  is $default->agent_args->{allow_unattended_autoapprove}, 0,
    'an absent opt-in normalizes to fail-closed';

  my $off = Overnet::Auth::Config->new(config => {allow_unattended_autoapprove => JSON::false},);
  is $off->agent_args->{allow_unattended_autoapprove}, 0,
    'an explicit false opt-in stays fail-closed';
};

subtest 'config rejects a non-boolean unattended-autoapprove setting' => sub {
  for my $bad ('false', 1, {}) {
    my $error = eval {
      Overnet::Auth::Config->new(config => {allow_unattended_autoapprove => $bad},);
      1;
    } ? undef : $@;

    like $error, qr/allow_unattended_autoapprove\ must\ be\ a\ boolean/mx,
      'a non-boolean opt-in value is rejected so a malformed setting cannot silently enable auto-approval';
  }
};

subtest 'agent_args can combine static identities with separately loaded mutable state' => sub {
  my $config = Overnet::Auth::Config->new(
    config => {
      daemon => {
        endpoint   => '/tmp/overnet-auth.sock',
        state_file => '/tmp/overnet-auth-state.json',
      },
      identities => [
        {
          identity_id    => 'default',
          backend_type   => 'direct_secret',
          backend_config => {
            secret => $fixture_secret,
          },
          public_identity => {
            scheme => 'nostr.pubkey',
            value  => $fixture_pubkey,
          },
        },
      ],
    },
  );

  my $agent_args = $config->agent_args(
    state => {
      policies => [
        {
          policy_id   => 'policy-1',
          identity_id => 'default',
          program_id  => 'irc.bridge',
          locators    => ['irc://irc.example.test/overnet'],
          scope       => 'irc://irc.example.test/overnet',
          action      => 'session.authenticate',
        },
      ],
      service_pins => {
        'wss://relay.example.test/auth' => {
          scheme => 'nostr.pubkey',
          value  => ('1' x 64),
        },
      },
      sessions => [
        {
          session_handle => {id => 'sess-1'},
          identity_id    => 'default',
          program_id     => 'irc.bridge',
          service        => {
            locators => ['wss://relay.example.test/auth'],
          },
          scope     => 'irc://irc.example.test/overnet',
          action    => 'session.authenticate',
          renewable => 1,
          artifacts => [],
        },
      ],
    },
  );

  is $agent_args->{identities}[0]{identity_id}, 'default',  'static identities remain in config';
  is $agent_args->{policies}[0]{policy_id},     'policy-1', 'mutable policies can come from separate state';
  is $agent_args->{service_pins}{'wss://relay.example.test/auth'}{value},
    ('1' x 64),
    'mutable service pins can come from separate state';
  is $agent_args->{sessions}[0]{session_handle}{id}, 'sess-1', 'mutable sessions can come from separate state';
};

subtest 'load_file rejects non-object JSON configs' => sub {
  my $dir         = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  _write_raw($config_file, qq{["not","an","object"]\n});

  my $error = eval {
    Overnet::Auth::Config->load_file(path => $config_file);
    1;
  } ? undef : $@;

  like $error, qr/auth\ config\ must\ decode\ to\ an\ object/mx, 'non-object auth config files are rejected';
};

subtest 'empty auth config remains valid without a daemon section' => sub {
  my $config = Overnet::Auth::Config->new(config => {});

  ok !defined($config->endpoint),   'empty config has no endpoint';
  ok !defined($config->state_file), 'empty config has no state file';
  is_deeply $config->mutable_state,
    {
    policies     => [],
    service_pins => {},
    sessions     => [],
    },
    'empty config still exposes empty mutable state';
};

done_testing;

sub _write_json {
  my ($path, $value) = @_;
  _write_raw($path, JSON::encode_json($value));
  return;
}

sub _write_raw {
  my ($path, $content) = @_;
  open my $fh, '>', $path
    or die "open $path failed: $!";
  print {$fh} $content
    or die "write $path failed: $!";
  close $fh
    or die "close $path failed: $!";
  return;
}
