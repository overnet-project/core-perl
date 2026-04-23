package Overnet::Auth::CLI;

use strict;
use warnings;

use Getopt::Long qw(GetOptionsFromArray);
use JSON::PP ();

use Overnet::Auth::Client;

our $VERSION = '0.001';

sub run {
  my ($class, %args) = @_;
  my @argv = @{$args{argv} || []};
  if (@argv && $argv[0] eq '--help') {
    return {
      exit_code => 0,
      output    => _usage(),
    };
  }
  my $command = shift @argv || '';
  my %options = (
    interactive => 1,
    pretty      => 1,
  );
  my $help = 0;

  GetOptionsFromArray(
    \@argv,
    'auth-sock=s'               => \$options{auth_sock},
    'policy-id=s'               => \$options{policy_id},
    'identity-id=s'             => \$options{identity_id},
    'program-id=s'              => \$options{program_id},
    'service-locator=s@'        => \$options{service_locators},
    'service-identity-scheme=s' => \$options{service_identity_scheme},
    'service-identity-value=s'  => \$options{service_identity_value},
    'service-identity-display=s' => \$options{service_identity_display},
    'scope=s'                   => \$options{scope},
    'action=s'                  => \$options{action},
    'challenge-type=s'          => \$options{challenge_type},
    'challenge-value=s'         => \$options{challenge_value},
    'artifact-json=s@'          => \$options{artifact_json},
    'artifact-file=s@'          => \$options{artifact_files},
    'session-id=s'              => \$options{session_id},
    'interactive!'              => \$options{interactive},
    'pretty!'                   => \$options{pretty},
    'help'                      => \$help,
  ) or die _usage();

  if ($help || !$command) {
    return {
      exit_code => $help ? 0 : 1,
      output    => _usage(),
    };
  }

  die _usage()
    unless $command eq 'identities'
        || $command eq 'policies'
        || $command eq 'policy-grant'
        || $command eq 'policy-revoke'
        || $command eq 'service-pins'
        || $command eq 'service-pin-set'
        || $command eq 'service-pin-forget'
        || $command eq 'sessions'
        || $command eq 'authorize'
        || $command eq 'renew'
        || $command eq 'revoke';

  die "unexpected positional arguments: @argv\n"
    if @argv;

  my $client = $args{client};
  if (!$client) {
    my $factory = $args{client_factory};
    if (ref($factory) eq 'CODE') {
      $client = $factory->(%options);
    }
    else {
      $client = Overnet::Auth::Client->new(
        (defined($options{auth_sock}) ? (endpoint => $options{auth_sock}) : ()),
      );
    }
  }

  my $response;
  if ($command eq 'identities') {
    $response = $client->identities_list;
  }
  elsif ($command eq 'policies') {
    $response = $client->policies_list;
  }
  elsif ($command eq 'policy-grant') {
    $response = $client->policies_grant(
      policy => $class->_policy_descriptor(%options),
    );
  }
  elsif ($command eq 'policy-revoke') {
    $response = $client->policies_revoke(
      $class->_policy_id_params(%options),
    );
  }
  elsif ($command eq 'service-pins') {
    $response = $client->service_pins_list;
  }
  elsif ($command eq 'service-pin-set') {
    $response = $client->service_pins_set(
      $class->_service_pin_set_params(%options),
    );
  }
  elsif ($command eq 'service-pin-forget') {
    $response = $client->service_pins_forget(
      $class->_service_locator_params(%options),
    );
  }
  elsif ($command eq 'sessions') {
    $response = $client->sessions_list;
  }
  elsif ($command eq 'authorize') {
    $response = $client->sessions_authorize(
      $class->_authorize_params(%options),
    );
  }
  elsif ($command eq 'renew') {
    $response = $client->sessions_renew(
      $class->_session_params(%options, include_interactive => 1),
    );
  }
  else {
    $response = $client->sessions_revoke(
      $class->_session_params(%options),
    );
  }

  return {
    exit_code => $response->{ok} ? 0 : 1,
    output    => $class->_render_response($response, pretty => $options{pretty}),
  };
}

sub _authorize_params {
  my ($class, %options) = @_;

  die "--program-id is required\n"
    unless defined($options{program_id}) && !ref($options{program_id}) && length($options{program_id});
  die "--scope is required\n"
    unless defined($options{scope}) && !ref($options{scope}) && length($options{scope});
  die "--action is required\n"
    unless defined($options{action}) && !ref($options{action}) && length($options{action});

  my $service = $class->_service_descriptor(%options);

  my %params = (
    program_id  => $options{program_id},
    service     => $service,
    scope       => $options{scope},
    action      => $options{action},
    interactive => $options{interactive} ? JSON::PP::true : JSON::PP::false,
    artifacts   => $class->_artifacts(%options),
  );
  $params{identity_id} = $options{identity_id}
    if defined($options{identity_id}) && !ref($options{identity_id}) && length($options{identity_id});

  if (defined($options{challenge_type}) || defined($options{challenge_value})) {
    die "--challenge-type and --challenge-value are required together\n"
      unless defined($options{challenge_type}) && !ref($options{challenge_type}) && length($options{challenge_type})
          && defined($options{challenge_value}) && !ref($options{challenge_value}) && length($options{challenge_value});
    $params{challenge} = {
      type  => $options{challenge_type},
      value => $options{challenge_value},
    };
  }

  return %params;
}

sub _policy_descriptor {
  my ($class, %options) = @_;

  die "--identity-id is required\n"
    unless defined($options{identity_id}) && !ref($options{identity_id}) && length($options{identity_id});
  die "--program-id is required\n"
    unless defined($options{program_id}) && !ref($options{program_id}) && length($options{program_id});
  die "--scope is required\n"
    unless defined($options{scope}) && !ref($options{scope}) && length($options{scope});
  die "--action is required\n"
    unless defined($options{action}) && !ref($options{action}) && length($options{action});

  return {
    identity_id => $options{identity_id},
    program_id  => $options{program_id},
    service     => $class->_service_descriptor(%options),
    scope       => $options{scope},
    action      => $options{action},
  };
}

sub _policy_id_params {
  my ($class, %options) = @_;

  die "--policy-id is required\n"
    unless defined($options{policy_id}) && !ref($options{policy_id}) && length($options{policy_id});

  return (
    policy_id => $options{policy_id},
  );
}

sub _session_params {
  my ($class, %options) = @_;

  die "--session-id is required\n"
    unless defined($options{session_id}) && !ref($options{session_id}) && length($options{session_id});

  my %params = (
    session_handle => {
      id => $options{session_id},
    },
  );
  if ($options{include_interactive}) {
    $params{interactive} = $options{interactive} ? JSON::PP::true : JSON::PP::false;
  }

  return %params;
}

sub _service_pin_set_params {
  my ($class, %options) = @_;
  my %params = $class->_service_locator_params(%options);
  my $service_identity = $class->_service_identity_descriptor(%options);
  die "--service-identity-scheme and --service-identity-value are required\n"
    unless $service_identity;

  $params{service_identity} = $service_identity;
  return %params;
}

sub _service_locator_params {
  my ($class, %options) = @_;

  die "--service-locator is required\n"
    unless ref($options{service_locators}) eq 'ARRAY' && @{$options{service_locators}};
  die "exactly one --service-locator is required\n"
    unless @{$options{service_locators}} == 1;

  return (
    locator => $options{service_locators}[0],
  );
}

sub _service_descriptor {
  my ($class, %options) = @_;

  die "--service-locator is required\n"
    unless ref($options{service_locators}) eq 'ARRAY' && @{$options{service_locators}};

  my $service = {
    locators => [ @{$options{service_locators}} ],
  };
  my $service_identity = $class->_service_identity_descriptor(%options);
  $service->{service_identity} = $service_identity if $service_identity;

  return $service;
}

sub _artifacts {
  my ($class, %options) = @_;
  my @artifacts;

  for my $json (@{$options{artifact_json} || []}) {
    push @artifacts, $class->_decode_artifact_json($json, '--artifact-json');
  }
  for my $path (@{$options{artifact_files} || []}) {
    open my $fh, '<', $path
      or die "open $path failed: $!";
    my $json = do { local $/; <$fh> };
    close $fh
      or die "close $path failed: $!";
    push @artifacts, $class->_decode_artifact_json($json, "--artifact-file $path");
  }

  die "--artifact-json or --artifact-file is required\n"
    unless @artifacts;

  return \@artifacts;
}

sub _decode_artifact_json {
  my ($class, $json, $source) = @_;
  my $artifact = eval { JSON::PP->new->utf8->decode($json) };
  die "$source did not contain valid JSON: $@"
    unless defined $artifact;
  die "$source must decode to an object\n"
    unless ref($artifact) eq 'HASH';
  return $artifact;
}

sub _service_identity_descriptor {
  my ($class, %options) = @_;
  my $scheme = $options{service_identity_scheme};
  my $value = $options{service_identity_value};

  return undef
    unless defined($scheme) || defined($value) || defined($options{service_identity_display});

  die "--service-identity-scheme and --service-identity-value are required together\n"
    unless defined($scheme) && !ref($scheme) && length($scheme)
        && defined($value) && !ref($value) && length($value);

  my %descriptor = (
    scheme => $scheme,
    value  => $value,
  );
  $descriptor{display} = $options{service_identity_display}
    if defined($options{service_identity_display}) && !ref($options{service_identity_display}) && length($options{service_identity_display});

  return \%descriptor;
}

sub _render_response {
  my ($class, $response, %options) = @_;
  my $encoder = JSON::PP->new->utf8->canonical;
  $encoder = $encoder->pretty if $options{pretty};

  if ($response->{ok}) {
    return $encoder->encode({
      ok     => JSON::PP::true,
      result => $response->{result} || {},
    });
  }

  return $encoder->encode({
    ok    => JSON::PP::false,
    error => $response->{error} || {},
  });
}

sub _usage {
  return <<'USAGE';
Usage:
  overnet-auth.pl identities [options]
  overnet-auth.pl policies [options]
  overnet-auth.pl policy-grant [options]
  overnet-auth.pl policy-revoke [options]
  overnet-auth.pl service-pins [options]
  overnet-auth.pl service-pin-set [options]
  overnet-auth.pl service-pin-forget [options]
  overnet-auth.pl sessions [options]
  overnet-auth.pl authorize [options]
  overnet-auth.pl renew [options]
  overnet-auth.pl revoke [options]

Shared options:
  --auth-sock PATH
  --pretty / --no-pretty
  --help

Policy grant options:
  --identity-id ID
  --program-id PROGRAM_ID
  --service-locator LOCATOR
  --service-identity-scheme SCHEME
  --service-identity-value VALUE
  --service-identity-display DISPLAY
  --scope SCOPE
  --action ACTION

Policy revoke options:
  --policy-id ID

Service pin options:
  --service-locator LOCATOR
  --service-identity-scheme SCHEME
  --service-identity-value VALUE
  --service-identity-display DISPLAY

Authorize options:
  --identity-id ID
  --program-id PROGRAM_ID
  --service-locator LOCATOR
  --service-identity-scheme SCHEME
  --service-identity-value VALUE
  --service-identity-display DISPLAY
  --scope SCOPE
  --action ACTION
  --challenge-type TYPE
  --challenge-value VALUE
  --artifact-json JSON
  --artifact-file PATH
  --interactive / --no-interactive

Renew options:
  --session-id ID
  --interactive / --no-interactive

Revoke options:
  --session-id ID
USAGE
}

1;
