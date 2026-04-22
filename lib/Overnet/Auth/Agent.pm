package Overnet::Auth::Agent;

use strict;
use warnings;

use Time::HiRes qw(time);
use Overnet::Authority::Delegation;
use Overnet::Core::Nostr;

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;

  my $self = bless {
    identities     => {},
    identity_order => [],
    policies       => [],
    service_pins   => {},
    sessions       => {},
    next_session_id => 1,
  }, $class;

  for my $identity (@{$args{identities} || []}) {
    next unless ref($identity) eq 'HASH';
    my $identity_id = $identity->{identity_id};
    next unless defined $identity_id && !ref($identity_id) && length($identity_id);

    my %stored = %{$identity};
    $stored{_signing_key} = _identity_signing_key(\%stored);
    $self->{identities}{$identity_id} = \%stored;
    push @{$self->{identity_order}}, $identity_id;
  }

  $self->{policies} = [
    map { ref($_) eq 'HASH' ? { %$_ } : () }
    @{$args{policies} || []}
  ];

  $self->{service_pins} = {
    map { $_ => { %{$args{service_pins}{$_}} } }
    grep { ref($args{service_pins}{$_}) eq 'HASH' }
    keys %{$args{service_pins} || {}}
  };

  for my $session (@{$args{sessions} || []}) {
    next unless ref($session) eq 'HASH';
    my $handle = _session_handle_id($session->{session_handle});
    next unless defined $handle;
    $self->{sessions}{$handle} = {
      %{$session},
      session_handle => { %{$session->{session_handle} || {}} },
    };
    $self->{next_session_id}++
      while exists $self->{sessions}{'sess-' . $self->{next_session_id}};
  }

  return $self;
}

sub dispatch {
  my ($self, $request) = @_;
  my $id = (ref($request) eq 'HASH' && defined($request->{id}) && !ref($request->{id}))
    ? $request->{id}
    : undef;

  return $self->_error_response($id, 'invalid_request', 'request must be an object')
    unless ref($request) eq 'HASH';
  return $self->_error_response($id, 'invalid_request', 'request type must be request')
    unless (($request->{type} || '') eq 'request');

  my $method = $request->{method};
  return $self->_error_response($id, 'invalid_request', 'method is required')
    unless defined $method && !ref($method) && length($method);

  my %dispatch = (
    'agent.info'         => sub { $self->_dispatch_agent_info($request) },
    'identities.list'    => sub { $self->_dispatch_identities_list($request) },
    'sessions.authorize' => sub { $self->_dispatch_authorize($request) },
    'sessions.renew'     => sub { $self->_dispatch_renew($request) },
    'sessions.revoke'    => sub { $self->_dispatch_revoke($request) },
  );

  my $handler = $dispatch{$method}
    or return $self->_error_response($id, 'invalid_request', "unsupported method: $method");

  return $handler->();
}

sub _dispatch_agent_info {
  my ($self, $request) = @_;
  my $id = $request->{id};

  return {
    type   => 'response',
    id     => $id,
    ok     => 1,
    result => {
      protocol_version => '0.1.0',
      capabilities     => [
        'agent.info',
        'identities.list',
        'sessions.authorize',
        'sessions.renew',
        'sessions.revoke',
      ],
    },
  };
}

sub _dispatch_identities_list {
  my ($self, $request) = @_;
  my $id = $request->{id};

  my @identities = map {
    my $identity = $self->{identities}{$_} || {};
    my %descriptor = (
      identity_id     => $_,
      public_identity => _clone_hash($identity->{public_identity}),
    );
    $descriptor{backend_type} = $identity->{backend_type}
      if defined $identity->{backend_type} && !ref($identity->{backend_type}) && length($identity->{backend_type});
    \%descriptor;
  } @{$self->{identity_order}};

  return {
    type   => 'response',
    id     => $id,
    ok     => 1,
    result => {
      identities => \@identities,
    },
  };
}

sub _dispatch_authorize {
  my ($self, $request) = @_;
  my $id = $request->{id};
  my $params = $request->{params};

  return $self->_error_response($id, 'invalid_request', 'params must be an object')
    unless ref($params) eq 'HASH';

  my $program_id = $params->{program_id};
  return $self->_error_response($id, 'invalid_request', 'program_id is required')
    unless defined $program_id && !ref($program_id) && length($program_id);

  my ($identity, $identity_error) = $self->_resolve_identity($params->{identity_id});
  return $self->_error_response($id, @{$identity_error})
    unless $identity;

  my $service = $params->{service};
  return $self->_error_response($id, 'invalid_request', 'service must be an object')
    unless ref($service) eq 'HASH';
  return $self->_error_response($id, 'invalid_request', 'service.locators must be a non-empty array')
    unless ref($service->{locators}) eq 'ARRAY' && @{$service->{locators}};

  my $scope = $params->{scope};
  my $action = $params->{action};
  my $artifacts = $params->{artifacts};
  return $self->_error_response($id, 'invalid_request', 'scope is required')
    unless defined $scope && !ref($scope) && length($scope);
  return $self->_error_response($id, 'unsupported_action', "unsupported action: $action")
    unless defined $action && !ref($action) && ($action eq 'session.authenticate' || $action eq 'session.delegate');
  return $self->_error_response($id, 'invalid_request', 'artifacts must be a non-empty array')
    unless ref($artifacts) eq 'ARRAY' && @{$artifacts};

  my ($service_pin_state, $service_error) = $self->_service_pin_state($service);
  return $self->_error_response($id, @{$service_error})
    unless defined $service_pin_state;

  my $interactive = exists($params->{interactive}) ? ($params->{interactive} ? 1 : 0) : 1;
  my $approved = $self->_policy_matches(
    identity_id => $identity->{identity_id},
    program_id  => $program_id,
    service     => $service,
    scope       => $scope,
    action      => $action,
  );

  return $self->_error_response($id, 'headless_unavailable', 'approval is required but interactive approval is unavailable')
    if !$approved && !$interactive;

  my @returned;
  for my $artifact (@{$artifacts}) {
    my ($built, $artifact_error) = $self->_build_artifact(
      identity  => $identity,
      action    => $action,
      scope     => $scope,
      challenge => $params->{challenge},
      artifact  => $artifact,
    );
    return $self->_error_response($id, @{$artifact_error})
      unless $built;
    push @returned, $built;
  }

  $self->_pin_service_identity($service)
    if $service_pin_state eq 'first_contact';

  my $session_handle = $self->_store_session(
    identity_id    => $identity->{identity_id},
    program_id     => $program_id,
    service        => _clone_hash($service),
    scope          => $scope,
    action         => $action,
    renewable      => 1,
    artifacts      => [ map { _clone_hash($_) } @{$artifacts} ],
  );

  return {
    type   => 'response',
    id     => $id,
    ok     => 1,
    result => {
      identity_id      => $identity->{identity_id},
      service_pin_state => $service_pin_state,
      artifacts        => \@returned,
      session_handle   => $session_handle,
    },
  };
}

sub _dispatch_renew {
  my ($self, $request) = @_;
  my $id = $request->{id};
  my $params = $request->{params};

  return $self->_error_response($id, 'invalid_request', 'params must be an object')
    unless ref($params) eq 'HASH';

  my $session_handle = _session_handle_id($params->{session_handle});
  return $self->_error_response($id, 'invalid_request', 'session_handle.id is required')
    unless defined $session_handle;

  my $session = $self->{sessions}{$session_handle}
    or return $self->_error_response($id, 'invalid_request', 'unknown session_handle');

  return $self->_error_response($id, 'policy_denied', 'session is not renewable')
    unless $session->{renewable};

  my ($identity, $identity_error) = $self->_resolve_identity($session->{identity_id});
  return $self->_error_response($id, @{$identity_error})
    unless $identity;

  my ($service_pin_state, $service_error) = $self->_service_pin_state($session->{service});
  return $self->_error_response($id, @{$service_error})
    unless defined $service_pin_state;

  my $interactive = exists($params->{interactive}) ? ($params->{interactive} ? 1 : 0) : 1;
  my $approved = $self->_policy_matches(
    identity_id => $session->{identity_id},
    program_id  => $session->{program_id},
    service     => $session->{service},
    scope       => $session->{scope},
    action      => $session->{action},
  );

  return $self->_error_response($id, 'headless_unavailable', 'approval is required but interactive approval is unavailable')
    if !$approved && !$interactive;

  my @returned;
  for my $artifact (@{$session->{artifacts} || []}) {
    my ($built, $artifact_error) = $self->_build_artifact(
      identity  => $identity,
      action    => $session->{action},
      scope     => $session->{scope},
      challenge => $params->{challenge},
      artifact  => $artifact,
    );
    return $self->_error_response($id, @{$artifact_error})
      unless $built;
    push @returned, $built;
  }

  return {
    type   => 'response',
    id     => $id,
    ok     => 1,
    result => {
      identity_id      => $session->{identity_id},
      service_pin_state => $service_pin_state,
      artifacts        => \@returned,
      session_handle   => _clone_hash($session->{session_handle}),
    },
  };
}

sub _dispatch_revoke {
  my ($self, $request) = @_;
  my $id = $request->{id};
  my $params = $request->{params};

  return $self->_error_response($id, 'invalid_request', 'params must be an object')
    unless ref($params) eq 'HASH';

  my $session_handle = _session_handle_id($params->{session_handle});
  return $self->_error_response($id, 'invalid_request', 'session_handle.id is required')
    unless defined $session_handle;

  delete $self->{sessions}{$session_handle};

  return {
    type   => 'response',
    id     => $id,
    ok     => 1,
    result => {},
  };
}

sub _resolve_identity {
  my ($self, $identity_id) = @_;

  if (defined $identity_id && !ref($identity_id) && length($identity_id)) {
    my $identity = $self->{identities}{$identity_id}
      or return (undef, [ 'unknown_identity', "unknown identity_id: $identity_id" ]);
    return ($identity, undef);
  }

  return (undef, [ 'identity_required', 'identity_id is required' ])
    unless @{$self->{identity_order}} == 1;

  my $default_id = $self->{identity_order}[0];
  return ($self->{identities}{$default_id}, undef);
}

sub _policy_matches {
  my ($self, %args) = @_;

  for my $policy (@{$self->{policies}}) {
    next unless (($policy->{identity_id} || '') eq ($args{identity_id} || ''));
    next unless (($policy->{program_id} || '') eq ($args{program_id} || ''));
    next unless (($policy->{scope} || '') eq ($args{scope} || ''));
    next unless (($policy->{action} || '') eq ($args{action} || ''));

    my $policy_identity = $policy->{service_identity};
    my $request_identity = $args{service}{service_identity};

    if (ref($request_identity) eq 'HASH') {
      next unless ref($policy_identity) eq 'HASH';
      next unless (($policy_identity->{scheme} || '') eq ($request_identity->{scheme} || ''));
      next unless (($policy_identity->{value} || '') eq ($request_identity->{value} || ''));
      return 1;
    }

    next if ref($policy_identity) eq 'HASH';
    next unless _sorted_list($policy->{locators}) eq _sorted_list($args{service}{locators});
    return 1;
  }

  return 0;
}

sub _service_pin_state {
  my ($self, $service) = @_;
  my $identity = $service->{service_identity};

  return ('provisional', undef)
    unless ref($identity) eq 'HASH';

  for my $locator (@{$service->{locators} || []}) {
    my $pinned = $self->{service_pins}{$locator};
    next unless ref($pinned) eq 'HASH';
    return (undef, [ 'service_identity_mismatch', 'presented service identity does not match pinned service identity' ])
      unless (($pinned->{scheme} || '') eq ($identity->{scheme} || ''))
          && (($pinned->{value} || '') eq ($identity->{value} || ''));
  }

  for my $locator (@{$service->{locators} || []}) {
    return ('known', undef)
      if ref($self->{service_pins}{$locator}) eq 'HASH';
  }

  return ('first_contact', undef);
}

sub _pin_service_identity {
  my ($self, $service) = @_;
  return unless ref($service->{service_identity}) eq 'HASH';

  for my $locator (@{$service->{locators} || []}) {
    next unless defined $locator && !ref($locator) && length($locator);
    $self->{service_pins}{$locator} = _clone_hash($service->{service_identity});
  }
}

sub _build_artifact {
  my ($self, %args) = @_;
  my $artifact = $args{artifact};
  return (undef, [ 'invalid_request', 'artifact must be an object' ])
    unless ref($artifact) eq 'HASH';

  my $type = $artifact->{type} || '';
  return (undef, [ 'unsupported_artifact', "unsupported artifact type: $type" ])
    unless $type eq 'nostr.event';

  my $params = $artifact->{params};
  return (undef, [ 'invalid_request', 'artifact params must be an object' ])
    unless ref($params) eq 'HASH';

  my $key = $args{identity}{_signing_key};
  my $event;

  return (undef, [ 'backend_unavailable', 'no signing backend is available for the selected identity' ])
    unless defined $key;

  if (($args{action} || '') eq 'session.authenticate') {
    return (undef, [ 'invalid_request', 'challenge.value is required for session.authenticate' ])
      unless ref($args{challenge}) eq 'HASH'
          && defined($args{challenge}{value})
          && !ref($args{challenge}{value})
          && length($args{challenge}{value});
    return (undef, [ 'invalid_request', 'session.authenticate requires kind 22242 nostr.event artifact' ])
      unless defined($params->{kind}) && $params->{kind} == 22242;

    my %tags = _first_tag_values($params->{tags});
    return (undef, [ 'invalid_request', 'auth event relay tag must match the requested scope' ])
      unless defined($tags{relay}) && $tags{relay} eq $args{scope};
    return (undef, [ 'invalid_request', 'auth event challenge tag must match the requested challenge' ])
      unless defined($tags{challenge}) && $tags{challenge} eq $args{challenge}{value};

    $event = Overnet::Authority::Delegation->create_auth_event(
      key        => $key,
      challenge  => $args{challenge}{value},
      scope      => $args{scope},
      created_at => _created_at(),
    );
  }
  elsif (($args{action} || '') eq 'session.delegate') {
    return (undef, [ 'invalid_request', 'session.delegate requires kind 14142 nostr.event artifact' ])
      unless defined($params->{kind}) && $params->{kind} == 14142;

    my %tags = _first_tag_values($params->{tags});
    return (undef, [ 'invalid_request', 'delegation event relay tag is required' ])
      unless defined $tags{relay} && length $tags{relay};
    return (undef, [ 'invalid_request', 'delegation event server tag must match the requested scope' ])
      unless defined($tags{server}) && $tags{server} eq $args{scope};
    return (undef, [ 'invalid_request', 'delegation event delegate tag is required' ])
      unless defined($tags{delegate}) && $tags{delegate} =~ /\A[0-9a-f]{64}\z/;
    return (undef, [ 'invalid_request', 'delegation event session tag is required' ])
      unless defined($tags{session}) && length($tags{session});
    return (undef, [ 'invalid_request', 'delegation event expires_at tag is required' ])
      unless defined($tags{expires_at}) && $tags{expires_at} =~ /\A\d+\z/;

    $event = Overnet::Authority::Delegation->create_delegation_grant_event(
      key             => $key,
      relay_url       => $tags{relay},
      scope           => $args{scope},
      delegate_pubkey => $tags{delegate},
      session_id      => $tags{session},
      expires_at      => $tags{expires_at},
      created_at      => _created_at(),
      (defined($tags{nick}) ? (nick => $tags{nick}) : ()),
    );
  }
  else {
    return (undef, [ 'unsupported_action', "unsupported action: $args{action}" ]);
  }

  return (undef, [ 'internal_failure', $event->{reason} ])
    if ref($event) eq 'HASH' && !$event->{valid} && $event->{reason};

  return ({
    type   => 'nostr.event',
    format => 'nostr.event',
    value  => $event,
  }, undef);
}

sub _store_session {
  my ($self, %args) = @_;
  my $id = 'sess-' . $self->{next_session_id}++;
  my $handle = { id => $id };

  $self->{sessions}{$id} = {
    %args,
    session_handle => _clone_hash($handle),
  };

  return $handle;
}

sub _identity_signing_key {
  my ($identity) = @_;

  if (defined($identity->{private_key}) && !ref($identity->{private_key}) && length($identity->{private_key})) {
    return Overnet::Core::Nostr->load_key(privkey => $identity->{private_key});
  }

  if (defined($identity->{privkey_secret}) && !ref($identity->{privkey_secret}) && length($identity->{privkey_secret})) {
    return Overnet::Core::Nostr->load_key(privkey => $identity->{privkey_secret});
  }

  return undef;
}

sub _session_handle_id {
  my ($handle) = @_;
  return undef unless ref($handle) eq 'HASH';
  return undef unless defined($handle->{id}) && !ref($handle->{id}) && length($handle->{id});
  return $handle->{id};
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

sub _created_at {
  return int(time());
}

sub _clone_hash {
  my ($value) = @_;
  return undef unless defined $value;
  return $value unless ref($value);

  if (ref($value) eq 'HASH') {
    return {
      map { $_ => _clone_hash($value->{$_}) }
      keys %{$value}
    };
  }

  if (ref($value) eq 'ARRAY') {
    return [ map { _clone_hash($_) } @{$value} ];
  }

  return "$value";
}

sub _sorted_list {
  my ($values) = @_;
  return '' unless ref($values) eq 'ARRAY';
  return join "\0", sort @{$values};
}

sub _error_response {
  my ($self, $id, $code, $message) = @_;
  return {
    type  => 'response',
    id    => $id,
    ok    => 0,
    error => {
      code    => $code,
      message => $message,
    },
  };
}

1;
