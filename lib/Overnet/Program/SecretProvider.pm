package Overnet::Program::SecretProvider;

use strict;
use warnings;
use JSON::PP ();
use Time::HiRes qw(time);

our $VERSION = '0.001';

sub new {
  my ($class, %args) = @_;

  my $now_cb = $args{now_cb} || sub { int(time() * 1000) };
  my $random_bytes_cb = $args{random_bytes_cb};
  my $secrets = exists $args{secrets} ? $args{secrets} : {};
  my $secret_policies = exists $args{secret_policies} ? $args{secret_policies} : {};
  my $secret_handle_ttl_ms = exists $args{secret_handle_ttl_ms}
    ? $args{secret_handle_ttl_ms}
    : 300_000;

  die "now_cb must be a code reference\n"
    unless ref($now_cb) eq 'CODE';
  die "random_bytes_cb must be a code reference\n"
    if defined $random_bytes_cb && ref($random_bytes_cb) ne 'CODE';
  die "secrets must be an object\n"
    unless ref($secrets) eq 'HASH';
  die "secret_policies must be an object\n"
    unless ref($secret_policies) eq 'HASH';
  die "secret_handle_ttl_ms must be a positive integer\n"
    unless defined $secret_handle_ttl_ms
      && !ref($secret_handle_ttl_ms)
      && $secret_handle_ttl_ms =~ /\A[1-9]\d*\z/;

  _validate_secrets($secrets);
  _validate_secret_policies($secret_policies);

  return bless {
    now_cb               => $now_cb,
    random_bytes_cb      => $random_bytes_cb,
    secrets              => _clone_json($secrets),
    secret_policies      => _clone_json($secret_policies),
    secret_handle_ttl_ms => 0 + $secret_handle_ttl_ms,
    secret_handles       => {},
    audit_events         => [],
  }, $class;
}

sub has_secret {
  my ($self, %args) = @_;
  my $name = _require_string_arg(name => $args{name});
  return exists $self->{secrets}{$name} ? 1 : 0;
}

sub audit_events {
  my ($self) = @_;
  return _clone_json($self->{audit_events});
}

sub issue_secret_handle {
  my ($self, %args) = @_;
  my $session_id = _require_string_arg(session_id => $args{session_id});
  my $name = _require_string_arg(name => $args{name});
  my $program_id = _optional_string_arg(program_id => $args{program_id});
  my $purpose = _optional_string_arg(purpose => $args{purpose});

  $self->_expire_secret_handles;

  unless ($self->_may_issue_secret(
    name       => $name,
    session_id => $session_id,
    program_id => $program_id,
    purpose    => $purpose,
  )) {
    $self->_audit(
      action     => 'secret_handle.issue',
      outcome    => 'denied',
      name       => $name,
      session_id => $session_id,
      (defined $program_id ? (program_id => $program_id) : ()),
      (defined $purpose ? (purpose => $purpose) : ()),
      reason     => 'secret_unavailable',
    );
    _invalid_secret_access(param => 'name');
  }

  my $handle_id = $self->_generate_secret_handle_id;
  my $expires_at_ms = $self->_now_ms + $self->{secret_handle_ttl_ms};
  $self->{secret_handles}{$handle_id} = {
    session_id    => $session_id,
    name          => $name,
    expires_at_ms => $expires_at_ms,
    (defined $program_id ? (program_id => $program_id) : ()),
    (defined $purpose ? (purpose => $purpose) : ()),
  };

  my $result = {
    name          => $name,
    secret_handle => {
      id         => $handle_id,
      expires_at => _ms_to_unix_seconds($expires_at_ms),
    },
  };

  $self->_audit(
    action     => 'secret_handle.issue',
    outcome    => 'issued',
    name       => $name,
    session_id => $session_id,
    (defined $program_id ? (program_id => $program_id) : ()),
    (defined $purpose ? (purpose => $purpose) : ()),
    expires_at => $result->{secret_handle}{expires_at},
  );

  return $result;
}

sub resolve_secret_handle {
  my ($self, %args) = @_;
  my $session_id = _require_string_arg(session_id => $args{session_id});
  my $handle_id = _require_string_arg(handle_id => $args{handle_id});
  my $program_id = _optional_string_arg(program_id => $args{program_id});
  my $purpose = _optional_string_arg(purpose => $args{purpose});
  my $method = _optional_string_arg(method => $args{method});
  my $adapter_id = _optional_string_arg(adapter_id => $args{adapter_id});
  my $secret_slot = _optional_string_arg(secret_slot => $args{secret_slot});
  my $error_param = _optional_string_arg(error_param => $args{error_param});

  $self->_expire_secret_handles;

  my $handle = $self->{secret_handles}{$handle_id};
  unless (defined $handle) {
    $self->_audit(
      action      => 'secret_handle.resolve',
      outcome     => 'denied',
      session_id  => $session_id,
      (defined $program_id ? (program_id => $program_id) : ()),
      (defined $purpose ? (purpose => $purpose) : ()),
      (defined $method ? (method => $method) : ()),
      (defined $adapter_id ? (adapter_id => $adapter_id) : ()),
      (defined $secret_slot ? (secret_slot => $secret_slot) : ()),
      reason      => 'secret_handle_unavailable',
    );
    _invalid_secret_access(param => $error_param);
  }

  my $name = $handle->{name};

  unless ($self->_may_resolve_secret_handle(
    handle      => $handle,
    session_id  => $session_id,
    program_id  => $program_id,
    purpose     => $purpose,
    method      => $method,
    adapter_id  => $adapter_id,
    secret_slot => $secret_slot,
  )) {
    $self->_audit(
      action      => 'secret_handle.resolve',
      outcome     => 'denied',
      name        => $name,
      session_id  => $session_id,
      (defined $program_id ? (program_id => $program_id) : ()),
      (defined $purpose ? (purpose => $purpose) : ()),
      (defined $method ? (method => $method) : ()),
      (defined $adapter_id ? (adapter_id => $adapter_id) : ()),
      (defined $secret_slot ? (secret_slot => $secret_slot) : ()),
      reason      => 'secret_handle_unavailable',
    );
    _invalid_secret_access(param => $error_param);
  }

  my $resolved = {
    name  => $name,
    value => $self->{secrets}{$name},
  };

  $self->_audit(
    action      => 'secret_handle.resolve',
    outcome     => 'resolved',
    name        => $name,
    session_id  => $session_id,
    (defined $program_id ? (program_id => $program_id) : ()),
    (defined $purpose ? (purpose => $purpose) : ()),
    (defined $method ? (method => $method) : ()),
    (defined $adapter_id ? (adapter_id => $adapter_id) : ()),
    (defined $secret_slot ? (secret_slot => $secret_slot) : ()),
  );

  return $resolved;
}

sub revoke_secret_handle {
  my ($self, %args) = @_;
  my $handle_id = _require_string_arg(handle_id => $args{handle_id});

  my $handle = delete $self->{secret_handles}{$handle_id};
  return 0 unless defined $handle;

  $self->_audit(
    action     => 'secret_handle.revoke',
    outcome    => 'revoked',
    name       => $handle->{name},
    session_id => $handle->{session_id},
    (defined $handle->{program_id} ? (program_id => $handle->{program_id}) : ()),
    reason     => 'explicit_revoke',
  );

  return 1;
}

sub revoke_secret_handles_for_session {
  my ($self, %args) = @_;
  my $session_id = _require_string_arg(session_id => $args{session_id});
  my $count = 0;

  for my $handle_id (keys %{$self->{secret_handles}}) {
    my $handle = $self->{secret_handles}{$handle_id};
    next unless defined $handle;
    next unless ($handle->{session_id} || '') eq $session_id;

    delete $self->{secret_handles}{$handle_id};
    $count++;
  }

  $self->_audit(
    action     => 'secret_handle.revoke_session',
    outcome    => 'revoked',
    session_id => $session_id,
    count      => $count,
  );

  return $count;
}

sub rotate_secret {
  my ($self, %args) = @_;
  my $name = _require_string_arg(name => $args{name});
  my $value = _require_string_arg(value => $args{value});
  my $revoked = 0;

  for my $handle_id (keys %{$self->{secret_handles}}) {
    my $handle = $self->{secret_handles}{$handle_id};
    next unless defined $handle;
    next unless ($handle->{name} || '') eq $name;

    delete $self->{secret_handles}{$handle_id};
    $revoked++;
  }

  $self->{secrets}{$name} = $value;
  $self->_audit(
    action  => 'secret.rotate',
    outcome => 'rotated',
    name    => $name,
    revoked => $revoked,
  );

  return {
    name    => $name,
    revoked => $revoked,
  };
}

sub _may_issue_secret {
  my ($self, %args) = @_;
  my $name = $args{name};
  return 0 unless exists $self->{secrets}{$name};

  my $policy = $self->{secret_policies}{$name} || {};
  return 0 unless $self->_matches_allowed_list(
    allowed => $policy->{allowed_session_ids},
    value   => $args{session_id},
  );
  return 0 unless $self->_matches_allowed_list(
    allowed => $policy->{allowed_program_ids},
    value   => $args{program_id},
  );
  return 0 unless $self->_matches_allowed_list(
    allowed => $policy->{allowed_purposes},
    value   => $args{purpose},
  );

  return 1;
}

sub _may_resolve_secret_handle {
  my ($self, %args) = @_;
  my $handle = $args{handle};
  my $name = $handle->{name};
  return 0 unless exists $self->{secrets}{$name};
  return 0 unless ($handle->{session_id} || '') eq ($args{session_id} || '');
  return 0 if defined $handle->{program_id}
    && (!defined $args{program_id} || $handle->{program_id} ne $args{program_id});
  return 0 if defined $handle->{purpose}
    && (!defined $args{purpose} || $handle->{purpose} ne $args{purpose});

  my $policy = $self->{secret_policies}{$name} || {};
  return 0 unless $self->_matches_allowed_list(
    allowed => $policy->{allowed_session_ids},
    value   => $args{session_id},
  );
  return 0 unless $self->_matches_allowed_list(
    allowed => $policy->{allowed_program_ids},
    value   => $args{program_id},
  );
  return 0 unless $self->_matches_allowed_list(
    allowed => $policy->{allowed_purposes},
    value   => $args{purpose},
  );
  return 0 unless $self->_matches_allowed_list(
    allowed => $policy->{allowed_methods},
    value   => $args{method},
  );
  return 0 unless $self->_matches_allowed_list(
    allowed => $policy->{allowed_adapter_ids},
    value   => $args{adapter_id},
  );
  return 0 unless $self->_matches_allowed_list(
    allowed => $policy->{allowed_secret_slots},
    value   => $args{secret_slot},
  );

  return 1;
}

sub _matches_allowed_list {
  my ($self, %args) = @_;
  my $allowed = $args{allowed};
  return 1 unless defined $allowed;

  return 0 unless ref($allowed) eq 'ARRAY' && @{$allowed};
  return 0 unless defined $args{value};

  for my $candidate (@{$allowed}) {
    return 1 if $candidate eq $args{value};
  }

  return 0;
}

sub _audit {
  my ($self, %event) = @_;
  $event{at} = _ms_to_unix_seconds($self->_now_ms)
    unless exists $event{at};
  push @{$self->{audit_events}}, _clone_json(\%event);
  return 1;
}

sub _now_ms {
  my ($self) = @_;
  my $now = $self->{now_cb}->();

  die "now_cb must return an integer millisecond timestamp\n"
    unless defined $now && !ref($now) && $now =~ /\A-?\d+\z/;

  return 0 + $now;
}

sub _expire_secret_handles {
  my ($self) = @_;
  my $now_ms = $self->_now_ms;

  for my $handle_id (keys %{$self->{secret_handles}}) {
    my $handle = $self->{secret_handles}{$handle_id};
    next unless defined $handle;
    delete $self->{secret_handles}{$handle_id}
      if ($handle->{expires_at_ms} || 0) <= $now_ms;
  }

  return 1;
}

sub _generate_secret_handle_id {
  my ($self) = @_;

  for (1 .. 10) {
    my $bytes = eval { $self->_secure_random_bytes(32) };
    if (!$@ && defined $bytes) {
      my $id = 'sh_' . unpack('H*', $bytes);
      next if exists $self->{secret_handles}{$id};
      return $id;
    }
  }

  die {
    code    => 'runtime.service_unavailable',
    message => 'Secure secret handle issuance unavailable',
    details => {
      method => 'secrets.get',
    },
  };
}

sub _secure_random_bytes {
  my ($self, $length) = @_;

  die "length must be a positive integer\n"
    unless defined $length && !ref($length) && $length =~ /\A[1-9]\d*\z/;

  if (my $cb = $self->{random_bytes_cb}) {
    my $bytes = $cb->($length);
    return $bytes
      if defined $bytes && !ref($bytes) && length($bytes) == $length;
    die "random_bytes_cb must return exactly $length bytes\n";
  }

  my $bytes = eval {
    require Crypt::URandom;
    Crypt::URandom::urandom($length);
  };
  return $bytes if defined $bytes && !ref($bytes) && length($bytes) == $length;

  $bytes = eval {
    require Bytes::Random::Secure;
    my $rng = Bytes::Random::Secure->new(NonBlocking => 1);
    $rng->bytes($length);
  };
  return $bytes if defined $bytes && !ref($bytes) && length($bytes) == $length;

  if (open my $fh, '<:raw', '/dev/urandom') {
    my $buffer = '';
    my $read = read($fh, $buffer, $length);
    close $fh;
    return $buffer if defined $read && $read == $length;
  }

  die "No secure random source available\n";
}

sub _validate_secrets {
  my ($secrets) = @_;

  for my $name (sort keys %{$secrets}) {
    die "secret names must be non-empty strings\n"
      unless defined $name && length($name);
    die "secret $name must be a string\n"
      if !defined $secrets->{$name} || ref($secrets->{$name});
  }

  return 1;
}

sub _validate_secret_policies {
  my ($policies) = @_;

  for my $name (sort keys %{$policies}) {
    die "secret policy names must be non-empty strings\n"
      unless defined $name && length($name);
    my $policy = $policies->{$name};
    die "secret policy $name must be an object\n"
      unless ref($policy) eq 'HASH';

    for my $field (
      qw(
        allowed_session_ids
        allowed_program_ids
        allowed_purposes
        allowed_methods
        allowed_adapter_ids
        allowed_secret_slots
      )
    ) {
      next unless exists $policy->{$field};
      die "secret policy $name.$field must be an array of non-empty strings\n"
        unless ref($policy->{$field}) eq 'ARRAY'
          && !grep {
            !defined($_) || ref($_) || !length($_)
          } @{$policy->{$field}};
    }
  }

  return 1;
}

sub _invalid_secret_access {
  my (%args) = @_;
  my $param = $args{param};

  die {
    code    => 'protocol.invalid_params',
    message => 'Secret access denied or unavailable',
    (defined $param ? (details => { param => $param }) : ()),
  };
}

sub _require_string_arg {
  my ($name, $value) = @_;

  die "$name is required\n"
    unless defined $value && !ref($value) && length($value);

  return $value;
}

sub _optional_string_arg {
  my ($name, $value) = @_;
  return undef unless defined $value;

  die "$name must be a non-empty string\n"
    if ref($value) || !length($value);

  return $value;
}

sub _clone_json {
  my ($value) = @_;
  return undef unless defined $value;
  return JSON::PP::decode_json(JSON::PP::encode_json($value));
}

sub _ms_to_unix_seconds {
  my ($ms) = @_;
  return int(($ms + 999) / 1000);
}

1;

=head1 NAME

Overnet::Program::SecretProvider - Host-managed secret material and handles

=head1 DESCRIPTION

Provides secret lookup, handle issuance and resolution, revocation, rotation,
and internal audit records for the Overnet program runtime.

=cut
