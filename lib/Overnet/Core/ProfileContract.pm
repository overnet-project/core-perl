package Overnet::Core::ProfileContract;

use strict;
use warnings;
use B qw(SVp_IOK SVp_NOK SVp_POK svref_2object);
use JSON::PP ();
use JSON::Schema::Modern;
use Scalar::Util qw(blessed);

my $JSON = JSON::PP->new->utf8;
my $JSON_SCHEMA = JSON::Schema::Modern->new(
  specification_version => 'draft2020-12',
  output_format         => 'flag',
);
my %TOP_LEVEL = map { $_ => 1 } qw(contract_version profile profile_version status description capabilities depends_on object_types event_types fixtures extensions);
my @REQUIRED_TOP_LEVEL = qw(contract_version profile profile_version status description capabilities object_types event_types fixtures extensions);
my %STATUS = map { $_ => 1 } qw(draft stable deprecated);
my %CORE_REQUIRED_TAG = map { $_ => 1 } qw(overnet_v overnet_et overnet_ot overnet_oid v t o d);
my %OBJECT_ID_SCHEME = map { $_ => 1 } qw(profile-defined uuid uri content-addressed opaque);
my %STATE_DERIVATION = map { $_ => 1 } qw(event-log latest-per-author external-authoritative profile-defined);
my %STATE_EFFECT = map { $_ => 1 } qw(none creates updates removes profile-defined);
my %AUTHORIZATION_MODEL = map { $_ => 1 } qw(open author-is-object-owner delegated external-authority profile-defined);
my %PRIVACY = map { $_ => 1 } qw(public encrypted profile-defined);

my %DEPENDENCY_FIELD = map { $_ => 1 } qw(profile version);
my %FIXTURES_FIELD = map { $_ => 1 } qw(valid invalid);
my %OBJECT_TYPE_FIELD = map { $_ => 1 } qw(description id state extensions);
my %OBJECT_ID_FIELD = map { $_ => 1 } qw(scheme pattern examples);
my %OBJECT_STATE_FIELD = map { $_ => 1 } qw(derivation state_event_type);
my %EVENT_TYPE_FIELD = map { $_ => 1 } qw(description kind object_type required_tags body_schema references state_effect authorization privacy extensions);
my %AUTHORIZATION_FIELD = map { $_ => 1 } qw(model description);
my %REFERENCE_FIELD = map { $_ => 1 } qw(name required tag target_object_type target_event_type);

sub validate_contract {
  my ($contract) = @_;
  my @errors;
  return _result(errors => ['profile_contract.document_not_object'])
    unless ref($contract) eq 'HASH';

  for my $field (sort keys %{$contract}) {
    push @errors, 'profile_contract.unknown_top_level_field'
      unless $TOP_LEVEL{$field};
  }

  for my $field (@REQUIRED_TOP_LEVEL) {
    next if exists $contract->{$field};
    push @errors, $field eq 'contract_version'
      ? 'profile_contract.missing_contract_version'
      : "profile_contract.missing_$field";
  }

  if (exists $contract->{contract_version} && (!_is_json_integer($contract->{contract_version})
      || $contract->{contract_version} != 1)) {
    push @errors, 'profile_contract.invalid_contract_version';
  }

  my $profile = $contract->{profile};
  push @errors, 'profile_contract.invalid_profile_namespace'
    unless _is_profile_name($profile);

  push @errors, 'profile_contract.invalid_profile_version'
    if exists $contract->{profile_version} && !_is_semver($contract->{profile_version});

  push @errors, 'profile_contract.invalid_status'
    if exists $contract->{status} && (!_is_non_empty_string($contract->{status}) || !$STATUS{$contract->{status}});

  push @errors, 'profile_contract.invalid_description'
    if exists $contract->{description} && !_is_non_empty_string($contract->{description});

  _validate_capabilities($contract, \@errors);
  _validate_dependencies($contract, \@errors);
  _validate_fixtures($contract, \@errors);
  _validate_extensions($contract->{extensions}, \@errors) if exists $contract->{extensions};

  my $object_types = ref($contract->{object_types}) eq 'HASH' ? $contract->{object_types} : {};
  my $event_types = ref($contract->{event_types}) eq 'HASH' ? $contract->{event_types} : {};

  push @errors, 'profile_contract.invalid_object_types'
    if exists $contract->{object_types}
    && (ref($contract->{object_types}) ne 'HASH' || !keys %{$object_types});

  push @errors, 'profile_contract.invalid_event_types'
    if exists $contract->{event_types}
    && (ref($contract->{event_types}) ne 'HASH' || !keys %{$event_types});

  for my $name (sort keys %{$object_types}) {
    my $object_type = $object_types->{$name};
    push @errors, 'profile_contract.object_type_outside_profile_namespace'
      unless _is_profile_scoped_name($name) && _is_local_name($profile, $name);

    _validate_object_type($object_type, \@errors);
  }

  for my $name (sort keys %{$event_types}) {
    my $event_type = $event_types->{$name};

    push @errors, 'profile_contract.event_type_outside_profile_namespace'
      unless _is_profile_scoped_name($name) && _is_local_name($profile, $name);

    _validate_event_type($contract, $event_type, $object_types, \@errors);
  }

  for my $name (sort keys %{$object_types}) {
    my $object_type = $object_types->{$name};
    next unless ref($object_type) eq 'HASH' && ref($object_type->{state}) eq 'HASH';
    my $state_event_type = $object_type->{state}{state_event_type};
    push @errors, 'profile_contract.state_event_type_undefined'
      if _is_non_empty_string($state_event_type) && !exists $event_types->{$state_event_type};
  }

  return _result(errors => \@errors, contract => $contract);
}

sub validate_contract_set {
  my ($contracts) = @_;
  my @errors;
  return _result(errors => ['profile_contract_set.contracts_not_array'])
    unless ref($contracts) eq 'ARRAY';

  my %by_profile;
  for my $contract (@{$contracts}) {
    my $result = validate_contract($contract);
    push @errors, @{$result->{errors}} unless $result->{valid};

    my $profile = ref($contract) eq 'HASH' ? $contract->{profile} : undef;
    next unless defined $profile;

    if (exists $by_profile{$profile}) {
      push @errors, 'profile_contract_set.duplicate_profile';
    } else {
      $by_profile{$profile} = $contract;
    }
  }

  if (!@errors) {
    for my $contract (@{$contracts}) {
      _validate_contract_dependencies_in_set($contract, \%by_profile, \@errors);
    }
  }

  if (!@errors) {
    for my $contract (@{$contracts}) {
      _validate_external_references_in_set($contract, \%by_profile, \@errors);
    }
  }

  if (!@errors) {
    for my $contract (@{$contracts}) {
      _validate_external_event_object_types_in_set($contract, \%by_profile, \@errors);
    }
  }

  return _result(errors => \@errors, contracts => $contracts, by_profile => \%by_profile);
}

sub validate_profile_event {
  my (%args) = @_;
  my @contracts;
  push @contracts, $args{contract}
    if exists $args{contract} && defined $args{contract};

  push @contracts, @{$args{contracts}}
    if ref($args{contracts}) eq 'ARRAY';

  return { valid => 1, applicable => 0, errors => [] }
    unless @contracts;

  my $context = @contracts == 1
    ? validate_contract($contracts[0])
    : validate_contract_set(\@contracts);

  return $context unless $context->{valid};

  my ($kind, $tags, $content) = _event_parts($args{event});
  my ($tag_values, $tag_counts) = _event_tags($tags);
  my $event_type_name = $tag_values->{overnet_et};
  my @matches;

  for my $contract (@contracts) {
    next unless ref($contract) eq 'HASH' && ref($contract->{event_types}) eq 'HASH';
    next unless defined $event_type_name && exists $contract->{event_types}{$event_type_name};
    push @matches, [ $contract, $contract->{event_types}{$event_type_name} ];
  }

  return _result(errors => ['profile_event.event_type_undefined'], applicable => 1)
    unless @matches;

  return _result(errors => ['profile_event.event_type_ambiguous'], applicable => 1)
    if @matches > 1;

  my ($contract, $event_type) = @{$matches[0]};
  my @errors;

  push @errors, 'profile_event.kind_mismatch'
    if !defined $kind || $kind != $event_type->{kind};

  push @errors, 'profile_event.object_type_mismatch'
    if ($tag_values->{overnet_ot} // '') ne ($event_type->{object_type} // '');

  for my $tag (@{$event_type->{required_tags} || []}) {
    push @errors, 'profile_event.required_tag_missing'
      unless $tag_counts->{$tag};
  }

  my $body = _event_body($content);
  push @errors, 'profile_event.body_schema_mismatch'
    unless ref($body) eq 'HASH' && _json_schema_valid($body, $event_type->{body_schema});

  for my $reference (@{$event_type->{references} || []}) {
    next unless ref($reference) eq 'HASH';
    next unless $reference->{required};
    my $tag = $reference->{tag};
    push @errors, 'profile_event.required_reference_tag_missing'
      if defined $tag && !$tag_counts->{$tag};
  }

  return _result(errors => \@errors, applicable => 1, contract => $contract);
}

sub _validate_capabilities {
  my ($contract, $errors) = @_;
  return unless exists $contract->{capabilities};
  return push @{$errors}, 'profile_contract.invalid_capabilities'
    unless ref($contract->{capabilities}) eq 'ARRAY';

  my %seen;
  for my $capability (@{$contract->{capabilities}}) {
    if (!_is_profile_scoped_name($capability)) {
      push @{$errors}, 'profile_contract.invalid_capability';
      next;
    }

    push @{$errors}, 'profile_contract.duplicate_capability'
      if $seen{$capability}++;
  }
}

sub _validate_fixtures {
  my ($contract, $errors) = @_;
  return unless exists $contract->{fixtures};
  return push @{$errors}, 'profile_contract.invalid_fixtures'
    unless ref($contract->{fixtures}) eq 'HASH';

  _validate_fields(
    $contract->{fixtures},
    \%FIXTURES_FIELD,
    [qw(valid invalid)],
    'profile_contract.invalid_fixtures',
    $errors,
  );

  for my $field (qw(valid invalid)) {
    next unless exists $contract->{fixtures}{$field};
    if (ref($contract->{fixtures}{$field}) ne 'ARRAY') {
      push @{$errors}, 'profile_contract.invalid_fixtures';
      next;
    }

    my %seen;
    for my $path (@{$contract->{fixtures}{$field}}) {
      if (!_is_relative_path($path)) {
        push @{$errors}, 'profile_contract.invalid_fixture_path';
        next;
      }

      push @{$errors}, 'profile_contract.duplicate_fixture_path'
        if $seen{$path}++;
    }
  }
}

sub _validate_extensions {
  my ($extensions, $errors) = @_;
  push @{$errors}, 'profile_contract.invalid_extensions'
    unless ref($extensions) eq 'HASH';
}

sub _validate_object_type {
  my ($object_type, $errors) = @_;
  return push @{$errors}, 'profile_contract.invalid_object_type'
    unless ref($object_type) eq 'HASH';

  _validate_fields(
    $object_type,
    \%OBJECT_TYPE_FIELD,
    [qw(description id state extensions)],
    'profile_contract.invalid_object_type',
    $errors,
  );

  push @{$errors}, 'profile_contract.invalid_object_type_description'
    unless _is_non_empty_string($object_type->{description});

  _validate_object_id($object_type->{id}, $errors);
  _validate_object_state($object_type->{state}, $errors);
  _validate_extensions($object_type->{extensions}, $errors) if exists $object_type->{extensions};
}

sub _validate_object_id {
  my ($id, $errors) = @_;
  return push @{$errors}, 'profile_contract.invalid_object_id'
    unless ref($id) eq 'HASH';

  _validate_fields(
    $id,
    \%OBJECT_ID_FIELD,
    [qw(scheme pattern examples)],
    'profile_contract.invalid_object_id',
    $errors,
  );

  push @{$errors}, 'profile_contract.invalid_object_id_scheme'
    unless _is_non_empty_string($id->{scheme}) && $OBJECT_ID_SCHEME{$id->{scheme}};

  push @{$errors}, 'profile_contract.invalid_object_id_pattern'
    unless exists $id->{pattern} && (!defined $id->{pattern} || _is_non_empty_string($id->{pattern}));

  if (ref($id->{examples}) ne 'ARRAY') {
    push @{$errors}, 'profile_contract.invalid_object_id_examples';
    return;
  }

  for my $example (@{$id->{examples}}) {
    push @{$errors}, 'profile_contract.invalid_object_id_examples'
      unless _is_non_empty_string($example);
  }
}

sub _validate_object_state {
  my ($state, $errors) = @_;
  return push @{$errors}, 'profile_contract.invalid_object_state'
    unless ref($state) eq 'HASH';

  _validate_fields(
    $state,
    \%OBJECT_STATE_FIELD,
    [qw(derivation state_event_type)],
    'profile_contract.invalid_object_state',
    $errors,
  );

  push @{$errors}, 'profile_contract.invalid_state_derivation'
    unless _is_non_empty_string($state->{derivation}) && $STATE_DERIVATION{$state->{derivation}};

  push @{$errors}, 'profile_contract.invalid_state_event_type'
    unless exists $state->{state_event_type}
    && (!defined $state->{state_event_type} || _is_non_empty_string($state->{state_event_type}));
}

sub _validate_event_type {
  my ($contract, $event_type, $object_types, $errors) = @_;
  return push @{$errors}, 'profile_contract.invalid_event_type'
    unless ref($event_type) eq 'HASH';

  _validate_fields(
    $event_type,
    \%EVENT_TYPE_FIELD,
    [qw(description kind object_type required_tags body_schema references state_effect authorization privacy extensions)],
    'profile_contract.invalid_event_type',
    $errors,
  );

  push @{$errors}, 'profile_contract.invalid_event_type_description'
    unless _is_non_empty_string($event_type->{description});

  if (_is_json_integer($event_type->{kind}) && $event_type->{kind} == 7801) {
    push @{$errors}, 'profile_contract.profile_event_type_uses_core_removal_kind';
  } elsif (!_is_json_integer($event_type->{kind}) || !_is_event_kind($event_type->{kind})) {
    push @{$errors}, 'profile_contract.invalid_event_kind';
  }

  my $event_object_type = $event_type->{object_type};
  if (!_is_profile_scoped_name($event_object_type)) {
    push @{$errors}, 'profile_contract.invalid_event_object_type';
  } elsif (_is_local_name($contract->{profile}, $event_object_type)) {
    push @{$errors}, 'profile_contract.event_object_type_undefined'
      unless exists $object_types->{$event_object_type};
  } elsif (!_dependency_for_target($contract, $event_object_type)) {
    push @{$errors}, 'profile_contract.event_object_type_dependency_missing';
  }

  _validate_required_tags($event_type->{required_tags}, $errors);

  if (ref($event_type->{body_schema}) ne 'HASH'
      || !_is_non_empty_string($event_type->{body_schema}{type})
      || $event_type->{body_schema}{type} ne 'object') {
    push @{$errors}, 'profile_contract.body_schema_not_object';
  }

  _validate_references($contract, $event_type->{references}, $errors);

  push @{$errors}, 'profile_contract.invalid_state_effect'
    unless _is_non_empty_string($event_type->{state_effect}) && $STATE_EFFECT{$event_type->{state_effect}};

  _validate_authorization($event_type->{authorization}, $errors);

  push @{$errors}, 'profile_contract.invalid_privacy'
    unless _is_non_empty_string($event_type->{privacy}) && $PRIVACY{$event_type->{privacy}};

  _validate_extensions($event_type->{extensions}, $errors) if exists $event_type->{extensions};
}

sub _validate_authorization {
  my ($authorization, $errors) = @_;
  return push @{$errors}, 'profile_contract.invalid_authorization'
    unless ref($authorization) eq 'HASH';

  _validate_fields(
    $authorization,
    \%AUTHORIZATION_FIELD,
    [qw(model description)],
    'profile_contract.invalid_authorization',
    $errors,
  );

  push @{$errors}, 'profile_contract.invalid_authorization_model'
    unless _is_non_empty_string($authorization->{model}) && $AUTHORIZATION_MODEL{$authorization->{model}};

  push @{$errors}, 'profile_contract.invalid_authorization_description'
    unless _is_non_empty_string($authorization->{description});
}

sub _validate_dependencies {
  my ($contract, $errors) = @_;
  return unless exists $contract->{depends_on};
  return push @{$errors}, 'profile_contract.invalid_dependencies'
    unless ref($contract->{depends_on}) eq 'ARRAY';

  my %seen;
  for my $dependency (@{$contract->{depends_on}}) {
    if (ref($dependency) ne 'HASH') {
      push @{$errors}, 'profile_contract.invalid_dependency';
      next;
    }

    _validate_fields(
      $dependency,
      \%DEPENDENCY_FIELD,
      [qw(profile version)],
      'profile_contract.invalid_dependency',
      $errors,
    );

    my $profile = $dependency->{profile};

    push @{$errors}, 'profile_contract.invalid_dependency_profile'
      unless _is_profile_name($profile);

    push @{$errors}, 'profile_contract.self_dependency'
      if defined $profile && defined $contract->{profile} && $profile eq $contract->{profile};

    push @{$errors}, 'profile_contract.duplicate_dependency_profile'
      if defined $profile && $seen{$profile}++;

    push @{$errors}, 'profile_contract.invalid_dependency_version'
      unless _is_version_requirement($dependency->{version});
  }
}

sub _validate_required_tags {
  my ($required_tags, $errors) = @_;
  return push @{$errors}, 'profile_contract.invalid_required_tags'
    unless ref($required_tags) eq 'ARRAY';

  my %seen;
  for my $tag (@{$required_tags}) {
    if (!_is_tag_name($tag)) {
      push @{$errors}, 'profile_contract.invalid_required_tag';
      next;
    }

    push @{$errors}, 'profile_contract.duplicate_required_tag'
      if $seen{$tag}++;
  }

  for my $tag (sort keys %CORE_REQUIRED_TAG) {
    push @{$errors}, 'profile_contract.required_core_tag_missing'
      unless $seen{$tag};
  }
}

sub _validate_references {
  my ($contract, $references, $errors) = @_;
  return push @{$errors}, 'profile_contract.invalid_references'
    unless ref($references) eq 'ARRAY';

  for my $reference (@{$references}) {
    if (ref($reference) ne 'HASH') {
      push @{$errors}, 'profile_contract.invalid_reference';
      next;
    }

    _validate_fields(
      $reference,
      \%REFERENCE_FIELD,
      [qw(name required tag target_object_type target_event_type)],
      'profile_contract.invalid_reference',
      $errors,
    );

    push @{$errors}, 'profile_contract.invalid_reference_name'
      unless _is_non_empty_string($reference->{name});

    push @{$errors}, 'profile_contract.invalid_reference_required'
      unless JSON::PP::is_bool($reference->{required});

    push @{$errors}, 'profile_contract.invalid_reference_tag'
      if exists $reference->{tag} && defined $reference->{tag} && !_is_tag_name($reference->{tag});

    my $target_object_type = $reference->{target_object_type};
    my $target_event_type = $reference->{target_event_type};
    my $has_object = defined $target_object_type;
    my $has_event = defined $target_event_type;

    push @{$errors}, 'profile_contract.invalid_reference_target_object_type'
      if $has_object && !_is_profile_scoped_name($target_object_type);

    push @{$errors}, 'profile_contract.invalid_reference_target_event_type'
      if $has_event && !_is_profile_scoped_name($target_event_type);

    if ($has_object && $has_event) {
      push @{$errors}, 'profile_contract.reference_target_ambiguous';
      next;
    }

    if (!$has_object && !$has_event) {
      push @{$errors}, 'profile_contract.reference_target_missing';
      next;
    }

    push @{$errors}, 'profile_contract.required_reference_tag_missing'
      if JSON::PP::is_bool($reference->{required}) && $reference->{required} && !defined $reference->{tag};

    my ($target, $kind) = $has_object
      ? ($target_object_type, 'object')
      : ($target_event_type, 'event');

    if (_is_local_name($contract->{profile}, $target)) {
      if ($kind eq 'object' && !exists $contract->{object_types}{$target}) {
        push @{$errors}, 'profile_contract.reference_target_object_type_undefined';
      } elsif ($kind eq 'event' && !exists $contract->{event_types}{$target}) {
        push @{$errors}, 'profile_contract.reference_target_event_type_undefined';
      }
    } elsif (!_dependency_for_target($contract, $target)) {
      push @{$errors}, 'profile_contract.reference_target_dependency_missing';
    }
  }
}

sub _validate_contract_dependencies_in_set {
  my ($contract, $by_profile, $errors) = @_;
  for my $dependency (@{$contract->{depends_on} || []}) {
    my $profile = $dependency->{profile};
    my $dependency_contract = $by_profile->{$profile};

    if (!$dependency_contract) {
      push @{$errors}, 'profile_contract_set.dependency_missing';
      next;
    }

    push @{$errors}, 'profile_contract_set.dependency_version_unsatisfied'
      unless _version_satisfies($dependency_contract->{profile_version}, $dependency->{version});
  }
}

sub _validate_external_references_in_set {
  my ($contract, $by_profile, $errors) = @_;
  for my $event_type (values %{$contract->{event_types} || {}}) {
    next unless ref($event_type) eq 'HASH' && ref($event_type->{references}) eq 'ARRAY';

    for my $reference (@{$event_type->{references}}) {
      next unless ref($reference) eq 'HASH';
      my $target = defined $reference->{target_object_type}
        ? $reference->{target_object_type}
        : $reference->{target_event_type};
      next unless defined $target && !_is_local_name($contract->{profile}, $target);

      my $dependency = _dependency_for_target($contract, $target);
      my $dependency_contract = $dependency ? $by_profile->{$dependency->{profile}} : undef;
      next unless $dependency_contract;

      if (defined $reference->{target_object_type}
          && !exists $dependency_contract->{object_types}{$target}) {
        push @{$errors}, 'profile_contract_set.reference_target_missing';
      } elsif (defined $reference->{target_event_type}
          && !exists $dependency_contract->{event_types}{$target}) {
        push @{$errors}, 'profile_contract_set.reference_target_missing';
      }
    }
  }
}

sub _validate_external_event_object_types_in_set {
  my ($contract, $by_profile, $errors) = @_;
  for my $event_type (values %{$contract->{event_types} || {}}) {
    next unless ref($event_type) eq 'HASH';
    my $target = $event_type->{object_type};
    next unless defined $target && !_is_local_name($contract->{profile}, $target);

    my $dependency = _dependency_for_target($contract, $target);
    my $dependency_contract = $dependency ? $by_profile->{$dependency->{profile}} : undef;
    next unless $dependency_contract;

    push @{$errors}, 'profile_contract_set.event_object_type_missing'
      unless exists $dependency_contract->{object_types}{$target};
  }
}

sub _event_parts {
  my ($event) = @_;

  if (ref($event) eq 'HASH') {
    return ($event->{kind}, $event->{tags}, $event->{content});
  }

  if (blessed($event) && $event->can('kind') && $event->can('tags') && $event->can('content')) {
    return ($event->kind, $event->tags, $event->content);
  }

  return;
}

sub _event_tags {
  my ($tags) = @_;
  my (%values, %counts);
  for my $tag (@{$tags || []}) {
    next unless ref($tag) eq 'ARRAY' && @{$tag};
    $counts{$tag->[0]}++;
    $values{$tag->[0]} = $tag->[1] if @{$tag} >= 2;
  }

  return (\%values, \%counts);
}

sub _event_body {
  my ($content) = @_;
  my $decoded = eval { $JSON->decode($content) };
  return undef if $@ || ref($decoded) ne 'HASH';
  return $decoded->{body};
}

sub _json_schema_valid {
  my ($value, $schema) = @_;
  return 0 unless ref($schema) eq 'HASH';
  my $result = eval { $JSON_SCHEMA->evaluate($value, $schema) };
  return 0 if $@ || !$result;
  return $result->valid ? 1 : 0;
}

sub _validate_fields {
  my ($value, $allowed, $required, $reason, $errors) = @_;

  for my $field (sort keys %{$value}) {
    push @{$errors}, $reason
      unless $allowed->{$field};
  }

  for my $field (@{$required}) {
    push @{$errors}, $reason
      unless exists $value->{$field};
  }
}

sub _dependency_for_target {
  my ($contract, $target) = @_;
  my @matches;
  for my $dependency (@{$contract->{depends_on} || []}) {
    next unless ref($dependency) eq 'HASH';
    my $profile = $dependency->{profile};
    next unless defined $profile && defined $target;
    push @matches, $dependency if $target =~ /\A\Q$profile\E\./;
  }

  return undef unless @matches;
  return (sort { length($b->{profile}) <=> length($a->{profile}) } @matches)[0];
}

sub _is_non_empty_string {
  my ($value) = @_;
  return _is_json_string($value) && length($value) > 0;
}

sub _is_json_string {
  my ($value) = @_;
  return 0 unless defined($value) && !ref($value);
  my $flags = svref_2object(\$value)->FLAGS;
  return ($flags & SVp_POK) && !($flags & (SVp_IOK | SVp_NOK)) ? 1 : 0;
}

sub _is_json_integer {
  my ($value) = @_;
  return 0 unless defined($value) && !ref($value);
  my $flags = svref_2object(\$value)->FLAGS;
  return ($flags & SVp_IOK) && !($flags & (SVp_NOK | SVp_POK)) ? 1 : 0;
}

sub _is_json_number {
  my ($value) = @_;
  return 0 unless defined($value) && !ref($value);
  my $flags = svref_2object(\$value)->FLAGS;
  return ($flags & (SVp_IOK | SVp_NOK)) && !($flags & SVp_POK) ? 1 : 0;
}

sub _is_local_name {
  my ($profile, $name) = @_;
  return defined($profile) && defined($name) && $name =~ /\A\Q$profile\E\./ ? 1 : 0;
}

sub _is_profile_name {
  my ($value) = @_;
  return _is_json_string($value) && $value =~ /\A[a-z0-9]+(?:[._-][a-z0-9]+)*\z/;
}

sub _is_profile_scoped_name {
  my ($value) = @_;
  return _is_json_string($value) && $value =~ /\A[a-z0-9]+(?:[._-][a-z0-9]+)+\z/;
}

sub _is_semver {
  my ($value) = @_;
  return _is_json_string($value) && $value =~ /\A\d+\.\d+\.\d+\z/;
}

sub _is_version_requirement {
  my ($value) = @_;
  return 0 unless _is_json_string($value);
  return 1 if _is_semver($value);
  return $value =~ /\A(?:=|>=|>|<=|<)\d+\.\d+\.\d+(?: (?:=|>=|>|<=|<)\d+\.\d+\.\d+)?\z/;
}

sub _is_event_kind {
  my ($value) = @_;
  return defined($value) && ($value == 7800 || $value == 37800);
}

sub _is_tag_name {
  my ($value) = @_;
  return _is_json_string($value) && $value =~ /\A[A-Za-z0-9_:-]+\z/;
}

sub _is_relative_path {
  my ($value) = @_;
  return _is_json_string($value)
    && length($value) > 0
    && $value !~ m{\A/}
    && $value !~ m{(?:\A|/)\.\.(?:/|\z)};
}

sub _version_satisfies {
  my ($version, $requirement) = @_;
  return 0 unless _is_semver($version) && _is_version_requirement($requirement);
  return _compare_versions($version, $requirement) == 0
    if _is_semver($requirement);

  for my $term (split / /, $requirement) {
    $term =~ /\A(=|>=|>|<=|<)(\d+\.\d+\.\d+)\z/ or return 0;
    my ($op, $required) = ($1, $2);
    my $cmp = _compare_versions($version, $required);
    return 0 if $op eq '='  && $cmp != 0;
    return 0 if $op eq '>'  && $cmp <= 0;
    return 0 if $op eq '>=' && $cmp < 0;
    return 0 if $op eq '<'  && $cmp >= 0;
    return 0 if $op eq '<=' && $cmp > 0;
  }

  return 1;
}

sub _compare_versions {
  my ($left, $right) = @_;
  my @left = split /\./, $left;
  my @right = split /\./, $right;
  for my $i (0 .. 2) {
    return -1 if $left[$i] < $right[$i];
    return 1 if $left[$i] > $right[$i];
  }

  return 0;
}

sub _result {
  my (%args) = @_;
  my $errors = $args{errors} || [];
  my %result = map { $_ => $args{$_} } grep { exists $args{$_} } qw(contract contracts by_profile applicable);
  return @{$errors}
    ? { %result, valid => 0, errors => $errors, reason => $errors->[0] }
    : { %result, valid => 1, errors => [] };
}

1;
