package Overnet::Program::Permissions;

use strict;
use warnings;

our $VERSION = '0.001';

my %METHOD_PERMISSIONS = (
  'config.get'              => 'config.read',
  'config.describe'         => 'config.read',
  'secrets.get'             => 'secrets.read',
  'storage.put'             => 'storage.write',
  'storage.get'             => 'storage.read',
  'storage.delete'          => 'storage.write',
  'storage.list'            => 'storage.read',
  'events.append'           => 'events.append',
  'events.read'             => 'events.read',
  'subscriptions.open'      => 'subscriptions.read',
  'subscriptions.close'     => 'subscriptions.read',
  'timers.schedule'         => 'timers.write',
  'timers.cancel'           => 'timers.write',
  'adapters.open_session'  => 'adapters.use',
  'adapters.map_input'     => 'adapters.use',
  'adapters.derive'        => 'adapters.use',
  'adapters.close_session' => 'adapters.use',
  'overnet.emit_event'      => 'overnet.emit_event',
  'overnet.emit_state'      => 'overnet.emit_state',
  'overnet.emit_private_message' => 'overnet.emit_private_message',
  'overnet.emit_capabilities' => 'overnet.emit_capabilities',
);

sub required_permission_for_method {
  my ($class, $method) = @_;

  die "method is required\n"
    unless defined $method && !ref($method) && length($method);

  return $METHOD_PERMISSIONS{$method};
}

sub has_permission {
  my ($class, %args) = @_;

  my $permissions = $args{permissions};
  my $permission = $args{permission};

  die "permissions must be an array\n"
    if defined $permissions && ref($permissions) ne 'ARRAY';
  die "permission is required\n"
    unless defined $permission && !ref($permission) && length($permission);

  $permissions ||= [];
  for my $granted (@{$permissions}) {
    next unless defined $granted && !ref($granted);
    return 1 if $granted eq $permission;
  }

  return 0;
}

sub assert_method_allowed {
  my ($class, %args) = @_;

  my $method = $args{method};
  my $permissions = $args{permissions};

  my $required_permission = $class->required_permission_for_method($method);
  return 1 unless defined $required_permission;

  return 1 if $class->has_permission(
    permissions => $permissions,
    permission  => $required_permission,
  );

  die {
    code    => 'runtime.permission_denied',
    message => "Permission denied for method $method",
    details => {
      method              => $method,
      required_permission => $required_permission,
    },
  };
}

1;

=head1 NAME

Overnet::Program::Permissions - Overnet program permission scaffold

=head1 DESCRIPTION

Scaffold module for runtime-managed program permission handling.

=cut
