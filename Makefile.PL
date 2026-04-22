use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
  NAME             => 'Overnet',
  DISTNAME         => 'Overnet-Core',
  AUTHOR           => 'Nicholas B. Hubbard <nicholashubbard@posteo.net>',
  ABSTRACT         => 'Perl reference implementation of the Overnet core and program runtime',
  VERSION_FROM     => 'lib/Overnet.pm',
  LICENSE          => 'gpl_3',
  MIN_PERL_VERSION => '5.024',
  PREREQ_PM        => {
    'AnyEvent'        => 0,
    'IO::Socket::SSL' => 0,
    'Net::Nostr'      => 0,
  },
  test => {
    TESTS => join(
      ' ',
      qw(
        t/00-load-program-runtime.t
        t/authority-hosted-channel.t
        t/makemaker-metadata.t
        t/manifest-skip-policy.t
        t/program-host.t
        t/program-instance.t
        t/program-protocol.t
        t/program-runtime-config.t
        t/program-runtime-construction.t
        t/program-runtime-emission.t
        t/program-runtime-private-messaging.t
        t/program-runtime-secrets.t
        t/program-runtime-store.t
        t/program-runtime-subscriptions.t
        t/program-runtime-timers.t
        t/program-runtime-tls.t
        t/repo-split.t
        t/validator.t
      )
    ),
  },
  META_MERGE => {
    resources => {
      repository => 'https://github.com/overnet-project/core-perl',
      bugtracker => 'https://github.com/overnet-project/core-perl/issues',
    },
  },
);
