#!/usr/bin/env perl

use strict;
use warnings;

use Overnet::Auth::CLI;

my $result = Overnet::Auth::CLI->run(argv => \@ARGV);
print $result->{output};
exit $result->{exit_code};
