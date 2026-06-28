#!/usr/bin/env perl

use strictures 2;

use Overnet::Auth::CLI;

my $result = Overnet::Auth::CLI->run(argv => \@ARGV);
print $result->{output};
exit $result->{exit_code};
