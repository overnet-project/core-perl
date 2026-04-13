package Alien::libsecp256k1::Install::Files;
use strict;
use warnings;
require Alien::libsecp256k1;
sub Inline { shift; Alien::libsecp256k1->Inline(@_) }
1;

=begin Pod::Coverage

  Inline

=cut
