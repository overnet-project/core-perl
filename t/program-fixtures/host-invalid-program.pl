use strict;
use warnings;
use IO::Handle;

binmode(STDOUT, ':raw');
STDOUT->autoflush(1);

print STDOUT "oops\n{}\n";
