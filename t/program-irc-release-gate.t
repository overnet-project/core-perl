use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

sub _slurp {
  my ($path) = @_;
  open my $fh, '<', $path
    or die "Can't open $path: $!";
  local $/;
  return <$fh>;
}

my $root = File::Spec->catdir($FindBin::Bin, '..');
my $script = File::Spec->catfile($root, 'bin', 'overnet-release-gate.pl');
my $readme = File::Spec->catfile($root, 'README.md');
my $claude = File::Spec->catfile($root, 'CLAUDE.md');

ok(-f $script, 'default IRC release gate script exists');

my $script_text = _slurp($script);
like $script_text, qr/t\/spec-conformance-irc-server\.t/,
  'release gate script runs server conformance';
like $script_text, qr/t\/program-irc-server\.t/,
  'release gate script runs the fast IRC server suite';
like $script_text, qr/t\/program-irc-server-relay\.t/,
  'release gate script runs the relay IRC server suite';

for my $doc (
  [ 'README', _slurp($readme) ],
  [ 'CLAUDE', _slurp($claude) ],
) {
  my ($label, $text) = @{$doc};
  like $text, qr/default release gate/i,
    "$label identifies the default release gate";
  like $text, qr/bin\/overnet-release-gate\.pl/,
    "$label points to the release gate script";
}

done_testing;
