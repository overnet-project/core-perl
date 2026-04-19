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

my $readme = File::Spec->catfile($FindBin::Bin, '..', 'README.md');
my $claude = File::Spec->catfile($FindBin::Bin, '..', 'CLAUDE.md');

my $readme_text = _slurp($readme);
my $claude_text = _slurp($claude);

for my $doc (
  [ 'README', $readme_text ],
  [ 'CLAUDE', $claude_text ],
) {
  my ($label, $text) = @{$doc};
  like $text, qr/IRC verification path/i,
    "$label documents the IRC verification path";
  like $text, qr/t\/spec-conformance-irc-server\.t/,
    "$label includes server conformance in the IRC verification path";
  like $text, qr/t\/program-irc-server\.t/,
    "$label includes the fast IRC server suite in the IRC verification path";
  like $text, qr/t\/program-irc-server-relay\.t/,
    "$label includes the relay IRC server suite in the IRC verification path";
}

done_testing;
