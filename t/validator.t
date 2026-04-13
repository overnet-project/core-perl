use strict;
use warnings;
use Test::More;
use JSON::PP;
use File::Basename;
use File::Spec;

use Overnet::Core::Validator;

my $fixtures_dir = File::Spec->catdir(dirname(__FILE__), 'fixtures');
opendir my $dh, $fixtures_dir or die "Can't open $fixtures_dir: $!";
my @fixture_files = sort grep { /\.json$/ } readdir $dh;
closedir $dh;

for my $file (@fixture_files) {
  my $path = File::Spec->catfile($fixtures_dir, $file);
  open my $fh, '<', $path or die "Can't read $path: $!";
  my $json = do { local $/; <$fh> };
  close $fh;

  my $fixture = decode_json($json);
  my $desc = $fixture->{description};
  my $input = $fixture->{input};
  my $expected = $fixture->{expected};
  my $context = $fixture->{context};

  subtest "$file - $desc" => sub {
    my $result = Overnet::Core::Validator::validate($input, $context);

    is $result->{valid}, $expected->{overnet_valid},
      "valid = $expected->{overnet_valid}";

    if (!$expected->{overnet_valid} && $expected->{reason}) {
      my $found = grep { /\Q$expected->{reason}\E/i } @{$result->{errors}};
      ok $found, "errors contain: $expected->{reason}";
    }
  };
}

done_testing;
