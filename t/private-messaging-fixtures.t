use strict;
use warnings;

use File::Basename qw(dirname);
use File::Spec;
use JSON::PP qw(decode_json);
use Test::More;

use Overnet::Core::PrivateMessaging;

my $fixtures_dir = File::Spec->catdir(
  dirname(__FILE__),
  '..',
  '..',
  'spec',
  'fixtures',
  'private-messaging',
);

opendir my $dh, $fixtures_dir or die "Can't open $fixtures_dir: $!";
my @fixture_files = sort grep { /\.json\z/ } readdir $dh;
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

  subtest "$file - $desc" => sub {
    my $result = Overnet::Core::PrivateMessaging::validate_transport($input);

    is $result->{valid}, $expected->{private_transport_valid},
      "valid = $expected->{private_transport_valid}";

    if (!$expected->{private_transport_valid} && $expected->{reason}) {
      my $found = grep { /\Q$expected->{reason}\E/i } @{$result->{errors}};
      ok $found, "errors contain: $expected->{reason}";
    }

    for my $assertion (@{$expected->{assertions} || []}) {
      my $value = _path_get($result, $assertion->{path});

      if (exists $assertion->{equals}) {
        is_deeply $value, $assertion->{equals},
          "$assertion->{path} equals expected value";
      } else {
        fail("Unsupported assertion shape in $file for path $assertion->{path}");
      }
    }
  };
}

done_testing;

sub _path_get {
  my ($root, $path) = @_;
  my @parts = split /\./, $path;
  my $value = $root;

  for my $part (@parts) {
    return undef if !defined $value;

    if (ref($value) eq 'HASH') {
      $value = $value->{$part};
      next;
    }

    if (ref($value) eq 'ARRAY' && $part =~ /\A\d+\z/) {
      $value = $value->[$part];
      next;
    }

    return undef;
  }

  return $value;
}
