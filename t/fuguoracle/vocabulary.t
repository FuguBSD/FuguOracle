#!/usr/bin/env perl
# ex:ts=8 sw=4:
# The vocabulary gate (OVW-VOCABULARY). No file that this repository
# owns names one application of the standards. The words come from
# spec/overview.md, so this file names none of them.

use v5.36;
use Test::More;
use FindBin qw($RealBin $RealScript);

my $root = "$RealBin/../..";
chdir $root or BAIL_OUT("chdir $root: $!");

# The rule names each word as inline code: the word `w`. The rule
# wraps, so the whole text is the unit of the match.
open my $spec, '<', 'spec/overview.md' or BAIL_OUT("spec/overview.md: $!");
my @words = do { local $/ = undef; <$spec> } =~ /the word\s+`([a-z]+)`/g;
close $spec;
is( scalar @words, 4, 'spec/overview.md names four banned words' );

# Each word matches whole, in any letter case, singular or plural.
my @forms;
for my $word (@words) {
	push @forms, $word, "${word}s";
	push @forms, substr( $word, 0, -1 ) . 'ies' if $word =~ /y\z/;
}
my $alt    = join '|', map { quotemeta } @forms;
my $banned = qr/\b(?:$alt)\b/i;

# A file that a pack of FuguBSD/Tooling owns says so in its first
# lines, and it is outside the rule.
sub _synced ($path)
{
	open my $fh, '<', $path or return 0;
	my $head = join q{}, map { <$fh> // q{} } 1 .. 6;
	close $fh;
	return $head =~ m{pack of FuguBSD/Tooling owns this file};
}

# _unfenced($text):
#	The text without its fenced code blocks. A removed block keeps
#	its line breaks, so the line numbers of the rest hold.
sub _unfenced ($text)
{
	$text =~ s{(^```[^\n]*\n.*?^```[^\n]*$)}{ "\n" x ( () = $1 =~ /\n/g ) }gmse;
	return $text;
}

# This file sits two directories under the root, and it is outside
# the rule.
my $self = join '/', ( split m{/}, $RealBin )[ -2, -1 ], $RealScript;
my @hits;
for my $path (`git ls-files --cached --others --exclude-standard`) {
	chomp $path;
	next if $path eq $self || $path =~ m{\Adocs/research/} || _synced($path);
	open my $fh, '<', $path or next;
	my $text = do { local $/ = undef; <$fh> };
	close $fh;
	my $n = 0;
	for my $line ( split /\n/, _unfenced($text) ) {
		$n++;
		# The rule that names the words is the one exception.
		next if $line =~ /the word `/;
		$line =~ s/`[^`]*`//g;
		push @hits, "$path:$n" if $line =~ $banned;
	}
}
is( "@hits", q{}, 'no file that this repository owns holds a banned word' );

done_testing();
