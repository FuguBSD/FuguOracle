#!/usr/bin/env perl
# ex:ts=8 sw=4:
# The vocabulary gate (OVW-VOCABULARY). No file that this repository
# owns names one application of the standards. The words come from
# spec/overview.md, so this file names none of them. The three
# repositories FuguSeed, FuguPass, and FuguOracle carry this one file.

use v5.34;
use warnings;
use experimental 'signatures';
no feature qw(indirect multidimensional bareword_filehandles);
use Test::More;
use FindBin    qw($RealBin $RealScript);
use File::Spec ();

my $root = "$RealBin/../..";
chdir $root or BAIL_OUT("chdir $root: $!");
my $self = File::Spec->abs2rel( "$RealBin/$RealScript", $root );

# _slurp($path):
#	The whole file as text, or undef when it does not open.
sub _slurp ($path)
{
	open my $fh, '<', $path or return;
	local $/ = undef;
	my $text = <$fh>;
	close $fh;
	return $text;
}

# _blank($text):
#	The line feeds of $text and nothing else, so a removal keeps
#	every line number true.
sub _blank ($text)
{
	return "\n" x ( () = $text =~ /\n/g );
}

# The rule names each word as inline code: the word `w`. The
# formatter can wrap between the two, so the match spans a line feed.
my $spec  = _slurp('spec/overview.md') // BAIL_OUT("spec/overview.md: $!");
my @words = $spec =~ /the word\s+`([a-z]+)`/g;
is( scalar @words, 5, 'spec/overview.md names five banned words' );

# Each word matches whole, in any letter case, as itself and as a
# plural: the word plus s, and for a word that ends in y, the stem
# plus ies (currency, currencies; money, monies).
my @forms;
for my $word (@words) {
	push @forms, $word, "${word}s";
	push @forms, ( $word =~ s/e?y\z/ies/r ) if $word =~ /y\z/;
}
my $alt    = join '|', map { quotemeta } @forms;
my $banned = qr/\b(?:$alt)\b/i;

# _synced($path):
#	True when a pack of FuguBSD/Tooling owns the file. Such a file
#	says so in its first lines, and it is outside the rule.
sub _synced ($path)
{
	my @head = split /^/m, _slurp($path) // q{};
	splice @head, 6;
	my $head = join q{}, @head;
	return $head =~ /pack of FuguBSD\/Tooling owns this file/;
}

my @hits;
for my $path (`git ls-files --cached --others --exclude-standard`) {
	chomp $path;

	# A port names its upstream, and the ports tree fixes that
	# name, so a file under ports/ is outside the rule.
	next
	    if $path eq $self
	    || $path =~ m{^docs/research/}
	    || $path =~ m{^ports/}
	    || _synced($path);
	my $text = _slurp($path) // next;

	# A fenced code block and an inline code span hold names, not
	# words. The rule that names the words is the one exception.
	my @lines = split /\n/, $text, -1;
	$text =~ s/^```.*?^```[^\n]*/_blank($&)/msge;
	$text =~ s/`[^`]*`/_blank($&)/ge;
	my $number = 0;
	for my $line ( split /\n/, $text, -1 ) {
		$number++;
		next if $lines[ $number - 1 ] =~ /the word `/;
		push @hits, "$path:$number" if $line =~ $banned;
	}
}
is( "@hits", q{}, 'no file that this repository owns holds a banned word' );

done_testing();
