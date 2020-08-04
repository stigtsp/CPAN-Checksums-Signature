use strict;
use warnings;
use Test::More;
use Test::Exception;
use Safe;

use_ok('CPAN::Checksums::Signature');


sub checksums {
    open my $fh, '<', 't/checksums/'.shift;
    binmode($fh);
    return join '', <$fh>;
};


my ($sigtext, $message, $signature) = CPAN::Checksums::Signature::_parse_cleartext(checksums("good"));

like($sigtext, qr/^-----BEGIN PGP SIGNED MESSAGE-----/, 'sigtext starts with BEGIN PGP SIGNED MESSAGE');
like($sigtext, qr/-----END PGP SIGNATURE-----\r?\n$/, 'sigtext ends with END PGP SIGNATURE');


like($signature, qr/^-----BEGIN PGP SIGNATURE-----/, 'signature starts with BEGIN PGP SIGNATURE');
like($signature, qr/-----END PGP SIGNATURE-----\r?\n$/, 'signature ends with END PGP SIGNATURE');



my $good_message = checksums("good_message");
is($message, $good_message,"\$message equals good_message");


my $unsafe = Safe->new->reval($message);
ok(exists $unsafe->{"CPAN-2.28.tar.gz"},
   "message parses and contains CPAN-2.28.tar.gz");

throws_ok(sub {CPAN::Checksums::Signature::_parse_cleartext(checksums("bad-prepend-clearsign")); },
      qr/FAILED VERIFICATION.+Found more/s);

throws_ok(sub {CPAN::Checksums::Signature::_parse_cleartext(checksums("bad-message-incomplete")); },
      qr/FAILED VERIFICATION.+Did not/s);



subtest 'gpgv' => sub {
    plan skip_all => 'gnupg is not installed'
      unless CPAN::Checksums::Signature::_which_gpgv();

    my $verified = CPAN::Checksums::Signature::_verify_gpgv($message, $signature);
    ok($verified eq $message, "verified and message is equal");

    ok(exists Safe->new->reval($verified)->{"CPAN-2.28.tar.gz"},
       "message parses and contains CPAN-2.28.tar.gz");

    throws_ok(sub { CPAN::Checksums::Signature::_verify_gpgv($message."extra", $signature); },
              qr/FAILED VERIFICATION.+gpgv: BAD signature from/s);

    throws_ok(sub { CPAN::Checksums::Signature::_verify_gpgv($message, ""); },
              qr/FAILED VERIFICATION.+verify signatures failed/s);

    done_testing();
};



subtest 'gpgv strong key' => sub {
    plan skip_all => 'gnupg is not installed'
      unless CPAN::Checksums::Signature::_which_gpgv();

    my ($sigtext, $message, $signature) = CPAN::Checksums::Signature::_parse_cleartext(checksums("strong"));

    no warnings;
    local $CPAN::Checksums::Signature::KEYRING = "t/checksums/stigtsp.gpg";

    my $verified = CPAN::Checksums::Signature::_verify_gpgv($message, $signature);
    ok($verified eq $message, "verified and message is equal");

    ok(exists Safe->new->reval($verified)->{"CPAN-2.28.tar.gz"},
       "message parses and contains CPAN-2.28.tar.gz");

    throws_ok(sub { CPAN::Checksums::Signature::_verify_gpgv($message."extra", $signature); },
              qr/FAILED VERIFICATION.+gpgv: BAD signature from/s);

    throws_ok(sub { CPAN::Checksums::Signature::_verify_gpgv($message, ""); },
              qr/FAILED VERIFICATION.+verify signatures failed/s);

    done_testing();
};


done_testing();
