use strict;
use warnings;

use Test::More;
use Test::Exception;
use Safe;

use_ok('CPAN::Checksums::Signature');

sub checksums {
    my $f = shift;
    local undef $/;
    open my $fh, '<', 't/'.$f;
    <$fh>;
};

### TODO: Add more negative tests: wrong keys, multisignatures, etc. binary data

my ($sigtext, $message, $signature) = CPAN::Checksums::Signature::_parse_clearsigned(checksums("CHECKSUMS"));

like($sigtext, qr/^-----BEGIN PGP SIGNED MESSAGE-----/, 'sigtext starts with BEGIN PGP SIGNED MESSAGE');
like($sigtext, qr/-----END PGP SIGNATURE-----\r?\n$/, 'sigtext ends with END PGP SIGNATURE');


like($signature, qr/^-----BEGIN PGP SIGNATURE-----/, 'signature starts with BEGIN PGP SIGNATURE');
like($signature, qr/-----END PGP SIGNATURE-----\r?\n$/, 'signature ends with END PGP SIGNATURE');


my $unsafe = Safe->new->reval($message);
ok(exists $unsafe->{"CPAN-2.28.tar.gz"},
   "message parses and contains CPAN-2.28.tar.gz");

my $sig = CPAN::Checksums::Signature->new;
isa_ok($sig, "CPAN::Checksums::Signature");


subtest 'gpgv' => sub {
    plan skip_all => 'gnupg is not installed'
      unless CPAN::Checksums::Signature::_which_gpgv();

    my $verified = $sig->_verify_gpgv($message, $signature);

    ok($verified eq $message, "verified and message is equal");

    ok(exists Safe->new->reval($verified)->{"CPAN-2.28.tar.gz"},
       "message parses and contains CPAN-2.28.tar.gz");

    throws_ok(sub { $sig->_verify_gpgv($message."extra", $signature); },
              qr/VERIFICATION FAILED.+gpgv: BAD signature from/s);

    throws_ok(sub { $sig->_verify_gpgv($message, ""); },
              qr/VERIFICATION FAILED.+verify signatures failed/s);

    done_testing();
};


subtest 'Crypt::OpenPGP' => sub {
    plan skip_all => 'Crypt::OpenPGP not installed'
      unless eval { require Crypt::OpenPGP; 1 };


    my $verified = $sig->_verify_crypt_openpgp($message, $signature);
    ok($verified eq $message, "verified and message is equal");

    ok(exists Safe->new->reval($verified)->{"CPAN-2.28.tar.gz"},
       "message parses and contains CPAN-2.28.tar.gz");

    throws_ok(sub { $sig->_verify_crypt_openpgp($message."extra", $signature); },
              qr/VERIFICATION FAILED.+Message hash does not match signature checkbytes/s);

    throws_ok(sub { $sig->_verify_crypt_openpgp($message, ""); },
              qr/VERIFICATION FAILED.+Need Signature or SigFile to verify/s);

    done_testing();
};


done_testing();
