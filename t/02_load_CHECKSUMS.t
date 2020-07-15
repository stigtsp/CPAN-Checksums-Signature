use strict;
use warnings;

use Test::More;
use Test::Exception;

use_ok('CPAN::Checksums::Signature');


my $chk = CPAN::Checksums::Signature::load("t/CHECKSUMS");

is($chk->{"CPAN-2.28.tar.gz"}->{sha256},
   "39d357489283d479695027640d7fc25b42ec3c52003071d1ec94496e34af5974");


my $chk_t1 = CPAN::Checksums::Signature::load("t/CHECKSUMS-tampered-1");

is($chk_t1->{"CPAN-2.28.tar.gz"}->{sha256},
   "39d357489283d479695027640d7fc25b42ec3c52003071d1ec94496e34af5974");

throws_ok sub { CPAN::Checksums::Signature::load("t/CHECKSUMS-tampered-2") },
  qr/FAILED VERIFICATION/;

throws_ok sub { CPAN::Checksums::Signature::load("t/CHECKSUMS-tampered-3") },
  qr/FAILED VERIFICATION/;

throws_ok sub { CPAN::Checksums::Signature::load("t/CHECKSUMS-tampered-4") },
  qr/FAILED VERIFICATION.+Unexpected\ data\ found/s;



done_testing();
