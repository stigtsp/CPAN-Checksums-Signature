use strict;
use warnings;

use Test::More;
use Test::Exception;

use_ok('CPAN::Checksums::Signature');


my $chk = CPAN::Checksums::Signature::load("t/checksums/good");

is($chk->{"CPAN-2.28.tar.gz"}->{sha256},
   "39d357489283d479695027640d7fc25b42ec3c52003071d1ec94496e34af5974");

{
  no warnings;
  local $CPAN::Checksums::Signature::KEYRING = "t/checksums/stigtsp.gpg";
  my $chk_strong = CPAN::Checksums::Signature::load("t/checksums/strong");

  is($chk->{"CPAN-2.28.tar.gz"}->{sha256},
     "39d357489283d479695027640d7fc25b42ec3c52003071d1ec94496e34af5974");
}

my $chk_ws = CPAN::Checksums::Signature::load("t/checksums/good-extra-whitespace");

is($chk_ws->{"CPAN-2.28.tar.gz"}->{sha256},
   "39d357489283d479695027640d7fc25b42ec3c52003071d1ec94496e34af5974");


my $chk_t1 = CPAN::Checksums::Signature::load("t/checksums/bad-prepend");

is($chk_t1->{"CPAN-2.28.tar.gz"}->{sha256},
   "39d357489283d479695027640d7fc25b42ec3c52003071d1ec94496e34af5974");

throws_ok sub { CPAN::Checksums::Signature::load("t/checksums/bad-message-content") },
  qr/FAILED VERIFICATION/;

throws_ok sub { CPAN::Checksums::Signature::load("t/checksums/bad-prepend-clearsign") },
  qr/FAILED VERIFICATION/;

throws_ok sub { CPAN::Checksums::Signature::load("t/checksums/bad-prepend-signed") },
  qr/FAILED VERIFICATION.+Unexpected\ data\ found/s;


throws_ok sub { CPAN::Checksums::Signature::load("t/checksums/bad-double") },
  qr/FAILED VERIFICATION.+Found\ more/s;



done_testing();
