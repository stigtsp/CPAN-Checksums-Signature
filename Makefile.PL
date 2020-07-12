use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'CPAN::Checksums::Signature',
    VERSION_FROM      => 'lib/CPAN/Checksums/Signature.pm', 
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    TEST_REQUIRES     => { 'Test::Exception' => 0 },
    ABSTRACT_FROM     => 'lib/CPAN/Checksums/Signature.pm', # retrieve abstract from module
    AUTHOR            => 'Stig Palmquist <stig@stig.io>',
    test              => {TESTS => 't/*.t'},
    LICENSE           => 'perl',
);
