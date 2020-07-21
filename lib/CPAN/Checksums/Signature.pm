package CPAN::Checksums::Signature;

use strict;
use warnings;

use 5.8.0;


use Carp;
use Safe;
use File::stat;
use File::Temp;
use File::Spec;
use File::Basename qw(dirname);

our $VERSION = '0.01';

our $KEYRING = File::Spec->catfile(dirname(__FILE__),
                                         'Signature',
                                         '2E66557AB97C19C791AF8E20328DA867450F89EC.gpg');

our $MAX_CHECKSUMS_SIZE = 2_000_000; # Max checksums file size

sub keyring {
  my $keyring = $KEYRING;
  if (!File::Spec->file_name_is_absolute($keyring)) {
    $keyring = File::Spec->rel2abs($keyring);
  }

  croak "Cannot find keyring $keyring" unless -f $keyring;
  croak "Keyring not readable $keyring" unless -r $keyring;

  return $keyring;
}

sub can_verify {
  return _which_gpgv() || eval { require Crypt::OpenPGP; 1 };
}

sub load {
  my $file = shift;

  _sanity_checksums_file($file);

  my $chk_unverified = _read_checksums_file($file);

  my $chk_verified = _verify_signature($chk_unverified);

  my $checksums = _reval($chk_verified);

  return $checksums;
}

sub _reval {
  my $code = shift;
  my $safe = Safe->new;

  $safe->permit_only(qw(:base_mem :base_core
                        rv2gv gv padany));

  my $ret = $safe->reval($code);
  croak($@) if $@;

  return $ret;
}



sub _sanity_checksums_file {
  my $file = shift;
  croak "Cannot find file $file" unless -f $file;
  croak "File not readable $file" unless -r $file;

  my $stat = stat($file) or croak($!);

  croak "$file is larger than \$MAX_CHECKSUMS_SIZE" if
    $stat->size > $MAX_CHECKSUMS_SIZE;

  return 1;
}

sub _read_checksums_file {
  my $file = shift;
  open(my $fh, '<', $file) or croak $!;
  my $r = do {
    local undef $/;
    <$fh>;
  };
  close($fh);
  return $r;
}

sub _verify_signature {
  my $text = shift;

  my ($sigtext, $message, $signature) = _parse_clearsigned($text);

  if (_which_gpgv()) {

    return _verify_gpgv($message,
                        $signature);

  } elsif (eval { require Crypt::OpenPGP; 1; }) {

    return _verify_crypt_openpgp($message,
                                 $signature);
  }
  croak("No verification method available. Install gnupg or Crypt::OpenPGP");
}


my $which_gpgv;
sub _which_gpgv {
  return $which_gpgv if $which_gpgv;

  return if $^O eq 'MSWin32'; # TODO: Need to work out how to support gpgv on
                              # Win32, some path issues.

  for my $gpgv_bin ('gpgv2', 'gpgv', 'gpgv1') {
    my $version = `$gpgv_bin --version 2>&1`;
    if( $version && $version =~ /GnuPG/ ) {
      $which_gpgv = $gpgv_bin;
      return $which_gpgv;
    }
  }
  return;
}

sub _verify_gpgv {
  my ($message, $signature) = @_;

  my $message_f = new File::Temp();
  $message_f->print($message);
  $message_f->close;

  my $signature_f = new File::Temp();
  $signature_f->print($signature);
  $signature_f->close;


  # The --output argument is avoided to maintain compatibility with gpgv1

  my @cmd = (_which_gpgv(),
             "-q",
             "--logger-fd", 1,
             "--keyring", $KEYRING,
             $signature_f->filename,
             $message_f->filename);

  my @debug;
  open(my $gpgv, "-|", @cmd)
    or croak("Could not call gpgv: $!");
  while (my $l = <$gpgv>) {
    push @debug, $l;
  }
  close($gpgv);

  my $exit = $?;

  _fail_verify(join("", @debug, "\nExit: $exit\n"))
    if $exit;

  return $message;
}

sub _verify_crypt_openpgp {
  my ($message, $signature)  = @_;

  require Crypt::OpenPGP;

  my $pgp = Crypt::OpenPGP->new( PubRing => $KEYRING );

  my ($rv, $sig) = $pgp->verify( Signature => $signature,
                                 Data      => $message )
    or _fail_verify($pgp->errstr);

  if (!$rv) {
    _fail_verify("Crypt::OpenPGP returned $rv");
  }

  return $message;
}

sub _parse_clearsigned {
  my $text = shift;

  # Need to parse this format to maintain compatibility with gpgv1 and
  # Crypt::OpenPGP since they don't seem to have a way of returning the message
  # part.
  #
  # This is not a complete parser for the format, as it doesn't handle nested
  # "-----BEGIN ..." blocks, etc.
  #

  if ($text =~ m/[^ -~\r\n\t]/g) {
    _fail_verify("Unexpected data found. Only printable ASCII and whitespace is accepted.");
  }


  my $begin_message = qr/-----BEGIN PGP SIGNED MESSAGE-----/;
  my $begin_sig     = qr/-----BEGIN PGP SIGNATURE-----/;
  my $end_sig       = qr/-----END PGP SIGNATURE-----/;

  for ($begin_message, $begin_sig, $end_sig) {
    my $found = () = $text =~ m/^$_\r?\n/mg;
    _fail_verify("Found more than one $_") if $found > 1;
    _fail_verify("Did not find $_") if $found < 1;
  }


  my ($sigtext, $message, $signature) = $text =~
    m{(
        ^$begin_message\r?\n
        ^Hash:\ [A-Z0-9]+\r?\n
        ^\r?\n

        ^([\ -~\r\n]+?) # message: Only allow printable ascii, linefeed and newline

        \r?\n           # the last newlines are not a part of the message

        ( # signature: Only allow printable ascii, linefeed and newline inside the armored signature
          ^$begin_sig\r?\n
          ^[ -~\r\n\ ]+?
          ^$end_sig\r?\n
        )
      )}msx;

  _fail_verify("Unable to parse clearsigned text")
    unless $sigtext && $message && $signature;

  # Normalize line endings to \r\n
  $message =~ s/\r?\n/\r\n/g;

  return ($sigtext, $message, $signature);
}


sub _fail_verify {
  my $msg = shift;
  my $err = __PACKAGE__ . " FAILED VERIFICATION\n".
    ("=" x 50)."\n$msg\n";
  croak $err;
}



1;
__END__

=head1 NAME

CPAN::Checksums::Signature - Load and verify PGP signed CHECKSUMS files from CPAN

=head1 SYNOPSIS

  use CPAN::Checksums::Signature;

  # To verify PGP-signature, and safely reval checksums from CPAN
  my $chksum = CPAN::Checksums::Signature::load("./CHECKSUMS");

  # To check if dependencies for signature verification is installed
  warn CPAN::Checksums::Signature::can_verify() ? "Can verify" : "Cannot verify";

  ...

=head1 DESCRIPTION

TODO: Write something

=head1 SEE ALSO


=head1 AUTHOR

Stig Palmquist <stig@stig.io>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2020 by Stig Palmquist

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.32.0 or,
at your option, any later version of Perl 5 you may have available.


=cut
