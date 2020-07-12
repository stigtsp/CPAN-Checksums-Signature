package CPAN::Checksums::Signature;

use strict;
use warnings;

use 5.8.0;

use Carp;
use File::Temp;
use File::Spec;
use File::Basename qw(dirname);

our $VERSION = '0.01';

our $PAUSE_KEYRING = File::Spec->catfile(dirname(__FILE__),
                                         'Signature',
                                         '328DA867450F89EC.kbx');

sub new {
  my ($class, %args) = @_;
  my $file = $args{keyring} ||= $PAUSE_KEYRING;

  if (!File::Spec->file_name_is_absolute($file)) {
    $file = File::Spec->catfile(Cwd::cwd(), $file);
  }

  croak "Cannot find keyring $file" unless -f $file;
  croak "Cannot read keyring $file" unless -r $file;
  $args{keyring} = $file;

  return bless \%args, $class;
}


sub verify {
  my $self = shift;
  my $text = shift;

  my ($sigtext, $message, $signature) = $self->_parse_clearsigned($text);

  if ($self->_which_gpgv()) {

    return $self->_verify_gpgv($message,
                               $signature);

  } elsif (eval { require Crypt::OpenPGP; 1; }) {

    return $self->_verify_crypt_openpgp($message,
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
}

sub _verify_gpgv {
  my ($self, $message, $signature) = @_;

  my $message_f = new File::Temp();
  $message_f->print($message);
  $message_f->close;

  my $signature_f = new File::Temp();
  $signature_f->print($signature);
  $signature_f->close;

  my $keyring = $self->{keyring};

  # The --output argument is avoided to maintain compatibility with gpgv1
  #
  my @cmd = (_which_gpgv(),
             "-q",
             "--logger-fd", 1,
             "--keyring", $keyring,
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

  fail(join("", @debug, "\nExit: $exit\n"))
    if $exit;

  return $message;
}

sub _verify_crypt_openpgp {
  my ($self, $message, $signature)  = @_;

  require Crypt::OpenPGP;

  my $pgp = Crypt::OpenPGP->new( PubRing => $self->{keyring} );

  my ($rv, $sig) = $pgp->verify( Signature => $signature,
                                 Data      => $message )
    or fail($pgp->errstr);

  if (!$rv) {
    fail("Crypt::OpenPGP returned $rv");
  }

  return $message;
}

sub _parse_clearsigned {
  my $text = shift;

  # Need to parse this format to maintain compatibility with gpgv1 and
  # Crypt::OpenPGP since they don't seem to have a way of returning the message
  # part.
  #
  # This is not a complete parser for the format, as it doesn't
  # handle nested "----- BEGIN ..." blocks, etc.
  #

  my ($sigtext, $message, $signature) = $text =~
    m{(
        ^-----BEGIN\ PGP\ SIGNED\ MESSAGE-----\r?\n
        ^Hash:\ [A-Z0-9]+\r?\n
        ^\r?\n

        ^([\ -~\r\n]+?) # message: Only allow printable ascii, linefeed and newline

        \r?\n           # the last newlines are not a part of the message

        ( # signature: Only allow printable ascii, linefeed and newline
          ^-----BEGIN\ PGP\ SIGNATURE-----\r?\n
          ^[\ -~\r\n]+?
          ^-----END\ PGP\ SIGNATURE-----\r?\n$
        )
      )}msx;

  # Normalize line endings to \r\n
  $message =~ s/\r?\n/\r\n/g;

  fail("Unable to parse clearsigned text")
    unless $sigtext && $message && $signature;

  return ($sigtext, $message, $signature);
}


sub fail {
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

  my $checksums = CPAN::Checksums::Signature->load("./CHECKSUMS");

  ...

=head1 DESCRIPTION

Blah blah blah.


=head1 SEE ALSO


=head1 AUTHOR

Stig Palmquist <stig@stig.io>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2020 by Stig Palmquist

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.32.0 or,
at your option, any later version of Perl 5 you may have available.


=cut
