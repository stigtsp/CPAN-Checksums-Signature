with import <nixpkgs> { } ;
with perlPackages;

let
  CryptOpenPGP = buildPerlPackage {
    pname = "Crypt-OpenPGP";
    version = "1.12";
    src = fetchurl {
      url = "mirror://cpan/authors/id/S/SR/SROMANOV/Crypt-OpenPGP-1.12.tar.gz";
      sha256 = "e8a7ff2a993b76a69ad6dffdbe55755be5678b84e6ec494dcd9ab966f766f50e";
    };
    buildInputs = [ TestException ];
    propagatedBuildInputs = [ AltCryptRSABigInt CryptBlowfish CryptCAST5_PP CryptDES_EDE3 CryptDSA CryptIDEA CryptRIPEMD160 CryptRijndael CryptTwofish DataBuffer FileHomeDir LWP URI BytesRandomSecure ];
  };
  AltCryptRSABigInt = buildPerlPackage {
    pname = "Alt-Crypt-RSA-BigInt";
    version = "0.06";
    src = fetchurl {
      url = "mirror://cpan/authors/id/D/DA/DANAJ/Alt-Crypt-RSA-BigInt-0.06.tar.gz";
      sha256 = "76f434cab36999cdf09811345bb39d6b7cbed7e085b02338328c7f46e08b38f3";
    };
    propagatedBuildInputs = [ ClassLoader ConvertASCIIArmour CryptBlowfish CryptCBC DataBuffer DigestMD2 MathBigIntGMP MathPrimeUtil MathPrimeUtilGMP SortVersions TieEncryptedHash ];
  };
  CryptCAST5_PP = buildPerlPackage {
    pname = "Crypt-CAST5_PP";
    version = "1.04";
    src = fetchurl {
      url = "mirror://cpan/authors/id/B/BO/BOBMATH/Crypt-CAST5_PP-1.04.tar.gz";
      sha256 = "cba98a80403fb898a14c928f237f44816b4848641840ce2517363c2c071b5327";
    };
    meta = {
    };
  };
   CryptDES_EDE3 = buildPerlPackage {
    pname = "Crypt-DES_EDE3";
    version = "0.01";
    src = fetchurl {
      url = "mirror://cpan/authors/id/B/BT/BTROTT/Crypt-DES_EDE3-0.01.tar.gz";
      sha256 = "9cb2e04b625e9cc0833cd499f76fd12556583ececa782a9758a55e3f969748d6";
    };
    propagatedBuildInputs = [ CryptDES ];
    meta = {
    };
   };
     CryptDSA = buildPerlPackage {
    pname = "Crypt-DSA";
    version = "1.17";
    src = fetchurl {
      url = "mirror://cpan/authors/id/A/AD/ADAMK/Crypt-DSA-1.17.tar.gz";
      sha256 = "d1b8585f6bf746f76e5dc5da3641d325ed656bc2e5f344b54514b55c31009a03";
    };
    propagatedBuildInputs = [ DataBuffer DigestSHA1 FileWhich ];
  };
  CryptRIPEMD160 = buildPerlPackage {
    pname = "Crypt-RIPEMD160";
    version = "0.06";
    src = fetchurl {
      url = "mirror://cpan/authors/id/T/TO/TODDR/Crypt-RIPEMD160-0.06.tar.gz";
      sha256 = "ea64a1e9eb42f3d79855a392e7cca6b86e8e0bcc9aabcc5efa5fa32415b67dba";
    };
  };
  CryptTwofish = buildPerlPackage {
    pname = "Crypt-Twofish";
    version = "2.17";
    src = fetchurl {
      url = "mirror://cpan/authors/id/A/AM/AMS/Crypt-Twofish-2.17.tar.gz";
      sha256 = "eed502012f0c63927a1a32e3154071cc81175d1992a893ec41f183b6e3e5d758";
    };
  };
  DataBuffer = buildPerlPackage {
    pname = "Data-Buffer";
    version = "0.04";
    src = fetchurl {
      url = "mirror://cpan/authors/id/B/BT/BTROTT/Data-Buffer-0.04.tar.gz";
      sha256 = "2b3d09b7bcf389fc116207b283bee250e348d44c9c63460bee67efab4dd21bb4";
    };
    meta = {
    };
  };
  ClassLoader = buildPerlPackage {
    pname = "Class-Loader";
    version = "2.03";
    src = fetchurl {
      url = "mirror://cpan/authors/id/V/VI/VIPUL/Class-Loader-2.03.tar.gz";
      sha256 = "4fef2076ead60423454ff1f4e82859a9a9b9942b5fb8eee0c98b9c63c9f2b8e7";
    };
    meta = {
    };
  };
  ConvertASCIIArmour = buildPerlPackage {
    pname = "Convert-ASCII-Armour";
    version = "1.4";
    src = fetchurl {
      url = "mirror://cpan/authors/id/V/VI/VIPUL/Convert-ASCII-Armour-1.4.tar.gz";
      sha256 = "97e8acb6eb2a2a91af7d6cf0d2dff6fa42aaf939fc7d6d1c6057a4f0df52c904";
    };
    meta = {
    };
  };
  DigestMD2 = buildPerlPackage {
    pname = "Digest-MD2";
    version = "2.04";
    src = fetchurl {
      url = "mirror://cpan/authors/id/G/GA/GAAS/Digest-MD2-2.04.tar.gz";
      sha256 = "d0aabf4834c20ac411bea427c4a308b59a5fcaa327679ef5294c1d68ab71eed3";
    };
    meta = {
    };
  };
  MathPrimeUtil = buildPerlPackage {
    pname = "Math-Prime-Util";
    version = "0.73";
    src = fetchurl {
      url = "mirror://cpan/authors/id/D/DA/DANAJ/Math-Prime-Util-0.73.tar.gz";
      sha256 = "4afa6dd8cdb97499bd4eca6925861812c29d9f5a0f1ac27ad9d2d9c9b5602894";
    };
    propagatedBuildInputs = [ MathPrimeUtilGMP ];
    meta = {
      homepage = https://github.com/danaj/Math-Prime-Util;
      description = "Utilities related to prime numbers, including fast sieves and factoring";
      license = with stdenv.lib.licenses; [ artistic1 gpl1Plus ];
    };
  };
  MathPrimeUtilGMP = buildPerlPackage {
    pname = "Math-Prime-Util-GMP";
    version = "0.52";
    src = fetchurl {
      url = "mirror://cpan/authors/id/D/DA/DANAJ/Math-Prime-Util-GMP-0.52.tar.gz";
      sha256 = "2697c7fd5c7e35fdec7f50ed56a67be807a2f22657589e637dad3592744003be";
    };
    buildInputs = [ pkgs.gmp ];
    NIX_CFLAGS_COMPILE = "-I${pkgs.gmp.dev}/include";
    NIX_CFLAGS_LINK = "-L${pkgs.gmp.out}/lib -lgmp";

  };
  TieEncryptedHash = buildPerlPackage {
    pname = "Tie-EncryptedHash";
    version = "1.24";
    src = fetchurl {
      url = "mirror://cpan/authors/id/V/VI/VIPUL/Tie-EncryptedHash-1.24.tar.gz";
      sha256 = "aa9a083a231e4046170a5894644e3c59679c7dbd0aa2d1217dc85150df2c1e21";
    };
    propagatedBuildInputs = [ CryptBlowfish CryptCBC CryptDES ];
    meta = {
    };
  };



in pkgs.mkShell {
  buildInputs = [
    perl
    CryptOpenPGP
    IOSocketSSL
    TestException
    SmartComments
    gnupg1orig
  ];
  shellHook = ''
  '';
}
