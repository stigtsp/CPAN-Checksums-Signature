#!/usr/bin/env bash
set -exuo pipefail
export GNUPGHOME=$(mktemp -d)

url=https://raw.githubusercontent.com/andk/cpanpm/master/PAUSE2021.pub
fpr=2E66557AB97C19C791AF8E20328DA867450F89EC

curl $url | gpg --import --no-options

gpg --no-options --export-options export-minimal --export $fpr \
    > lib/CPAN/Checksums/Signature/$fpr.gpg
