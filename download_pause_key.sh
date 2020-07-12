#!/usr/bin/env bash
set -exuo pipefail
keyid=328DA867450F89EC
gpg --recv $keyid
gpg --export-options export-minimal --export $keyid > $keyid.kbx
