# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause

if(-Not(Get-Command -ErrorAction Ignore perl.exe)) {
    Write-Host "perl required, abort"
    pause
    exit
}

$currentDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
cd $currentDir/..

$RC = 0
git ls-files '*.[ch]' '*.cc' | ForEach-object {
perl ci/checksrc.pl -i4 -m79 -AFIXME -AERRNOVAR -AFOPENMODE -ATYPEDEFSTRUCT `
  -aaccept `
  -aatoi `
  -acalloc `
  -aCreateFileA `
  -afclose `
  -afopen `
  -afprintf `
  -afree `
  -amalloc `
  -aprintf `
  -arealloc `
  -arecv `
  -asend `
  -asnprintf `
  -asocket `
  -asocketpair `
  -astrdup `
  -astrtok `
  -astrtol `
  -avsnprintf `
  $_

  if ($LASTEXITCODE) {$RC = $LASTEXITCODE}
}

exit $RC
