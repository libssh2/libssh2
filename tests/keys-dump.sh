#!/usr/bin/env bash
#
# Copyright (C) Viktor Szakats
# SPDX-License-Identifier: BSD-3-Clause

# Dump keys in more human-parsable formats

for dir in keys openssh_server; do
  [ -d "${dir}-dump" ] || mkdir "${dir}-dump"
  rm -f "${dir}-dump"/*

  find "${dir}" -maxdepth 1 \( -name 'ca_*' -o -name 'id_*' -o -name 'ssh_*' \) | while read -r f; do
    o="${dir}-dump/$(basename "$f")"
    echo "$f"
    if [[ "$f" = *'.pub' ]]; then
      b64="$(grep -o -E ' .+ ' "$f")"
      [ -z "$b64" ] && b64="$(grep -o -E ' .+$' "$f")"
      echo "$b64" | tr -d ' ' | gbase64 -d > "$o.bin"
      if [[ "$f" = *'cert'* ]]; then
        ssh-keygen -L -f "$f" > "$o.cert.txt"
      fi
    else
      if [[ "$f" = *'pkcs8'* ]]; then
        openssl asn1parse -dump -in "$f" > "$o.pkey.asn1.txt"
      else
        grep -v -E '^(-----|DEK-Info|Proc-Type)' "$f" | gbase64 -d > "$o.pkey.bin"
      fi
      openssl pkey -text -noout -passin pass:libssh2 -in "$f" >> "$o.pkey.txt" 2>/dev/null
      [ -s "$o.pkey.txt" ] || rm -f "$o.pkey.txt"
    fi
    cp -p "$f" "$o"
  done
done

openssl -version
