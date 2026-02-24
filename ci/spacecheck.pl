#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Viktor Szakats
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################

use strict;
use warnings;

my @tabs = (
    "Makefile\\.[a-z]+\$",
    "m4/lib-.+\\.m4\$",
);

my @mixed_eol = (
);

my @need_crlf = (
);

my @double_empty_lines = (
);

my @non_ascii = (
    "AUTHORS",
    "RELEASE-NOTES",
);

sub fn_match {
    my ($filename, @masklist) = @_;

    foreach my $mask (@masklist) {
        if($filename =~ $mask) {
            return 1;
        }
    }
    return 0;
}

sub eol_detect {
    my ($content) = @_;

    my $cr = () = $content =~ /\r/g;
    my $lf = () = $content =~ /\n/g;

    if($cr > 0 && $lf == 0) {
        return "cr";
    }
    elsif($cr == 0 && $lf > 0) {
        return "lf";
    }
    elsif($cr == 0 && $lf == 0) {
        return "bin";
    }
    elsif($cr == $lf) {
        return "crlf";
    }

    return "";
}

my $issues = 0;

open(my $git_ls_files, '-|', 'git ls-files') or die "Failed running git ls-files: $!";
while(my $filename = <$git_ls_files>) {
    chomp $filename;

    open(my $fh, '<', $filename) or die "Cannot open '$filename': $!";
    my $content = do { local $/; <$fh> };
    close $fh;

    my @err = ();

    if(!fn_match($filename, @tabs) &&
       $content =~ /\t/) {
        push @err, "content: has tab";
    }

    my $eol = eol_detect($content);

    if($eol eq "") {
        push @err, "content: has mixed EOL types";
    }

    if($eol ne "crlf" &&
       fn_match($filename, @need_crlf)) {
        push @err, "content: must use CRLF EOL for this file type";
    }

    if($eol ne "lf" && $content ne "" &&
       !fn_match($filename, @need_crlf)) {
        push @err, "content: must use LF EOL for this file type";
    }

    if($content =~ /[ \t]\n/) {
        my $line;
        for my $l (split(/\n/, $content)) {
            $line++;
            if($l =~ /[ \t]$/) {
                push @err, "line $line: trailing whitespace";
            }
        }
    }

    if($content ne "" &&
       $content !~ /\n\z/) {
        push @err, "content: has no EOL at EOF";
    }

    if($content =~ /\n\n\z/ ||
       $content =~ /\r\n\r\n\z/) {
        push @err, "content: has multiple EOL at EOF";
    }

    if($content =~ /\n\n\n\n/ ||
       $content =~ /\r\n\r\n\r\n\r\n/) {
        push @err, "content: has 3 or more consecutive empty lines";
    }

    if(!fn_match($filename, @double_empty_lines)) {
        if($content =~ /\n\n\n/ ||
           $content =~ /\r\n\r\n\r\n/) {
            push @err, "content: has 2 consecutive empty lines";
        }
    }

    if($content =~ /([\x00-\x08\x0b\x0c\x0e-\x1f\x7f])/) {
        push @err, "content: has binary contents";
    }

    if(!fn_match($filename, @non_ascii) &&
       ($content =~ /([\x80-\xff]+)/)) {
        my $non = $1;
        my $hex;
        for my $e (split(//, $non)) {
            $hex .= sprintf("%s%02x", $hex ? " ": "", ord($e));
        }
        my $line;
        for my $l (split(/\n/, $content)) {
            $line++;
            if($l =~ /([\x80-\xff]+)/) {
                push @err, "line $line: has non-ASCII: '$non' ($hex)";
            }
        }
    }

    if(@err) {
        $issues++;
        foreach my $err (@err) {
            print "$filename: $err\n";
        }
    }
}
close $git_ls_files;

if($issues) {
    exit 1;
}
