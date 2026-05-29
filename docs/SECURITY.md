<!--
Copyright (C) The libssh2 project and its contributors.

SPDX-License-Identifier: BSD-3-Clause
-->

# libssh2 security

This document is intended to provide guidance on how security vulnerabilities
should be handled in the libssh2 project.

## Publishing Information

All known and public libssh2 vulnerabilities will be listed on [the libssh2
web site](https://libssh2.org/).

Security vulnerabilities should not be entered in the project's public bug
tracker unless the necessary configuration is in place to limit access to the
issue to only the reporter and the project's security team.

## Vulnerability Handling

The typical process for handling a new security vulnerability is as follows.

No information should be made public about a vulnerability until it is
formally announced at the end of this process. That means, for example that a
bug tracker entry must NOT be created to track the issue since that will make
the issue public and it should not be discussed on the project's public
mailing list. Also messages associated with any commits should not make any
reference to the security nature of the commit if done prior to the public
announcement.

- The person discovering the issue, the reporter, reports the vulnerability
  privately to `libssh2-security@haxx.se`. That is an email alias that reaches
  a handful of selected and trusted people.

- Messages that do not relate to the reporting or managing of an undisclosed
  security vulnerability in libssh2 are ignored and no further action is
  required.

- A person in the security team sends an e-mail to the original reporter to
  acknowledge the report.

- The security team investigates the report and either rejects it or accepts
  it.

- If the report is rejected, the team writes to the reporter to explain why.

- If the report is accepted, the team writes to the reporter to let him/her
  know it is accepted and that they are working on a fix.

- The security team discusses the problem, works out a fix, considers the
  impact of the problem and suggests a release schedule. This discussion
  should involve the reporter as much as possible.

- The release of the information should be "as soon as possible" and is most
  often synced with an upcoming release that contains the fix. If the
  reporter, or anyone else, thinks the next planned release is too far away
  then a separate earlier release for security reasons should be considered.

- Write a security advisory draft about the problem that explains what the
  problem is, its impact, which versions it affects, solutions or
  workarounds, when the release is out and make sure to credit all
  contributors properly.

- Request a CVE number from
  [distros@openwall](https://oss-security.openwall.org/wiki/mailing-lists/distros)
  when also informing and preparing them for the upcoming public security
  vulnerability announcement - attach the advisory draft for information. Note
  that 'distros' will not accept an embargo longer than 14 days.

- Update the "security advisory" with the CVE number.

- The security team commits the fix in a private branch. The commit message
  should ideally contain the CVE number. This fix is usually also distributed
  to the 'distros' mailing list to allow them to use the fix prior to the
  public announcement.

- At the day of the next release, the private branch is merged into the master
  branch and pushed. Once pushed, the information is accessible to the public
  and the actual release should follow suit immediately afterwards.

- The project team creates a release that includes the fix.

- The project team announces the release and the vulnerability to the world in
  the same manner we always announce releases. It gets sent to the libssh2
  mailing list and the oss-security mailing list.

- The security web page on the web site should get the new vulnerability
  mentioned.

# Not security issues

This is an incomplete list of issues that are not considered vulnerabilities.

## Small memory leaks

We do not consider a small memory leak a security problem; even if the amount
of allocated memory grows by a small amount every now and then. Long-living
applications and services already need to have countermeasures and deal with
growing memory usage, be it leaks or increased use. A small memory or resource
leak is then expected to *not* cause a security problem.

Of course there can be a discussion if a leak is small or not. A large leak
can be considered a security problem due to the DOS risk. If leaked memory
contains sensitive data it might also qualify as a security problem.

## API misuse

If a reported issue only triggers by an application using the API in a way
that is not documented to work or even documented to not work, it is probably
not going to be considered a security problem. We only guarantee secure and
proper functionality when the APIs are used as expected and documented.

There can be a discussion about what the documentation actually means and how
to interpret the text, which might end up with us still agreeing that it is a
security problem.

## Debug & Experiments

Vulnerabilities in features which are off by default (in the build) and
documented as experimental, or exist only in debug mode, are not eligible for a
reward and we do not consider them security problems.

## NULL dereferences and crashes

If a malicious server can trigger a NULL dereference in libssh2 or otherwise
cause libssh2 to crash (and nothing worse), chances are big that we do not
consider that a security problem.

Malicious servers can already cause considerable harm and denial of service
like scenarios without having to trigger such code paths. For example by
stalling, being terribly slow or by delivering enormous amounts of data.
Additionally, applications are expected to handle "normal" crashes without
that being the end of the world.

There need to be more and special circumstances to treat such problems as
security issues.

# LIBSSH2-SECURITY (at haxx dot se)

Who is on this list? There are a couple of criteria you must meet, and then we
might ask you to join the list or you can ask to join it. It really is not very
formal. We basically only require that you have a long-term presence in the
libssh2 project and you have shown an understanding for the project and its way
of working. You must have been around for a good while and you should have no
plans in vanishing in the near future.

We do not make the list of participants public mostly because it tends to vary
somewhat over time and a list somewhere will only risk getting outdated.

# GitHub Private Vulnerability Reporting

We also accept reports via:
https://github.com/libssh2/libssh2/security
