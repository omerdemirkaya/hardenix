# Changelog

## 0.1.1

Fixes found while testing 0.1.0 on a production Ubuntu 24.04 server:

- HIST-001: regular expressions, shell expansions and placeholders (`\\K[^"]+`, `.*`, `$(...)`,
  `<password>`) are no longer reported as secrets.
- SYS-001: `fs.suid_dumpable = 2` is no longer reported when core dumps go to a pipe handler
  (Ubuntu's apport sets this on purpose and resets it at every boot).
- `hardenix fix`: input typed or pasted before a question is discarded, so a pasted next command
  is never taken as the answer. Unclear answers are asked again instead of counting as "no".

## 0.1.0

First release.
