# Changelog

## Unreleased

- `scan` and `redact` reports have a `coverage` block (values redacted, matches kept by an allow list, and a note on what the patterns cannot see), a one-line summary on stderr and in the HTML report.
- `--min-coverage PCT`: exit 3 when fewer than PCT percent of items were decided.
- Opt-in allow list for shared mailboxes and helplines: `--allow-role-addresses`, `--allow GLOB`, `--allow-file` (and `allow_role_addresses` / `allow` in `scan` input). Allowed values stay in the text and are counted in the report as `allowed_kept`. Only emails and phone numbers can be allowed. Default behaviour is unchanged.
- New `redact_allowing()` returns the kept counts; `redact()` is unchanged.

## 0.1.0

First release.

- Redaction of emails, international and Nigerian phone numbers, Luhn-valid card numbers, BVN/NIN and bank account numbers (when labelled), JWTs, API keys, passwords and private keys.
- Stable placeholders: the same value always gets the same placeholder within one run.
- Optional restore from an explicit mapping file.
