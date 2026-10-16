<p align="center">
  <img src="assets/logo.png" alt="PrivacyGate logo" width="420">
</p>

# PrivacyGate

Redact sensitive values from text before you paste it into an AI service.

PrivacyGate replaces emails, phone numbers (including Nigerian formats), card numbers, BVN and NIN, bank account numbers, API keys, passwords, JWTs and private keys with stable placeholders such as `[EMAIL_001]`. It runs on your machine, uses only the Python standard library, and never makes a network request.

```text
$ privacygate redact notes.txt -r notes.clean.txt -t "Project Falcon"
```

```text
before: Ring 0803 123 4567 or ada@example.com about Project Falcon.
after:  Ring [PHONE_001] or [EMAIL_001] about [CONFIDENTIAL_001].
```

## Install

Requires Python 3.10 or newer.

```bash
pip install git+https://github.com/seun-john/privacygate.git
```

## Use

| Command | What it does |
| --- | --- |
| `privacygate redact FILE -r OUT [-t TERM ...] [--terms-file F] [--mapping-out M]` | Redact a UTF-8 text file and write the cleaned copy to `OUT`. |
| `privacygate restore FILE -m MAP -r OUT` | Put the originals back using a mapping saved by `--mapping-out`. |
| `privacygate scan input.json` | Redact the `text` field of a JSON file (`{"text": "...", "confidential_terms": [...]}`) and print the report. |

Every command also takes `-o report.json`, `--html report.html` and `--strict`. With `--strict`, the exit code is 1 when anything was redacted, which suits a CI step that blocks text containing secrets. Exit codes: 0 completed, 1 strict findings, 2 unusable input, 3 `--min-coverage` was not met.

**Coverage.** `scan` and `redact` add a `coverage` object and print a line on stderr, for example `coverage: decided 4 of 4 values`. The items are the distinct values the patterns found and redacted; `suppressed` counts the matches an allow list left in the text. Names, addresses and other free text are not looked for unless listed as confidential terms, and the `notes` say so every time. `--min-coverage PCT` exits 3 when fewer than PCT percent of items were decided, which includes a text in which nothing was found.

The same value always gets the same placeholder within one run, so a model can still tell that two mentions are the same person or number. The report counts what was redacted by kind and never repeats the original values.

## Shared mailboxes and helplines

Role mailboxes (`support@`, `hr@`) and published helplines name a function, not a person, but they look like personal data, so they are redacted by default. To keep them in the text:

| Option | Effect |
| --- | --- |
| `--allow-role-addresses` | Leave addresses whose local part is a common role name (`info`, `support`, `help`, `billing`, `hr`, `noreply`, and similar; see `ROLE_LOCAL_PARTS` in `redact.py`). A `+tag` suffix is ignored. |
| `--allow GLOB` | Leave any email or phone number matching a case-insensitive glob, for example `recon@example.org`, `*@example.org` or `+234 1 555 *`. Repeatable. |
| `--allow-file F` | The same globs, one per line. |

In `scan` input the same settings are `"allow_role_addresses": true` and `"allow": [...]`. Allowed values stay in the output text; the report states how many were kept per kind (`allowed_kept`) and never lists them. Only `EMAIL` and `PHONE` can be allowed: passwords, tokens, keys, national IDs, bank accounts and card numbers are always redacted, and a confidential term always wins over an allow rule. A personal address at the same domain as an allowed role address is still redacted.

## What it detects

| Kind | Rule |
| --- | --- |
| `EMAIL` | Standard address syntax. |
| `PHONE` | International numbers starting with `+`, and Nigerian mobile numbers (`0803 123 4567`, `08031234567`, `2348031234567`). |
| `NATIONAL_ID` | An 11-digit number next to the label `BVN`, `NIN` or `National ID`. |
| `BANK_ACCOUNT` | A 10-digit number next to the label `account`, `acct` or `a/c`. |
| `CARD` | 13 to 19 digits that pass the Luhn check. Random long numbers are left alone. |
| `PASSWORD` | The value after `password`, `passwd`, `api key`, `secret`, `access token` and similar. |
| `TOKEN`, `JWT`, `PRIVATE_KEY` | Common API key formats, JSON web tokens and PEM private keys. |
| `CONFIDENTIAL` | Any term you pass with `-t` or `--terms-file`, matched case-insensitively. |

## Limits

- **Pattern matching is incomplete.** Names, addresses, organisations and free-text identifiers are only caught when you list them as terms. Read the cleaned text before sharing it.
- An unlabelled 11-digit number is not treated as a BVN, because that would redact order numbers and timestamps. Label it or list it as a term.
- The mapping file written by `--mapping-out` contains the original confidential values in plain text. It is only created when you ask for it. Keep it somewhere safe or delete it. PrivacyGate does not encrypt it.
- Text that already contains a generated placeholder such as `[EMAIL_001]` is refused, because restoring it would be ambiguous.
- Files over 10 MiB are refused.

## Develop

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest -q
```

MIT licence.
