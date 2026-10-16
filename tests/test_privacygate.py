from __future__ import annotations

import json
from pathlib import Path

import pytest

from privacygate.cli import main
from privacygate.core import InputError
from privacygate.redact import Allow, redact, redact_allowing, restore


def kinds(text: str) -> set[str]:
    return {k[1:].rsplit("_", 1)[0] for k in redact(text)[1]}


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("mail me at ada@example.com", "EMAIL"),
        ("call +234 803 123 4567 now", "PHONE"),
        ("call 08031234567 now", "PHONE"),
        ("call 0803 123 4567 now", "PHONE"),
        ("call 2348031234567 now", "PHONE"),
        ("call +44 20 7946 0958 now", "PHONE"),
        ("my BVN is 12345678901", "NATIONAL_ID"),
        ("NIN: 98765432109", "NATIONAL_ID"),
        ("account number 0123456789 at the bank", "BANK_ACCOUNT"),
        ("card 4111 1111 1111 1111 expires", "CARD"),
        ("password: hunter2", "PASSWORD"),
        ("api_key=abc123def456", "PASSWORD"),
        ("key sk-abcdefghijklmnopqrstuv", "TOKEN"),
        ("tok ghp_abcdefghijklmnopqrstuvwx", "TOKEN"),
        ("jwt eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4", "JWT"),
        ("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "PRIVATE_KEY"),
    ],
)
def test_detects(text: str, kind: str) -> None:
    assert kind in kinds(text)


@pytest.mark.parametrize(
    "text",
    [
        "order number 12345678901",
        "card 4111 1111 1111 1112",
        "phone 0603 123 4567",
        "version 1.2.3 released in 2026",
    ],
)
def test_does_not_over_redact(text: str) -> None:
    assert redact(text)[0] == text


def test_password_keeps_the_label() -> None:
    assert redact("password: hunter2")[0] == "password: [PASSWORD_001]"


def test_same_value_same_placeholder() -> None:
    clean, mapping = redact("a@b.com then c@d.com then a@b.com")
    assert clean == "[EMAIL_001] then [EMAIL_002] then [EMAIL_001]"
    assert mapping["[EMAIL_001]"] == "a@b.com"


def test_confidential_terms_case_insensitive() -> None:
    clean, _ = redact("Project Falcon uses falcon", ["falcon"])
    assert "falcon" not in clean.lower()


def test_blank_term_rejected() -> None:
    with pytest.raises(InputError):
        redact("x", [" "])


def test_existing_placeholder_collision_is_refused() -> None:
    with pytest.raises(InputError):
        redact("[EMAIL_001] a@b.com")


def test_restore_round_trip_and_single_pass() -> None:
    text = "mail a@b.com, phone 08031234567"
    clean, mapping = redact(text)
    assert restore(clean, mapping) == text
    assert restore("[X_001]", {"[X_001]": "[Y_001]", "[Y_001]": "no"}) == "[Y_001]"


def test_cli_scan_does_not_leak_originals(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = tmp_path / "in.json"
    src.write_text(json.dumps({"text": "mail a@b.com"}), encoding="utf-8")
    assert main(["scan", str(src)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["redacted_text"] == "mail [EMAIL_001]"
    assert "a@b.com" not in json.dumps(out)


def test_cli_strict_exit_codes(tmp_path: Path) -> None:
    clean = tmp_path / "c.json"
    clean.write_text(json.dumps({"text": "nothing here"}), encoding="utf-8")
    dirty = tmp_path / "d.json"
    dirty.write_text(json.dumps({"text": "a@b.com"}), encoding="utf-8")
    assert main(["scan", str(clean), "--strict", "-o", str(tmp_path / "r1.json")]) == 0
    assert main(["scan", str(dirty), "--strict", "-o", str(tmp_path / "r2.json")]) == 1


def test_cli_redact_then_restore(tmp_path: Path) -> None:
    src = tmp_path / "note.txt"
    src.write_text("Ring 08031234567 about Falcon.", encoding="utf-8")
    clean, mapping = tmp_path / "clean.txt", tmp_path / "map.json"
    code = main(
        [
            "redact",
            str(src),
            "-r",
            str(clean),
            "-t",
            "Falcon",
            "--mapping-out",
            str(mapping),
            "-o",
            str(tmp_path / "rep.json"),
        ]
    )
    assert code == 0
    assert clean.read_text(encoding="utf-8") == "Ring [PHONE_001] about [CONFIDENTIAL_001]."
    back = tmp_path / "back.txt"
    code = main(
        [
            "restore",
            str(clean),
            "-m",
            str(mapping),
            "-r",
            str(back),
            "-o",
            str(tmp_path / "r2.json"),
        ]
    )
    assert code == 0
    assert back.read_text(encoding="utf-8") == src.read_text(encoding="utf-8")


def test_role_addresses_are_redacted_unless_allowed() -> None:
    assert redact("write to support@brightwave.example")[0] == "write to [EMAIL_001]"
    clean, mapping, kept = redact_allowing(
        "write to support@brightwave.example", allow=Allow(role_addresses=True)
    )
    assert clean == "write to support@brightwave.example"
    assert mapping == {}
    assert kept == {"EMAIL": 1}


def test_allowed_role_address_does_not_protect_a_personal_address() -> None:
    text = "ask info@acme.example or ada.obi@acme.example"
    clean, mapping, kept = redact_allowing(text, allow=Allow(role_addresses=True))
    assert clean == "ask info@acme.example or [EMAIL_001]"
    assert mapping == {"[EMAIL_001]": "ada.obi@acme.example"}
    assert kept == {"EMAIL": 1}


def test_role_address_with_plus_tag_and_capitals() -> None:
    clean, _, kept = redact_allowing("Support+vip@Acme.example", allow=Allow(role_addresses=True))
    assert clean == "Support+vip@Acme.example"
    assert kept == {"EMAIL": 1}


def test_glob_patterns_allow_a_domain_and_a_helpline_prefix() -> None:
    allow = Allow(patterns=("recon@ledgerline.example", "+234 1 555 *"))
    text = "recon@ledgerline.example, helpline +234 1 555 0111, mobile +234 803 123 4567"
    clean, mapping, kept = redact_allowing(text, allow=allow)
    assert clean == "recon@ledgerline.example, helpline +234 1 555 0111, mobile [PHONE_001]"
    assert list(mapping.values()) == ["+234 803 123 4567"]
    assert kept == {"EMAIL": 1, "PHONE": 1}


def test_allow_list_can_never_release_secrets_ids_or_cards() -> None:
    allow = Allow(role_addresses=True, patterns=("*",))
    for text, kind in [
        ("password: hunter2", "PASSWORD"),
        ("key sk-abcdefghijklmnopqrstuv", "TOKEN"),
        ("my BVN is 12345678901", "NATIONAL_ID"),
        ("card 4111 1111 1111 1111 expires", "CARD"),
        ("account number 0123456789 at the bank", "BANK_ACCOUNT"),
    ]:
        _, mapping, kept = redact_allowing(text, allow=allow)
        assert kind in {k[1:].rsplit("_", 1)[0] for k in mapping}, text
        assert kept == {}, text


def test_confidential_terms_win_over_the_allow_list() -> None:
    allow = Allow(patterns=("*@acme.example",))
    clean, _, _ = redact_allowing("mail hr@acme.example", ["hr@acme.example"], allow)
    assert "hr@acme.example" not in clean


def test_cli_scan_reports_what_the_allow_list_kept(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = tmp_path / "in.json"
    src.write_text(
        json.dumps(
            {
                "text": "support@x.example and ada@x.example",
                "allow_role_addresses": True,
                "allow": ["nobody@*"],
            }
        ),
        encoding="utf-8",
    )
    assert main(["scan", str(src)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["redacted_text"] == "support@x.example and [EMAIL_001]"
    assert out["findings"][0]["evidence"]["allowed_kept"] == {"EMAIL": 1}


def test_cli_scan_without_allow_has_no_allowed_kept_field(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = tmp_path / "in.json"
    src.write_text(json.dumps({"text": "support@x.example"}), encoding="utf-8")
    assert main(["scan", str(src)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["redacted_text"] == "[EMAIL_001]"
    assert "allowed_kept" not in json.dumps(out)


def test_cli_redact_with_allow_options(tmp_path: Path) -> None:
    src = tmp_path / "note.txt"
    src.write_text("info@x.example, help +234 1 555 0142, ada@x.example", encoding="utf-8")
    allow_file = tmp_path / "allow.txt"
    allow_file.write_text("+234 1 555 *\n", encoding="utf-8")
    clean = tmp_path / "clean.txt"
    code = main(
        [
            "redact",
            str(src),
            "-r",
            str(clean),
            "--allow-role-addresses",
            "--allow-file",
            str(allow_file),
            "-o",
            str(tmp_path / "rep.json"),
        ]
    )
    assert code == 0
    assert clean.read_text(encoding="utf-8") == "info@x.example, help +234 1 555 0142, [EMAIL_001]"


def test_blank_allow_pattern_rejected(tmp_path: Path) -> None:
    src = tmp_path / "in.json"
    src.write_text(json.dumps({"text": "x", "allow": [" "]}), encoding="utf-8")
    assert main(["scan", str(src)]) == 2


def test_cli_refuses_to_overwrite_input(tmp_path: Path) -> None:
    src = tmp_path / "note.txt"
    src.write_text("a@b.com", encoding="utf-8")
    assert main(["redact", str(src), "-r", str(src), "-o", str(tmp_path / "r.json")]) == 2
    assert src.read_text(encoding="utf-8") == "a@b.com"


def test_cli_bad_input_exits_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    assert main(["scan", str(bad)]) == 2
    assert main(["scan", str(tmp_path / "missing.json")]) == 2
