import pytest
from backend.features import normalize_url, url_features, parse_email, domain_group


@pytest.mark.parametrize("value", ["", "https://", "garbage", "javascript:alert(1)", "ftp://example.com", "https://bad host.com", "https://example.com:99999", "https://-bad.example", "https://foo..com", "https://example.com\n.evil.test", "https://example.com\\@evil.test", "http://127.1/", "http://999.999.999.999/"])
def test_invalid_urls_are_rejected(value):
    with pytest.raises(ValueError):
        normalize_url(value)


def test_path_dots_and_ip_do_not_change_hostname_features():
    _, features = url_features("https://example.com/path/192.168.1.1/a.b.c.d")
    assert features["ip_host"] == 0
    assert features["subdomains"] == 0


def test_authority_and_ipv6():
    normalized, features = url_features("https://bank.example@evil.test/login")
    assert normalized.startswith("https://bank.example@evil.test/")
    assert features["at_authority"] == 1
    normalized, features = url_features("http://[2001:db8::1]:8080/")
    assert features["ip_host"] == 1
    assert normalized == "http://[2001:db8::1]:8080/"


def test_domain_group_uses_public_suffixes_and_private_hosts():
    assert domain_group("a.shop.example.co.uk") == "example.co.uk"
    assert domain_group("alice.github.io") != domain_group("bob.github.io")


def test_email_extracts_header_mismatch_and_html_destination_without_executing():
    raw = '''From: Accounts <security@bank.example>
Reply-To: person@evil.test
Subject: Urgent: verify your password
Content-Type: text/html; charset=utf-8

<script>fetch('https://hidden.evil.test')</script>
<a href="http://192.0.2.1/account">https://bank.example/</a>'''
    parsed = parse_email(raw)
    assert parsed["features"]["reply_mismatch"] == 1
    assert parsed["features"]["link_label_mismatch"] == 1
    assert parsed["links"] == ["http://192.0.2.1/account", "https://bank.example/"]
    assert "fetch" not in parsed["model_text"]


def test_missing_headers_remain_unknown_and_plain_text_is_accepted():
    parsed = parse_email("Hi team, please bring the project report tomorrow.")
    assert parsed["authentication_results"] == ""
    assert parsed["features"]["reply_mismatch"] == 0
    assert "project report" in parsed["model_text"]


def test_malformed_html_links_do_not_crash_email_parser():
    parsed = parse_email('Content-Type: text/html\n\n<a href="https://[invalid/">https://bank.example/</a>')
    assert parsed["features"]["link_label_mismatch"] == 1
