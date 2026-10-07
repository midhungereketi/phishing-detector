"""The same deterministic, offline feature extractors are used in training and inference."""
import html
import ipaddress
import math
import re
from collections import Counter
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit, urlunsplit

import tldextract

PSL = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
KEYWORDS = ("login", "verify", "update", "secure", "account", "bank", "payment", "password", "free", "confirm")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "shorturl.at"}


def normalize_url(value):
    value = value.strip()
    if not value or len(value) > 4096 or "\\" in value or re.search(r"[\s\x00-\x1f\x7f]", value):
        raise ValueError("Enter a valid URL without spaces (maximum 4096 characters).")
    if "://" not in value:
        value = "https://" + value
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
        if parsed.scheme.lower() not in ("http", "https") or not host:
            raise ValueError()
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if "." not in host or host.split(".")[-1].isdigit() or len(host) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")
            ):
                raise ValueError()
        authority = f"[{host}]" if ":" in host else host
        if port is not None:
            authority += f":{port}"
        if parsed.username is not None:
            authority = parsed.netloc.rsplit("@", 1)[0] + "@" + authority
        return urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", parsed.query, parsed.fragment))
    except (ValueError, UnicodeError):
        raise ValueError("Enter an HTTP or HTTPS URL with a valid domain or IP address.") from None


def domain_group(host):
    extracted = PSL(host)
    return extracted.top_domain_under_public_suffix or host


def url_features(value):
    normalized = normalize_url(value)
    parsed = urlsplit(normalized)
    host = parsed.hostname
    text = unquote(normalized).lower()
    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        is_ip = 0
    extracted = PSL(host)
    counts = Counter(host)
    entropy = -sum((n / len(host)) * math.log2(n / len(host)) for n in counts.values())
    features = {
        "url_length": len(normalized), "host_length": len(host), "path_length": len(parsed.path),
        "query_length": len(parsed.query), "https": int(parsed.scheme == "https"),
        "ip_host": is_ip, "subdomains": len(extracted.subdomain.split(".")) if extracted.subdomain else 0,
        "host_hyphens": host.count("-"), "host_digits": sum(c.isdigit() for c in host),
        "digit_ratio": sum(c.isdigit() for c in text) / max(len(text), 1),
        "host_entropy": entropy, "path_depth": len([p for p in parsed.path.split("/") if p]),
        "query_parameters": parsed.query.count("&") + int(bool(parsed.query)),
        "at_authority": int(parsed.username is not None), "percent_count": normalized.count("%"),
        "double_slash_path": int("//" in parsed.path), "punycode": int("xn--" in host),
        "nonstandard_port": int(parsed.port is not None and parsed.port not in (80, 443)),
        "shortener": int(domain_group(host) in SHORTENERS),
        "keyword_count": sum(word in text for word in KEYWORDS),
        "host_keyword_count": sum(word in host for word in KEYWORDS),
    }
    return normalized, features


def url_signals(features):
    checks = [
        (not features["https"], "HTTPS is absent; the URL alone does not prove the site's identity."),
        (features["ip_host"], "The host is an IP address rather than a domain name."),
        (features["at_authority"], "User information before @ can disguise the actual destination."),
        (features["subdomains"] >= 3, "The hostname has several subdomain levels."),
        (features["punycode"], "The hostname uses internationalized (punycode) labels; inspect lookalike characters."),
        (features["shortener"], "A URL shortener conceals the final destination; redirects are not followed."),
        (features["host_keyword_count"] > 0, "Account or security keywords occur in the hostname."),
        (features["url_length"] > 100, "The URL is unusually long."),
        (features["nonstandard_port"], "The URL uses a nonstandard web port."),
    ]
    return [message for condition, message in checks if condition]


class HTMLText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links, self.link_labels = [], [], []
        self.hidden_depth = 0
        self.active = None

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.hidden_depth += 1
        if tag == "a":
            href = dict(attrs).get("href", "")
            if href.lower().startswith(("http://", "https://")):
                self.links.append(href)
                self.active = [href, ""]

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.hidden_depth = max(0, self.hidden_depth - 1)
        if tag == "a" and self.active:
            self.link_labels.append(tuple(self.active))
            self.active = None

    def handle_data(self, data):
        if not self.hidden_depth:
            self.text.append(data)
            if self.active:
                self.active[1] += data


def parse_email(raw):
    message = BytesParser(policy=policy.default).parsebytes(raw.encode("utf-8") if isinstance(raw, str) else raw)
    subject = str(message.get("Subject", ""))[:1000]
    sender = str(message.get("From", ""))[:1000]
    reply = str(message.get("Reply-To", ""))[:1000]
    texts, links, labels, attachment_names = [], [], [], []
    html_parts = 0
    # Never execute HTML, fetch remote images, or open attachments.
    for part in message.walk():
        if part.get_content_disposition() == "attachment" or part.get_filename():
            attachment_names.append(str(part.get_filename() or "unnamed attachment")[:200])
            continue
        if part.get_content_type() in ("text/plain", "text/html"):
            payload = part.get_payload(decode=True) or b""
            try:
                text = payload[:200000].decode(part.get_content_charset() or "utf-8", errors="replace")
            except LookupError:
                text = payload[:200000].decode("utf-8", errors="replace")
            if part.get_content_type() == "text/html":
                html_parts += 1
                parser = HTMLText()
                parser.feed(text)
                links.extend(parser.links)
                labels.extend(parser.link_labels)
                text = " ".join(parser.text)
            texts.append(text)
    body = "\n".join(texts)[:200000]
    links += re.findall(r"https?://[^\s<>\"']+", body, flags=re.I)
    clean_links = []
    for link in links:
        try:
            link = normalize_url(html.unescape(link).rstrip(".,;!)]}"))
            if link not in clean_links:
                clean_links.append(link)
        except ValueError:
            continue
    from_domain = parseaddr(sender)[1].split("@")[-1].lower()
    reply_domain = parseaddr(reply)[1].split("@")[-1].lower()
    mismatch = 0
    for href, label in labels:
        if re.match(r"https?://", label.strip(), re.I):
            try:
                target_host = urlsplit(normalize_url(href)).hostname
                label_host = urlsplit(normalize_url(label.strip())).hostname
                mismatch += int(target_host != label_host)
            except ValueError:
                mismatch += 1  # Malformed displayed/destination URL deserves inspection.
    auth = " ".join(str(v) for v in message.get_all("Authentication-Results", []))
    combined = subject + "\n" + body
    lower = combined.lower()
    features = {
        "link_count": len(clean_links), "html_parts": html_parts,
        "reply_mismatch": int(bool(reply_domain and from_domain and domain_group(reply_domain) != domain_group(from_domain))),
        "link_label_mismatch": mismatch, "attachment_count": len(attachment_names),
        "dangerous_attachment": int(any(re.search(r"\.(exe|scr|js|vbs|bat|cmd|ps1|html?)$", n, re.I) for n in attachment_names)),
        "urgent_words": sum(w in lower for w in ("urgent", "immediately", "suspended", "expire", "24 hours", "action required")),
        "credential_words": sum(w in lower for w in ("password", "verify your", "confirm your", "sign in", "credit card", "bank account")),
    }
    # Remove addresses and URL identities so the text model cannot simply memorize hosts.
    model_text = re.sub(r"https?://\S+|www\.\S+", " URLTOKEN ", combined, flags=re.I)
    model_text = re.sub(r"[\w.+-]+@[\w.-]+", " EMAILTOKEN ", model_text)
    model_text = re.sub(r"\d+", " NUMTOKEN ", model_text)
    return {
        "subject": subject, "sender": sender, "reply_to": reply, "links": clean_links[:20],
        "links_truncated": len(clean_links) > 20, "attachments": attachment_names,
        "authentication_results": auth[:2000], "features": features, "model_text": model_text,
    }


def email_signals(parsed):
    f = parsed["features"]
    signals = []
    for key, text in (
        ("reply_mismatch", "From and Reply-To use different registered domains."),
        ("link_label_mismatch", "A displayed URL differs from its underlying link destination."),
        ("dangerous_attachment", "An attachment has a potentially executable or HTML extension."),
        ("urgent_words", "The message uses urgency or account-suspension language."),
        ("credential_words", "The message contains credential or payment-related language."),
    ):
        if f[key]:
            signals.append(text)
    if re.search(r"(?:spf|dkim|dmarc)\s*=\s*(?:fail|softfail)", parsed["authentication_results"], re.I):
        signals.append("Pasted Authentication-Results reports a failure. These headers have not been independently verified.")
    if not parsed["authentication_results"]:
        signals.append("Authentication-Results is missing; SPF, DKIM and DMARC status is unknown.")
    return signals
