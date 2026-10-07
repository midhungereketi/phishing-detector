"""Bounded public-network observations. Resolve, validate, then connect to that IP.

No proxies, cookies, authentication, browser rendering or target response bodies.
Every redirect is independently checked to prevent SSRF and DNS rebinding.
"""
import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import dns.resolver

from .features import domain_group, normalize_url


class UnsafeTarget(ValueError):
    pass


def public_addresses(host):
    try:
        addresses = [str(ipaddress.ip_address(host))]
    except ValueError:
        addresses = []
        resolver = dns.resolver.Resolver()
        for kind in ("A", "AAAA"):
            try:
                addresses.extend(str(answer) for answer in resolver.resolve(host, kind, lifetime=2))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.exception.DNSException as error:
                if not addresses:
                    raise OSError("DNS lookup unavailable") from error
    if not addresses:
        raise OSError("No public address found")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        mapped = getattr(ip, "ipv4_mapped", None)
        if not ip.is_global or (mapped and not mapped.is_global):
            raise UnsafeTarget("Private, loopback, reserved and link-local destinations are not contacted.")
    return sorted(set(addresses))


def public_request(value, method="HEAD", max_bytes=200000, redirects=3, headers=None, timeout=3):
    url = normalize_url(value)
    chain = []
    deadline = time.monotonic() + 12
    for hop in range(redirects + 1):
        parsed = urlsplit(url)
        if parsed.username is not None or parsed.port not in (None, 80, 443):
            raise UnsafeTarget("Credentials and nonstandard ports are not allowed in network checks.")
        addresses = public_addresses(parsed.hostname)
        if time.monotonic() >= deadline:
            raise TimeoutError("Network check deadline exceeded")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        kwargs = {"timeout": min(timeout, max(.1, deadline - time.monotonic()))}
        if parsed.scheme == "https":
            kwargs["context"] = ssl.create_default_context()
        connection = connection_class(parsed.hostname, port, **kwargs)

        def connect_pinned(_address, connect_timeout, source_address=None):
            # Construct the socket ourselves: create_connection could resolve again.
            address = addresses[0]
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(connect_timeout)
            try:
                sock.connect((address, port))
                return sock
            except Exception:
                sock.close()
                raise

        connection._create_connection = connect_pinned
        timer = None
        try:
            connection.connect()  # HTTPSConnection verifies hostname with original SNI.
            connected_socket = connection.sock

            def expire():
                try:
                    connected_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            timer = threading.Timer(max(.01, deadline - time.monotonic()), expire)
            timer.daemon = True
            timer.start()
            cert = connection.sock.getpeercert() if parsed.scheme == "https" else None
            path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            connection.request(method, path, headers={"User-Agent": "PhishGuard-College-Research/2.0", "Accept-Encoding": "identity", **(headers or {})})
            response = connection.getresponse()
            body = response.read(max_bytes + 1) if method != "HEAD" else b""
            if len(body) > max_bytes:
                raise ValueError("Provider response exceeded the size limit")
            location = response.getheader("Location")
            chain.append({"url": url, "status": response.status, "addresses": addresses})
            if response.status in (301, 302, 303, 307, 308) and location:
                if hop == redirects:
                    raise ValueError("Redirect limit reached")
                next_url = normalize_url(urljoin(url, location))
                if parsed.scheme == "https" and urlsplit(next_url).scheme != "https":
                    raise UnsafeTarget("HTTPS-to-HTTP redirect was not followed.")
                if headers and urlsplit(next_url).hostname != parsed.hostname:
                    raise UnsafeTarget("Provider credential headers cannot follow cross-host redirects.")
                url = next_url
                continue
            return {"url": url, "status": response.status, "body": body, "chain": chain, "certificate": cert}
        finally:
            if timer:
                timer.cancel()
            connection.close()
    raise ValueError("Redirect limit reached")


def registration(host):
    domain = domain_group(host)
    try:
        ipaddress.ip_address(domain)
        return {"status": "not_applicable", "message": "An IP address has no domain registration date."}
    except ValueError:
        pass
    try:
        response = public_request("https://rdap.org/domain/" + quote(domain, safe=""), "GET", redirects=4)
        if response["status"] != 200:
            return {"status": "unavailable", "message": f"RDAP returned HTTP {response['status']}."}
        data = json.loads(response["body"])
        dates = [event["eventDate"] for event in data.get("events", []) if event.get("eventAction") == "registration" and event.get("eventDate")]
        if not dates:
            return {"status": "unknown", "domain": domain, "message": "Registry did not provide a registration date."}
        created = datetime.fromisoformat(dates[0].replace("Z", "+00:00"))
        age = max(0, (datetime.now(timezone.utc) - created.astimezone(timezone.utc)).days)
        return {"status": "observed", "domain": domain, "registered_at": dates[0], "age_days": age, "source": "RDAP registry response"}
    except Exception:
        return {"status": "unavailable", "message": "Registration lookup failed or timed out; age is unknown."}


def observe(value):
    started = time.monotonic()
    try:
        result = public_request(value)
        http_status = result.pop('status')
        cert = result.pop("certificate")
        result.pop("body")
        if cert:
            expires = cert.get("notAfter")
            tls = {"status": "verified", "issuer": ", ".join(v for part in cert.get("issuer", []) for _, v in part), "expires_at": expires,
                   "days_remaining": int((ssl.cert_time_to_seconds(expires) - time.time()) / 86400) if expires else None,
                   "message": "TLS chain and hostname verified; HTTPS does not establish legitimacy."}
        else:
            tls = {"status": "absent", "message": "Destination uses HTTP; no TLS certificate was checked."}
        return {"status": "observed", "http_status": http_status, **result, "tls": tls, "duration_ms": round((time.monotonic() - started) * 1000)}
    except UnsafeTarget as error:
        return {"status": "refused", "message": str(error)}
    except ssl.SSLCertVerificationError:
        return {"status": "unavailable", "tls": {"status": "invalid", "message": "Certificate verification failed."}, "message": "Target request stopped because its TLS certificate could not be verified."}
    except Exception:
        return {"status": "unavailable", "message": "DNS or HTTP check failed, timed out, or exceeded its redirect limit. This is not a clean verdict."}
