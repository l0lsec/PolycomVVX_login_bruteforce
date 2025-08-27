#!/usr/bin/env python3
"""
Login checker for servers using Basic Authentication on /form-submit/auth.htm.

Reads a file of hosts or URLs and tries two credential combinations:
- Polycom:456
- User:123

A login is considered successful if the response body contains
"lockparams|SUCCESS|0" and a cookie named "session" is set.

Example hosts file (one per line):
10.10.97.23
https://10.10.97.24
my-hostname.local

Usage:
  python3 login_bruteforce.py --file hosts.txt

Optional:
  --path /form-submit/auth.htm (default)
  --timeout 10 (seconds)
  --verify (enable TLS verification; default disabled for self-signed certs)
"""

from __future__ import annotations

import argparse
import sys
from typing import Iterable, List, Tuple
from urllib.parse import urlparse, urlunparse

try:
    import requests
    from requests.auth import HTTPBasicAuth
    from requests.exceptions import RequestException
except Exception as exc:  # pragma: no cover
    print("[!] Failed to import 'requests'. Please install dependencies: pip install -r requirements.txt", file=sys.stderr)
    raise


CREDENTIALS: List[Tuple[str, str]] = [
    ("Polycom", "456"),
    ("User", "123"),
]


def read_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f]
    return [line for line in lines if line and not line.startswith("#")]


def build_url(host_or_url: str, endpoint_path: str) -> str:
    endpoint_path = endpoint_path if endpoint_path.startswith("/") else f"/{endpoint_path}"
    parsed = urlparse(host_or_url)
    if parsed.scheme:
        # Normalize to provided path
        return urlunparse((parsed.scheme, parsed.netloc, endpoint_path, "", "", ""))
    # Treat input as hostname/IP
    return f"https://{host_or_url}{endpoint_path}"


def get_origin_and_referer(url: str) -> Tuple[str, str]:
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    referer = f"{origin}/"
    return origin, referer


def attempt_login(session: requests.Session, url: str, username: str, password: str, timeout: int, verify_tls: bool) -> Tuple[bool, str | None, int, str | None]:
    origin, referer = get_origin_and_referer(url)
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X)",
        "Accept": "*/*",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": origin,
        "Referer": referer,
    }
    try:
        resp = session.post(
            url,
            headers=headers,
            data=b"",
            auth=HTTPBasicAuth(username, password),
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=False,
        )
    except RequestException as exc:
        return False, None, 0, f"request_error: {exc}"

    body = resp.text or ""
    set_cookie_header = resp.headers.get("set-cookie", "")
    has_success_marker = "lockparams|SUCCESS|0" in body
    has_session_cookie = ("session" in resp.cookies) or ("session=" in set_cookie_header.lower())
    cookie_value = resp.cookies.get("session") if has_session_cookie else None
    is_success = has_success_marker and has_session_cookie
    return is_success, cookie_value, resp.status_code, None


def process_host(session: requests.Session, host_or_url: str, endpoint_path: str, timeout: int, verify_tls: bool) -> None:
    url = build_url(host_or_url, endpoint_path)
    for username, password in CREDENTIALS:
        ok, session_cookie, status_code, err = attempt_login(session, url, username, password, timeout, verify_tls)
        if err:
            print(f"{host_or_url}\tERROR\t{err}")
            break
        if ok:
            cookie_str = f"session={session_cookie}" if session_cookie else "session=<set>"
            print(f"{host_or_url}\tSUCCESS\t{username}:{password}\t{cookie_str}")
            break
        else:
            print(f"{host_or_url}\tFAIL\t{username}:{password}\tstatus={status_code}")


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Basic-Auth login checker for /form-submit/auth.htm")
    parser.add_argument("--file", "-f", required=True, help="Path to file containing hosts or URLs (one per line)")
    parser.add_argument("--path", default="/form-submit/auth.htm", help="Login endpoint path (default: /form-submit/auth.htm)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--verify", action="store_true", help="Enable TLS verification (default: disabled)")
    return parser.parse_args(list(argv))


def main(argv: Iterable[str]) -> int:
    args = parse_args(argv)
    hosts = read_lines(args.file)
    if not hosts:
        print("[!] No hosts found in file", file=sys.stderr)
        return 2

    # For likely self-signed certs on IPs, default to verify=False unless --verify provided
    verify_tls = bool(args.verify)

    # Optionally silence InsecureRequestWarning when verify=False
    if not verify_tls:
        try:  # pragma: no cover
            from urllib3.exceptions import InsecureRequestWarning  # type: ignore
            import urllib3  # type: ignore

            urllib3.disable_warnings(category=InsecureRequestWarning)
        except Exception:
            pass

    with requests.Session() as session:
        for host in hosts:
            process_host(session, host, args.path, args.timeout, verify_tls)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


