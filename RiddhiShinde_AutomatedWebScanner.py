#!/usr/bin/env python3
"""
Automated Web Scanner
Audits HTTP security headers and performs basic, non-invasive CORS misconfiguration checks.
Only scan websites you own or have explicit permission to test.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "strict-transport-security": "Encourages HTTPS-only connections (HSTS).",
    "content-security-policy": "Helps mitigate cross-site scripting and content injection.",
    "x-content-type-options": "Prevents MIME-type sniffing.",
    "x-frame-options": "Helps protect against clickjacking.",
    "referrer-policy": "Controls how much referrer information is sent.",
    "permissions-policy": "Restricts browser features and APIs.",
}

TEST_ORIGIN = "https://scanner-test.invalid"


def normalize_url(url):
    """Validate and normalize a target URL."""
    url = url.strip()
    if not url:
        raise ValueError("Target URL cannot be empty.")
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL.")
    return url


def audit_site(url, timeout=8, verify_tls=True):
    """Perform a single GET request and a benign Origin-header CORS check."""
    url = normalize_url(url)
    result = {
        "target": url,
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "checks": {},
        "cors": {},
        "errors": [],
    }
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_tls,
            headers={"User-Agent": "AutomatedWebScanner/1.0 (authorized defensive audit)"},
        )
        result["status_code"] = response.status_code
        result["final_url"] = response.url
        result["https"] = urlparse(response.url).scheme == "https"

        headers = {key.lower(): value.strip() for key, value in response.headers.items()}
        for header, description in SECURITY_HEADERS.items():
            value = headers.get(header)
            result["checks"][header] = {
                "present": bool(value),
                "value": value,
                "description": description,
                "status": "PASS" if value else "REVIEW",
            }

        # A deliberately non-credentialed request with a synthetic Origin.
        # This detects suspicious reflection/wildcard combinations, not every CORS flaw.
        cors_response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_tls,
            headers={
                "Origin": TEST_ORIGIN,
                "User-Agent": "AutomatedWebScanner/1.0 (authorized defensive audit)",
            },
        )
        cors_headers = {key.lower(): value.strip() for key, value in cors_response.headers.items()}
        allow_origin = cors_headers.get("access-control-allow-origin")
        allow_credentials = cors_headers.get("access-control-allow-credentials", "").lower()
        reflected = allow_origin == TEST_ORIGIN
        wildcard = allow_origin == "*"
        credentials = allow_credentials == "true"

        if reflected and credentials:
            cors_status = "HIGH RISK: supplied Origin is reflected and credentials are allowed"
        elif reflected:
            cors_status = "REVIEW: supplied Origin is reflected; verify the allowlist and response behavior"
        elif wildcard and credentials:
            # Browsers reject wildcard ACAO with credentials, but it is still a policy misconfiguration.
            cors_status = "REVIEW: wildcard origin and credentials header are both present"
        elif wildcard:
            cors_status = "REVIEW: wildcard origin allows cross-origin reads of non-credentialed responses"
        elif allow_origin:
            cors_status = "OBSERVED: explicit origin policy; validate against intended allowlist"
        else:
            cors_status = "NO CORS ALLOW-ORIGIN HEADER OBSERVED"

        result["cors"] = {
            "test_origin": TEST_ORIGIN,
            "access_control_allow_origin": allow_origin,
            "access_control_allow_credentials": allow_credentials or None,
            "origin_reflected": reflected,
            "wildcard_origin": wildcard,
            "credentials_allowed": credentials,
            "status": cors_status,
            "note": "Heuristic check only; confirm findings manually. No credentials or state-changing requests are sent.",
        }
    except requests.exceptions.SSLError as exc:
        result["errors"].append(f"TLS verification failed: {exc}")
    except requests.exceptions.Timeout:
        result["errors"].append(f"Request timed out after {timeout} seconds.")
    except requests.exceptions.RequestException as exc:
        result["errors"].append(f"Request failed: {exc}")
    return result


def print_report(report):
    print(f"\nAutomated Web Scanner — {report['target']}")
    print("=" * 62)
    if "status_code" in report:
        print(f"HTTP status: {report['status_code']} | Final URL: {report.get('final_url')}")
        print("\nSecurity headers:")
        for name, item in report["checks"].items():
            print(f"  [{item['status']}] {name}: {item['value'] or 'not present'}")
        print("\nCORS check:")
        print(f"  {report['cors'].get('status', 'Not completed')}")
        print(f"  Access-Control-Allow-Origin: {report['cors'].get('access_control_allow_origin') or 'not present'}")
    for error in report.get("errors", []):
        print(f"\n[ERROR] {error}")
    print("\nNote: Missing headers are review findings, not proof of an exploitable vulnerability.")


def main():
    parser = argparse.ArgumentParser(
        description="Check HTTP security headers and basic CORS policy signals on an authorized target."
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=float, default=8, help="Request timeout in seconds (default: 8)")
    parser.add_argument("--no-verify-tls", action="store_true", help="Disable TLS certificate verification (not recommended)")
    parser.add_argument("--json", dest="json_path", help="Write full results to a JSON file")
    args = parser.parse_args()

    try:
        report = audit_site(args.url, timeout=args.timeout, verify_tls=not args.no_verify_tls)
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    print_report(report)
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2, ensure_ascii=False)
        print(f"\nJSON report saved to: {args.json_path}")
    return 0 if not report["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
