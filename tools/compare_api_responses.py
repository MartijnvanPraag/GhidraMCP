#!/usr/bin/env python3
"""Compare API responses between the GUI plugin server and the headless server.

The script expects both servers to be running and accessible. It loads a list
of endpoint definitions from a JSON configuration file and issues identical
requests against both base URLs, reporting any differences discovered between
responses.

Usage example:
    python tools/compare_api_responses.py \
        --headless http://localhost:8192 \
        --gui http://localhost:8193 \
        --config tools/compare_api_responses.sample.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
import urllib.request
from urllib import error as urllib_error
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional

# Fields that differ between runs (IDs, timestamps, instance URLs).
DYNAMIC_FIELDS = {"id", "timestamp", "instance"}


@dataclass
class EndpointDefinition:
    """Represents an endpoint call to compare."""

    method: str
    path: str
    label: str = ""
    params: Mapping[str, Any] | None = None
    body: Any | None = None
    headers: Mapping[str, str] | None = None

    @staticmethod
    def from_dict(raw: Mapping[str, Any]) -> "EndpointDefinition":
        method = raw.get("method", "GET").upper()
        path = raw["path"]
        return EndpointDefinition(
            method=method,
            path=path,
            label=raw.get("label", path),
            params=raw.get("params"),
            body=raw.get("body"),
            headers=raw.get("headers"),
        )


def load_config(path: str) -> List[EndpointDefinition]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    if not isinstance(data, list):
        raise ValueError("Configuration file must contain a list of endpoint objects")

    return [EndpointDefinition.from_dict(item) for item in data]


def build_url(base_url: str, endpoint: EndpointDefinition) -> str:
    url = urllib.parse.urljoin(base_url.rstrip("/"), endpoint.path)
    if endpoint.params:
        query = urllib.parse.urlencode(endpoint.params, doseq=True)
        url = f"{url}?{query}"
    return url


def make_request(base_url: str, endpoint: EndpointDefinition) -> Dict[str, Any]:
    url = build_url(base_url, endpoint)
    data: Optional[bytes] = None

    if endpoint.body is not None:
        body_json = json.dumps(endpoint.body).encode("utf-8")
        data = body_json

    request = urllib.request.Request(url=url, data=data, method=endpoint.method)
    headers = {"Accept": "application/json"}
    if endpoint.body is not None:
        headers["Content-Type"] = "application/json"
    if endpoint.headers:
        headers.update(endpoint.headers)

    for key, value in headers.items():
        request.add_header(key, value)

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read().decode("utf-8")
            if not payload:
                return {}
            return json.loads(payload)
    except urllib_error.HTTPError as err:
        # Attempt to read the response body, falling back to the status line.
        try:
            payload = err.read().decode("utf-8")
            parsed = json.loads(payload)
            return parsed
        except Exception:
            return {"error": f"HTTP {err.code}: {err.reason}"}
    except urllib_error.URLError as err:
        raise RuntimeError(f"Failed to contact {url}: {err.reason}") from err


def normalize_payload(payload: Any) -> Any:
    if isinstance(payload, Mapping):
        normalized = {}
        for key, value in payload.items():
            if key in DYNAMIC_FIELDS:
                continue
            normalized[key] = normalize_payload(value)
        return normalized
    if isinstance(payload, list):
        return [normalize_payload(item) for item in payload]
    return payload


def compare_payloads(gui_payload: Any, headless_payload: Any) -> Dict[str, Any]:
    differences: Dict[str, Any] = {}
    if gui_payload == headless_payload:
        return differences

    # When payloads are dicts, check key-by-key to highlight differing fields.
    if isinstance(gui_payload, Mapping) and isinstance(headless_payload, Mapping):
        all_keys = set(gui_payload.keys()) | set(headless_payload.keys())
        for key in sorted(all_keys):
            gui_value = gui_payload.get(key, "<missing>")
            headless_value = headless_payload.get(key, "<missing>")
            if normalize_payload(gui_value) != normalize_payload(headless_value):
                differences[key] = {
                    "gui": gui_value,
                    "headless": headless_value,
                }
        return differences

    # Fallback: payloads differ but are not both dicts.
    differences["payload"] = {"gui": gui_payload, "headless": headless_payload}
    return differences


def pretty_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)


def run_comparisons(
    headless_base: str,
    gui_base: str,
    endpoints: Iterable[EndpointDefinition],
    pause: float = 0.0,
) -> int:
    total = 0
    failures = 0

    for endpoint in endpoints:
        total += 1
        print(f"\n[{total}] Comparing {endpoint.label or endpoint.path} ({endpoint.method})")
        gui_payload = make_request(gui_base, endpoint)
        headless_payload = make_request(headless_base, endpoint)

        gui_normalized = normalize_payload(gui_payload)
        headless_normalized = normalize_payload(headless_payload)

        diff = compare_payloads(gui_normalized, headless_normalized)
        if diff:
            failures += 1
            print("  ❌ Responses differ:")
            print(pretty_json(diff))
        else:
            print("  ✅ Responses match")

        if pause:
            time.sleep(pause)

    print(f"\nCompleted {total} comparisons with {failures} mismatches.")
    return failures


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--headless", required=True, help="Base URL for the headless server")
    parser.add_argument("--gui", required=True, help="Base URL for the GUI plugin server")
    parser.add_argument(
        "--config",
        default="tools/compare_api_responses.sample.json",
        help="Path to JSON file describing endpoint requests",
    )
    parser.add_argument(
        "--pause",
        type=float,
        default=0.0,
        help="Optional delay between requests in seconds",
    )
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    endpoints = load_config(args.config)
    mismatches = run_comparisons(args.headless, args.gui, endpoints, pause=args.pause)
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
