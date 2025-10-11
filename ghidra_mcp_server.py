# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "mcp==1.6.0",
#     "requests==2.32.3",
# ]
# ///
# GhydraMCP Bridge for Ghidra HATEOAS API - Optimized for MCP integration
# Provides namespaced tools for interacting with Ghidra's reverse engineering capabilities
import os
import signal
import sys
import threading
import time
import re
import math
import base64
from threading import Lock
from typing import Dict, List, Optional, Union, Any, Tuple
from urllib.parse import quote, urlencode, urlparse

import requests
from mcp.server.fastmcp import FastMCP

# ================= Core Infrastructure =================

ALLOWED_ORIGINS = os.environ.get(
    "GHIDRA_ALLOWED_ORIGINS", "http://localhost").split(",")

active_instances: Dict[int, dict] = {}
instances_lock = Lock()
DEFAULT_GHIDRA_PORT = int(os.environ.get("GHIDRA_DEFAULT_PORT", "8192"))
DEFAULT_GHIDRA_HOST = "localhost"
# Discovery ranges start from a fixed baseline to avoid shifting with DEFAULT_GHIDRA_PORT env:
# we still include DEFAULT_GHIDRA_PORT explicitly during discovery calls.
QUICK_DISCOVERY_RANGE = range(8192, 8192+10)
FULL_DISCOVERY_RANGE = range(8192, 8192+20)

BRIDGE_VERSION = "v2.0.0-beta.5"
REQUIRED_API_VERSION = 2005

# Soft gate for API version mismatches. When set to "0"/"false" (case-insensitive),
# the bridge will WARN and continue on API version mismatch instead of failing.
# Any other value (default) enforces a strict equality check.
def _env_truthy(name: str, default: str = "1") -> bool:
    val = os.environ.get(name, default)
    if val is None:
        return default not in ("0", "false", "False", "no", "No")
    return str(val).strip().lower() not in ("0", "false", "no")

GHIDRA_REQUIRE_API_VERSION_STRICT = _env_truthy("GHIDRA_REQUIRE_API_VERSION", "1")

# Session-local current instance tracking
SESSION_KEY_ENV = "ORCH_SESSION_ID"
DEFAULT_SESSION_KEY = "default"
current_instance_ports: Dict[str, int] = {}

def _get_session_key() -> str:
    try:
        key = os.environ.get(SESSION_KEY_ENV)
        return key if key else DEFAULT_SESSION_KEY
    except Exception:
        return DEFAULT_SESSION_KEY

def _get_current_port() -> int:
    key = _get_session_key()
    with instances_lock:
        if key not in current_instance_ports:
            base = int(os.environ.get("GHIDRA_FORCE_PORT", os.environ.get("GHIDRA_LOCK_PORT", str(DEFAULT_GHIDRA_PORT))))
            current_instance_ports[key] = base
        return int(current_instance_ports[key])

def _set_current_port(port: int) -> None:
    key = _get_session_key()
    with instances_lock:
        current_instance_ports[key] = int(port)

# Simple per-port cache for program base address to support guard checks
_program_base_cache: Dict[int, Optional[int]] = {}
_failed_create_cache: Dict[int, set] = {}

def _port_failed_create_set(port: int) -> set:
    try:
        p = int(port)
    except Exception:
        p = -1
    s = _failed_create_cache.get(p)
    if s is None:
        s = set()
        _failed_create_cache[p] = s
    return s

def _block_is_executable(block: Dict[str, Any]) -> bool:
    try:
        # Common shapes from HATEOAS plugins: execute/read/write booleans or permissions string
        if isinstance(block.get("execute"), bool):
            return bool(block.get("execute"))
        perms = str(block.get("permissions") or "").lower()
        if perms:
            # accept x or rx/r-x style flags
            return ("x" in perms) or ("exec" in perms)
        name = str(block.get("name") or block.get("block") or block.get("section") or "").lower()
        # Heuristic: code sections
        return any(seg in name for seg in (".text", "code", ".code"))
    except Exception:
        return False

def _bytes_look_like_fn_prologue(b: bytes) -> bool:
    """Very light prologue heuristics for x86/x64/ARM/Thumb.
    Best-effort only; returns True when bytes look like a plausible function start.
    """
    try:
        if not b or len(b) < 2:
            return False
        # x86 classic prologue: push ebp; mov ebp, esp
        if len(b) >= 3 and b[0] == 0x55 and b[1] == 0x8B and b[2] in (0xEC, 0xE5):
            return True
        # x64 common prologue: push rbp (0x55) often preceded by REX (0x40-0x4F)
        if b[0] in range(0x40, 0x50):
            # REX prefix followed by push rbp (0x55) or sub rsp, imm8/imm32 (48 83 EC or 48 81 EC)
            if len(b) >= 2 and b[1] == 0x55:
                return True
            if len(b) >= 3 and b[1] == 0x83 and b[2] == 0xEC:
                return True
            if len(b) >= 3 and b[1] == 0x81 and b[2] == 0xEC:
                return True
        if b[0] == 0x55:
            return True
        # Thumb/ARM (very rough): push {lr} (Thumb: 0xB5), stmdb sp!, {...,lr} (ARM: 0xE92Dxxxx)
        if b[0] in (0xB4, 0xB5):  # push in Thumb variants
            return True
        if len(b) >= 2 and b[0] == 0x2D and b[1] == 0xE9:  # E92D little-endian
            return True
        # Fallback: if first byte is a plausible instruction prefix/operand (not 0x00/0xFF NOPs pattern only)
        if b[0] not in (0x00, 0xFF):
            return True
        return False
    except Exception:
        return False

def _addr_viable_for_function_create(port: int, addr_hex: str) -> Tuple[bool, Optional[str]]:
    """Strict preflight to decide if we should attempt function creation at address.
    Returns (ok, reason_if_not_ok).
    """
    try:
        # Avoid repeated failing attempts per-port
        failed = _port_failed_create_set(port)
        ax = str(addr_hex).upper().replace("0X", "0x")
        if ax in failed:
            return (False, "PREVIOUS_CREATE_FAILED")

        # Parse address
        try:
            a = int(str(addr_hex).replace("0x", ""), 16)
        except Exception:
            return (False, "BAD_ADDRESS")

        # Must be inside a known memory block and executable
        blocks = safe_get(port, "programs/current/memory/blocks")
        ok_block = False
        if isinstance(blocks, dict) and blocks.get("success") and isinstance(blocks.get("result"), list):
            for b in blocks.get("result") or []:
                try:
                    s = int(str((b.get("start") or b.get("address") or "0")).replace("0x", ""), 16)
                    e = int(str(b.get("end")).replace("0x", ""), 16)
                    if s <= a <= e and _block_is_executable(b):
                        ok_block = True
                        break
                except Exception:
                    continue
        if not ok_block:
            return (False, "NOT_IN_EXECUTABLE_BLOCK")

        # Avoid creating in guarded header region
        if _guard_overlaps_header(port, a, 1):
            return (False, "IN_HEADER_GUARD")

        # Prefer an actual CALL xref to this address
        xr = xrefs_list(to_addr=f"{a:08X}", type="CALL", port=port)
        has_call_xref = False
        try:
            if isinstance(xr, dict) and xr.get("success") and isinstance(xr.get("result"), list):
                has_call_xref = len(xr.get("result") or []) > 0
        except Exception:
            has_call_xref = False

        # Quick prologue heuristics using memory_read
        mr = memory_read(address=f"{a:08X}", length=16, format="hex", port=port)
        looks_prologue = False
        try:
            if isinstance(mr, dict) and mr.get("success"):
                hx = (mr.get("hexBytes") or "").replace(" ", "")
                if hx:
                    import binascii as _ba
                    try:
                        b = _ba.unhexlify(hx)
                    except Exception:
                        b = b""
                    looks_prologue = _bytes_look_like_fn_prologue(b)
        except Exception:
            looks_prologue = False

        # Final decision: require either CALL xref or strong prologue indicator
        if not (has_call_xref or looks_prologue):
            return (False, "NO_XREF_OR_PROLOGUE")

        return (True, None)
    except Exception as e:
        return (False, f"PREFLIGHT_ERROR:{e}")

def _get_program_base_address(port: int) -> Optional[int]:
    """Return image base address as int for the current program on a port (cached)."""
    try:
        base = _program_base_cache.get(int(port))
        if base is not None:
            return base
        info = safe_get(port, "program")
        if isinstance(info, dict) and info.get("success"):
            res = info.get("result", {}) or {}
            b = res.get("imageBase") or res.get("image_base") or res.get("base_address")
            if isinstance(b, str):
                try:
                    base_int = int(b.replace("0x", ""), 16)
                    _program_base_cache[int(port)] = base_int
                    return base_int
                except Exception:
                    pass
        # Cache negative result to avoid repeated calls
        _program_base_cache[int(port)] = None
        return None
    except Exception:
        return None

def _guard_overlaps_header(port: int, start_addr: int, length: int) -> bool:
    """Return True if [start, start+length) overlaps MZ/PE header guard window.

    Controlled by env:
      - GHIDRA_REFUSE_HEADER_READS (default: "1")
      - GHIDRA_HEADER_GUARD_SIZE (default: "4096")
    """
    try:
        if str(os.environ.get("GHIDRA_REFUSE_HEADER_READS", "1")).strip().lower() in ("0", "false", "no", "off"):
            return False
        base = _get_program_base_address(port)
        if base is None:
            return False
        hdr_size = int(os.environ.get("GHIDRA_HEADER_GUARD_SIZE", "4096"))
        if hdr_size <= 0:
            return False
        s0 = int(start_addr)
        e0 = int(start_addr) + max(0, int(length))
        s1 = int(base)
        e1 = int(base) + int(hdr_size)
        return not (e0 <= s1 or e1 <= s0)
    except Exception:
        return False

def _guard_require_anchor(params: Dict[str, Any] | None) -> Optional[dict]:
    """Enforce presence of an 'anchor' argument when GHIDRA_ENFORCE_ANCHORED_READS=1.

    Accept any non-empty anchor (dict or str). Returns error dict on violation, else None.
    """
    try:
        if str(os.environ.get("GHIDRA_ENFORCE_ANCHORED_READS", "0")).strip().lower() in ("0", "false", "no", "off"):
            return None
        anchor = None
        if isinstance(params, dict):
            anchor = params.get("anchor")
        if anchor is None or (isinstance(anchor, (str, list)) and len(anchor) == 0):
            return {
                "success": False,
                "error": {
                    "code": "ANCHOR_REQUIRED",
                    "message": "Anchored reads enforced: provide 'anchor' describing provenance (e.g., function/callsite)."
                },
                "timestamp": int(time.time() * 1000)
            }
        return None
    except Exception:
        return None

# Helper: infer a reasonable auto-anchor when enforcement is on and caller omitted it
def _infer_anchor_for_addr(port: int, addr: int, length: int) -> Optional[dict]:
    try:
        # Try memory blocks/sections first
        resp = safe_get(port, "programs/current/memory/blocks")
        blocks = []
        if isinstance(resp, dict) and resp.get("success") and isinstance(resp.get("result"), list):
            blocks = resp.get("result") or []
        if blocks:
            for b in blocks:
                try:
                    s = b.get("start") or b.get("address")
                    e = b.get("end")
                    n = b.get("name") or b.get("block") or b.get("section") or "section"
                    if isinstance(s, str) and isinstance(e, str):
                        s_i = int(s.replace("0x", ""), 16)
                        e_i = int(e.replace("0x", ""), 16)
                        if s_i <= addr < (e_i + 1):
                            return {"type": "section", "name": str(n)}
                except Exception:
                    continue
        # Fallback: entropy_window tied to the requested span
        return {"type": "entropy_window", "rank": 0, "address": f"{int(addr):08X}", "length": int(max(0, length))}
    except Exception:
        return None

# Helper: crop a [addr, addr+len) span to avoid header-guard overlap
def _crop_away_header_guard(port: int, addr: int, length: int) -> Tuple[int, int, Optional[str]]:
    try:
        if not _guard_overlaps_header(port, addr, length):
            return addr, length, None
        base = _get_program_base_address(port)
        if base is None:
            return addr, length, None
        hdr_size = int(os.environ.get("GHIDRA_HEADER_GUARD_SIZE", "4096"))
        guard_end = int(base) + int(hdr_size)
        new_start = max(addr, guard_end)
        new_len = max(0, (addr + length) - new_start)
        if new_len <= 0:
            return new_start, 0, f"fully inside guarded header region at 0x{addr:08X}"
        return new_start, new_len, f"cropped around guarded header region; new_start=0x{new_start:08X}"
    except Exception:
        return addr, length, None

# If GHIDRA_LOCK_PORT is set, prevent switching away from that port via instances_use
_LOCKED_PORT: Optional[int] = None
try:
    _LOCKED_PORT = int(os.environ["GHIDRA_LOCK_PORT"]) if os.environ.get("GHIDRA_LOCK_PORT") else None
except Exception:
    _LOCKED_PORT = None

instructions = """
GhydraMCP allows interacting with multiple Ghidra SRE instances. Ghidra SRE is a tool for reverse engineering and analyzing binaries, e.g. malware.

First, run `instances_discover()` to find all available Ghidra instances (both already known and newly discovered). Then use `instances_use(port)` to set your working instance.

The API is organized into namespaces for different types of operations:
- instances_* : For managing Ghidra instances
- functions_* : For working with functions
- data_* : For working with data items
- memory_* : For memory access
- xrefs_* : For cross-references
- analysis_* : For program analysis
"""

mcp = FastMCP("GhydraMCP", instructions=instructions)

ghidra_host = os.environ.get("GHIDRA_HYDRA_HOST", DEFAULT_GHIDRA_HOST)

# Helper function to get the current instance or validate a specific port
def _get_instance_port(port=None):
    """Internal helper to get the current instance port or validate a specific port"""
    # Respect forced/locked port from environment if provided
    if _LOCKED_PORT is not None:
        eff_port = _LOCKED_PORT
        forced = None
    else:
        forced = os.environ.get("GHIDRA_FORCE_PORT")
        eff_port = int(forced) if forced else (int(port) if port is not None else int(_get_current_port()))
    # Validate that the instance exists and is active
    if eff_port not in active_instances:
        # Try to register it if not found
        register_instance(eff_port)
        if eff_port not in active_instances:
            raise ValueError(f"No active Ghidra instance on port {eff_port}")

    # Only change the global current instance via explicit instances_use, not implicitly here.
    # If you want implicit behavior, set GHIDRA_AUTOSTICK_ON_PORT=1 explicitly.
    try:
        if forced is None and _LOCKED_PORT is None and (port is not None):
            if _env_truthy("GHIDRA_AUTOSTICK_ON_PORT", "0"):
                _set_current_port(int(eff_port))
    except Exception:
        pass

    return eff_port

# The rest of the utility functions (HTTP helpers, etc.) remain the same...
def get_instance_url(port: int) -> str:
    """Get URL for a Ghidra instance by port"""
    with instances_lock:
        if port in active_instances:
            return active_instances[port]["url"]

        if 8192 <= port <= 65535:
            register_instance(port)
            if port in active_instances:
                return active_instances[port]["url"]

        return f"http://{ghidra_host}:{port}"

def validate_origin(headers: dict) -> bool:
    """Validate request origin against allowed origins"""
    origin = headers.get("Origin")
    if not origin:
        # No origin header - allow (browser same-origin policy applies)
        return True

    # Parse origin to get scheme+hostname
    try:
        parsed = urlparse(origin)
        origin_base = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            origin_base += f":{parsed.port}"
    except:
        return False

    return origin_base in ALLOWED_ORIGINS

# Helper: resolve a function reference when the model supplies a shorthand name like
# "FUN_4100" or "FUN_4a9f" that doesn't exist exactly in Ghidra.
# Strategy: extract a hex suffix (4-8 digits) and find a unique function whose
# address ends with that suffix. Returns (address, canonical_name) or None.
def _resolve_function_hint(name_hint: str, port: int) -> Optional[Tuple[str, str]]:
    try:
        s = str(name_hint or "")
        m = re.search(r"([0-9A-Fa-f]{4,8})$", s)
        if not m:
            return None
        suffix = m.group(1).upper()
        # Page through functions and find best unique suffix match
        limit = 200
        offset = 0
        best: List[Tuple[str, str]] = []  # (address, name)
        best_len = 0
        while True:
            resp = safe_get(port, "functions", {"offset": offset, "limit": limit})
            simp = simplify_response(resp)
            if not (isinstance(simp, dict) and simp.get("success")):
                break
            items = simp.get("result") or []
            if not isinstance(items, list):
                break
            for it in items:
                try:
                    addr = str(it.get("address", "")).upper()
                    nm = str(it.get("name", ""))
                except Exception:
                    continue
                if addr.endswith(suffix):
                    match_len = len(suffix)
                    if match_len > best_len:
                        best = [(addr, nm)]
                        best_len = match_len
                    elif match_len == best_len:
                        best.append((addr, nm))
            # Robust paging that does not depend on plugin-reported size and tolerates server caps
            got = len(items)
            if got <= 0:
                break
            # If server caps to < requested limit, advance by what we actually got and stop on short page
            offset += got
            if got < limit:
                break
        # Only accept a unique best match with at least 4 hex digits to reduce ambiguity
        if best_len >= 4 and len(best) == 1:
            return best[0]
        return None
    except Exception:
        return None

def _env_int(name: str, default: int) -> int:
    """Parse an integer environment variable with a default and safe fallback."""
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default

def _resolve_timeout(method: str, endpoint: str):
    """Resolve requests timeout from environment with sensible defaults.

    Supports per-method and operation-specific overrides:
      - GHIDRA_MCP_CONNECT_TIMEOUT_SEC (default 3)
      - GHIDRA_MCP_READ_TIMEOUT_SEC (default 10)
      - GHIDRA_MCP_PATCH_TIMEOUT_SEC (default: falls back to READ timeout)
      - GHIDRA_MCP_FUNCTIONS_RENAME_TIMEOUT_SEC (default: falls back to PATCH/READ timeout)
    Returns either a (connect, read) tuple or a single integer (seconds) when no env is set.
    """
    # Preserve previous behavior when no env tuning is provided
    if not (
        os.environ.get("GHIDRA_MCP_CONNECT_TIMEOUT_SEC") or
        os.environ.get("GHIDRA_MCP_READ_TIMEOUT_SEC") or
        os.environ.get("GHIDRA_MCP_PATCH_TIMEOUT_SEC") or
        os.environ.get("GHIDRA_MCP_FUNCTIONS_RENAME_TIMEOUT_SEC")
    ):
        return 10

    connect_timeout = _env_int("GHIDRA_MCP_CONNECT_TIMEOUT_SEC", 3)
    read_timeout = _env_int("GHIDRA_MCP_READ_TIMEOUT_SEC", 20)

    if method.upper() == "PATCH":
        # Allow a longer window for PATCH operations
        read_timeout = _env_int("GHIDRA_MCP_PATCH_TIMEOUT_SEC", read_timeout)
        # And an even longer window for function renames, which may be slower on large programs
        if endpoint.startswith("functions/") or endpoint.startswith("functions/by-name"):
            read_timeout = _env_int("GHIDRA_MCP_FUNCTIONS_RENAME_TIMEOUT_SEC", read_timeout)

    return (connect_timeout, read_timeout)

def _make_request(method: str, port: int, endpoint: str, params: Optional[dict] = None, 
                 json_data: Optional[dict] = None, data: Optional[str] = None, 
                 headers: Optional[dict] = None) -> dict:
    """Internal helper to make HTTP requests and handle common errors."""
    url = f"{get_instance_url(port)}/{endpoint}"
    
    # Set up headers according to HATEOAS API expected format
    request_headers = {
        'Accept': 'application/json',
        'X-Request-ID': f"mcp-bridge-{int(time.time() * 1000)}"
    }
    
    if headers:
        request_headers.update(headers)

    is_state_changing = method.upper() in ["POST", "PUT", "PATCH", "DELETE"]
    if is_state_changing:
        check_headers = json_data.get("headers", {}) if isinstance(
            json_data, dict) else (headers or {})
        if not validate_origin(check_headers):
            return {
                "success": False,
                "error": {
                    "code": "ORIGIN_NOT_ALLOWED",
                    "message": "Origin not allowed for state-changing request"
                },
                "status_code": 403,
                "timestamp": int(time.time() * 1000)
            }
        if json_data is not None:
            request_headers['Content-Type'] = 'application/json'
        elif data is not None:
            request_headers['Content-Type'] = 'text/plain'

    try:
        # Compute timeout (tuple(connect, read) or single int)
        req_timeout = _resolve_timeout(method, endpoint)
        response = requests.request(
            method,
            url,
            params=params,
            json=json_data,
            data=data,
            headers=request_headers,
            timeout=req_timeout
        )

        try:
            parsed_json = response.json()
            
            # Add timestamp if not present
            if isinstance(parsed_json, dict) and "timestamp" not in parsed_json:
                parsed_json["timestamp"] = int(time.time() * 1000)
                
            # Check for HATEOAS compliant error response format and reformat if needed
            if not response.ok and isinstance(parsed_json, dict) and "success" in parsed_json and not parsed_json["success"]:
                # Check if error is in the expected HATEOAS format
                if "error" in parsed_json and not isinstance(parsed_json["error"], dict):
                    # Convert string error to the proper format
                    error_message = parsed_json["error"]
                    parsed_json["error"] = {
                        "code": f"HTTP_{response.status_code}",
                        "message": error_message
                    }
            
            return parsed_json
            
        except ValueError:
            if response.ok:
                return {
                    "success": False,
                    "error": {
                        "code": "NON_JSON_RESPONSE",
                        "message": "Received non-JSON success response from Ghidra plugin"
                    },
                    "status_code": response.status_code,
                    "response_text": response.text[:500],
                    "timestamp": int(time.time() * 1000)
                }
            else:
                return {
                    "success": False,
                    "error": {
                        "code": f"HTTP_{response.status_code}",
                        "message": f"Non-JSON error response: {response.text[:100]}..."
                    },
                    "status_code": response.status_code,
                    "response_text": response.text[:500],
                    "timestamp": int(time.time() * 1000)
                }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error": {
                "code": "REQUEST_TIMEOUT",
                "message": "Request timed out"
            },
            "status_code": 408,
            "timestamp": int(time.time() * 1000)
        }
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "error": {
                "code": "CONNECTION_ERROR",
                "message": f"Failed to connect to Ghidra instance at {url}"
            },
            "status_code": 503,
            "timestamp": int(time.time() * 1000)
        }
    except Exception as e:
        return {
            "success": False,
            "error": {
                "code": "UNEXPECTED_ERROR",
                "message": f"An unexpected error occurred: {str(e)}"
            },
            "exception": e.__class__.__name__,
            "timestamp": int(time.time() * 1000)
        }

def safe_get(port: int, endpoint: str, params: Optional[dict] = None) -> dict:
    """Make GET request to Ghidra instance"""
    return _make_request("GET", port, endpoint, params=params)

def safe_put(port: int, endpoint: str, data: dict) -> dict:
    """Make PUT request to Ghidra instance with JSON payload"""
    headers = data.pop("headers", None) if isinstance(data, dict) else None
    return _make_request("PUT", port, endpoint, json_data=data, headers=headers)

def safe_post(port: int, endpoint: str, data: Union[dict, str]) -> dict:
    """Perform a POST request to a specific Ghidra instance with JSON or text payload"""
    headers = None
    json_payload = None
    text_payload = None

    if isinstance(data, dict):
        headers = data.pop("headers", None)
        json_payload = data
    else:
        text_payload = data

    return _make_request("POST", port, endpoint, json_data=json_payload, data=text_payload, headers=headers)

def safe_patch(port: int, endpoint: str, data: dict) -> dict:
    """Perform a PATCH request to a specific Ghidra instance with JSON payload"""
    headers = data.pop("headers", None) if isinstance(data, dict) else None
    return _make_request("PATCH", port, endpoint, json_data=data, headers=headers)

def safe_delete(port: int, endpoint: str) -> dict:
    """Perform a DELETE request to a specific Ghidra instance"""
    return _make_request("DELETE", port, endpoint)

def simplify_response(response: dict) -> dict:
    """
    Simplify HATEOAS response data for easier AI agent consumption
    - Removes _links from result entries
    - Flattens nested structures when appropriate
    - Preserves important metadata
    - Converts structured data like disassembly to text for easier consumption
    """
    if not isinstance(response, dict):
        return response

    # Make a copy to avoid modifying the original
    result = response.copy()
    
    # Store API response metadata
    api_metadata = {}
    for key in ["id", "instance", "timestamp", "size", "offset", "limit"]:
        if key in result:
            api_metadata[key] = result.get(key)
    
    # Simplify the main result data if present
    if "result" in result:
        # Handle array results
        if isinstance(result["result"], list):
            simplified_items = []
            for item in result["result"]:
                if isinstance(item, dict):
                    # Store but remove HATEOAS links from individual items
                    item_copy = item.copy()
                    links = item_copy.pop("_links", None)
                    
                    # Optionally store direct href links as more accessible properties
                    # This helps AI agents navigate the API without understanding HATEOAS
                    if isinstance(links, dict):
                        for link_name, link_data in links.items():
                            if isinstance(link_data, dict) and "href" in link_data:
                                item_copy[f"{link_name}_url"] = link_data["href"]
                    
                    simplified_items.append(item_copy)
                else:
                    simplified_items.append(item)
            result["result"] = simplified_items
        
        # Handle object results
        elif isinstance(result["result"], dict):
            result_copy = result["result"].copy()
            
            # Store but remove links from result object
            links = result_copy.pop("_links", None)
            
            # Add direct href links for easier navigation
            if isinstance(links, dict):
                for link_name, link_data in links.items():
                    if isinstance(link_data, dict) and "href" in link_data:
                        result_copy[f"{link_name}_url"] = link_data["href"]
            
            # Special case for disassembly - convert to text for easier consumption
            if "instructions" in result_copy and isinstance(result_copy["instructions"], list):
                disasm_text = ""
                for instr in result_copy["instructions"]:
                    if isinstance(instr, dict):
                        addr = instr.get("address", "")
                        mnemonic = instr.get("mnemonic", "")
                        operands = instr.get("operands", "")
                        bytes_str = instr.get("bytes", "")
                        
                        # Format: address: bytes  mnemonic operands
                        disasm_text += f"{addr}: {bytes_str.ljust(10)}  {mnemonic} {operands}\n"
                
                # Add the text representation
                result_copy["disassembly_text"] = disasm_text
                # Remove the original structured instructions to simplify the response
                result_copy.pop("instructions", None)
            
            # Special case for decompiled code - make sure it's directly accessible
            if "ccode" in result_copy:
                result_copy["decompiled_text"] = result_copy["ccode"]
            elif "decompiled" in result_copy:
                result_copy["decompiled_text"] = result_copy["decompiled"]
            
            result["result"] = result_copy
    
    # Store but remove HATEOAS links from the top level
    links = result.pop("_links", None)
    
    # Add direct href links in a more accessible format
    if isinstance(links, dict):
        api_links = {}
        for link_name, link_data in links.items():
            if isinstance(link_data, dict) and "href" in link_data:
                api_links[link_name] = link_data["href"]
        
        # Add simplified links
        if api_links:
            result["api_links"] = api_links
    
    # Restore API metadata
    for key, value in api_metadata.items():
        if key not in result:
            result[key] = value
    
    return result

def register_instance(port: int, url: Optional[str] = None) -> str:
    """Register a new Ghidra instance
    
    Args:
        port: Port number of the Ghidra instance
        url: Optional URL if different from default http://host:port
    
    Returns:
        str: Confirmation message or error
    """
    if url is None:
        url = f"http://{ghidra_host}:{port}"

    try:
        # Check for HATEOAS API by checking plugin-version endpoint
        test_url = f"{url}/plugin-version"
        response = requests.get(test_url, timeout=2)
        
        if not response.ok:
            return f"Error: Instance at {url} is not responding properly to HATEOAS API"

        project_info = {"url": url}

        try:
            # Check plugin version to ensure compatibility
            try:
                version_data = response.json()
                if "result" in version_data:
                    result = version_data["result"]
                    if isinstance(result, dict):
                        plugin_version = result.get("plugin_version", "")
                        api_version = result.get("api_version", 0)
                        
                        project_info["plugin_version"] = plugin_version
                        project_info["api_version"] = api_version
                        
                        # Verify API version compatibility (soft gate supported via env)
                        if api_version != REQUIRED_API_VERSION:
                            error_msg = (
                                f"API version mismatch: Plugin reports version {api_version}, "
                                f"but bridge requires version {REQUIRED_API_VERSION}"
                            )
                            if GHIDRA_REQUIRE_API_VERSION_STRICT:
                                print(error_msg, file=sys.stderr)
                                return error_msg
                            else:
                                print(
                                    f"WARNING: {error_msg} — proceeding due to GHIDRA_REQUIRE_API_VERSION=0",
                                    file=sys.stderr,
                                )
                        
                        print(f"Connected to Ghidra plugin version {plugin_version} with API version {api_version}", file=sys.stderr)
            except Exception as e:
                print(f"Error parsing plugin version: {e}", file=sys.stderr)
            
            # Get program info from HATEOAS API
            info_url = f"{url}/program"
            
            try:
                info_response = requests.get(info_url, timeout=2)
                if info_response.ok:
                    try:
                        info_data = info_response.json()
                        if "result" in info_data:
                            result = info_data["result"]
                            if isinstance(result, dict):
                                # Extract project and file from programId (format: "project:/file")
                                program_id = result.get("programId", "")
                                if ":" in program_id:
                                    project_name, file_path = program_id.split(":", 1)
                                    project_info["project"] = project_name
                                    # Remove leading slash from file path if present
                                    if file_path.startswith("/"):
                                        file_path = file_path[1:]
                                    project_info["path"] = file_path
                                
                                # Get file name directly from the result
                                project_info["file"] = result.get("name", "")
                                
                                # Get other metadata
                                project_info["language_id"] = result.get("languageId", "")
                                project_info["compiler_spec_id"] = result.get("compilerSpecId", "")
                                project_info["image_base"] = result.get("image_base", "")
                                
                                # Store _links from result for HATEOAS navigation
                                if "_links" in result:
                                    project_info["_links"] = result.get("_links", {})
                    except Exception as e:
                        print(f"Error parsing info endpoint: {e}", file=sys.stderr)
            except Exception as e:
                print(f"Error connecting to info endpoint: {e}", file=sys.stderr)
        except Exception:
            # Non-critical, continue with registration even if project info fails
            pass

        with instances_lock:
            active_instances[port] = project_info

        return f"Registered instance on port {port} at {url}"
    except Exception as e:
        return f"Error: Could not connect to instance at {url}: {str(e)}"

def _discover_instances(port_range, host=None, timeout=0.5) -> dict:
    """Internal function to discover NEW Ghidra instances by scanning ports

    This function only returns newly discovered instances that weren't already
    in the active_instances registry. Use instances_discover() for a complete
    list including already known instances.
    """
    found_instances = []
    scan_host = host if host is not None else ghidra_host

    for port in port_range:
        if port in active_instances:
            continue  # Skip already known instances

        url = f"http://{scan_host}:{port}"
        try:
            # Try HATEOAS API via plugin-version endpoint
            test_url = f"{url}/plugin-version"
            response = requests.get(test_url, 
                                  headers={'Accept': 'application/json', 
                                           'X-Request-ID': f"discovery-{int(time.time() * 1000)}"},
                                  timeout=timeout)
            
            if response.ok:
                # Further validate it's a GhydraMCP instance by checking response format
                try:
                    json_data = response.json()
                    if "success" in json_data and json_data["success"] and "result" in json_data:
                        # Looks like a valid HATEOAS API response
                        # Instead of relying only on register_instance, which already checks program info,
                        # extract additional information here for more detailed discovery results
                        result = register_instance(port, url)
                        
                        # Initialize report info
                        instance_info = {
                            "port": port, 
                            "url": url
                        }
                        
                        # Extract version info for reporting
                        if isinstance(json_data["result"], dict):
                            instance_info["plugin_version"] = json_data["result"].get("plugin_version", "unknown")
                            instance_info["api_version"] = json_data["result"].get("api_version", "unknown")
                        else:
                            instance_info["plugin_version"] = "unknown"
                            instance_info["api_version"] = "unknown"
                        
                        # Include project details from registered instance in the report
                        if port in active_instances:
                            instance_info["project"] = active_instances[port].get("project", "")
                            instance_info["file"] = active_instances[port].get("file", "")
                        
                        instance_info["result"] = result
                        found_instances.append(instance_info)
                except (ValueError, KeyError):
                    # Not a valid JSON response or missing expected keys
                    print(f"Port {port} returned non-HATEOAS response", file=sys.stderr)
                    continue
            
        except requests.exceptions.RequestException:
            # Instance not available, just continue
            continue

    return {
        "found": len(found_instances),
        "instances": found_instances
    }

def periodic_discovery():
    """Periodically discover new instances"""
    while True:
        try:
            _discover_instances(FULL_DISCOVERY_RANGE, timeout=0.5)

            with instances_lock:
                ports_to_remove = []
                for port, info in active_instances.items():
                    url = info["url"]
                    try:
                        # Check HATEOAS API via plugin-version endpoint
                        response = requests.get(f"{url}/plugin-version", timeout=1)
                        if not response.ok:
                            ports_to_remove.append(port)
                            continue
                            
                        # Update program info if available (especially to get project name)
                        try:
                            info_url = f"{url}/program"
                            info_response = requests.get(info_url, timeout=1)
                            if info_response.ok:
                                try:
                                    info_data = info_response.json()
                                    if "result" in info_data:
                                        result = info_data["result"]
                                        if isinstance(result, dict):
                                            # Extract project and file from programId (format: "project:/file")
                                            program_id = result.get("programId", "")
                                            if ":" in program_id:
                                                project_name, file_path = program_id.split(":", 1)
                                                info["project"] = project_name
                                                # Remove leading slash from file path if present
                                                if file_path.startswith("/"):
                                                    file_path = file_path[1:]
                                                info["path"] = file_path
                                            
                                            # Get file name directly from the result
                                            info["file"] = result.get("name", "")
                                            
                                            # Get other metadata
                                            info["language_id"] = result.get("languageId", "")
                                            info["compiler_spec_id"] = result.get("compilerSpecId", "")
                                            info["image_base"] = result.get("image_base", "")
                                except Exception as e:
                                    print(f"Error parsing info endpoint during discovery: {e}", file=sys.stderr)
                        except Exception:
                            # Non-critical, continue even if update fails
                            pass
                            
                    except requests.exceptions.RequestException:
                        ports_to_remove.append(port)

                for port in ports_to_remove:
                    del active_instances[port]
                    print(f"Removed unreachable instance on port {port}", file=sys.stderr)
        except Exception as e:
            print(f"Error in periodic discovery: {e}", file=sys.stderr)

        time.sleep(30)

def handle_sigint(signum, frame):
    """Handle SIGINT gracefully without forcing process exit"""
    print("Received SIGINT, shutting down MCP bridge gracefully...", file=sys.stderr)
    # Don't force exit - let the main process handle shutdown
    # os._exit(0)  # Removed - this was causing the backend to exit
    pass

# ================= MCP Resources =================
# Resources provide information that can be loaded directly into context
# They focus on data and minimize metadata

@mcp.resource(uri="/instance/{port}")
def ghidra_instance(port: Optional[int] = None) -> dict:
    """Get detailed information about a Ghidra instance and the loaded program
    
    Args:
        port: Specific Ghidra instance port (optional, uses current if omitted)
        
    Returns:
        dict: Detailed information about the Ghidra instance and loaded program
    """
    port = _get_instance_port(port)
    response = safe_get(port, "program")
    
    if not isinstance(response, dict) or not response.get("success", False):
        return {"error": f"Unable to access Ghidra instance on port {port}"}
    
    # Extract only the most relevant information for the resource
    result = response.get("result", {})
    
    if not isinstance(result, dict):
        return {
            "success": False,
            "error": {
                "code": "INVALID_RESPONSE",
                "message": "Invalid response format from Ghidra instance"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    instance_info = {
        "port": port,
        "url": get_instance_url(port),
        "program_name": result.get("name", "unknown"),
        "program_id": result.get("programId", "unknown"),
        "language": result.get("languageId", "unknown"),
        "compiler": result.get("compilerSpecId", "unknown"),
        "base_address": result.get("imageBase", "0x0"),
        "memory_size": result.get("memorySize", 0),
        "analysis_complete": result.get("analysisComplete", False)
    }
    
    # Add project information if available
    if "project" in active_instances[port]:
        instance_info["project"] = active_instances[port]["project"]
    
    return instance_info

@mcp.resource(uri="/instance/{port}/function/decompile/address/{address}")
def decompiled_function_by_address(port: Optional[int] = None, address: Optional[str] = None) -> str:
    """Get decompiled C code for a function by address
    
    Args:
        port: Specific Ghidra instance port
        address: Function address in hex format
        
    Returns:
        str: The decompiled C code as a string, or error message
    """
    if not address:
        return "Error: Address parameter is required"
    
    port = _get_instance_port(port)
    
    params = {
        "syntax_tree": "false",
        "style": "normalize"
    }
    
    endpoint = f"functions/{address}/decompile"
    
    response = safe_get(port, endpoint, params)
    simplified = simplify_response(response)
    
    # For a resource, we want to directly return just the decompiled code
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        error_message = "Error: Could not decompile function"
        if isinstance(simplified, dict) and "error" in simplified:
            if isinstance(simplified["error"], dict):
                error_message = simplified["error"].get("message", error_message)
            else:
                error_message = str(simplified["error"])
        return error_message
    
    # Extract just the decompiled code text
    result = simplified["result"]
    
    # Different endpoints may return the code in different fields, try all of them
    if isinstance(result, dict):
        for key in ["decompiled_text", "ccode", "decompiled"]:
            if key in result:
                return result[key]
    
    return "Error: Could not extract decompiled code from response"

@mcp.resource(uri="/instance/{port}/function/decompile/name/{name}")
def decompiled_function_by_name(port: Optional[int] = None, name: Optional[str] = None) -> str:
    """Get decompiled C code for a function by name
    
    Args:
        port: Specific Ghidra instance port
        name: Function name
        
    Returns:
        str: The decompiled C code as a string, or error message
    """
    if not name:
        return "Error: Name parameter is required"
    
    port = _get_instance_port(port)
    
    params = {
        "syntax_tree": "false",
        "style": "normalize"
    }
    
    endpoint = f"functions/by-name/{quote(name)}/decompile"
    
    response = safe_get(port, endpoint, params)
    simplified = simplify_response(response)
    
    # For a resource, we want to directly return just the decompiled code
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        error_message = "Error: Could not decompile function"
        if isinstance(simplified, dict) and "error" in simplified:
            if isinstance(simplified["error"], dict):
                error_message = simplified["error"].get("message", error_message)
            else:
                error_message = str(simplified["error"])
        return error_message
    
    # Extract just the decompiled code text
    result = simplified["result"]
    
    # Different endpoints may return the code in different fields, try all of them
    if isinstance(result, dict):
        for key in ["decompiled_text", "ccode", "decompiled"]:
            if key in result:
                return result[key]
    
    return "Error: Could not extract decompiled code from response"

@mcp.resource(uri="/instance/{port}/function/info/address/{address}")
def function_info_by_address(port: Optional[int] = None, address: Optional[str] = None) -> dict:
    """Get detailed information about a function by address
    
    Args:
        port: Specific Ghidra instance port
        address: Function address in hex format
        
    Returns:
        dict: Complete function information including signature, parameters, etc.
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    endpoint = f"functions/{address}"
    
    response = safe_get(port, endpoint)
    simplified = simplify_response(response)
    
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        return {
            "success": False,
            "error": {
                "code": "FUNCTION_NOT_FOUND",
                "message": "Could not get function information",
                "details": simplified.get("error") if isinstance(simplified, dict) else None
            },
            "timestamp": int(time.time() * 1000)
        }
    
    # Return just the function data without API metadata
    return simplified["result"]

@mcp.resource(uri="/instance/{port}/function/info/name/{name}")
def function_info_by_name(port: Optional[int] = None, name: Optional[str] = None) -> dict:
    """Get detailed information about a function by name
    
    Args:
        port: Specific Ghidra instance port
        name: Function name
        
    Returns:
        dict: Complete function information including signature, parameters, etc.
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    endpoint = f"functions/by-name/{quote(name)}"
    
    response = safe_get(port, endpoint)
    simplified = simplify_response(response)
    
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        return {
            "success": False,
            "error": {
                "code": "FUNCTION_NOT_FOUND",
                "message": "Could not get function information",
                "details": simplified.get("error") if isinstance(simplified, dict) else None
            },
            "timestamp": int(time.time() * 1000)
        }
    
    # Return just the function data without API metadata
    return simplified["result"]

@mcp.resource(uri="/instance/{port}/function/disassembly/address/{address}")
def disassembly_by_address(port: Optional[int] = None, address: Optional[str] = None) -> str:
    """Get disassembled instructions for a function by address
    
    Args:
        port: Specific Ghidra instance port
        address: Function address in hex format
        
    Returns:
        str: Formatted disassembly listing as a string
    """
    if not address:
        return "Error: Address parameter is required"
    
    port = _get_instance_port(port)
    
    endpoint = f"functions/{address}/disassembly"
    
    response = safe_get(port, endpoint)
    simplified = simplify_response(response)
    
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        error_message = "Error: Could not get disassembly"
        if isinstance(simplified, dict) and "error" in simplified:
            if isinstance(simplified["error"], dict):
                error_message = simplified["error"].get("message", error_message)
            else:
                error_message = str(simplified["error"])
        return error_message
    
    # For a resource, we want to directly return just the disassembly text
    result = simplified["result"]
    
    # Check if we have a disassembly_text field already
    if isinstance(result, dict) and "disassembly_text" in result:
        return result["disassembly_text"]
    
    # Otherwise if we have raw instructions, format them ourselves
    if isinstance(result, dict) and "instructions" in result and isinstance(result["instructions"], list):
        disasm_text = ""
        for instr in result["instructions"]:
            if isinstance(instr, dict):
                addr = instr.get("address", "")
                mnemonic = instr.get("mnemonic", "")
                operands = instr.get("operands", "")
                bytes_str = instr.get("bytes", "")
                
                # Format: address: bytes  mnemonic operands
                disasm_text += f"{addr}: {bytes_str.ljust(10)}  {mnemonic} {operands}\n"
        
        return disasm_text
    
    # If we have a direct disassembly field, try that as well
    if isinstance(result, dict) and "disassembly" in result:
        return result["disassembly"]
    
    return "Error: Could not extract disassembly from response"

@mcp.resource(uri="/instance/{port}/function/disassembly/name/{name}")
def disassembly_by_name(port: Optional[int] = None, name: Optional[str] = None) -> str:
    """Get disassembled instructions for a function by name
    
    Args:
        port: Specific Ghidra instance port
        name: Function name
        
    Returns:
        str: Formatted disassembly listing as a string
    """
    if not name:
        return "Error: Name parameter is required"
    
    port = _get_instance_port(port)
    
    endpoint = f"functions/by-name/{quote(name)}/disassembly"
    
    response = safe_get(port, endpoint)
    simplified = simplify_response(response)
    
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        error_message = "Error: Could not get disassembly"
        if isinstance(simplified, dict) and "error" in simplified:
            if isinstance(simplified["error"], dict):
                error_message = simplified["error"].get("message", error_message)
            else:
                error_message = str(simplified["error"])
        return error_message
    
    # For a resource, we want to directly return just the disassembly text
    result = simplified["result"]
    
    # Check if we have a disassembly_text field already
    if isinstance(result, dict) and "disassembly_text" in result:
        return result["disassembly_text"]
    
    # Otherwise if we have raw instructions, format them ourselves
    if isinstance(result, dict) and "instructions" in result and isinstance(result["instructions"], list):
        disasm_text = ""
        for instr in result["instructions"]:
            if isinstance(instr, dict):
                addr = instr.get("address", "")
                mnemonic = instr.get("mnemonic", "")
                operands = instr.get("operands", "")
                bytes_str = instr.get("bytes", "")
                
                # Format: address: bytes  mnemonic operands
                disasm_text += f"{addr}: {bytes_str.ljust(10)}  {mnemonic} {operands}\n"
        
        return disasm_text
    
    # If we have a direct disassembly field, try that as well
    if isinstance(result, dict) and "disassembly" in result:
        return result["disassembly"]
    
    return "Error: Could not extract disassembly from response"

# ================= MCP Prompts =================
# Prompts define reusable templates for LLM interactions

@mcp.prompt("analyze_function")
def analyze_function_prompt(name: Optional[str] = None, address: Optional[str] = None, port: Optional[int] = None):
    """A prompt to guide the LLM through analyzing a function
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with address)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    
    # Get function name if only address is provided
    if address and not name:
        fn_info = function_info_by_address(address=address, port=port)
        if isinstance(fn_info, dict) and "name" in fn_info:
            name = fn_info["name"]
    
    # Create the template that guides analysis
    decompiled = ""
    disasm = ""
    fn_info = None
    
    if address:
        decompiled = decompiled_function_by_address(address=address, port=port)
        disasm = disassembly_by_address(address=address, port=port)
        fn_info = function_info_by_address(address=address, port=port)
    elif name:
        decompiled = decompiled_function_by_name(name=name, port=port)
        disasm = disassembly_by_name(name=name, port=port)
        fn_info = function_info_by_name(name=name, port=port)
    
    return {
        "prompt": f"""
        Analyze the following function: {name or address}
        
        Decompiled code:
        ```c
        {decompiled}
        ```
        
        Disassembly:
        ```
        {disasm}
        ```
        
        1. What is the purpose of this function?
        2. What are the key parameters and their uses?
        3. What are the return values and their meanings?
        4. Are there any security concerns in this implementation?
        5. Describe the algorithm or process being implemented.
        """,
        "context": {
            "function_info": fn_info
        }
    }

@mcp.prompt("identify_vulnerabilities")
def identify_vulnerabilities_prompt(name: Optional[str] = None, address: Optional[str] = None, port: Optional[int] = None):
    """A prompt to help identify potential vulnerabilities in a function
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with address)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    
    # Get function name if only address is provided
    if address and not name:
        fn_info = function_info_by_address(address=address, port=port)
        if isinstance(fn_info, dict) and "name" in fn_info:
            name = fn_info["name"]
    
    # Create the template focused on security analysis
    decompiled = ""
    disasm = ""
    fn_info = None
    
    if address:
        decompiled = decompiled_function_by_address(address=address, port=port)
        disasm = disassembly_by_address(address=address, port=port)
        fn_info = function_info_by_address(address=address, port=port)
    elif name:
        decompiled = decompiled_function_by_name(name=name, port=port)
        disasm = disassembly_by_name(name=name, port=port)
        fn_info = function_info_by_name(name=name, port=port)
    
    return {
        "prompt": f"""
        Analyze the following function for security vulnerabilities: {name or address}
        
        Decompiled code:
        ```c
        {decompiled}
        ```
        
        Look for these vulnerability types:
        1. Buffer overflows or underflows
        2. Integer overflow/underflow
        3. Use-after-free or double-free bugs
        4. Format string vulnerabilities
        5. Missing bounds checks
        6. Insecure memory operations
        7. Race conditions or timing issues
        8. Input validation problems
        
        For each potential vulnerability:
        - Describe the vulnerability and where it occurs
        - Explain the security impact
        - Suggest how it could be exploited
        - Recommend a fix
        """,
        "context": {
            "function_info": fn_info,
            "disassembly": disasm
        }
    }

@mcp.prompt("reverse_engineer_binary")
def reverse_engineer_binary_prompt(port: Optional[int] = None):
    """A comprehensive prompt to guide the process of reverse engineering an entire binary
    
    Args:
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    
    # Get program info for context
    program_info = ghidra_instance(port=port)
    
    # Create a comprehensive reverse engineering guide
    return {
        "prompt": f"""
        # Comprehensive Binary Reverse Engineering Plan
        
        Begin reverse engineering the binary {program_info.get('program_name', 'unknown')} using a methodical approach.
        
        ## Phase 1: Initial Reconnaissance
        1. Analyze entry points and the main function
        2. Identify and catalog key functions and libraries
        3. Map the overall program structure
        4. Identify important data structures
        
        ## Phase 2: Functional Analysis
        1. Start with main() or entry point functions and trace the control flow
        2. Find and rename all unnamed functions (FUN_*) called from main
        3. For each function:
           - Decompile and analyze its purpose
           - Rename with descriptive names following consistent patterns
           - Add comments for complex logic
           - Identify parameters and return values
        4. Follow cross-references (xrefs) to understand context of function usage
        5. Pay special attention to:
           - File I/O operations
           - Network communication
           - Memory allocation/deallocation
           - Authentication/encryption routines
           - Data processing algorithms
        
        ## Phase 3: Data Flow Mapping
        1. Identify key data structures and rename them meaningfully
        2. Track global variables and their usage across functions
        3. Map data transformations through the program
        4. Identify sensitive data handling (keys, credentials, etc.)
        
        ## Phase 4: Deep Analysis
        1. For complex functions, perform deeper analysis using:
           - Data flow analysis
           - Call graph analysis
           - Security vulnerability scanning
        2. Look for interesting patterns:
           - Command processing routines
           - State machines
           - Protocol implementations
           - Cryptographic operations
        
        ## Implementation Strategy
        1. Start with functions called from main
        2. Search for unnamed functions with pattern "FUN_*"
        3. Decompile each function and analyze its purpose
        4. Look at its call graph and cross-references to understand context
        5. Rename the function based on its behavior
        6. Document key insights
        7. Continue iteratively until the entire program flow is mapped
        
        ## Function Prioritization
        1. Start with entry points and initialization functions
        2. Focus on functions with high centrality in the call graph
        3. Pay special attention to functions with:
           - Command processing logic
           - Error handling
           - Security checks
           - Data transformation
        
        Remember to use the available GhydraMCP tools:
        - Use functions_list to find functions matching patterns
        - Use xrefs_list to find cross-references
        - Use functions_decompile for C-like representations
        - Use functions_disassemble for lower-level analysis
        - Use functions_rename to apply meaningful names
        - Use data_* tools to work with program data
        """,
        "context": {
            "program_info": program_info 
        }
    }

# ================= MCP Tools =================
# Since we can't use tool groups, we'll use namespaces in the function names

# Instance management tools
@mcp.tool()
def instances_list() -> dict:
    """List all active Ghidra instances"""
    with instances_lock:
        return {
            "instances": [
                {
                    "port": port,
                    "url": info["url"],
                    "project": info.get("project", ""),
                    "file": info.get("file", "")
                }
                for port, info in active_instances.items()
            ]
        }

@mcp.tool()
def instances_discover(host: Optional[str] = None) -> dict:
    """Discover available Ghidra instances by scanning ports

    Args:
        host: Optional host to scan (default: configured ghidra_host)

    Returns:
        dict: Contains 'found' count, 'new_instances' count, and 'instances' list with all available instances
    """
    # Get newly discovered instances
    discovery_result = _discover_instances(QUICK_DISCOVERY_RANGE, host=host, timeout=0.5)
    new_instances = discovery_result.get("instances", [])
    new_count = len(new_instances)

    # Get all currently known instances (including ones that were already registered)
    all_instances = []
    with instances_lock:
        for port, info in active_instances.items():
            instance_info = {
                "port": port,
                "url": info["url"],
                "project": info.get("project", ""),
                "file": info.get("file", ""),
                "plugin_version": info.get("plugin_version", "unknown"),
                "api_version": info.get("api_version", "unknown")
            }

            # Mark if this was newly discovered in this call
            instance_info["newly_discovered"] = any(inst["port"] == port for inst in new_instances)

            all_instances.append(instance_info)

    # Sort by port for consistent ordering
    all_instances.sort(key=lambda x: x["port"])

    return {
        "found": len(all_instances),  # Total instances available
        "new_instances": new_count,   # How many were newly discovered
        "instances": all_instances    # All available instances
    }

@mcp.tool()
def instances_register(port: int, url: Optional[str] = None) -> str:
    """Register a new Ghidra instance
    
    Args:
        port: Port number of the Ghidra instance
        url: Optional URL if different from default http://host:port
    
    Returns:
        str: Confirmation message or error
    """
    return register_instance(port, url)

@mcp.tool()
def instances_unregister(port: int) -> str:
    """Unregister a Ghidra instance
    
    Args:
        port: Port number of the instance to unregister
    
    Returns:
        str: Confirmation message or error
    """
    with instances_lock:
        if port in active_instances:
            del active_instances[port]
            return f"Unregistered instance on port {port}"
        return f"No instance found on port {port}"

@mcp.tool()
def instances_use(port: int) -> str:
    """Set the current working Ghidra instance
    
    Args:
        port: Port number of the instance to use
        
    Returns:
        str: Confirmation message or error
    """
    # Set the current working instance for this session key
    # Determine effective port considering lock/force
    forced_env = None
    if _LOCKED_PORT is not None:
        if int(port) != int(_LOCKED_PORT):
            return f"Error: Port is locked to {int(_LOCKED_PORT)} via GHIDRA_LOCK_PORT"
        eff_port = int(_LOCKED_PORT)
    else:
        forced_env = os.environ.get("GHIDRA_FORCE_PORT")
        eff_port = int(forced_env) if forced_env else int(port)

    # Validate/register the effective port
    if eff_port not in active_instances:
        register_instance(eff_port)
        if eff_port not in active_instances:
            return f"Error: No active Ghidra instance found on port {eff_port}"

    # Set as current instance
    _set_current_port(eff_port)

    # Return information about the selected instance (effective)
    with instances_lock:
        info = active_instances[eff_port]
        program = info.get("file", "unknown program")
        project = info.get("project", "unknown project")
        msg_prefix = "Now using" if forced_env is None and _LOCKED_PORT is None else (
            "Using forced" if forced_env is not None else "Using locked"
        )
        return f"{msg_prefix} Ghidra instance on port {eff_port} with {program} in project {project} [session={_get_session_key()}]"

@mcp.tool()
def instances_current() -> dict:
    """Get information about the current working Ghidra instance
    
    Returns:
        dict: Details about the current instance and program
    """
    data = ghidra_instance(port=_get_current_port())
    try:
        if isinstance(data, dict):
            data.setdefault("session_id", _get_session_key())
    except Exception:
        pass
    return data

# Function tools
@mcp.tool()
def functions_list(offset: int = 0, limit: int = 100, 
                  name_contains: Optional[str] = None, 
                  name_matches_regex: Optional[str] = None,
                  port: Optional[int] = None) -> dict:
    """List functions with filtering and pagination
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        name_contains: Substring name filter (case-insensitive)
        name_matches_regex: Regex name filter
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: List of functions with pagination information
    """
    port = _get_instance_port(port)
    
    params: Dict[str, Any] = {
        "offset": offset,
        "limit": limit
    }
    if name_contains:
        params["name_contains"] = name_contains
    if name_matches_regex:
        params["name_matches_regex"] = name_matches_regex

    response = safe_get(port, "functions", params)
    simplified = simplify_response(response)
    
    # Ensure we maintain pagination metadata
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    
    return simplified

@mcp.tool()
def functions_get(name: Optional[str] = None, address: Optional[str] = None, port: Optional[int] = None) -> dict:
    """Get detailed information about a function
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Detailed function information
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    if address:
        endpoint = f"functions/{address}"
    elif name:
        endpoint = f"functions/by-name/{quote(name)}"
    else:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER", 
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    response = safe_get(port, endpoint)
    simplified = simplify_response(response)
    # Fallback: if exact name not found, try resolving a shorthand name hint
    try:
        if (
            isinstance(simplified, dict)
            and not simplified.get("success", True)
            and isinstance(simplified.get("error"), dict)
            and simplified["error"].get("code") in ("FUNCTION_NOT_FOUND", "HTTP_404")
            and name and not address
        ):
            hint = _resolve_function_hint(name, port)
            if hint:
                addr, _nm = hint
                endpoint2 = f"functions/{addr}"
                response2 = safe_get(port, endpoint2)
                return simplify_response(response2)
    except Exception:
        pass
    return simplified

@mcp.tool()
def functions_decompile(name: Optional[str] = None, address: Optional[str] = None, 
                        syntax_tree: bool = False, style: str = "normalize",
                        port: Optional[int] = None) -> dict:
    """Get decompiled code for a function
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        syntax_tree: Include syntax tree (default: False)
        style: Decompiler style (default: "normalize")
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Contains function information and decompiled code
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    params = {
        "syntax_tree": str(syntax_tree).lower(),
        "style": style
    }
    
    if address:
        endpoint = f"functions/{address}/decompile"
    elif name:
        endpoint = f"functions/by-name/{quote(name)}/decompile"
    else:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    response = safe_get(port, endpoint, params)
    simplified = simplify_response(response)

    # Fallback: if function not found by exact address, try creating a function at that address and retry once
    try:
        if (
            isinstance(simplified, dict)
            and not simplified.get("success", True)
            and isinstance(simplified.get("error"), dict)
            and simplified["error"].get("code") == "FUNCTION_NOT_FOUND"
            and address
        ):
            ok, reason = _addr_viable_for_function_create(port, address)
            create_res = {"success": False, "error": {"code": "CREATE_SKIPPED", "message": reason or "Address not viable for function creation"}}
            if ok:
                create_res = functions_create(address=address, port=port)
            if isinstance(create_res, dict) and create_res.get("success"):
                # retry decompile once
                response2 = safe_get(port, endpoint, params)
                return simplify_response(response2)
    except Exception:
        pass
    # Fallback 2: name hint resolution to address then retry
    try:
        if (
            isinstance(simplified, dict)
            and not simplified.get("success", True)
            and isinstance(simplified.get("error"), dict)
            and simplified["error"].get("code") in ("FUNCTION_NOT_FOUND", "HTTP_404")
            and name and not address
        ):
            hint = _resolve_function_hint(name, port)
            if hint:
                addr, _nm = hint
                endpoint3 = f"functions/{addr}/decompile"
                response3 = safe_get(port, endpoint3, params)
                return simplify_response(response3)
    except Exception:
        pass
    return simplified

@mcp.tool()
def functions_disassemble(name: Optional[str] = None, address: Optional[str] = None, port: Optional[int] = None) -> dict:
    """Get disassembly for a function
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Contains function information and disassembly text
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    if address:
        endpoint = f"functions/{address}/disassembly"
    elif name:
        endpoint = f"functions/by-name/{quote(name)}/disassembly"
    else:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    response = safe_get(port, endpoint)
    simplified = simplify_response(response)
    # Fallback similar to decompile: create function then retry once (with viability check)
    try:
        if (
            isinstance(simplified, dict)
            and not simplified.get("success", True)
            and isinstance(simplified.get("error"), dict)
            and simplified["error"].get("code") == "FUNCTION_NOT_FOUND"
            and address
        ):
            ok, reason = _addr_viable_for_function_create(port, address)
            create_res = {"success": False, "error": {"code": "CREATE_SKIPPED", "message": reason or "Address not viable for function creation"}}
            if ok:
                create_res = functions_create(address=address, port=port)
            if isinstance(create_res, dict) and create_res.get("success"):
                response2 = safe_get(port, endpoint)
                return simplify_response(response2)
    except Exception:
        pass
    # Fallback 2: name hint resolution to address then retry
    try:
        if (
            isinstance(simplified, dict)
            and not simplified.get("success", True)
            and isinstance(simplified.get("error"), dict)
            and simplified["error"].get("code") in ("FUNCTION_NOT_FOUND", "HTTP_404")
            and name and not address
        ):
            hint = _resolve_function_hint(name, port)
            if hint:
                addr, _nm = hint
                endpoint3 = f"functions/{addr}/disassembly"
                response3 = safe_get(port, endpoint3)
                return simplify_response(response3)
    except Exception:
        pass
    return simplified

@mcp.tool()
def functions_list_immediates(name: Optional[str] = None, address: Optional[str] = None, min_hex_len: int = 8, port: Optional[int] = None) -> dict:
    """Extract 32-bit immediate constants from a function's disassembly.

    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex (mutually exclusive with name)
        min_hex_len: Minimum hex digit length to consider (default 8 for u32)
        port: Specific Ghidra instance port (optional)

    Returns:
        { success, items: [ { value_hex, count } ], raw: [values_hex...] }
    Notes:
        - Parses the disassembly text for 0xXXXXXXXX patterns and aggregates counts.
        - Does not attempt to filter out code addresses; caller may cross-check against sections.
    """
    try:
        port = _get_instance_port(port)
        # Reuse our disassembly helper
        dis = functions_disassemble(name=name, address=address, port=port)
        if not (isinstance(dis, dict) and dis.get("success")):
            return dis if isinstance(dis, dict) else {"success": False, "error": {"code": "DISASM_ERROR", "message": "unexpected response"}}
        # Disassembly text may be under result.text or result.disassembly
        txt = ""
        res = dis.get("result") if isinstance(dis.get("result"), dict) else dis
        try:
            if isinstance(res, dict):
                txt = res.get("text") or res.get("disassembly") or ""
        except Exception:
            txt = ""
        if not isinstance(txt, str):
            txt = ""
        import re as _re
        pat = _re.compile(r"0x[0-9A-Fa-f]{" + str(max(1, int(min_hex_len))) + r"}")
        vals = pat.findall(txt or "")
        counts: Dict[str, int] = {}
        for v in vals:
            # Normalize to 0xXXXXXXXX uppercase
            vv = f"0x{int(v, 16):08X}"
            counts[vv] = counts.get(vv, 0) + 1
        items = [{"value_hex": k, "count": counts[k]} for k in sorted(counts.keys())]
        return {"success": True, "items": items, "raw": [it["value_hex"] for it in items]}
    except Exception as e:
        return {"success": False, "error": {"code": "IMMEDIATES_ERROR", "message": str(e)}}

@mcp.tool()
def functions_list_call_args(
    name: Optional[str] = None,
    address: Optional[str] = None,
    callee: Optional[str] = None,
    port: Optional[int] = None,
) -> dict:
    """Extract immediate arguments passed to callees within a function (via decompiled text).

    Args:
        name: Function name to analyze (mutually exclusive with address)
        address: Function address in hex (mutually exclusive with name)
        callee: Optional target callee name to match (e.g., 'FUN_12345678'). If omitted, returns matches for all callees with immediates.
        port: Specific Ghidra instance port (optional)

    Returns:
        { success, calls: [ { callee, args: [ {idx, value_hex, value_dec}... ] }... ], values_hex: [unique list], notes }

    Notes:
        - Parses decompiler pseudocode via functions_decompile and finds occurrences like: CALLEE(arg0, arg1, ...).
        - Captures numeric immediates (hex or decimal, including negative) from the argument list.
        - Values are normalized to unsigned 32-bit (0xXXXXXXXX) for downstream HashDB use.
        - If callee is omitted, attempts a best-effort extraction for all function-like calls and filters to those with at least one immediate.
    """
    try:
        port = _get_instance_port(port)
        # Use decompile as primary source; it's more structured than raw disassembly text
        dec = functions_decompile(name=name, address=address, port=port)
        if not (isinstance(dec, dict) and dec.get("success")):
            return dec if isinstance(dec, dict) else {"success": False, "error": {"code": "DECOMP_ERROR", "message": "unexpected response"}}
        res = dec.get("result") if isinstance(dec.get("result"), dict) else dec
        code_txt = ""
        try:
            if isinstance(res, dict):
                code_txt = res.get("code") or res.get("decompiled") or res.get("text") or res.get("pseudocode") or ""
        except Exception:
            code_txt = ""
        if not isinstance(code_txt, str):
            code_txt = ""
        import re as _re

        calls = []
        values_set = set()

        def _parse_num(tok: str) -> Optional[int]:
            t = tok.strip()
            # strip casts like (code *), (int), (undefined4) etc.
            t = _re.sub(r"\([^\)]*\)", "", t).strip()
            if not t:
                return None
            try:
                # hex with optional sign
                if t.lower().startswith("-0x"):
                    return (-int(t[3:], 16)) & 0xFFFFFFFF
                if t.lower().startswith("0x"):
                    return int(t, 16) & 0xFFFFFFFF
                # decimal with optional sign
                if t[0] in "+-" or t.isdigit():
                    return int(t, 10) & 0xFFFFFFFF
            except Exception:
                return None
            return None

        matches: list[tuple[str, str]] = []
        if callee and isinstance(callee, str) and callee.strip():
            # Regex to capture a specific callee: callee(arglist)
            callee_esc = _re.escape(callee.strip())
            pattern = _re.compile(rf"{callee_esc}\s*\(([^)]*)\)")
            for m in pattern.finditer(code_txt or ""):
                matches.append((callee.strip(), m.group(1)))
        else:
            # Broad match: function-like token followed by (...) capturing simple arg list
            pattern = _re.compile(r"(?P<callee>[A-Za-z_][A-Za-z0-9_@$]*)\s*\((?P<args>[^)]*)\)")
            blocked = {"if", "for", "while", "switch", "return", "sizeof", "case", "else", "do", "goto", "break", "continue"}
            for m in pattern.finditer(code_txt or ""):
                cn = (m.group("callee") or "").strip()
                if not cn or cn.lower() in blocked:
                    continue
                matches.append((cn, m.group("args") or ""))

        for callee_name, arglist in matches:
            # crude split on commas (sufficient for simple immediate args)
            raw_args = [a.strip() for a in (arglist or "").split(',')]
            args_norm = []
            for idx, a in enumerate(raw_args):
                v = _parse_num(a)
                if v is None:
                    continue
                vh = f"0x{v:08X}"
                args_norm.append({"idx": idx, "value_hex": vh, "value_dec": int(v)})
                values_set.add(vh)
            if args_norm:
                calls.append({"callee": callee_name, "args": args_norm})

        return {
            "success": True,
            "calls": calls,
            "values_hex": sorted(values_set),
            "notes": f"source=decompile; callee={'specified' if callee else 'auto'}",
        }
    except Exception as e:
        return {"success": False, "error": {"code": "CALL_ARGS_ERROR", "message": str(e)}}

@mcp.tool()
def functions_analyze_indirect_calls(
    name: Optional[str] = None,
    address: Optional[str] = None,
    port: Optional[int] = None,
) -> dict:
    """Analyze function for indirect call patterns and extract potential hash arguments.
    
    This tool is designed to handle cases where API hash resolvers use function pointers
    or indirect calls that don't show up in direct call analysis.
    
    Args:
        name: Function name to analyze (mutually exclusive with address)
        address: Function address in hex (mutually exclusive with address)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        {
            success: bool,
            indirect_call_patterns: [
                {
                    pattern_type: str,  # "function_pointer", "indirect_call", "memory_reference"
                    context: str,       # Code context where pattern was found
                    extracted_values: [
                        {
                            value_hex: str,
                            value_dec: int,
                            confidence: float,
                            source: str     # "immediate", "memory_ref", "computed"
                        }
                    ]
                }
            ],
            memory_references: [
                {
                    address: str,
                    value_hex: str,
                    value_dec: int,
                    context: str
                }
            ],
            suggested_analysis: [str]  # Suggestions for further analysis
        }
    """
    try:
        port = _get_instance_port(port)
        
        # Get the decompiled function
        dec = functions_decompile(name=name, address=address, port=port)
        if not (isinstance(dec, dict) and dec.get("success")):
            return dec if isinstance(dec, dict) else {"success": False, "error": {"code": "DECOMP_ERROR", "message": "unexpected response"}}
        
        res = dec.get("result") if isinstance(dec.get("result"), dict) else dec
        code_txt = ""
        try:
            if isinstance(res, dict):
                code_txt = res.get("code") or res.get("decompiled") or res.get("text") or res.get("pseudocode") or ""
        except Exception:
            code_txt = ""
        if not isinstance(code_txt, str):
            code_txt = ""
        
        import re as _re
        
        patterns = []
        memory_refs = []
        suggestions = []
        
        # Pattern 1: Function pointer dereference - (*function_ptr)(args...)
        fp_pattern = _re.compile(r'\(\s*\*\s*([^)]+)\s*\)\s*\(\s*([^)]*)\s*\)')
        for match in fp_pattern.finditer(code_txt):
            ptr_expr = match.group(1).strip()
            args_expr = match.group(2).strip()
            
            # Extract numeric values from arguments
            extracted_values = []
            if args_expr:
                arg_parts = [a.strip() for a in args_expr.split(',')]
                for i, arg in enumerate(arg_parts):
                    value = _parse_numeric_value(arg)
                    if value is not None:
                        extracted_values.append({
                            "value_hex": f"0x{value:08X}",
                            "value_dec": int(value),
                            "confidence": 0.9,
                            "source": "immediate",
                            "arg_index": i
                        })
            
            patterns.append({
                "pattern_type": "function_pointer",
                "context": match.group(0),
                "pointer_expression": ptr_expr,
                "extracted_values": extracted_values
            })
            
            if extracted_values:
                suggestions.append(f"Function pointer call found with {len(extracted_values)} immediate arguments")
        
        # Pattern 2: Indirect calls through variables/memory
        indirect_pattern = _re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*([^)]*)\s*\)')
        for match in indirect_pattern.finditer(code_txt):
            func_var = match.group(1)
            args_expr = match.group(2).strip()
            
            # Check if this looks like a variable (not a direct function name)
            if not func_var.startswith('FUN_') and not func_var.startswith('SUB_'):
                # Look for assignment to this variable in the same function
                assign_pattern = _re.compile(rf'{_re.escape(func_var)}\s*=\s*([^;]+)')
                assignments = assign_pattern.findall(code_txt)
                
                if assignments:
                    # Extract numeric arguments
                    extracted_values = []
                    if args_expr:
                        arg_parts = [a.strip() for a in args_expr.split(',')]
                        for i, arg in enumerate(arg_parts):
                            value = _parse_numeric_value(arg)
                            if value is not None:
                                extracted_values.append({
                                    "value_hex": f"0x{value:08X}",
                                    "value_dec": int(value),
                                    "confidence": 0.8,
                                    "source": "immediate",
                                    "arg_index": i
                                })
                    
                    patterns.append({
                        "pattern_type": "indirect_call",
                        "context": match.group(0),
                        "variable_name": func_var,
                        "assignments": assignments,
                        "extracted_values": extracted_values
                    })
                    
                    if extracted_values:
                        suggestions.append(f"Indirect call through variable '{func_var}' with {len(extracted_values)} arguments")
        
        # Pattern 3: Memory references that might contain API hashes
        mem_pattern = _re.compile(r'(?:0x[0-9a-fA-F]+|\*\s*\([^)]+\))')
        potential_hashes = []
        for match in mem_pattern.finditer(code_txt):
            ref_text = match.group(0)
            # Try to extract address
            addr_match = _re.search(r'0x([0-9a-fA-F]+)', ref_text)
            if addr_match:
                try:
                    addr_value = int(addr_match.group(1), 16)
                    if 0x1000 <= addr_value <= 0xFFFFFFFF:  # Reasonable address range
                        memory_refs.append({
                            "address": f"0x{addr_value:X}",
                            "value_hex": f"0x{addr_value:08X}",
                            "value_dec": addr_value,
                            "context": ref_text
                        })
                        potential_hashes.append(addr_value)
                except ValueError:
                    pass
        
        # Pattern 4: Enhanced XOR key extraction
        xor_keys = []
        xor_patterns = [
            # Pattern 1: Equality checks with XOR (e.g., if (var == (expr ^ 0x60705dc6)))
            r'(\w+)\s*==\s*\([^)]*\s*\^\s*(0x[0-9a-fA-F]+)\)',
            # Pattern 2: Direct XOR operations (e.g., var ^ 0x60705dc6)
            r'(\w+)\s*\^\s*(0x[0-9a-fA-F]+)',
            # Pattern 3: Reverse XOR operations (e.g., 0x60705dc6 ^ var)
            r'(0x[0-9a-fA-F]+)\s*\^\s*(\w+)',
            # Pattern 4: Conditional XOR checks (e.g., if (expr ^ 0x60705dc6))
            r'if\s*\([^)]*\s*\^\s*(0x[0-9a-fA-F]+)\)',
            # Pattern 5: Variable assignment with XOR (e.g., result = expr ^ 0x60705dc6)
            r'\w+\s*=\s*[^;]*\s*\^\s*(0x[0-9a-fA-F]+)',
            # Pattern 6: Function parameter XOR (e.g., func(expr ^ 0x60705dc6))
            r'\w+\s*\([^)]*\s*\^\s*(0x[0-9a-fA-F]+)\)'
        ]
        
        for pattern in xor_patterns:
            for match in _re.finditer(pattern, code_txt):
                # Extract the XOR key (hex value)
                key_match = None
                for group in match.groups():
                    if group and group.startswith('0x'):
                        key_match = group
                        break
                
                if key_match:
                    try:
                        key_value = int(key_match, 16)
                        # Valid XOR key range check
                        if 0x1000000 <= key_value <= 0xFFFFFFFF:
                            xor_keys.append({
                                "key_hex": key_match,
                                "key_dec": key_value,
                                "context": match.group(0),
                                "confidence": 0.9,
                                "source": "xor_pattern"
                            })
                    except ValueError:
                        pass

        # Look for patterns that suggest this is a resolver
        resolver_indicators = [
            r'hash.*api|api.*hash',
            r'resolve.*name|name.*resolve',
            r'get.*proc.*address',
            r'load.*library',
            r'function.*address',
            r'crc32|hash|xor.*key'
        ]
        
        is_likely_resolver = False
        for indicator in resolver_indicators:
            if _re.search(indicator, code_txt, _re.IGNORECASE):
                is_likely_resolver = True
                suggestions.append(f"Function contains resolver-like patterns: {indicator}")
                break
        
        # If we found potential hashes but no direct arguments, suggest memory analysis
        if memory_refs and not any(p["extracted_values"] for p in patterns):
            suggestions.append("No direct arguments found, but memory references detected. Consider memory analysis.")
        
        # If this looks like a resolver but we found no arguments, suggest different approaches
        if is_likely_resolver and not any(p["extracted_values"] for p in patterns):
            suggestions.append("Function appears to be a resolver but no direct arguments found. Check for data sections or global variables.")
        
        return {
            "success": True,
            "indirect_call_patterns": patterns,
            "memory_references": memory_refs,
            "xor_keys": xor_keys,
            "suggested_analysis": suggestions,
            "is_likely_resolver": is_likely_resolver,
            "notes": f"Analyzed {len(patterns)} call patterns, {len(memory_refs)} memory references, {len(xor_keys)} XOR keys"
        }
        
    except Exception as e:
        return {"success": False, "error": {"code": "INDIRECT_CALL_ANALYSIS_ERROR", "message": str(e)}}

def _parse_numeric_value(expr: str) -> Optional[int]:
    """Helper function to parse numeric values from expressions."""
    import re as _re
    try:
        expr = expr.strip()
        # Remove common casts
        expr = _re.sub(r'\([^)]*\)', '', expr).strip()
        
        if not expr:
            return None
            
        # Hex values
        if expr.lower().startswith('-0x'):
            return (-int(expr[3:], 16)) & 0xFFFFFFFF
        if expr.lower().startswith('0x'):
            return int(expr, 16) & 0xFFFFFFFF
            
        # Decimal values
        if expr[0] in '+-' or expr.isdigit():
            return int(expr, 10) & 0xFFFFFFFF
            
        return None
    except Exception:
        return None

@mcp.tool()
def memory_analyze_hash_arrays(
    start_address: Optional[str] = None,
    end_address: Optional[str] = None,
    section_name: Optional[str] = None,
    mode: str = "summary",
    min_confidence: float = 0.8,
    max_results: int = 100,
    address_range: Optional[str] = None,
    port: Optional[int] = None,
) -> dict:
    """Analyze memory sections for potential API hash arrays with batching support.
    
    This tool prevents rate limiting by offering summary and detail modes.
    Start with 'summary' mode to get an overview, then use 'detail' mode for specific ranges.
    
    Args:
        start_address: Starting address in hex (e.g., "0x401000")
        end_address: Ending address in hex (e.g., "0x402000") 
        section_name: Section name to analyze (e.g., ".rdata", ".data")
        mode: Analysis mode - "summary" for overview, "detail" for specific analysis
        min_confidence: Minimum confidence threshold (0.0-1.0, default 0.8)
        max_results: Maximum number of results to return (default 100)
        address_range: Specific address range for detail mode (e.g., "0x401000-0x401200")
        port: Specific Ghidra instance port (optional)
        
    Returns:
        Summary mode: {
            success: bool,
            mode: "summary",
            total_arrays: int,
            high_confidence_arrays: int,
            sections_analyzed: [str],
            top_arrays: [...],  // Top arrays by confidence
            confidence_distribution: {...},
            recommended_detail_ranges: [...],
            memory_sections: [...]
        }
        
        Detail mode: {
            success: bool,
            mode: "detail", 
            address_range: str,
            hash_arrays: [...],  // Full detail for specific range
            batch_info: {
                current_range: str,
                total_ranges_available: int,
                next_suggested_range: str
            }
        }
    """
    try:
        port = _get_instance_port(port)
        mode = mode.lower().strip()
        
        if mode not in ["summary", "detail"]:
            return {"success": False, "error": {"code": "INVALID_MODE", "message": "Mode must be 'summary' or 'detail'"}}
        
        # Validate confidence threshold
        min_confidence = max(0.0, min(1.0, float(min_confidence)))
        max_results = max(1, min(1000, int(max_results)))
        
        if mode == "summary":
            return _analyze_hash_arrays_summary(
                start_address, end_address, section_name, min_confidence, max_results, port
            )
        else:  # detail mode
            return _analyze_hash_arrays_detail(
                start_address, end_address, address_range, min_confidence, max_results, port
            )
        
    except Exception as e:
        return {"success": False, "error": {"code": "HASH_ARRAY_ANALYSIS_ERROR", "message": str(e)}}


def _analyze_hash_arrays_summary(
    start_address: Optional[str],
    end_address: Optional[str], 
    section_name: Optional[str],
    min_confidence: float,
    max_results: int,
    port: int
) -> dict:
    """Analyze memory for hash arrays in summary mode."""
    result = {
        "success": True,
        "mode": "summary",
        "total_arrays": 0,
        "high_confidence_arrays": 0,
        "sections_analyzed": [],
        "top_arrays": [],
        "confidence_distribution": {"high": 0, "medium": 0, "low": 0},
        "recommended_detail_ranges": [],
        "memory_sections": []
    }
    
    all_arrays = []
    
    # Get memory sections for analysis
    if section_name:
        sections_info = sections_list(port=port)
        if isinstance(sections_info, dict) and sections_info.get("success"):
            sections = sections_info.get("result", [])
            for section in sections:
                if isinstance(section, dict) and section.get("name") == section_name:
                    start_address = section.get("start")
                    end_address = section.get("end")
                    result["memory_sections"].append({
                        "name": section.get("name", ""),
                        "start": section.get("start", ""),
                        "end": section.get("end", ""),
                        "size": section.get("size", 0),
                        "permissions": section.get("permissions", "")
                    })
                    result["sections_analyzed"].append(section_name)
                    break
    
    if not start_address or not end_address:
        # Get memory sections for analysis
        sections_info = sections_list(port=port)
        if isinstance(sections_info, dict) and sections_info.get("success"):
            sections = sections_info.get("result", [])
            for section in sections:
                if isinstance(section, dict):
                    name = section.get("name", "")
                    # Focus on data sections that might contain hash arrays
                    if any(data_section in name.lower() for data_section in [".rdata", ".data", ".rodata"]):
                        result["memory_sections"].append({
                            "name": name,
                            "start": section.get("start", ""),
                            "end": section.get("end", ""),
                            "size": section.get("size", 0),
                            "permissions": section.get("permissions", "")
                        })
                        result["sections_analyzed"].append(name)
                        
                        # Analyze this section for hash arrays with limited depth in summary mode
                        section_start = section.get("start", "")
                        section_end = section.get("end", "")
                        if section_start and section_end:
                            try:
                                start_int = int(section_start.replace("0x", ""), 16)
                                end_int = int(section_end.replace("0x", ""), 16)
                                size = end_int - start_int
                                
                                # Only analyze reasonably sized sections (up to 64KB)
                                if size > 0 and size <= 65536:
                                    # In summary mode, analyze with stricter confidence and limited results
                                    hash_arrays = _find_hash_arrays_in_range_limited(
                                        section_start, section_end, port, min_confidence, 20  # Max 20 arrays per section
                                    )
                                    all_arrays.extend(hash_arrays)
                            except ValueError:
                                continue
    else:
        # Analyze specific range with limits in summary mode  
        hash_arrays = _find_hash_arrays_in_range_limited(start_address, end_address, port, min_confidence, 50)
        all_arrays.extend(hash_arrays)
    
    # Filter by confidence and sort
    filtered_arrays = [arr for arr in all_arrays if arr["confidence_score"] >= min_confidence]
    filtered_arrays.sort(key=lambda x: x["confidence_score"], reverse=True)
    
    # Generate summary statistics
    result["total_arrays"] = len(all_arrays)
    result["high_confidence_arrays"] = len(filtered_arrays)
    
    # Confidence distribution
    for arr in all_arrays:
        conf = arr["confidence_score"]
        if conf >= 0.8:
            result["confidence_distribution"]["high"] += 1
        elif conf >= 0.6:
            result["confidence_distribution"]["medium"] += 1
        else:
            result["confidence_distribution"]["low"] += 1
    
    # Top arrays (limited number for summary)
    top_count = min(10, len(filtered_arrays), max_results // 10)
    result["top_arrays"] = filtered_arrays[:top_count]
    
    # Generate recommended detail ranges based on high-value areas
    result["recommended_detail_ranges"] = _generate_detail_ranges(filtered_arrays[:20])  # Top 20 for recommendations
    
    # Summary message
    total_values = sum(len(arr["values"]) for arr in all_arrays)
    result["analysis_summary"] = (
        f"Summary: Found {len(all_arrays)} potential hash arrays "
        f"with {total_values} total values. "
        f"{len(filtered_arrays)} arrays meet confidence threshold (≥{min_confidence:.1f}). "
        f"Use detail mode on recommended ranges for full analysis."
    )
    
    return result


def _analyze_hash_arrays_detail(
    start_address: Optional[str],
    end_address: Optional[str],
    address_range: Optional[str],
    min_confidence: float,
    max_results: int,
    port: int
) -> dict:
    """Analyze memory for hash arrays in detail mode."""
    result = {
        "success": True,
        "mode": "detail",
        "address_range": "",
        "hash_arrays": [],
        "batch_info": {
            "current_range": "",
            "total_ranges_available": 0,
            "next_suggested_range": ""
        }
    }
    
    # Parse address range if provided
    if address_range:
        try:
            if "-" in address_range:
                start_addr, end_addr = address_range.split("-", 1)
                start_address = start_addr.strip()
                end_address = end_addr.strip()
                result["address_range"] = address_range
                result["batch_info"]["current_range"] = address_range
            else:
                return {"success": False, "error": {"code": "INVALID_RANGE", "message": "Address range must be in format '0x401000-0x401200'"}}
        except Exception:
            return {"success": False, "error": {"code": "INVALID_RANGE", "message": "Failed to parse address range"}}
    
    if not start_address or not end_address:
        return {"success": False, "error": {"code": "MISSING_RANGE", "message": "Detail mode requires start_address/end_address or address_range"}}
    
    # Analyze specific range with full detail
    hash_arrays = _find_hash_arrays_in_range(start_address, end_address, port)
    
    # Filter by confidence
    filtered_arrays = [arr for arr in hash_arrays if arr["confidence_score"] >= min_confidence]
    filtered_arrays.sort(key=lambda x: x["confidence_score"], reverse=True)
    
    # Apply max results limit
    result["hash_arrays"] = filtered_arrays[:max_results]
    
    # Generate batch info for navigation
    if address_range:
        result["batch_info"]["total_ranges_available"] = _estimate_available_ranges(start_address, end_address)
        result["batch_info"]["next_suggested_range"] = _suggest_next_range(start_address, end_address)
    
    return result


def _find_hash_arrays_in_range_limited(start_addr: str, end_addr: str, port: int, min_confidence: float, max_arrays: int) -> list:
    """Find hash arrays with limits for summary mode."""
    arrays = _find_hash_arrays_in_range(start_addr, end_addr, port)
    
    # Filter by confidence and limit count
    filtered = [arr for arr in arrays if arr["confidence_score"] >= min_confidence]
    filtered.sort(key=lambda x: x["confidence_score"], reverse=True)
    
    return filtered[:max_arrays]


def _generate_detail_ranges(top_arrays: list) -> list:
    """Generate recommended address ranges for detail analysis."""
    if not top_arrays:
        return []
    
    ranges = []
    for arr in top_arrays[:5]:  # Top 5 arrays
        start_addr = arr["start_address"]
        try:
            start_int = int(start_addr.replace("0x", ""), 16)
            # Create a range around this array (±512 bytes)
            range_start = max(0, start_int - 512)
            range_end = start_int + len(arr["values"]) * 4 + 512
            
            ranges.append({
                "address_range": f"0x{range_start:X}-0x{range_end:X}",
                "description": f"Around high-confidence array at {start_addr}",
                "confidence": arr["confidence_score"],
                "array_size": len(arr["values"])
            })
        except ValueError:
            continue
    
    return ranges


def _estimate_available_ranges(start_address: str, end_address: str) -> int:
    """Estimate number of available ranges for batching."""
    try:
        start_int = int(start_address.replace("0x", ""), 16)
        end_int = int(end_address.replace("0x", ""), 16)
        size = end_int - start_int
        
        # Estimate based on 1KB chunks
        return max(1, size // 1024)
    except ValueError:
        return 1


def _suggest_next_range(start_address: str, end_address: str) -> str:
    """Suggest next address range for continued analysis."""
    try:
        end_int = int(end_address.replace("0x", ""), 16)
        # Suggest next 1KB range
        next_start = end_int
        next_end = end_int + 1024
        
        return f"0x{next_start:X}-0x{next_end:X}"
    except ValueError:
        return ""


def _find_hash_arrays_in_range(start_addr: str, end_addr: str, port: int) -> list:
    """Helper function to find potential hash arrays in a memory range."""
    try:
        # Read memory in the specified range
        memory_data = memory_read_range(
            start_address=start_addr,
            end_address=end_addr,
            format="base64",
            port=port
        )
        
        if not (isinstance(memory_data, dict) and memory_data.get("success")):
            return []
        
        # Get the raw bytes from base64 format
        raw_b64 = memory_data.get("rawBytes")
        if not raw_b64:
            return []
        
        try:
            import base64 as _b64
            bytes_data = _b64.b64decode(raw_b64)
        except Exception:
            return []
        
        # Parse bytes as potential 32-bit values
        potential_arrays = []
        start_int = int(start_addr.replace("0x", ""), 16)
        
        # Process in 4-byte chunks (32-bit values)
        for i in range(0, len(bytes_data) - 3, 4):
            try:
                # Read as little-endian 32-bit value
                value = (bytes_data[i] | 
                        (bytes_data[i+1] << 8) |
                        (bytes_data[i+2] << 16) |
                        (bytes_data[i+3] << 24))
                
                # Skip obvious non-hash values
                if value == 0 or value == 0xFFFFFFFF:
                    continue
                
                # Look for sequences of plausible hash values
                if _is_plausible_hash_value(value):
                    # Start a new potential array
                    array_start = start_int + i
                    array_values = []
                    
                    # Collect consecutive values
                    j = i
                    while j < len(bytes_data) - 3:
                        val = (bytes_data[j] | 
                              (bytes_data[j+1] << 8) |
                              (bytes_data[j+2] << 16) |
                              (bytes_data[j+3] << 24))
                        
                        if not _is_plausible_hash_value(val):
                            break
                            
                        array_values.append({
                            "offset": j - i,
                            "value_hex": f"0x{val:08X}",
                            "value_dec": val,
                            "confidence": _calculate_hash_confidence(val)
                        })
                        
                        j += 4
                        
                        # Limit array size to reasonable bounds
                        if len(array_values) >= 100:
                            break
                    
                    # Only consider arrays with multiple values
                    if len(array_values) >= 2:
                        avg_confidence = sum(v["confidence"] for v in array_values) / len(array_values)
                        
                        potential_arrays.append({
                            "start_address": f"0x{array_start:X}",
                            "values": array_values,
                            "confidence_score": avg_confidence,
                            "analysis_notes": f"Found {len(array_values)} consecutive 32-bit values that could be API hashes"
                        })
                        
                        # Skip past this array to avoid overlaps
                        i = j - 4
                        
            except (IndexError, ValueError):
                continue
        
        return potential_arrays
        
    except Exception:
        return []


def _is_plausible_hash_value(value: int) -> bool:
    """Check if a 32-bit value could plausibly be an API hash."""
    # Basic heuristics for API hash detection
    if value == 0 or value == 0xFFFFFFFF:
        return False
    
    # API hashes are typically distributed across the full 32-bit range
    # but avoid values that are too small (likely indices) or too large (likely pointers in high memory)
    if value < 0x1000 or value > 0xF0000000:
        return False
    
    # Check for reasonable distribution of bits (not too many zeros or ones)
    bit_count = bin(value).count('1')
    if bit_count < 8 or bit_count > 24:
        return False
    
    return True


def _calculate_hash_confidence(value: int) -> float:
    """Calculate confidence that a value is an API hash."""
    confidence = 0.5  # Base confidence
    
    # Higher confidence for values in typical API hash ranges
    if 0x10000000 <= value <= 0xF0000000:
        confidence += 0.2
    
    # Good bit distribution increases confidence
    bit_count = bin(value).count('1')
    if 12 <= bit_count <= 20:
        confidence += 0.2
    
    # Values that look like CRC32 outputs (common for API hashing)
    if value & 0x80000000:  # High bit set is common in CRC32
        confidence += 0.1
    
    return min(confidence, 1.0)

@mcp.tool()
def functions_create(address: str, port: Optional[int] = None) -> dict:
    """Create a new function at the specified address
    
    Args:
        address: Memory address in hex format where function starts
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the created function information
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    # Preflight to avoid triggering Ghidra exceptions
    ok, reason = _addr_viable_for_function_create(port, address)
    if not ok:
        return {
            "success": False,
            "error": {"code": "CREATE_SKIPPED", "message": reason or "Address not viable for function creation"},
            "timestamp": int(time.time() * 1000)
        }

    payload = {"address": address}
    response = safe_post(port, "functions", payload)
    simplified = simplify_response(response)
    # Record failing addresses to backoff future attempts on this port
    if isinstance(simplified, dict) and not simplified.get("success", True):
        try:
            _port_failed_create_set(port).add(str(address).upper().replace("0X", "0x"))
        except Exception:
            pass
    return simplified

@mcp.tool()
def functions_rename(
    old_name: Optional[str] = None,
    name: Optional[str] = None,  # alias for old_name for broader compatibility
    address: Optional[str] = None,
    new_name: str = "",
    newName: Optional[str] = None,  # compatibility alias for camelCase callers
    port: Optional[int] = None,
) -> dict:
    """Rename a function
    
    Args:
        old_name: Current function name (mutually exclusive with address)
        name: Alias for old_name (accepted for compatibility)
        address: Function address in hex format (mutually exclusive with name)
        new_name: New function name
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the updated function information
    """
    # Back-compat: accept either new_name or newName
    if (not new_name) and newName:
        try:
            new_name = str(newName)
        except Exception:
            new_name = ""

    # Back-compat: accept `name` as an alias for `old_name`
    if (not old_name) and name:
        try:
            old_name = str(name)
        except Exception:
            old_name = None

    if not (old_name or address) or not new_name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either old_name or address, and new_name parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload = {
        "name": new_name
    }
    
    if address:
        endpoint = f"functions/{address}"
    elif old_name:
        endpoint = f"functions/by-name/{quote(old_name)}"
    else:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either old_name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    # Rename operations can be slower on large programs; perform a targeted retry on timeout
    retries = _env_int("GHIDRA_MCP_FUNCTIONS_RENAME_RETRIES", 1)  # number of retries upon timeout (default 1)
    backoff_ms = _env_int("GHIDRA_MCP_RETRY_BACKOFF_MS", 500)

    attempt = 0
    response = None
    while True:
        response = safe_patch(port, endpoint, payload)
        # If not a timeout, break
        if not (isinstance(response, dict) and (
            response.get("status_code") == 408 or (
                isinstance(response.get("error"), dict) and response.get("error", {}).get("code") == "REQUEST_TIMEOUT"
            ))):
            break
        if attempt >= retries:
            break
        attempt += 1
        try:
            time.sleep(max(0.0, backoff_ms / 1000.0))
        except Exception:
            pass

    return simplify_response(response)

@mcp.tool()
def functions_set_signature(name: Optional[str] = None, address: Optional[str] = None, signature: str = "", port: Optional[int] = None) -> dict:
    """Set function signature/prototype
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        signature: New function signature (e.g., "int func(char *data, int size)")
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the updated function information
    """
    if not (name or address) or not signature:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address, and signature parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload = {
        "signature": signature
    }
    
    if address:
        endpoint = f"functions/{address}"
    elif name:
        endpoint = f"functions/by-name/{quote(name)}"
    else:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    response = safe_patch(port, endpoint, payload)
    return simplify_response(response)

@mcp.tool()
def programs_list_imports(port: Optional[int] = None) -> dict:
    """List imported functions and modules from the current program.

    Returns: { success, items: [ { module, name, ordinal? } ] }
    Note: Requires plugin support for endpoint 'programs/current/imports'.
    """
    p = _get_instance_port(port)
    resp = safe_get(p, "programs/current/imports")
    return simplify_response(resp)

@mcp.tool()
def datatypes_create_enum(name: str, size_bits: int = 32, category: str = "/Auto", replace: bool = True, port: Optional[int] = None, force: bool = False) -> dict:
    """Create (or replace) an Enum DataType in the program DataTypeManager.

    Returns: { success, name, size_bits, category }
    Note: Requires plugin endpoint 'datatypes/enum/create'.
    """
    if not name:
        return {"success": False, "error": {"code": "MISSING_PARAMETER", "message": "name is required"}}
    p = _get_instance_port(port)

    # If not forcing, and the server lists enums and our target already exists, short-circuit as success
    if not force:
        try:
            existing = safe_get(p, "datatypes/enums")
            if isinstance(existing, dict) and existing.get("success") and isinstance(existing.get("result"), list):
                if any(str(e.get("name")) == name for e in existing.get("result") or []):
                    return {"success": True, "result": {"name": name, "present": True, "created": False}}
        except Exception:
            pass

    payload = {"name": name, "size_bits": int(size_bits), "category": category, "replace": bool(replace)}

    # Try known/likely routes in order
    routes = [
        ("POST", "datatypes/enum/create"),
        ("PUT", "datatypes/enum/create"),
        ("POST", f"datatypes/enums/{quote(name)}"),
        ("PUT", f"datatypes/enums/{quote(name)}"),
        ("POST", f"datatypes/enum/{quote(name)}"),
        ("PUT", f"datatypes/enum/{quote(name)}"),
        ("POST", "programs/current/datatypes/enum/create"),
        ("PUT", "programs/current/datatypes/enum/create"),
    ]

    last = None
    for method, path in routes:
        last = safe_post(p, path, payload) if method == "POST" else safe_put(p, path, payload)
        try:
            if isinstance(last, dict) and last.get("success"):
                return simplify_response(last)
            # Some servers reply with ENUM_EXISTS or similar but success=false; treat as present
            if isinstance(last, dict) and isinstance(last.get("error"), dict):
                code = str(last.get("error", {}).get("code"))
                if code and code.upper() in ("ENUM_EXISTS", "ALREADY_EXISTS"):
                    return {"success": True, "result": {"name": name, "present": True, "created": False}, "note": code}
        except Exception:
            pass

    return simplify_response(last if isinstance(last, dict) else {"success": False, "error": {"code": "NO_ENUM_ENDPOINT", "message": "No working enum create endpoint"}})

@mcp.tool()
def datatypes_add_enum_constants(enum_name: str, items: List[dict], port: Optional[int] = None) -> dict:
    """Add constants to an existing Enum DataType.

    items: [ { name: string, value: string|int } ]
    Note: Requires plugin endpoint 'datatypes/enum/constants'.
    """
    if not enum_name:
        return {"success": False, "error": {"code": "MISSING_PARAMETER", "message": "enum_name is required"}}
    if not isinstance(items, list) or not items:
        return {"success": False, "error": {"code": "MISSING_PARAMETER", "message": "items must be a non-empty list"}}
    p = _get_instance_port(port)
    payload = {"enum_name": enum_name, "items": items}

    # Try common endpoint shapes for adding constants
    routes = [
        ("POST", "datatypes/enum/constants", payload),
        ("POST", f"datatypes/enums/{quote(enum_name)}/constants", {"items": items}),
        ("POST", f"datatypes/enum/{quote(enum_name)}/constants", {"items": items}),
        ("PUT", f"datatypes/enums/{quote(enum_name)}/constants", {"items": items}),
    ]

    last = None
    for method, path, body in routes:
        last = safe_post(p, path, body) if method == "POST" else safe_put(p, path, body)
        try:
            if isinstance(last, dict) and last.get("success"):
                return simplify_response(last)
        except Exception:
            pass
    return simplify_response(last if isinstance(last, dict) else {"success": False, "error": {"code": "NO_ENUM_CONSTANTS_ENDPOINT", "message": "No working enum constants endpoint"}})

@mcp.tool()
def imports_apply_resolved_hashes(
    resolver_name: str,
    api_enum_name: str = "API_HASH_CRC32",
    module_enum_name: str = "MODULE_HASH_CRC32",
    mappings: Optional[List[dict]] = None,
    set_signature: bool = True,
    rename_resolver_to: Optional[str] = None,
    authoritative: bool = False,
    port: Optional[int] = None,
) -> dict:
    """Apply resolved API/module hashes into Ghidra so decompiler shows names.

    Creates/updates two Enum DataTypes with your resolved values and (optionally)
    updates the resolver's prototype to use these enums, so callsites like
    resolver_func(module_hash, api_hash) decompile as
    resolve_api_by_hash(MODULE_HASH_CRC32.module_name, API_HASH_CRC32.api_name).

    Args:
        resolver_name: Name or address of the hash resolver function (e.g., 'FUN_12345678')
        api_enum_name: Enum name for API-hash values (second argument)
        module_enum_name: Enum name for module-hash values (first argument)
        mappings: List of dict items describing resolved values. Accepted shapes:
            - { "type": "api", "value": "0x12345678", "name": "SomeAPIFunction" }
            - { "type": "module", "value": "0x87654321", "name": "somemodule.dll" }
            - { "hash": "0xABCDEF01", "api": "SomeFunction", "dll": "kernel32.dll" }  # type inferred
        set_signature: If true, set resolver signature to use these enums
        rename_resolver_to: If provided, rename resolver function to this name
        port: Specific Ghidra instance port

    Returns:
        dict: { success, api_enum, module_enum, signature_set, renamed }
    """
    p = _get_instance_port(port)

    def _u32(v: Any) -> Optional[int]:
        try:
            if v is None:
                return None
            if isinstance(v, int):
                return v & 0xFFFFFFFF
            s = str(v).strip()
            if s.lower().startswith("0x"):
                return int(s, 16) & 0xFFFFFFFF
            return int(s) & 0xFFFFFFFF
        except Exception:
            return None

    def _enum_label(name: str, kind: str) -> str:
        # Ghidra Enum labels must be valid identifiers. Keep API names as-is when safe; sanitize modules.
        try:
            s = str(name).strip()
            if kind == "module":
                # Normalize module names like 'iphlpapi.dll' -> 'IPHLPAPI_DLL'
                base = s.replace(".dll", "").replace(".DLL", "")
                s = re.sub(r"[^0-9A-Za-z_]", "_", base).upper()
                # Avoid double suffixing
                if not s.endswith("_DLL"):
                    s = s + "_DLL"
            else:
                # API names like 'CreateProcessW' -> keep, but replace invalids
                s = re.sub(r"[^0-9A-Za-z_]", "_", s)
                if not s:
                    s = "API_0"
            # Cannot start with digit
            if re.match(r"^[0-9]", s):
                s = f"_{s}"
            return s
        except Exception:
            return "UNKNOWN"

    # Normalize incoming mappings into two lists for enums
    apis: List[dict] = []
    modules: List[dict] = []
    if isinstance(mappings, list):
        for m in mappings:
            try:
                if not isinstance(m, dict):
                    continue
                # Support multiple shapes
                v = m.get("value") or m.get("hash") or m.get("hash_hex")
                h = _u32(v)
                if h is None:
                    continue
                # Determine kind and name
                if m.get("type") == "module" or (m.get("dll") and not m.get("api")):
                    nm = m.get("name") or m.get("dll")
                    if not nm:
                        continue
                    modules.append({"name": _enum_label(str(nm), "module"), "value": f"0x{h:08X}"})
                elif m.get("type") == "api" or m.get("api") or m.get("name"):
                    nm = m.get("name") or m.get("api")
                    if not nm:
                        continue
                    apis.append({"name": _enum_label(str(nm), "api"), "value": f"0x{h:08X}"})
                # If both api and dll present, push both
                if m.get("api") and m.get("dll"):
                    modules.append({"name": _enum_label(str(m.get("dll")), "module"), "value": f"0x{h:08X}"})
            except Exception:
                continue

    # Create/ensure enums exist (best-effort; some servers may not expose these endpoints)
    # Resolve target enum names to existing ones if similar enums are already present.
    def _resolve_enum_targets(p: int, api_name: str, mod_name: str) -> Tuple[str, str, dict]:
        chosen_api = api_name
        chosen_mod = mod_name
        existing_map = {"api": None, "module": None}
        try:
            lst = safe_get(p, "datatypes/enums")
            if isinstance(lst, dict) and lst.get("success") and isinstance(lst.get("result"), list):
                names = [str(e.get("name")) for e in lst.get("result") or [] if isinstance(e, dict) and e.get("name")]
                # Prefer exact matches; else fallback to common historical names
                if api_name not in names:
                    for cand in ("API_HASH", "API_HASH_CRC32", api_name.upper(), api_name):
                        if cand in names:
                            chosen_api = cand
                            existing_map["api"] = cand
                            break
                else:
                    existing_map["api"] = api_name
                if mod_name not in names:
                    for cand in ("MODULE_HASH", "MODULE_HASH_CRC32", mod_name.upper(), mod_name):
                        if cand in names:
                            chosen_mod = cand
                            existing_map["module"] = cand
                            break
                else:
                    existing_map["module"] = mod_name
        except Exception:
            pass
        return chosen_api, chosen_mod, existing_map  # existing_map values may be None if not found

    api_enum_name_eff, module_enum_name_eff, existing_enums = _resolve_enum_targets(p, api_enum_name, module_enum_name)

    created = {"api": False, "module": False}
    enums_supported = True
    # Authoritative mode will recreate enums (replace=True, force=True) to purge stale/wrong labels
    api_enum_result = datatypes_create_enum(
        api_enum_name_eff,
        size_bits=32,
        category="/Auto",
        replace=True if authoritative else False,
        port=p,
        force=authoritative,
    )
    if not (isinstance(api_enum_result, dict) and api_enum_result.get("success")):
        enums_supported = False
    else:
        created["api"] = True
    module_enum_result = datatypes_create_enum(
        module_enum_name_eff,
        size_bits=32,
        category="/Auto",
        replace=True if authoritative else False,
        port=p,
        force=authoritative,
    )
    if not (isinstance(module_enum_result, dict) and module_enum_result.get("success")):
        enums_supported = False
    else:
        created["module"] = True

    # Add constants (batch in chunks to avoid payload bloat)
    def _chunk(lst: List[dict], n: int = 128):
        for i in range(0, len(lst), n):
            yield lst[i:i+n]

    api_added = 0
    mod_added = 0
    if enums_supported:
        if apis:
            for chunk in _chunk(apis, 256):
                _ = datatypes_add_enum_constants(api_enum_name_eff, chunk, port=p)
        if modules:
            for chunk in _chunk(modules, 256):
                _ = datatypes_add_enum_constants(module_enum_name_eff, chunk, port=p)
        # Read-back verification: count actually persisted enum members matching what we sent
        try:
            api_info = safe_get(p, f"datatypes/enums/{api_enum_name_eff}")
            if isinstance(api_info, dict) and api_info.get("success"):
                res = api_info.get("result") or {}
                members = res.get("members") or {}
                if isinstance(members, dict):
                    wanted = {it["name"] for it in apis if isinstance(it, dict) and it.get("name")}
                    api_added = sum(1 for k in members.keys() if k in wanted)
        except Exception:
            api_added = 0
        try:
            mod_info = safe_get(p, f"datatypes/enums/{module_enum_name_eff}")
            if isinstance(mod_info, dict) and mod_info.get("success"):
                res = mod_info.get("result") or {}
                members = res.get("members") or {}
                if isinstance(members, dict):
                    wanted = {it["name"] for it in modules if isinstance(it, dict) and it.get("name")}
                    mod_added = sum(1 for k in members.keys() if k in wanted)
        except Exception:
            mod_added = 0

    # Optionally set resolver signature to use these enums
    signature_set = False
    if set_signature and enums_supported:
        # Allow resolver_name to be an address (0x...), otherwise treat as name
        try:
            is_addr = False
            rn = str(resolver_name).strip()
            if rn.lower().startswith("0x"):
                int(rn, 16)
                is_addr = True
        except Exception:
            is_addr = False
        # Resolve address for name when possible to prefer address-based update
        target_addr_for_sig: Optional[str] = None
        if not is_addr:
            try:
                info_for_sig = functions_get(name=rn, port=p)
                if isinstance(info_for_sig, dict) and info_for_sig.get("success"):
                    r_obj = info_for_sig.get("result") or {}
                    a = r_obj.get("address") or r_obj.get("entry")
                    if isinstance(a, str) and a:
                        target_addr_for_sig = a
            except Exception:
                target_addr_for_sig = None

        # Use enums by name as parameter types; Ghidra will resolve to DataTypeManager enums
        sig = f"void * {resolver_name}( {module_enum_name_eff} moduleHash, {api_enum_name_eff} apiHash )"
        # Proceed if enums have members already (even if we didn't add any this run)
        has_any_members = False
        if (api_added > 0) or (mod_added > 0):
            has_any_members = True
        else:
            try:
                chk_api = safe_get(p, f"datatypes/enums/{api_enum_name_eff}")
                chk_mod = safe_get(p, f"datatypes/enums/{module_enum_name_eff}")
                for chk in (chk_api, chk_mod):
                    if isinstance(chk, dict) and chk.get("success"):
                        mem = (chk.get("result") or {}).get("members") or {}
                        if isinstance(mem, dict) and len(mem) > 0:
                            has_any_members = True
                            break
            except Exception:
                pass
        if has_any_members:
            # Prefer address-based signature update for robustness
            res = functions_set_signature(address=(rn if is_addr else (target_addr_for_sig or None)), name=(None if (is_addr or target_addr_for_sig) else rn), signature=sig, port=p)
            if isinstance(res, dict) and res.get("success"):
                signature_set = True

    # Optionally rename resolver
    renamed = False
    if rename_resolver_to:
        # Tighten renaming: validate target, avoid no-op, avoid collisions, sanitize name
        def _sanitize_name(n: str) -> str:
            n = re.sub(r"[^0-9A-Za-z_]", "_", str(n).strip())
            if not n:
                n = "renamed"
            if re.match(r"^[0-9]", n):
                n = f"_{n}"
            return n

        new_name_target = _sanitize_name(str(rename_resolver_to))

        # Resolve resolver function info (by addr or name)
        try:
            rn = str(resolver_name).strip()
            is_addr = rn.lower().startswith("0x")
        except Exception:
            is_addr = False

        resolver_info = functions_get(address=rn if is_addr else None, name=None if is_addr else rn, port=p)
        current_name = None
        resolver_addr = None
        if isinstance(resolver_info, dict) and resolver_info.get("success"):
            res_obj = resolver_info.get("result") or {}
            current_name = res_obj.get("name") or None
            resolver_addr = res_obj.get("address") or None

        # Skip if current name matches
        if current_name and str(current_name) == new_name_target:
            renamed = True  # already desired
        else:
            # Check for name collision; if another function already has the new name, generate a unique suffix
            def _name_taken(n: str) -> bool:
                info = functions_get(name=n, port=p)
                if isinstance(info, dict) and info.get("success"):
                    f = info.get("result") or {}
                    if resolver_addr and f.get("address") and str(f.get("address")) == str(resolver_addr):
                        return False
                    return True
                return False

            candidate = new_name_target
            if _name_taken(candidate):
                for i in range(1, 6):
                    alt = f"{new_name_target}_{i}"
                    if not _name_taken(alt):
                        candidate = alt
                        break

            # Prefer address-based rename when address is known
            if resolver_addr and isinstance(resolver_addr, str) and resolver_addr:
                r = functions_rename(address=resolver_addr, old_name=None, new_name=candidate, port=p)
            else:
                r = functions_rename(address=rn if is_addr else None, old_name=None if is_addr else rn, new_name=candidate, port=p)
            if isinstance(r, dict) and r.get("success"):
                renamed = True

    out = {
        "success": True,
        "api_enum": {"name": api_enum_name_eff, "created": created["api"], "constants_added": api_added},
        "module_enum": {"name": module_enum_name_eff, "created": created["module"], "constants_added": mod_added},
        "signature_set": signature_set,
        "renamed": renamed,
        "resolver": resolver_name,
        "port": p,
    }
    if not enums_supported:
        out.setdefault("warnings", []).append("Enum endpoints not supported; skipped enum creation and signature update.")
    # If endpoints exist but members didn't persist, surface a clear warning
    if enums_supported and (api_added == 0 and mod_added == 0) and (apis or modules):
        out.setdefault("warnings", []).append(
            "Enum constants appear not persisted (members empty after add). Server must implement datatypes/enums/{name}/constants to add members within a transaction and return members on GET."
        )
    return out

# Common Windows modules for bulk hash preloading
# Focused set of modules most frequently used by malware (reduces from ~30K to ~10K APIs)
DEFAULT_PRELOAD_MODULES = [
    # Core Windows APIs (essential for any malware)
    "kernel32.dll",    # ~1,500 APIs - Process, thread, memory, file I/O
    "ntdll.dll",       # ~2,000 APIs - Native API layer, system calls
    
    # Network & Communication (C2, data exfiltration)
    "ws2_32.dll",      # ~100 APIs - Windows Sockets (networking)
    "wininet.dll",     # ~200 APIs - Internet/HTTP APIs
    "winhttp.dll",     # ~80 APIs - HTTP client APIs
    
    # Crypto & Security (encryption, credential theft)
    "advapi32.dll",    # ~600 APIs - Registry, services, crypto
    "crypt32.dll",     # ~200 APIs - Cryptography APIs
    "bcrypt.dll",      # ~50 APIs - Next-gen crypto APIs
    
    # User Interface & Shell (persistence, user interaction)
    "user32.dll",      # ~800 APIs - Windows, messages, input
    "shell32.dll",     # ~300 APIs - Shell operations, file associations
]


def _fetch_module_api_hashes(
    module_name: str,
    algorithm: str = "crc32",
    xor_key: Optional[str] = None,
    base_url: str = "https://hashdb.openanalysis.net"
) -> List[dict]:
    """Fetch all API hashes for a given module from HashDB.
    
    Args:
        module_name: Module name (e.g., "kernel32.dll")
        algorithm: Hash algorithm (e.g., "crc32")
        xor_key: Optional XOR key for hash encoding
        base_url: HashDB base URL
        
    Returns:
        List of dicts with 'api' and 'hash' keys
    """
    try:
        import json as _json
        from urllib.request import urlopen, Request
        
        # Normalize module name - remove extension for HashDB API
        module = module_name.strip().lower()
        if module.endswith('.dll'):
            module = module[:-4]
        elif module.endswith('.sys'):
            module = module[:-4]
        elif module.endswith('.drv'):
            module = module[:-4]
        
        # HashDB module API endpoint: /module/{module_name}/{algorithm}/api
        url = f"{base_url.rstrip('/')}/module/{module}/{algorithm.strip().lower()}/api"
        
        req = Request(url, headers={"User-Agent": "ghydra-bridge/1.0"})
        
        with urlopen(req, timeout=30) as resp:  # nosec B310
            data = resp.read()
            payload = _json.loads(data.decode("utf-8", errors="ignore"))
        
        results = []
        
        # Parse HashDB response format: { "hashes": [ { "hash": int, "string": { "api": "...", ... } } ] }
        if isinstance(payload, dict):
            hashes_list = payload.get("hashes", [])
            
            if isinstance(hashes_list, list):
                for item in hashes_list:
                    if isinstance(item, dict):
                        hash_value = item.get("hash")
                        string_obj = item.get("string")
                        
                        api_name = None
                        if isinstance(string_obj, dict):
                            # Prefer "api" field, fallback to "string" field
                            api_name = string_obj.get("api") or string_obj.get("string")
                        
                        if api_name and hash_value is not None:
                            # Apply XOR key if provided
                            if xor_key is not None and str(xor_key).strip() != "":
                                try:
                                    # Coerce hash to u32
                                    if isinstance(hash_value, str):
                                        hash_int = int(hash_value.replace("0x", ""), 16)
                                    else:
                                        hash_int = int(hash_value)
                                    
                                    # Coerce XOR key to u32
                                    key_str = str(xor_key).strip().lower()
                                    if key_str.startswith("-0x"):
                                        key_int = (-int(key_str[3:], 16)) & 0xFFFFFFFF
                                    elif key_str.startswith("0x"):
                                        key_int = int(key_str, 16) & 0xFFFFFFFF
                                    else:
                                        key_int = int(key_str, 10) & 0xFFFFFFFF
                                    
                                    # XOR and format
                                    xored = (hash_int ^ key_int) & 0xFFFFFFFF
                                    hash_value = f"0x{xored:08X}"
                                except Exception:
                                    pass
                            
                            # Normalize hash format
                            if isinstance(hash_value, int):
                                hash_value = f"0x{hash_value:08X}"
                            elif isinstance(hash_value, str) and not hash_value.startswith("0x"):
                                try:
                                    hash_value = f"0x{int(hash_value):08X}"
                                except Exception:
                                    pass
                            
                            results.append({
                                "api": str(api_name).strip(),
                                "hash": hash_value
                            })
        
        return results
        
    except Exception as e:
        # Return empty list on failure - caller will handle gracefully
        return []


@mcp.tool()
def imports_apply_from_hashdb(
    function_name: str,
    callee_name: str,
    algorithm: str = "crc32",
    xor_key: Optional[str] = None,
    api_enum_name: str = "API_HASH_CRC32",
    module_enum_name: str = "MODULE_HASH_CRC32",
    rename_resolver_to: Optional[str] = None,
    authoritative: bool = False,
    preload_modules: Optional[List[str]] = None,
    enable_bulk_preload: bool = False,
    port: Optional[int] = None,
) -> dict:
    """Resolve hashed module/API args in a function using HashDB and apply labels directly.

    Args:
        function_name: Name or address of the function that calls the resolver (e.g., "FUN_12345678")
        callee_name: Name or address of the hash resolver function (e.g., "FUN_87654321")
        algorithm: Hash algorithm to use for lookups (default: "crc32")
        xor_key: Optional XOR key for hash decoding (e.g., "0x12345678")
        api_enum_name: Name for the API hash enum (default: "API_HASH_CRC32")
        module_enum_name: Name for the module hash enum (default: "MODULE_HASH_CRC32")
        rename_resolver_to: Optional new name for the resolver function (e.g., "resolve_api_by_hash")
        authoritative: Whether to replace existing enum entries (default: False, preserves existing correct values)
        preload_modules: List of module names to bulk-preload API hashes for (e.g., ["kernel32.dll", "ntdll.dll"])
        enable_bulk_preload: Enable automatic bulk preloading of common Windows modules (default: False)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Summary with counts, preloaded APIs, and any warnings

    Notes:
        - This tool extracts immediate args passed to the specified callee within function_name
        - Queries OALabs HashDB live for names (algorithm default crc32, optional xor)
        - Builds mappings and applies them via imports_apply_resolved_hashes
        - Works with any binary - no hard-coded function names or addresses
        
        Bulk Preloading:
        - When enable_bulk_preload=True or preload_modules is provided, fetches ALL API hashes
          for specified modules from HashDB and creates enum entries for them
        - This allows the decompiler to show meaningful names even for APIs not yet observed
          in the analyzed function
        - Preloaded hashes are merged with observed hashes from the binary
        - Use this when you've identified the correct algorithm and XOR key to populate
          comprehensive API mappings across common Windows modules
    """
    p = _get_instance_port(port)

    # 1) Harvest immediate args at callsites
    calls = functions_list_call_args(name=function_name, callee=callee_name, port=p)
    if not (isinstance(calls, dict) and calls.get("success")):
        return calls if isinstance(calls, dict) else {"success": False, "error": {"code": "CALL_ARGS", "message": "failed to harvest call args"}}
    mods_set, apis_set = set(), set()
    for c in calls.get("calls", []) or []:
        for a in c.get("args", []) or []:
            try:
                if int(a.get("idx", -1)) == 0 and a.get("value_hex"):
                    mods_set.add(a["value_hex"])
                if int(a.get("idx", -1)) == 1 and a.get("value_hex"):
                    apis_set.add(a["value_hex"])
            except Exception:
                continue

    # 1.5) Bulk preload API hashes for specified modules
    preloaded_apis = {}
    preloaded_modules = {}
    preload_stats = {
        "enabled": False,
        "modules_requested": 0,
        "modules_successful": 0,
        "total_apis_fetched": 0,
        "failed_modules": []
    }
    
    if enable_bulk_preload or preload_modules:
        preload_stats["enabled"] = True
        
        # Determine which modules to preload
        modules_to_preload = []
        if preload_modules:
            modules_to_preload = preload_modules
        elif enable_bulk_preload:
            modules_to_preload = DEFAULT_PRELOAD_MODULES
        
        preload_stats["modules_requested"] = len(modules_to_preload)
        
        # Fetch API hashes for each module
        base_url = "https://hashdb.openanalysis.net"
        for module in modules_to_preload:
            try:
                api_hashes = _fetch_module_api_hashes(
                    module_name=module,
                    algorithm=algorithm,
                    xor_key=xor_key,
                    base_url=base_url
                )
                
                if api_hashes:
                    preload_stats["modules_successful"] += 1
                    preload_stats["total_apis_fetched"] += len(api_hashes)
                    
                    # Store preloaded APIs indexed by hash
                    for item in api_hashes:
                        hash_val = item["hash"]
                        api_name = item["api"]
                        preloaded_apis[hash_val] = api_name
                    
                    # Compute module hash using the same convention as HashDB
                    # HashDB stores modules as uppercase with extension (e.g., "KERNEL32.DLL")
                    module_hash = None
                    try:
                        import zlib
                        # Normalize module name to uppercase with extension (HashDB convention)
                        module_upper = module.upper()
                        if not module_upper.endswith('.DLL') and not module_upper.endswith('.SYS') and not module_upper.endswith('.DRV'):
                            module_upper = module_upper + '.DLL'
                        
                        if algorithm.lower() == "crc32":
                            # Compute CRC32 (this is the POST-XOR / "clean" hash)
                            crc_val = zlib.crc32(module_upper.encode()) & 0xFFFFFFFF
                            
                            # DEBUG: Log before XOR to STDERR (not stdout - would break MCP JSON-RPC)
                            print(f"DEBUG: Module={module_upper}, CRC32=0x{crc_val:08X}, xor_key={repr(xor_key)}", file=sys.stderr)
                            
                            # Apply XOR key to convert to PRE-XOR (observed binary value)
                            # This is REQUIRED - we must store the value as it appears in the binary
                            if xor_key and str(xor_key).strip():
                                key_str = str(xor_key).strip().lower()
                                if key_str.startswith("-0x"):
                                    key_int = (-int(key_str[3:], 16)) & 0xFFFFFFFF
                                elif key_str.startswith("0x"):
                                    key_int = int(key_str, 16) & 0xFFFFFFFF
                                else:
                                    key_int = int(key_str, 10) & 0xFFFFFFFF
                                crc_val = (crc_val ^ key_int) & 0xFFFFFFFF
                                print(f"DEBUG: After XOR with 0x{key_int:08X}: module_hash=0x{crc_val:08X}", file=sys.stderr)
                            else:
                                print(f"DEBUG: XOR key check FAILED - xor_key={repr(xor_key)}, truthy={bool(xor_key)}, stripped={repr(str(xor_key).strip() if xor_key else None)}", file=sys.stderr)
                            
                            module_hash = f"0x{crc_val:08X}"
                    except Exception as e:
                        # Don't silently fail - log the error
                        import traceback
                        traceback.print_exc()
                        pass
                    
                    if module_hash:
                        preloaded_modules[module_hash] = module
                else:
                    preload_stats["failed_modules"].append(module)
                    
            except Exception as e:
                preload_stats["failed_modules"].append(f"{module} ({str(e)})")
                continue

    # Helper: HTTP GET JSON with stdlib (avoid adding hard deps here)
    def _http_get_json(url: str) -> dict:
        try:
            import json as _json
            from urllib.request import urlopen, Request  # type: ignore
            req = Request(url, headers={"User-Agent": "ghydra-bridge/1.0"})
            with urlopen(req, timeout=20) as resp:  # nosec B310
                data = resp.read()
                try:
                    return _json.loads(data.decode("utf-8", errors="ignore"))
                except Exception:
                    return {"status": getattr(resp, "status", None), "text": data[:512].decode("utf-8", errors="ignore")}
        except Exception as e:
            return {"error": str(e)}

    # Normalize value (hex or dec) -> unsigned 32-bit dec
    def _coerce_u32(v: str) -> int:
        s = str(v).strip().lower()
        if s.startswith("-0x"):
            return ((-int(s[3:], 16)) & 0xFFFFFFFF)
        if s.startswith("0x"):
            return (int(s, 16) & 0xFFFFFFFF)
        try:
            # bare hex if any a-f
            if any(c in s for c in "abcdef"):
                return (int(s, 16) & 0xFFFFFFFF)
            return (int(s, 10) & 0xFFFFFFFF)
        except Exception:
            return 0

    # 2) Query HashDB per value (algorithm default crc32; xor adjustment optional)
    base = "https://hashdb.openanalysis.net".rstrip("/")
    def _lookup_one(value_hex: str) -> list:
        dec = _coerce_u32(value_hex)
        if xor_key is not None and str(xor_key).strip() != "":
            try:
                key_dec = _coerce_u32(str(xor_key))
                dec = (dec ^ key_dec) & 0xFFFFFFFF
            except Exception:
                pass
        url = f"{base}/hash/{algorithm.strip().lower()}/{dec}"
        payload = _http_get_json(url)
        out = []
        if isinstance(payload, dict):
            # Enhanced parsing for multiple HashDB response formats
            
            # Shape A: { results: [ { string, module?, type? } ] }
            res = payload.get("results") or payload.get("result")
            if isinstance(res, list):
                for it in res:
                    if isinstance(it, dict):
                        # Try multiple field names for the string value
                        s = (it.get("string") or it.get("name") or it.get("value") or 
                             it.get("text") or it.get("api") or it.get("function"))
                        if isinstance(s, dict):
                            s = (s.get("string") or s.get("name") or s.get("value") or 
                                s.get("text") or s.get("api") or s.get("function"))
                        if isinstance(s, str) and s.strip():
                            out.append(s.strip())
                    elif isinstance(it, str) and it.strip():
                        # Direct string values
                        out.append(it.strip())
            
            # Shape B: { hashes: [ { hash, string: { string } } ] }
            hashes = payload.get("hashes")
            if isinstance(hashes, list):
                for h in hashes:
                    if isinstance(h, dict):
                        s = h.get("string")
                        if isinstance(s, dict):
                            sval = (s.get("string") or s.get("name") or s.get("value") or 
                                   s.get("text") or s.get("api") or s.get("function"))
                            if isinstance(sval, str) and sval.strip():
                                out.append(sval.strip())
                        elif isinstance(s, str) and s.strip():
                            out.append(s.strip())
            
            # Shape C: Direct array of strings
            if isinstance(payload.get("data"), list):
                for item in payload["data"]:
                    if isinstance(item, str) and item.strip():
                        out.append(item.strip())
                    elif isinstance(item, dict):
                        name_val = (item.get("name") or item.get("string") or 
                                   item.get("value") or item.get("api"))
                        if isinstance(name_val, str) and name_val.strip():
                            out.append(name_val.strip())
            
            # Shape D: Single string result
            if isinstance(payload.get("name"), str) and payload["name"].strip():
                out.append(payload["name"].strip())
            
            # Shape E: Legacy format with string field at top level
            if isinstance(payload.get("string"), str) and payload["string"].strip():
                out.append(payload["string"].strip())
        
        # Dedup preserving order and filter out empty strings
        seen = set()
        dedup = []
        for s in out:
            if s and s not in seen:
                seen.add(s)
                dedup.append(s)
        return dedup

    # Build mappings from candidates (simple preferences; use HashDB top hit if unambiguous)
    mappings = []
    def _norm_module_name(s: str) -> str:
        x = s.strip()
        if not x:
            return x
        # If missing extension and looks like module base, add .dll
        if "." not in x:
            x = x + ".dll"
        return x

    # Modules first arg
    for mv in sorted(mods_set):
        # Always look up observed module hashes in HashDB
        # (Preloaded modules are added separately later)
        candidates = _lookup_one(mv)
        choice = None
        
        # Enhanced module selection logic
        if candidates:
            # Strategy 1: Look for obvious DLL names
            dll_candidates = [c for c in candidates if isinstance(c, str) and c.lower().endswith('.dll')]
            if dll_candidates:
                choice = _norm_module_name(dll_candidates[0])
            
            # Strategy 2: Look for module base names, avoiding API-like names
            elif not choice:
                for c in candidates:
                    if isinstance(c, str) and c and c.isalpha() and 3 <= len(c) <= 16:
                        # Avoid names that look like APIs (usually have mixed case or start with uppercase)
                        if (not c[0].isupper() or  # Lowercase start is likely module
                            c.lower() in ['kernel32', 'ntdll', 'user32', 'advapi32', 'shell32', 'ole32', 'oleaut32', 'ws2_32', 'iphlpapi', 'wininet', 'crypt32']):
                            choice = _norm_module_name(c)
                            break
            
            # Strategy 3: Look for any reasonable string that could be a module
            if not choice:
                for c in candidates:
                    if isinstance(c, str) and c and len(c) >= 3:
                        # Clean the string and check if it's reasonable
                        clean = c.strip().lower()
                        # Prefer shorter names without mixed case (modules are usually simple)
                        if (len(clean) <= 12 and  # Short names are more likely modules
                            not any(char.isupper() for char in c[1:]) and  # No internal uppercase
                            not any(char in c for char in ['(', ')', '[', ']']) and  # No brackets
                            c.count('_') <= 1):  # At most one underscore
                            choice = _norm_module_name(c)
                            break
            
            # Strategy 4: Fallback to shortest candidate (modules are usually shorter)
            if not choice and candidates:
                shortest = min(candidates, key=len)
                choice = _norm_module_name(shortest)
        
        if choice:
            mappings.append({"type": "module", "value": mv, "name": choice})

    # APIs second arg
    for av in sorted(apis_set):
        # Check preloaded APIs first
        if av in preloaded_apis:
            choice = preloaded_apis[av]
            mappings.append({"type": "api", "value": av, "name": choice})
            continue
        
        candidates = _lookup_one(av)
        choice = None
        
        # Enhanced API selection logic with multiple strategies
        if candidates:
            # Strategy 1: Look for typical WinAPI function names (starts with letter, contains alphanumeric)
            winapi_candidates = []
            for c in candidates:
                if isinstance(c, str) and c and c[0].isalpha() and c.replace('_', '').replace('A', '').replace('W', '').isalnum():
                    winapi_candidates.append(c)
            
            # Strategy 2: Prefer W variant over A variant if both exist
            if winapi_candidates:
                # Check for W/A pairs and prefer W
                w_candidates = [c for c in winapi_candidates if c.endswith('W')]
                a_candidates = [c for c in winapi_candidates if c.endswith('A')]
                
                # If we have W variants, prefer those
                if w_candidates:
                    choice = w_candidates[0]
                # Otherwise use any WinAPI candidate
                elif winapi_candidates:
                    choice = winapi_candidates[0]
            
            # Strategy 3: Look for any string that looks like a function name (less strict)
            if choice is None:
                for c in candidates:
                    if isinstance(c, str) and c and len(c) >= 3:
                        # Accept names that are mostly alphanumeric (allowing some symbols)
                        clean_name = ''.join(ch for ch in c if ch.isalnum() or ch in '_-')
                        if len(clean_name) >= len(c) * 0.8:  # 80% alphanumeric
                            choice = c
                            break
            
            # Strategy 4: Fallback to first valid string candidate
            if choice is None:
                for c in candidates:
                    if isinstance(c, str) and c.strip():
                        choice = c.strip()
                        break
        
        if choice:
            mappings.append({"type": "api", "value": av, "name": choice})

    # Add all preloaded APIs and modules that weren't observed in the binary
    # (This populates the enums with comprehensive API/module coverage)
    # Normalize both sets to lowercase for case-insensitive comparison
    apis_set_lower = {str(v).lower() for v in apis_set}
    mods_set_lower = {str(v).lower() for v in mods_set}
    
    for hash_val, api_name in preloaded_apis.items():
        # Skip if already added from observed values (case-insensitive comparison)
        if str(hash_val).lower() not in apis_set_lower:
            mappings.append({"type": "api", "value": hash_val, "name": api_name})
    
    # Add all preloaded modules that weren't observed
    # Module hashes are computed using HashDB convention: uppercase with extension (e.g., "KERNEL32.DLL")
    for hash_val, module_name in preloaded_modules.items():
        # Skip if already added from observed values (case-insensitive comparison)
        if str(hash_val).lower() not in mods_set_lower:
            mappings.append({"type": "module", "value": hash_val, "name": module_name})

    if not mappings:
        # Enhanced error reporting to help diagnose resolution failures
        debug_info = {
            "modules_found": len(mods_set),
            "apis_found": len(apis_set),
            "modules_observed": sorted(list(mods_set)),
            "apis_observed": sorted(list(apis_set))
        }
        
        # Test a few lookups to see what HashDB is returning
        sample_lookups = {}
        test_values = list(mods_set)[:2] + list(apis_set)[:2]  # Test first 2 of each
        for val in test_values:
            try:
                candidates = _lookup_one(val)
                sample_lookups[val] = {
                    "candidates_count": len(candidates),
                    "candidates": candidates[:5] if candidates else [],  # First 5
                    "url_tested": f"{base}/hash/{algorithm.strip().lower()}/{_coerce_u32(val)}"
                }
            except Exception as e:
                sample_lookups[val] = {"error": str(e)}
        
        debug_info["sample_lookups"] = sample_lookups
        
        return {
            "success": False, 
            "error": {
                "code": "NO_MAPPINGS", 
                "message": "No resolvable values from HashDB - check if hashes are in database or XOR key is correct"
            }, 
            "calls": calls,
            "debug": debug_info
        }

    # 3) Apply into enums and set resolver prototype
    apply_res = imports_apply_resolved_hashes(
        resolver_name=callee_name,
        api_enum_name=api_enum_name,
        module_enum_name=module_enum_name,
        mappings=mappings,
        set_signature=True,
        rename_resolver_to=rename_resolver_to,
        authoritative=authoritative,
        port=p,
    )
    out = {
        "success": True, 
        "applied": apply_res, 
        "observed": {
            "modules": sorted(list(mods_set)), 
            "apis": sorted(list(apis_set))
        },
        "mappings_created": {
            "total": len(mappings),
            "modules": len([m for m in mappings if m.get("type") == "module"]),
            "apis": len([m for m in mappings if m.get("type") == "api"]),
            "observed_modules": len([m for m in mappings if m.get("type") == "module" and m.get("value") in mods_set]),
            "observed_apis": len([m for m in mappings if m.get("type") == "api" and m.get("value") in apis_set]),
            "preloaded_modules": len([m for m in mappings if m.get("type") == "module" and m.get("value") not in mods_set]),
            "preloaded_apis": len([m for m in mappings if m.get("type") == "api" and m.get("value") not in apis_set]),
            "details": mappings
        },
        "preload_stats": preload_stats
    }
    # If any obvious mismatch (e.g., empty members), surface warning
    if isinstance(apply_res, dict) and apply_res.get("warnings"):
        out["warnings"] = apply_res["warnings"]
    
    # Add summary message about preloading
    if preload_stats["enabled"]:
        summary_parts = []
        if preload_stats["modules_successful"] > 0:
            summary_parts.append(
                f"Successfully preloaded {preload_stats['total_apis_fetched']} API hashes "
                f"from {preload_stats['modules_successful']}/{preload_stats['modules_requested']} modules"
            )
        if preload_stats["failed_modules"]:
            summary_parts.append(f"Failed to load: {', '.join(preload_stats['failed_modules'][:3])}")
        
        if summary_parts:
            out.setdefault("info", []).extend(summary_parts)
    
    return out

@mcp.tool()
def functions_get_variables(name: Optional[str] = None, address: Optional[str] = None, port: Optional[int] = None) -> dict:
    """Get variables for a function
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Contains function information and list of variables
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    if address:
        endpoint = f"functions/{address}/variables"
    elif name:
        endpoint = f"functions/by-name/{quote(name)}/variables"
    else:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    response = safe_get(port, endpoint)
    return simplify_response(response)

@mcp.tool()
def functions_detect_xor_constants(
    name: Optional[str] = None, 
    address: Optional[str] = None,
    min_constant_size: int = 3,  # Reduced from 4 to catch 24+ bit constants
    port: Optional[int] = None
) -> dict:
    """Detect XOR constants in decompiled function code for obfuscation analysis.
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        min_constant_size: Minimum size in bytes for constants (default: 4)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: {
            success: bool,
            xor_constants: [
                {
                    constant_hex: str,
                    constant_dec: int,
                    context: str,
                    confidence: float,
                    line_number: int,
                    operation_type: str
                }
            ],
            patterns_found: int
        }
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    # Get decompiled code first
    dec_result = functions_decompile(name=name, address=address, port=port)
    if not (isinstance(dec_result, dict) and dec_result.get("success")):
        return {
            "success": False,
            "error": {
                "code": "DECOMPILE_FAILED",
                "message": "Could not decompile function for XOR analysis"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    try:
        result = dec_result.get("result", {})
        if isinstance(result, dict):
            code_text = result.get("decompiled_text") or result.get("ccode") or result.get("code") or ""
        else:
            code_text = str(result) if result else ""
            
        if not code_text:
            return {
                "success": False,
                "error": {
                    "code": "NO_CODE",
                    "message": "No decompiled code available for analysis"
                },
                "timestamp": int(time.time() * 1000)
            }
        
        import re
        xor_constants = []
        lines = code_text.split('\n')
        
        # Enhanced patterns to match XOR operations with hex constants
        xor_patterns = [
            # Direct XOR operations (highest priority for actual XOR keys)
            r'(\w+)\s*=\s*([^;]+)\s*\^\s*(0x[0-9a-fA-F]+)',        # var = something ^ 0xCONST
            r'return\s+([^;]+)\s*\^\s*(0x[0-9a-fA-F]+)',           # return something ^ 0xCONST
            r'\^\s*(0x[0-9a-fA-F]+)',                              # general ^ 0xCONST pattern
            r'(\w+)\s*\^=\s*(0x[0-9a-fA-F]+)',                    # var ^= 0xCONST
            r'\(\s*([^)]+)\s*\^\s*(0x[0-9a-fA-F]+)\s*\)',         # (something ^ 0xCONST)
            
            # XOR in conditional expressions
            r'(\w+)\s*==?\s*\(([^)]+)\s*\^\s*(0x[0-9a-fA-F]+)\)',  # if (var == (something ^ 0xCONST))
            r'if\s*\(\s*([^)]+)\s*\^\s*(0x[0-9a-fA-F]+)',          # if (something ^ 0xCONST
            
            # Comparison patterns (medium priority - could be module hashes)
            r'(\w+)\s*[!=]=\s*(-?0x[0-9a-fA-F]+)',                # param != -0xCONST (potential XOR key)
            r'(\w+)\s*[!=]=\s*(-?\d+)',                            # param != -12345 (potential XOR key)
            
            # Assignment of hex constants (could be XOR keys)
            r'(\w+)\s*=\s*(0x[0-9a-fA-F]+)',                      # var = 0xCONST
            r'(int|uint32_t|unsigned\s+int|DWORD)\s+(\w+)\s*=\s*(0x[0-9a-fA-F]+)', # typed assignments
        ]
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//'):
                continue
                
            for pattern in xor_patterns:
                matches = re.finditer(pattern, line_stripped, re.IGNORECASE)
                for match in matches:
                    # Extract the constant value (last capturing group)
                    group_count = len(match.groups())
                    if group_count == 0:
                        continue
                    const_str = match.group(group_count)  # Last group
                    
                    try:
                        # Handle both hex and decimal (including negative) values
                        if const_str.startswith(('-0x', '0x')):
                            # Hex value (possibly negative)
                            if const_str.startswith('-0x'):
                                const_val = -int(const_str[3:], 16)
                                # Convert negative to 32-bit unsigned representation for XOR key analysis
                                unsigned_val = (const_val + 2**32) % 2**32
                                hex_const = f"0x{unsigned_val:08X}"
                                operation_type = "negative_comparison_potential_xor_key"
                            else:
                                const_val = int(const_str, 16)
                                hex_const = const_str.upper()
                        elif const_str.startswith('-'):
                            # Negative decimal value
                            const_val = int(const_str)
                            # Convert to positive hex for easier analysis
                            if const_val < 0:
                                # Convert negative to 32-bit unsigned representation
                                unsigned_val = (const_val + 2**32) % 2**32
                                hex_const = f"0x{unsigned_val:08X}"
                                # Also store the original negative form
                                operation_type = "negative_comparison_potential_xor_key"
                            else:
                                hex_const = f"0x{const_val:08X}"
                        else:
                            # Regular decimal
                            const_val = int(const_str)
                            hex_const = f"0x{const_val:08X}"
                        
                        # Filter by minimum size (check absolute value)
                        if abs(const_val).bit_length() < min_constant_size * 8:
                            continue
                            
                        # Determine operation type and confidence based on pattern
                        if 'operation_type' not in locals():
                            operation_type = "unknown"
                        confidence = 0.3  # Base confidence
                        
                        # High confidence for direct XOR operations (actual XOR keys)
                        if any(op in line_stripped for op in [' ^ 0x', ' ^= 0x', 'return ', ' ^ ']):
                            operation_type = "direct_xor_operation"
                            confidence = 0.9  # Very high confidence for actual XOR operations
                        elif "!=" in line_stripped and const_str.startswith('-'):
                            operation_type = "negative_comparison_potential_module_hash"
                            confidence = 0.8  # High confidence for negative comparisons (likely module hashes)
                        elif " = 0x" in line_stripped and "!=" not in line_stripped:
                            operation_type = "hex_assignment_potential_xor_key"
                            confidence = 0.7  # Good confidence for hex assignments
                        elif any(op in line_stripped for op in ['==', '!=']):
                            operation_type = "comparison_operation"
                            confidence = 0.6  # Medium confidence for comparisons
                        
                        # Boost confidence for larger constants
                        if abs(const_val) > 0xFFFFFF:  # 24+ bit constants
                            confidence += 0.1
                            
                        # Boost confidence if near hash-related keywords
                        hash_keywords = ['hash', 'crc', 'checksum', 'uVar', 'iVar']
                        if any(keyword.lower() in line_stripped.lower() for keyword in hash_keywords):
                            confidence += 0.1
                            
                        confidence = min(confidence, 1.0)
                        
                        xor_constants.append({
                            "constant_hex": hex_const,
                            "constant_dec": const_val,
                            "context": line_stripped,
                            "confidence": round(confidence, 2),
                            "line_number": line_num,
                            "operation_type": operation_type
                        })
                        
                    except ValueError:
                        continue
        
        # Remove duplicates while preserving order
        seen_constants = set()
        unique_constants = []
        for const in xor_constants:
            const_key = const["constant_hex"]
            if const_key not in seen_constants:
                seen_constants.add(const_key)
                unique_constants.append(const)
        
        # Sort by confidence and constant value
        unique_constants.sort(key=lambda x: (-x["confidence"], -x["constant_dec"]))
        
        return {
            "success": True,
            "xor_constants": unique_constants,
            "patterns_found": len(unique_constants),
            "function": name or address,
            "timestamp": int(time.time() * 1000)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": {
                "code": "ANALYSIS_ERROR",
                "message": f"Error analyzing XOR constants: {str(e)}"
            },
            "timestamp": int(time.time() * 1000)
        }


@mcp.tool()
def functions_analyze_resolver_dependencies(
    resolver_name: Optional[str] = None,
    resolver_address: Optional[str] = None,
    port: Optional[int] = None
) -> dict:
    """Analyze a resolver function and its dependencies to find actual XOR keys.
    
    This function specifically looks for XOR keys in called functions since resolvers
    often use helper functions that contain the actual XOR operations.
    
    Args:
        resolver_name: Name of the resolver function
        resolver_address: Address of the resolver function  
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: {
            success: bool,
            resolver_analysis: dict,
            dependency_analysis: [
                {
                    function_name: str,
                    xor_constants: [...],
                    call_context: str
                }
            ],
            candidate_xor_keys: [...],
            best_xor_key: dict (highest confidence candidate)
        }
    """
    if not resolver_name and not resolver_address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER", 
                "message": "Either resolver_name or resolver_address is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    try:
        # Step 1: Analyze the resolver function itself
        resolver_analysis = functions_detect_xor_constants(
            name=resolver_name, 
            address=resolver_address, 
            port=port
        )
        
        # Step 2: Get functions called by the resolver using decompiled code analysis
        # Since functions_get_called_functions doesn't exist, analyze decompiled code for function calls
        resolver_decompile = functions_decompile(
            name=resolver_name,
            address=resolver_address, 
            port=port
        )
        
        called_functions = []
        if resolver_decompile.get("success"):
            decompiled_text = resolver_decompile.get("result", {}).get("decompiled_text", "")
            if decompiled_text:
                import re
                # Extract function calls from decompiled code
                func_call_pattern = r'(FUN_[0-9a-fA-F]{8})\s*\('
                matches = re.findall(func_call_pattern, decompiled_text)
                called_functions = [{"name": match, "address": match.replace("FUN_", "")} for match in set(matches)]
        
        dependency_analysis = []
        all_candidate_keys = []
        
        if called_functions:
            # Analyze each called function for XOR constants
            for func_info in called_functions[:10]:  # Limit to first 10 to avoid excessive analysis
                func_name = func_info.get("name")
                if not func_name:
                    continue
                    
                # Analyze this dependency for XOR constants
                dep_analysis = functions_detect_xor_constants(name=func_name, port=port)
                if dep_analysis.get("success") and dep_analysis.get("xor_constants"):
                    dep_info = {
                        "function_name": func_name,
                        "function_address": func_info.get("address"),
                        "xor_constants": dep_analysis["xor_constants"],
                        "call_context": f"Called by {resolver_name or resolver_address}"
                    }
                    dependency_analysis.append(dep_info)
                    
                    # Collect high-confidence XOR constants as candidates
                    for const in dep_analysis["xor_constants"]:
                        if const.get("confidence", 0) >= 0.7 and const.get("operation_type") in [
                            "direct_xor_operation", "hex_assignment_potential_xor_key"
                        ]:
                            all_candidate_keys.append({
                                **const,
                                "source_function": func_name,
                                "source_type": "dependency"
                            })
        
        # Add resolver's own constants as candidates
        if resolver_analysis.get("success") and resolver_analysis.get("xor_constants"):
            for const in resolver_analysis["xor_constants"]:
                all_candidate_keys.append({
                    **const,
                    "source_function": resolver_name or resolver_address,
                    "source_type": "resolver"
                })
        
        # Sort candidates by confidence and operation type priority
        all_candidate_keys.sort(key=lambda x: (
            -x.get("confidence", 0),
            0 if x.get("operation_type") == "direct_xor_operation" else 1,
            -x.get("constant_dec", 0)
        ))
        
        # Select best XOR key candidate (highest confidence, prioritizing direct XOR operations)
        best_xor_key = None
        if all_candidate_keys:
            # Find the best candidate by prioritizing direct XOR operations with high confidence
            direct_xor_candidates = [
                candidate for candidate in all_candidate_keys 
                if candidate.get("operation_type") == "direct_xor_operation" and candidate.get("confidence", 0) >= 0.7
            ]
            
            if direct_xor_candidates:
                best_xor_key = direct_xor_candidates[0]
            else:
                # Fall back to highest confidence candidate overall
                high_confidence_candidates = [
                    candidate for candidate in all_candidate_keys 
                    if candidate.get("confidence", 0) >= 0.6
                ]
                if high_confidence_candidates:
                    best_xor_key = high_confidence_candidates[0]
                elif all_candidate_keys:
                    best_xor_key = all_candidate_keys[0]
        
        return {
            "success": True,
            "resolver_analysis": resolver_analysis,
            "dependency_analysis": dependency_analysis,
            "candidate_xor_keys": all_candidate_keys,
            "best_xor_key": best_xor_key,
            "functions_analyzed": len(dependency_analysis) + 1,
            "timestamp": int(time.time() * 1000)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": {
                "code": "DEPENDENCY_ANALYSIS_ERROR",
                "message": f"Error analyzing resolver dependencies: {str(e)}"
            },
            "timestamp": int(time.time() * 1000)
        }

@mcp.tool()
def analysis_identify_resolvers(
    min_calls: int = 5,
    port: Optional[int] = None
) -> dict:
    """Identify potential API hash resolver functions by analyzing call patterns.
    
    Args:
        min_calls: Minimum number of calls to consider a function a resolver candidate
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: {
            success: bool,
            resolvers: [
                {
                    function_name: str,
                    function_address: str,
                    call_count: int,
                    unique_arg_patterns: int,
                    confidence: float,
                    evidence: dict
                }
            ]
        }
    """
    port = _get_instance_port(port)
    
    try:
        # Get all functions
        functions_result = functions_list(port=port, limit=1000)
        if not (isinstance(functions_result, dict) and functions_result.get("success")):
            return {
                "success": False,
                "error": {
                    "code": "FUNCTIONS_LIST_FAILED",
                    "message": "Could not retrieve function list"
                },
                "timestamp": int(time.time() * 1000)
            }
        
        functions_data = functions_result.get("result", {})
        functions_list_data = functions_data.get("functions", []) if isinstance(functions_data, dict) else []
        
        resolvers = []
        
        # Analyze each function for resolver characteristics
        for func in functions_list_data[:50]:  # Limit to first 50 for performance
            if not isinstance(func, dict):
                continue
                
            func_name = func.get("name", "")
            func_addr = func.get("address", "")
            
            if not func_name or not func_addr:
                continue
            
            # Get cross-references to this function
            try:
                xrefs_result = xrefs_list(to_addr=func_addr, port=port)
                if not (isinstance(xrefs_result, dict) and xrefs_result.get("success")):
                    continue
                    
                xrefs_data = xrefs_result.get("result", {})
                call_xrefs = []
                
                if isinstance(xrefs_data, dict):
                    xrefs_list_data = xrefs_data.get("xrefs", [])
                    call_xrefs = [x for x in xrefs_list_data if isinstance(x, dict) and x.get("type") == "CALL"]
                
                call_count = len(call_xrefs)
                
                if call_count < min_calls:
                    continue
                
                # Analyze call arguments to detect resolver patterns
                arg_patterns = set()
                takes_constants = False
                
                for xref in call_xrefs[:10]:  # Sample first 10 calls
                    caller_addr = xref.get("from_address", "")
                    if caller_addr:
                        try:
                            # Get the calling function and analyze call arguments
                            caller_func = functions_get(address=caller_addr, port=port)
                            if isinstance(caller_func, dict) and caller_func.get("success"):
                                caller_result = caller_func.get("result", {})
                                caller_name = caller_result.get("name", "") if isinstance(caller_result, dict) else ""
                                
                                if caller_name:
                                    call_args = functions_list_call_args(name=caller_name, callee=func_name, port=port)
                                    if isinstance(call_args, dict) and call_args.get("success"):
                                        calls_data = call_args.get("calls", [])
                                        for call in calls_data:
                                            if isinstance(call, dict):
                                                args = call.get("args", [])
                                                if len(args) >= 2:  # Resolvers typically take 2+ args
                                                    arg_pattern = f"{len(args)}_args"
                                                    arg_patterns.add(arg_pattern)
                                                    
                                                    # Check for constant arguments
                                                    for arg in args:
                                                        if isinstance(arg, dict):
                                                            val = arg.get("value_hex", "")
                                                            if val and val.startswith("0x"):
                                                                takes_constants = True
                        except Exception:
                            continue
                
                # Calculate confidence based on characteristics
                confidence = 0.0
                evidence = {
                    "takes_constants": takes_constants,
                    "call_count": call_count,
                    "called_frequently": call_count >= min_calls,
                    "multiple_arg_patterns": len(arg_patterns) > 1
                }
                
                if takes_constants:
                    confidence += 0.4
                if call_count >= min_calls * 2:
                    confidence += 0.3
                if len(arg_patterns) > 0:
                    confidence += 0.2
                if "hash" in func_name.lower() or "resolve" in func_name.lower():
                    confidence += 0.1
                
                if confidence >= 0.5:  # Only include likely candidates
                    resolvers.append({
                        "function_name": func_name,
                        "function_address": func_addr,
                        "call_count": call_count,
                        "unique_arg_patterns": len(arg_patterns),
                        "confidence": round(confidence, 2),
                        "evidence": evidence
                    })
                    
            except Exception:
                continue
        
        # Sort by confidence and call count
        resolvers.sort(key=lambda x: (-x["confidence"], -x["call_count"]))
        
        return {
            "success": True,
            "resolvers": resolvers,
            "candidates_found": len(resolvers),
            "timestamp": int(time.time() * 1000)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": {
                "code": "ANALYSIS_ERROR",
                "message": f"Error identifying resolvers: {str(e)}"
            },
            "timestamp": int(time.time() * 1000)
        }

@mcp.tool()
def functions_detect_hash_algorithms(
    name: Optional[str] = None,
    address: Optional[str] = None,
    port: Optional[int] = None
) -> dict:
    """Detect hashing algorithm patterns in function code.
    
    Args:
        name: Function name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: {
            success: bool,
            algorithms: [
                {
                    type: str,
                    confidence: float,
                    evidence: [str],
                    constants: [str],
                    loop_detected: bool
                }
            ]
        }
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    # Get decompiled code
    dec_result = functions_decompile(name=name, address=address, port=port)
    if not (isinstance(dec_result, dict) and dec_result.get("success")):
        return {
            "success": False,
            "error": {
                "code": "DECOMPILE_FAILED",
                "message": "Could not decompile function for algorithm detection"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    try:
        result = dec_result.get("result", {})
        if isinstance(result, dict):
            code_text = result.get("decompiled_text") or result.get("ccode") or result.get("code") or ""
        else:
            code_text = str(result) if result else ""
            
        if not code_text:
            return {
                "success": False,
                "error": {
                    "code": "NO_CODE",
                    "message": "No decompiled code available for analysis"
                },
                "timestamp": int(time.time() * 1000)
            }
        
        import re
        algorithms = []
        
        # CRC32 detection patterns
        crc32_evidence = []
        crc32_constants = []
        
        # CRC32 polynomial constants
        crc_polynomials = [
            "0xedb88320",  # Standard CRC32 polynomial (reversed)
            "0x04c11db7",  # Standard CRC32 polynomial (normal)
            "0x82f63b78",  # Another CRC variant
        ]
        
        for poly in crc_polynomials:
            if poly in code_text.lower():
                crc32_evidence.append(f"CRC32 polynomial {poly.upper()} found")
                crc32_constants.append(poly.upper())
        
        # Look for typical CRC32 patterns
        crc_patterns = [
            r'(\w+)\s*>>\s*8',                    # right shift by 8
            r'(\w+)\s*<<\s*8',                    # left shift by 8  
            r'(\w+)\s*&\s*0xff',                  # mask with 0xFF
            r'(\w+)\s*\^\s*(\w+)',                # XOR operations
            r'for\s*\([^)]*;\s*\w+\s*<\s*8',     # loop with 8 iterations
            r'while\s*\([^)]*8[^)]*\)',           # while loop with 8
        ]
        
        crc_pattern_count = 0
        for pattern in crc_patterns:
            matches = re.findall(pattern, code_text, re.IGNORECASE)
            if matches:
                crc_pattern_count += len(matches)
        
        # Detect loops (common in hashing algorithms)
        loop_detected = bool(re.search(r'(for|while)\s*\(', code_text, re.IGNORECASE))
        if loop_detected:
            crc32_evidence.append("Loop structure detected")
        
        # CRC32 table detection
        if re.search(r'(\w+)\[\s*(\w+)\s*&\s*0xff\s*\]', code_text, re.IGNORECASE):
            crc32_evidence.append("Table lookup pattern detected")
            crc_pattern_count += 2
        
        # Calculate CRC32 confidence
        if crc32_constants or crc_pattern_count >= 3:
            confidence = 0.3 + (len(crc32_constants) * 0.3) + (min(crc_pattern_count, 5) * 0.1)
            if loop_detected:
                confidence += 0.1
            confidence = min(confidence, 1.0)
            
            algorithms.append({
                "type": "crc32",
                "confidence": round(confidence, 2),
                "evidence": crc32_evidence,
                "constants": crc32_constants,
                "loop_detected": loop_detected
            })
        
        # DJB2 hash detection
        djb2_evidence = []
        djb2_constants = []
        
        # DJB2 magic numbers
        if "5381" in code_text:
            djb2_evidence.append("DJB2 initial value 5381 found")
            djb2_constants.append("5381")
        
        # DJB2 characteristic operations
        if re.search(r'(\w+)\s*\*\s*33', code_text):
            djb2_evidence.append("Multiplication by 33 detected")
        if re.search(r'(\w+)\s*<<\s*5.*\+.*(\w+)', code_text):
            djb2_evidence.append("Left shift by 5 plus addition pattern")
        
        if djb2_evidence:
            confidence = 0.4 + (len(djb2_evidence) * 0.2)
            if loop_detected:
                confidence += 0.1
            confidence = min(confidence, 1.0)
            
            algorithms.append({
                "type": "djb2",
                "confidence": round(confidence, 2),
                "evidence": djb2_evidence,
                "constants": djb2_constants,
                "loop_detected": loop_detected
            })
        
        # FNV hash detection
        fnv_evidence = []
        fnv_constants = []
        
        # FNV magic numbers
        fnv_constants_list = ["0x811c9dc5", "0x01000193"]
        for const in fnv_constants_list:
            if const in code_text.lower():
                fnv_evidence.append(f"FNV constant {const.upper()} found")
                fnv_constants.append(const.upper())
        
        if fnv_evidence:
            confidence = 0.5 + (len(fnv_evidence) * 0.2)
            if loop_detected:
                confidence += 0.1
            confidence = min(confidence, 1.0)
            
            algorithms.append({
                "type": "fnv1a",
                "confidence": round(confidence, 2),
                "evidence": fnv_evidence,
                "constants": fnv_constants,
                "loop_detected": loop_detected
            })
        
        # API Hash (ROR13/ROR7) detection
        ror_evidence = []
        ror_constants = []
        
        # Look for rotation patterns
        if re.search(r'(\w+)\s*>>\s*13.*(\w+)\s*<<\s*19', code_text) or re.search(r'(\w+)\s*>>\s*19.*(\w+)\s*<<\s*13', code_text):
            ror_evidence.append("ROR13 rotation pattern detected")
        if re.search(r'(\w+)\s*>>\s*7.*(\w+)\s*<<\s*25', code_text) or re.search(r'(\w+)\s*>>\s*25.*(\w+)\s*<<\s*7', code_text):
            ror_evidence.append("ROR7 rotation pattern detected")
        
        # Character processing loop (typical for API hashing)
        if re.search(r'for.*ch.*string', code_text, re.IGNORECASE) or re.search(r'while.*\*.*\+\+', code_text):
            ror_evidence.append("Character processing loop detected")
        
        if ror_evidence:
            confidence = 0.4 + (len(ror_evidence) * 0.2)
            if loop_detected:
                confidence += 0.1
            confidence = min(confidence, 1.0)
            
            algorithms.append({
                "type": "api_hash_ror",
                "confidence": round(confidence, 2),
                "evidence": ror_evidence,
                "constants": ror_constants,
                "loop_detected": loop_detected
            })
        
        # Sort algorithms by confidence
        algorithms.sort(key=lambda x: -x["confidence"])
        
        return {
            "success": True,
            "algorithms": algorithms,
            "function": name or address,
            "loop_detected": loop_detected,
            "timestamp": int(time.time() * 1000)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": {
                "code": "ANALYSIS_ERROR",
                "message": f"Error detecting hash algorithms: {str(e)}"
            },
            "timestamp": int(time.time() * 1000)
        }

@mcp.tool()
def analysis_auto_detect_obfuscation(
    port: Optional[int] = None
) -> dict:
    """Automatically detect obfuscation patterns across the program.
    
    Args:
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: {
            obfuscation_detected: bool,
            techniques: [
                {
                    type: str,
                    confidence: float,
                    affected_functions: [str],
                    key_constants: [str],
                    recommended_tools: [str]
                }
            ],
            auto_analysis_results: dict
        }
    """
    port = _get_instance_port(port)
    
    try:
        # Step 1: Identify potential resolver functions
        resolvers_result = analysis_identify_resolvers(min_calls=3, port=port)
        resolvers = []
        if isinstance(resolvers_result, dict) and resolvers_result.get("success"):
            resolvers = resolvers_result.get("resolvers", [])
        
        techniques = []
        auto_analysis_results = {
            "resolvers_found": len(resolvers),
            "xor_constants_by_function": {},
            "hash_algorithms_by_function": {},
            "high_confidence_findings": []
        }
        
        # Step 2: Analyze top resolver candidates for obfuscation patterns
        for resolver in resolvers[:5]:  # Analyze top 5 candidates
            func_name = resolver.get("function_name", "")
            func_addr = resolver.get("function_address", "")
            
            if not func_name:
                continue
            
            # Detect XOR constants in resolver
            xor_result = functions_detect_xor_constants(name=func_name, port=port)
            if isinstance(xor_result, dict) and xor_result.get("success"):
                xor_constants = xor_result.get("xor_constants", [])
                auto_analysis_results["xor_constants_by_function"][func_name] = xor_constants
                
                # High confidence XOR constants indicate API hashing
                high_conf_xor = [x for x in xor_constants if x.get("confidence", 0) >= 0.8]
                if high_conf_xor:
                    auto_analysis_results["high_confidence_findings"].extend([
                        f"High confidence XOR constant {x['constant_hex']} in {func_name}"
                        for x in high_conf_xor
                    ])
            
            # Detect hash algorithms in resolver
            hash_result = functions_detect_hash_algorithms(name=func_name, port=port)
            if isinstance(hash_result, dict) and hash_result.get("success"):
                algorithms = hash_result.get("algorithms", [])
                auto_analysis_results["hash_algorithms_by_function"][func_name] = algorithms
                
                # High confidence algorithms
                high_conf_algos = [a for a in algorithms if a.get("confidence", 0) >= 0.7]
                if high_conf_algos:
                    auto_analysis_results["high_confidence_findings"].extend([
                        f"High confidence {a['type']} algorithm in {func_name}"
                        for a in high_conf_algos
                    ])
        
        # Step 3: Analyze calling functions for obfuscation patterns
        analyzed_callers = set()
        for resolver in resolvers[:3]:  # Top 3 resolvers
            func_name = resolver.get("function_name", "")
            
            # Get functions that call this resolver
            try:
                # Resolve function name to address first
                func_addr = None
                func_info = functions_get(name=func_name, port=port)
                if isinstance(func_info, dict) and func_info.get("success"):
                    func_result = func_info.get("result", {})
                    func_addr = func_result.get("addr") or func_result.get("address")
                
                if func_addr:
                    xrefs_result = xrefs_list(to_addr=func_addr, port=port)
                    if isinstance(xrefs_result, dict) and xrefs_result.get("success"):
                        xrefs_data = xrefs_result.get("result", {})
                    if isinstance(xrefs_data, dict):
                        xrefs_list_data = xrefs_data.get("xrefs", [])
                        
                        for xref in xrefs_list_data[:5]:  # Limit analysis
                            if not isinstance(xref, dict) or xref.get("type") != "CALL":
                                continue
                            
                            caller_addr = xref.get("from_address", "")
                            if not caller_addr or caller_addr in analyzed_callers:
                                continue
                            
                            analyzed_callers.add(caller_addr)
                            
                            # Get the calling function
                            caller_func = functions_get(address=caller_addr, port=port)
                            if isinstance(caller_func, dict) and caller_func.get("success"):
                                caller_result = caller_func.get("result", {})
                                caller_name = caller_result.get("name", "") if isinstance(caller_result, dict) else ""
                                
                                if caller_name and caller_name not in auto_analysis_results["xor_constants_by_function"]:
                                    # Analyze caller for XOR constants
                                    caller_xor = functions_detect_xor_constants(name=caller_name, port=port)
                                    if isinstance(caller_xor, dict) and caller_xor.get("success"):
                                        caller_xor_constants = caller_xor.get("xor_constants", [])
                                        if caller_xor_constants:
                                            auto_analysis_results["xor_constants_by_function"][caller_name] = caller_xor_constants
            except Exception:
                continue
        
        # Step 4: Classify obfuscation techniques based on findings
        all_xor_constants = []
        all_algorithms = []
        
        for func_constants in auto_analysis_results["xor_constants_by_function"].values():
            all_xor_constants.extend(func_constants)
        
        for func_algorithms in auto_analysis_results["hash_algorithms_by_function"].values():
            all_algorithms.extend(func_algorithms)
        
        # API Hashing technique detection
        if resolvers and (all_xor_constants or all_algorithms):
            high_conf_xor = [x for x in all_xor_constants if x.get("confidence", 0) >= 0.8]
            high_conf_algo = [a for a in all_algorithms if a.get("confidence", 0) >= 0.7]
            
            api_hashing_confidence = 0.0
            key_constants = []
            affected_functions = list(auto_analysis_results["xor_constants_by_function"].keys())
            
            if high_conf_xor:
                api_hashing_confidence += 0.4
                key_constants.extend([x["constant_hex"] for x in high_conf_xor])
            
            if high_conf_algo:
                api_hashing_confidence += 0.3
            
            if len(resolvers) >= 2:
                api_hashing_confidence += 0.2
            
            if len(affected_functions) >= 2:
                api_hashing_confidence += 0.1
            
            if api_hashing_confidence >= 0.5:
                recommended_tools = ["hashdb_crc32_lookup_batch_xor", "imports_apply_from_hashdb"]
                if key_constants:
                    recommended_tools.append("derive_crc32_xor_keys_name_forms")
                
                techniques.append({
                    "type": "api_hashing",
                    "confidence": round(api_hashing_confidence, 2),
                    "affected_functions": affected_functions,
                    "key_constants": list(set(key_constants)),
                    "recommended_tools": recommended_tools
                })
        
        # String XOR technique detection
        string_xor_functions = []
        for func_name, constants in auto_analysis_results["xor_constants_by_function"].items():
            # Look for functions with XOR but not in resolvers (likely string decryption)
            if func_name not in [r.get("function_name", "") for r in resolvers]:
                if any(c.get("confidence", 0) >= 0.7 for c in constants):
                    string_xor_functions.append(func_name)
        
        if string_xor_functions:
            techniques.append({
                "type": "string_xor",
                "confidence": 0.6,
                "affected_functions": string_xor_functions,
                "key_constants": [],
                "recommended_tools": ["repeating_xor_decrypt", "table_try_single_byte_keys"]
            })
        
        # Sort techniques by confidence
        techniques.sort(key=lambda x: -x["confidence"])
        
        obfuscation_detected = len(techniques) > 0
        
        return {
            "success": True,
            "obfuscation_detected": obfuscation_detected,
            "techniques": techniques,
            "auto_analysis_results": auto_analysis_results,
            "timestamp": int(time.time() * 1000)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": {
                "code": "ANALYSIS_ERROR",
                "message": f"Error in automatic obfuscation detection: {str(e)}"
            },
            "timestamp": int(time.time() * 1000)
        }

@mcp.tool()
def analysis_comprehensive_api_deobfuscation(
    target_function: str,
    port: Optional[int] = None
) -> dict:
    """Comprehensive API deobfuscation analysis following program logic.
    
    Args:
        target_function: Starting function to analyze
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: {
            success: bool,
            analysis_results: {
                resolver_candidates: [dict],
                xor_keys: [dict],
                hash_algorithms: [dict],
                api_mappings: [dict],
                program_flow: dict
            }
        }
    """
    port = _get_instance_port(port)
    
    try:
        analysis_results = {
            "resolver_candidates": [],
            "xor_keys": [],
            "hash_algorithms": [],
            "api_mappings": [],
            "program_flow": {},
            "analysis_steps": []
        }
        
        analysis_results["analysis_steps"].append(f"Starting comprehensive analysis of {target_function}")
        
        # Step 1: Identify resolver functions
        analysis_results["analysis_steps"].append("Step 1: Identifying resolver candidates")
        resolver_result = analysis_identify_resolvers(min_calls=3, port=port)
        if isinstance(resolver_result, dict) and resolver_result.get("success"):
            analysis_results["resolver_candidates"] = resolver_result.get("resolvers", [])
        
        # Step 2: For each resolver candidate, perform comprehensive dependency analysis
        analysis_results["analysis_steps"].append("Step 2: Performing comprehensive resolver dependency analysis")
        all_xor_keys = []
        
        for resolver in analysis_results["resolver_candidates"]:
            if isinstance(resolver, dict):
                resolver_name = resolver.get("function_name", "")
                if resolver_name:
                    analysis_results["analysis_steps"].append(f"  Analyzing resolver dependencies: {resolver_name}")
                    
                    # Use new comprehensive dependency analysis (NO hardcoded keys)
                    dep_analysis = functions_analyze_resolver_dependencies(
                        resolver_name=resolver_name,
                        port=port
                    )
                    
                    if isinstance(dep_analysis, dict) and dep_analysis.get("success"):
                        candidate_keys = dep_analysis.get("candidate_xor_keys", [])
                        all_xor_keys.extend(candidate_keys)
                        
                        # Log dependency analysis results
                        analysis_results["analysis_steps"].append(f"    Found {len(candidate_keys)} XOR key candidates in dependency analysis")
                        
                        # Show top candidates by confidence
                        top_candidates = sorted(candidate_keys, key=lambda x: x.get("confidence", 0), reverse=True)[:3]
                        for i, candidate in enumerate(top_candidates, 1):
                            const_hex = candidate.get("constant_hex", "unknown")
                            confidence = candidate.get("confidence", 0)
                            op_type = candidate.get("operation_type", "unknown")
                            source_func = candidate.get("source_function", "unknown")
                            analysis_results["analysis_steps"].append(f"      #{i}: {const_hex} (confidence: {confidence:.2f}, type: {op_type}, from: {source_func})")
                    
                    # Still run guided search as backup
                    xor_search = analysis_guided_xor_key_search(resolver_function=resolver_name, port=port)
                    if isinstance(xor_search, dict) and xor_search.get("success"):
                        search_data = xor_search.get("search_results", {})
                        found_keys = search_data.get("xor_keys_found", [])
                        all_xor_keys.extend(found_keys)
                        
                        # Add recommended key with high confidence
                        recommended_key = search_data.get("recommended_key")
                        if recommended_key:
                            analysis_results["analysis_steps"].append(f"    Backup search recommended key: {recommended_key}")
        
        # Step 3: Trace function dependencies to understand program flow
        analysis_results["analysis_steps"].append("Step 3: Tracing program flow dependencies")
        trace_result = analysis_trace_function_dependencies(name=target_function, max_depth=3, port=port)
        if isinstance(trace_result, dict) and trace_result.get("success"):
            analysis_results["program_flow"] = trace_result.get("trace_results", {})
            
            # Extract XOR keys from dependency chain
            dependency_chain = analysis_results["program_flow"].get("dependency_chain", [])
            for dep in dependency_chain:
                dep_xor_keys = dep.get("xor_constants", [])
                all_xor_keys.extend(dep_xor_keys)
        
        # Step 4: Detect hash algorithms across all related functions
        analysis_results["analysis_steps"].append("Step 4: Detecting hash algorithms")
        all_hash_algorithms = []
        
        # Check target function
        hash_result = functions_detect_hash_algorithms(name=target_function, port=port)
        if isinstance(hash_result, dict) and hash_result.get("success"):
            algorithms = hash_result.get("algorithms", [])
            all_hash_algorithms.extend(algorithms)
        
        # Check resolver functions
        for resolver in analysis_results["resolver_candidates"]:
            if isinstance(resolver, dict):
                resolver_name = resolver.get("function_name", "")
                if resolver_name:
                    resolver_hash = functions_detect_hash_algorithms(name=resolver_name, port=port)
                    if isinstance(resolver_hash, dict) and resolver_hash.get("success"):
                        algorithms = resolver_hash.get("algorithms", [])
                        all_hash_algorithms.extend(algorithms)
        
        # Step 5: Consolidate and intelligently rank XOR keys (distinguish from module hashes)
        analysis_results["analysis_steps"].append("Step 5: Consolidating and intelligently ranking XOR key findings")
        xor_key_ranking = {}
        module_hash_candidates = {}
        
        for xor_key in all_xor_keys:
            if isinstance(xor_key, dict):
                key_hex = xor_key.get("constant_hex", "")
                confidence = xor_key.get("confidence", 0)
                source_func = xor_key.get("source_function", "")
                op_type = xor_key.get("operation_type", "")
                context = xor_key.get("context", "")
                
                # Distinguish between actual XOR keys and module hash comparisons
                is_likely_xor_key = (
                    op_type in ["direct_xor_operation", "hex_assignment_potential_xor_key"] or
                    any(pattern in context.lower() for pattern in [" ^ ", " ^= ", "xor", "return"])
                )
                
                is_likely_module_hash = (
                    op_type in ["negative_comparison_potential_module_hash", "comparison_operation"] and
                    any(pattern in context.lower() for pattern in ["!=", "==", "param_", "if ("])
                )
                
                target_dict = xor_key_ranking if is_likely_xor_key else module_hash_candidates
                
                if key_hex not in target_dict:
                    target_dict[key_hex] = {
                        "key": key_hex,
                        "total_confidence": 0,
                        "occurrences": 0,
                        "sources": [],
                        "contexts": [],
                        "classification": "xor_key" if is_likely_xor_key else "module_hash"
                    }
                
                target_dict[key_hex]["total_confidence"] += confidence
                target_dict[key_hex]["occurrences"] += 1
                target_dict[key_hex]["sources"].append(source_func)
                target_dict[key_hex]["contexts"].append(context)
        
        # Sort XOR keys by confidence and occurrences (prioritize actual XOR operations)
        ranked_keys = sorted(xor_key_ranking.values(), 
                           key=lambda x: (x["total_confidence"], x["occurrences"]), 
                           reverse=True)
        
        # Also track module hash candidates separately
        ranked_module_hashes = sorted(module_hash_candidates.values(),
                                    key=lambda x: (x["total_confidence"], x["occurrences"]),
                                    reverse=True)
        
        analysis_results["analysis_steps"].append(f"  Classified {len(ranked_keys)} XOR key candidates and {len(ranked_module_hashes)} module hash candidates")
        
        analysis_results["xor_keys"] = ranked_keys
        analysis_results["module_hashes"] = ranked_module_hashes
        analysis_results["hash_algorithms"] = all_hash_algorithms
        
        # Step 6: Attempt API resolution with discovered keys
        analysis_results["analysis_steps"].append("Step 6: Attempting API resolution with discovered keys")
        if ranked_keys:
            top_key = ranked_keys[0]["key"]
            analysis_results["analysis_steps"].append(f"  Using dynamically discovered top XOR key: {top_key}")
            
            # Add validation by checking if this key produces meaningful results
            # This would integrate with HashDB lookups to verify the key works
            analysis_results["analysis_steps"].append(f"  Recommended for HashDB validation: {top_key}")
        else:
            analysis_results["analysis_steps"].append("  No XOR keys discovered - may need deeper analysis")
        
        # Step 7: Generate actionable recommendations with discovered keys
        analysis_results["analysis_steps"].append("Step 7: Generating autonomous discovery recommendations")
        recommendations = []
        
        if ranked_keys:
            top_key = ranked_keys[0]
            confidence_score = top_key['total_confidence'] / max(top_key['occurrences'], 1)  # Average confidence
            recommendations.append(f"AUTONOMOUS DISCOVERY: Primary XOR key candidate: {top_key['key']}")
            recommendations.append(f"  Confidence: {confidence_score:.2f}/1.0 (from {top_key['occurrences']} occurrences)")
            recommendations.append(f"  Sources: {', '.join(set(top_key['sources']))}")
            
            # Add validation recommendations
            if confidence_score >= 0.8:
                recommendations.append(f"  HIGH CONFIDENCE: Recommend immediate HashDB validation with {top_key['key']}")
            elif confidence_score >= 0.6:
                recommendations.append(f"  MEDIUM CONFIDENCE: Suggest testing {top_key['key']} with sample hash values")
            else:
                recommendations.append(f"  LOW CONFIDENCE: Consider deeper analysis or manual validation of {top_key['key']}")
            
            # Show alternative candidates
            if len(ranked_keys) > 1:
                alternatives = [f"{key['key']} (conf: {key['total_confidence']/max(key['occurrences'], 1):.2f})" 
                              for key in ranked_keys[1:3]]
                recommendations.append(f"  Alternative candidates: {', '.join(alternatives)}")
        else:
            recommendations.append("NO XOR KEYS DISCOVERED: Consider analyzing resolver helper functions manually")
            recommendations.append("  Suggestion: Examine functions called by identified resolvers")
            recommendations.append("  Suggestion: Look for constants in comparison operations that might be module hashes")
        
        if analysis_results["resolver_candidates"]:
            resolver_names = [r.get("function_name", "") for r in analysis_results["resolver_candidates"] if isinstance(r, dict)]
            recommendations.append(f"Resolver function(s): {', '.join(resolver_names)}")
        
        if all_hash_algorithms:
            hash_types = list(set([h.get("type", "") for h in all_hash_algorithms if isinstance(h, dict)]))
            recommendations.append(f"Hash algorithm(s) detected: {', '.join(hash_types)}")
        
        analysis_results["recommendations"] = recommendations
        
        return {
            "success": True,
            "analysis_results": analysis_results,
            "target_function": target_function,
            "timestamp": int(time.time() * 1000)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": {
                "code": "COMPREHENSIVE_ANALYSIS_ERROR",
                "message": f"Error in comprehensive API deobfuscation analysis: {str(e)}"
            },
            "timestamp": int(time.time() * 1000)
        }

@mcp.tool()
def analysis_trace_function_dependencies(
    name: Optional[str] = None,
    address: Optional[str] = None,
    max_depth: int = 3,
    port: Optional[int] = None
) -> dict:
    """Trace function dependencies to understand program logic flow.
    
    Args:
        name: Starting function name (mutually exclusive with address)
        address: Starting function address (mutually exclusive with name)
        max_depth: Maximum depth to trace dependencies (default: 3)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: {
            success: bool,
            trace_results: {
                starting_function: str,
                called_functions: [str],
                calling_functions: [str],
                dependency_chain: [dict],
                potential_helpers: [str]
            }
        }
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    try:
        start_func = name or address
        
        # Get functions this one calls (outgoing calls)
        called_functions = []
        calling_functions = []
        dependency_chain = []
        potential_helpers = []
        
        # Analyze the starting function's calls
        call_args_result = functions_list_call_args(name=name, address=address, port=port)
        if isinstance(call_args_result, dict) and call_args_result.get("success"):
            calls = call_args_result.get("calls", [])
            for call in calls:
                if isinstance(call, dict):
                    callee = call.get("callee", "")
                    if callee and callee not in called_functions:
                        called_functions.append(callee)
        
        # Get xrefs to find what calls this function
        # First, resolve function name to address if needed
        func_address = address
        if not func_address and name:
            func_info = functions_get(name=name, port=port)
            if isinstance(func_info, dict) and func_info.get("success"):
                func_result = func_info.get("result", {})
                func_address = func_result.get("addr") or func_result.get("address")
        
        if func_address:
            xrefs_result = xrefs_list(to_addr=func_address, port=port)
            if isinstance(xrefs_result, dict) and xrefs_result.get("success"):
                xrefs_data = xrefs_result.get("result", {})
            if isinstance(xrefs_data, dict):
                xrefs_list_data = xrefs_data.get("xrefs", [])
                
                for xref in xrefs_list_data:
                    if isinstance(xref, dict) and xref.get("type") == "CALL":
                        caller_addr = xref.get("from_address", "")
                        if caller_addr:
                            # Get the function containing this address
                            caller_func = functions_get(address=caller_addr, port=port)
                            if isinstance(caller_func, dict) and caller_func.get("success"):
                                caller_result = caller_func.get("result", {})
                                caller_name = caller_result.get("name", "") if isinstance(caller_result, dict) else ""
                                if caller_name and caller_name not in calling_functions:
                                    calling_functions.append(caller_name)
        
        # Build dependency chain by analyzing called functions recursively
        analyzed_functions = {start_func}
        
        def analyze_function_depth(func_name, current_depth):
            if current_depth >= max_depth or func_name in analyzed_functions:
                return
            
            analyzed_functions.add(func_name)
            
            # Get this function's information
            func_info = functions_get(name=func_name, port=port)
            if isinstance(func_info, dict) and func_info.get("success"):
                func_result = func_info.get("result", {})
                func_addr = func_result.get("address", "") if isinstance(func_result, dict) else ""
                
                chain_entry = {
                    "function": func_name,
                    "address": func_addr,
                    "depth": current_depth,
                    "calls": [],
                    "xor_constants": [],
                    "hash_algorithms": []
                }
                
                # Analyze this function for XOR constants
                xor_result = functions_detect_xor_constants(name=func_name, port=port)
                if isinstance(xor_result, dict) and xor_result.get("success"):
                    constants = xor_result.get("xor_constants", [])
                    high_conf_constants = [c for c in constants if c.get("confidence", 0) >= 0.7]
                    chain_entry["xor_constants"] = high_conf_constants
                    
                    if high_conf_constants:
                        potential_helpers.append(f"{func_name} (XOR constants found)")
                
                # Analyze for hash algorithms
                hash_result = functions_detect_hash_algorithms(name=func_name, port=port)
                if isinstance(hash_result, dict) and hash_result.get("success"):
                    algorithms = hash_result.get("algorithms", [])
                    high_conf_algos = [a for a in algorithms if a.get("confidence", 0) >= 0.6]
                    chain_entry["hash_algorithms"] = high_conf_algos
                    
                    if high_conf_algos:
                        potential_helpers.append(f"{func_name} (Hash algorithm: {', '.join([a['type'] for a in high_conf_algos])})")
                
                # Get functions this one calls
                call_args = functions_list_call_args(name=func_name, port=port)
                if isinstance(call_args, dict) and call_args.get("success"):
                    calls = call_args.get("calls", [])
                    for call in calls:
                        if isinstance(call, dict):
                            callee = call.get("callee", "")
                            if callee:
                                chain_entry["calls"].append(callee)
                                # Recursively analyze called functions
                                analyze_function_depth(callee, current_depth + 1)
                
                dependency_chain.append(chain_entry)
        
        # Start recursive analysis from called functions
        for called_func in called_functions:
            analyze_function_depth(called_func, 1)
        
        # Also analyze calling functions (they might contain the XOR key)
        for calling_func in calling_functions:
            if calling_func not in analyzed_functions:
                analyze_function_depth(calling_func, 1)
        
        return {
            "success": True,
            "trace_results": {
                "starting_function": start_func,
                "called_functions": called_functions,
                "calling_functions": calling_functions,
                "dependency_chain": dependency_chain,
                "potential_helpers": list(set(potential_helpers)),
                "analyzed_function_count": len(analyzed_functions)
            },
            "timestamp": int(time.time() * 1000)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": {
                "code": "TRACE_ERROR",
                "message": f"Error tracing function dependencies: {str(e)}"
            },
            "timestamp": int(time.time() * 1000)
        }

@mcp.tool()
def analysis_find_related_functions(
    target_function: str,
    relationship_types: Optional[List[str]] = None,
    port: Optional[int] = None
) -> dict:
    """Find functions related to a target function through various relationships.
    
    Args:
        target_function: Function name or address to find relationships for
        relationship_types: Types of relationships to find (calls, xrefs, shared_data, similar_names)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: {
            success: bool,
            relationships: {
                calls: [str],
                called_by: [str],
                shared_constants: [dict],
                similar_names: [str],
                data_references: [str]
            }
        }
    """
    port = _get_instance_port(port)
    
    if relationship_types is None:
        relationship_types = ["calls", "xrefs", "shared_data", "similar_names"]
    
    try:
        relationships = {
            "calls": [],
            "called_by": [],
            "shared_constants": [],
            "similar_names": [],
            "data_references": []
        }
        
        # Find direct call relationships
        if "calls" in relationship_types or "xrefs" in relationship_types:
            # Functions this target calls
            call_args_result = functions_list_call_args(name=target_function, port=port)
            if isinstance(call_args_result, dict) and call_args_result.get("success"):
                calls = call_args_result.get("calls", [])
                for call in calls:
                    if isinstance(call, dict):
                        callee = call.get("callee", "")
                        if callee and callee not in relationships["calls"]:
                            relationships["calls"].append(callee)
            
            # Functions that call this target
            # First resolve target function name to address if needed
            target_address = None
            if target_function.startswith("0x") or target_function.isdigit():
                target_address = target_function
            else:
                func_info = functions_get(name=target_function, port=port)
                if isinstance(func_info, dict) and func_info.get("success"):
                    func_result = func_info.get("result", {})
                    target_address = func_result.get("addr") or func_result.get("address")
            
            if target_address:
                xrefs_result = xrefs_list(to_addr=target_address, port=port)
                if isinstance(xrefs_result, dict) and xrefs_result.get("success"):
                    xrefs_data = xrefs_result.get("result", {})
                if isinstance(xrefs_data, dict):
                    xrefs_list_data = xrefs_data.get("xrefs", [])
                    
                    for xref in xrefs_list_data:
                        if isinstance(xref, dict) and xref.get("type") == "CALL":
                            caller_addr = xref.get("from_address", "")
                            if caller_addr:
                                caller_func = functions_get(address=caller_addr, port=port)
                                if isinstance(caller_func, dict) and caller_func.get("success"):
                                    caller_result = caller_func.get("result", {})
                                    caller_name = caller_result.get("name", "") if isinstance(caller_result, dict) else ""
                                    if caller_name and caller_name not in relationships["called_by"]:
                                        relationships["called_by"].append(caller_name)
        
        # Find functions with shared constants (potential XOR keys, hash values)
        if "shared_data" in relationship_types:
            target_constants = set()
            
            # Get constants from target function
            xor_result = functions_detect_xor_constants(name=target_function, port=port)
            if isinstance(xor_result, dict) and xor_result.get("success"):
                constants = xor_result.get("xor_constants", [])
                for const in constants:
                    target_constants.add(const.get("constant_hex", ""))
            
            # Check related functions for shared constants
            all_related = relationships["calls"] + relationships["called_by"]
            for related_func in all_related:
                related_xor = functions_detect_xor_constants(name=related_func, port=port)
                if isinstance(related_xor, dict) and related_xor.get("success"):
                    related_constants = related_xor.get("xor_constants", [])
                    for const in related_constants:
                        const_hex = const.get("constant_hex", "")
                        if const_hex in target_constants:
                            relationships["shared_constants"].append({
                                "function": related_func,
                                "shared_constant": const_hex,
                                "context": const.get("context", "")
                            })
        
        # Find functions with similar names (might be part of same module)
        if "similar_names" in relationship_types:
            functions_result = functions_list(port=port, limit=1000)
            if isinstance(functions_result, dict) and functions_result.get("success"):
                functions_data = functions_result.get("result", {})
                functions_list_data = functions_data.get("functions", []) if isinstance(functions_data, dict) else []
                
                target_base = target_function.split('_')[0] if '_' in target_function else target_function[:8]
                
                for func in functions_list_data:
                    if isinstance(func, dict):
                        func_name = func.get("name", "")
                        if func_name and func_name != target_function:
                            # Check for similar naming patterns
                            if (target_base in func_name or 
                                func_name.startswith(target_function[:6]) or
                                (len(target_function) > 8 and target_function[:8] in func_name)):
                                relationships["similar_names"].append(func_name)
        
        return {
            "success": True,
            "relationships": relationships,
            "target_function": target_function,
            "timestamp": int(time.time() * 1000)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": {
                "code": "RELATIONSHIP_ERROR",
                "message": f"Error finding related functions: {str(e)}"
            },
            "timestamp": int(time.time() * 1000)
        }

@mcp.tool()
def analysis_guided_xor_key_search(
    resolver_function: str,
    port: Optional[int] = None
) -> dict:
    """Perform guided search for XOR keys by following program logic from resolver.
    
    Args:
        resolver_function: Name of the identified resolver function
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: {
            success: bool,
            search_results: {
                xor_keys_found: [dict],
                search_path: [str],
                confidence_analysis: dict,
                recommended_key: str
            }
        }
    """
    port = _get_instance_port(port)
    
    try:
        search_results = {
            "xor_keys_found": [],
            "search_path": [],
            "confidence_analysis": {},
            "recommended_key": None
        }
        
        # Step 1: Analyze the resolver function itself
        search_results["search_path"].append(f"Analyzing resolver: {resolver_function}")
        
        resolver_xor = functions_detect_xor_constants(name=resolver_function, port=port)
        if isinstance(resolver_xor, dict) and resolver_xor.get("success"):
            constants = resolver_xor.get("xor_constants", [])
            for const in constants:
                const["source_function"] = resolver_function
                const["search_step"] = "resolver_analysis"
                search_results["xor_keys_found"].append(const)
        
        # Step 2: Find and analyze functions called by the resolver
        trace_result = analysis_trace_function_dependencies(name=resolver_function, max_depth=2, port=port)
        if isinstance(trace_result, dict) and trace_result.get("success"):
            trace_data = trace_result.get("trace_results", {})
            dependency_chain = trace_data.get("dependency_chain", [])
            
            for dep in dependency_chain:
                func_name = dep.get("function", "")
                if func_name:
                    search_results["search_path"].append(f"Analyzing dependency: {func_name}")
                    
                    # Add XOR constants from dependency chain
                    xor_constants = dep.get("xor_constants", [])
                    for const in xor_constants:
                        const["source_function"] = func_name
                        const["search_step"] = "dependency_analysis"
                        search_results["xor_keys_found"].append(const)
        
        # Step 3: Find and analyze functions that call the resolver
        related_result = analysis_find_related_functions(resolver_function, ["xrefs"], port=port)
        if isinstance(related_result, dict) and related_result.get("success"):
            relationships = related_result.get("relationships", {})
            called_by = relationships.get("called_by", [])
            
            for caller in called_by:
                search_results["search_path"].append(f"Analyzing caller: {caller}")
                
                caller_xor = functions_detect_xor_constants(name=caller, port=port)
                if isinstance(caller_xor, dict) and caller_xor.get("success"):
                    constants = caller_xor.get("xor_constants", [])
                    for const in constants:
                        const["source_function"] = caller
                        const["search_step"] = "caller_analysis"
                        search_results["xor_keys_found"].append(const)
        
        # Step 4: Look for functions with similar names (might be related modules)
        similar_funcs = []
        if resolver_function.startswith("FUN_"):
            # Extract address pattern and look for nearby functions
            try:
                addr_part = resolver_function.split("_")[1]
                base_addr = int(addr_part, 16)
                
                # Look for functions within a reasonable range
                functions_result = functions_list(port=port, limit=1000)
                if isinstance(functions_result, dict) and functions_result.get("success"):
                    functions_data = functions_result.get("result", {})
                    functions_list_data = functions_data.get("functions", []) if isinstance(functions_data, dict) else []
                    
                    for func in functions_list_data:
                        if isinstance(func, dict):
                            func_name = func.get("name", "")
                            if func_name.startswith("FUN_"):
                                try:
                                    func_addr_part = func_name.split("_")[1]
                                    func_addr = int(func_addr_part, 16)
                                    # Look for functions within 0x10000 range
                                    if abs(func_addr - base_addr) <= 0x10000 and func_name != resolver_function:
                                        similar_funcs.append(func_name)
                                except (ValueError, IndexError):
                                    continue
            except (ValueError, IndexError):
                pass
        
        # Analyze similar functions
        for similar_func in similar_funcs[:10]:  # Limit to 10 to avoid too much processing
            search_results["search_path"].append(f"Analyzing similar function: {similar_func}")
            
            similar_xor = functions_detect_xor_constants(name=similar_func, port=port)
            if isinstance(similar_xor, dict) and similar_xor.get("success"):
                constants = similar_xor.get("xor_constants", [])
                for const in constants:
                    const["source_function"] = similar_func
                    const["search_step"] = "similar_function_analysis"
                    search_results["xor_keys_found"].append(const)
        
        # Step 5: Confidence analysis and recommendation
        if search_results["xor_keys_found"]:
            # Group by constant value
            constant_groups = {}
            for const in search_results["xor_keys_found"]:
                const_hex = const.get("constant_hex", "")
                if const_hex not in constant_groups:
                    constant_groups[const_hex] = []
                constant_groups[const_hex].append(const)
            
            # Analyze each constant group
            best_confidence = 0
            best_constant = None
            
            for const_hex, instances in constant_groups.items():
                total_confidence = sum(inst.get("confidence", 0) for inst in instances)
                avg_confidence = total_confidence / len(instances)
                occurrence_count = len(instances)
                
                # Boost score for multiple occurrences
                final_score = avg_confidence + (occurrence_count - 1) * 0.1
                
                search_results["confidence_analysis"][const_hex] = {
                    "average_confidence": round(avg_confidence, 2),
                    "occurrence_count": occurrence_count,
                    "final_score": round(final_score, 2),
                    "sources": [inst.get("source_function", "") for inst in instances]
                }
                
                if final_score > best_confidence:
                    best_confidence = final_score
                    best_constant = const_hex
            
            search_results["recommended_key"] = best_constant
        
        return {
            "success": True,
            "search_results": search_results,
            "resolver_function": resolver_function,
            "timestamp": int(time.time() * 1000)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": {
                "code": "SEARCH_ERROR",
                "message": f"Error in guided XOR key search: {str(e)}"
            },
            "timestamp": int(time.time() * 1000)
        }

# Memory tools
@mcp.tool()
def memory_read(address: str, length: int = 16, format: str = "hex", port: Optional[int] = None) -> dict:
    """Read bytes from memory
    
    Args:
        address: Memory address in hex format
        length: Number of bytes to read (default: 16)
        format: Output format - "hex", "base64", or "string" (default: "hex")
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: {
            "address": original address,
            "length": bytes read,
            "format": output format,
            "hexBytes": the memory contents as hex string,
            "rawBytes": the memory contents as base64 string,
            "timestamp": response timestamp
        }
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    # Original implementation: query-style parameters against /memory
    params = {
        "address": address,
        "length": length,
        "format": format,
    }

    # Header/MZ guard with cropping
    try:
        p = _get_instance_port(port)
        a_int = int(str(address).replace("0x", ""), 16)
        a_int, length, warn = _crop_away_header_guard(p, a_int, int(length))
        address = f"{a_int:08X}"
    except Exception:
        warn = None

    response = safe_get(port, "memory", params)
    simplified = simplify_response(response)

    # Shape result to pass through important fields, like in the original bridge
    if "result" in simplified and isinstance(simplified["result"], dict):
        result = simplified["result"]
        memory_info = {
            "success": True,
            "address": result.get("address", address),
            "length": result.get("bytesRead", length),
            "format": format,
            "timestamp": simplified.get("timestamp", int(time.time() * 1000)),
        }
        if warn:
            memory_info.setdefault("warnings", []).append(warn)
        if "hexBytes" in result:
            memory_info["hexBytes"] = result["hexBytes"]
        if "rawBytes" in result:
            memory_info["rawBytes"] = result["rawBytes"]
        return memory_info

    return simplified

@mcp.tool()
def memory_write(address: str, bytes_data: str, format: str = "hex", port: Optional[int] = None) -> dict:
    """Write bytes to memory (use with caution)
    
    Args:
        address: Memory address in hex format
        bytes_data: Data to write (format depends on 'format' parameter)
        format: Input format - "hex", "base64", or "string" (default: "hex")
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: Operation result with success status
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    if not bytes_data:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Bytes parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    payload = {
        "bytes": bytes_data,
        "format": format,
    }
    response = safe_patch(port, f"programs/current/memory/{address}", payload)
    return simplify_response(response)


# Range-based memory helpers for exact-byte extraction
@mcp.tool()
def memory_read_range(
    start_address: Optional[str] = None,
    end_address: Optional[str] = None,
    format: str = "base64",
    port: Optional[int] = None,
    address: Optional[str] = None,
    length: Optional[int] = None,
    anchor: Optional[dict] = None,
) -> dict:
    """Read a contiguous range of bytes [start, end] from memory.

    Args:
        start_address: Start address in hex string (e.g., "00420000")
        end_address: End address in hex string (inclusive)
        format: hex|base64|string (default base64)
        port: Specific Ghidra instance port (optional)

    Returns: Same shape as memory_read, with rawBytes/hexBytes for the full range.
    """
    # Support both (start_address,end_address) and (address,length)
    if start_address and end_address:
        try:
            start = int(start_address, 16)
            end = int(end_address, 16)
        except Exception:
            return {
                "success": False,
                "error": {"code": "INVALID_ADDRESS", "message": "Addresses must be hex strings"},
                "timestamp": int(time.time() * 1000),
            }
    elif address and isinstance(length, int):
        try:
            start = int(address, 16)
            end = start + int(length) - 1
        except Exception:
            return {
                "success": False,
                "error": {"code": "INVALID_PARAMETER", "message": "address must be hex and length integer"},
                "timestamp": int(time.time() * 1000),
            }
    else:
        return {
            "success": False,
            "error": {"code": "MISSING_PARAMETER", "message": "Provide start_address+end_address or address+length"},
            "timestamp": int(time.time() * 1000),
        }
    if end < start:
        start, end = end, start
    total_len = (end - start) + 1

    # Optional anchor enforcement with auto-synthesis
    p = _get_instance_port(port)
    if str(os.environ.get("GHIDRA_ENFORCE_ANCHORED_READS", "0")).strip().lower() not in ("0", "false", "no", "off"):
        if not isinstance(anchor, dict) or not anchor.get("type"):
            auto = _infer_anchor_for_addr(p, int(start), int(total_len))
            if auto is not None:
                anchor = auto
            else:
                err = _guard_require_anchor({"anchor": None})
                if err:
                    return err

    # Page reads at 1024 bytes due to observed server limit
    CHUNK = 1024
    # Crop away header guard once up-front
    cur, cropped_len, crop_warn = _crop_away_header_guard(p, int(start), int(total_len))
    remaining = int(cropped_len)
    buf = bytearray()
    # Collect any first-error details (optional)
    first_error = None

    # Import local to avoid global dependency elsewhere
    import base64 as _b64  # noqa: F401

    while remaining > 0:
        req = CHUNK if remaining > CHUNK else remaining
        # Guard against header overlap at chunk level too
        # Chunk-level guard should not hit after cropping, but keep defensive check
        if _guard_overlaps_header(p, cur, int(req)):
            first_error = {
                "success": False,
                "error": {"code": "GUARD_HEADER", "message": "Reads overlapping MZ/PE headers are refused by policy"},
                "timestamp": int(time.time() * 1000)
            }
            break
        res = memory_read(address=f"{cur:08X}", length=int(req), format=format, port=port)  # type: ignore
        if not res or not res.get("success", False):
            first_error = res
            break
        raw_b64 = res.get("rawBytes")
        hex_str = res.get("hexBytes")
        try:
            if isinstance(raw_b64, str):
                chunk = _b64.b64decode(raw_b64)
            elif isinstance(hex_str, str):
                # hex string is space-separated bytes; remove spaces
                chunk = bytes.fromhex(hex_str.replace(" ", ""))
            else:
                # Nothing to append, stop
                break
        except Exception:
            # Malformed payload; stop
            break

        if not chunk:
            # Avoid infinite loop
            break

        buf.extend(chunk)
        got = len(chunk)
        cur += got
        remaining -= got

        # If the server returned less than requested, don't assume more is available
        if got < req:
            break

    # Build aggregated result in the same shape as memory_read
    agg = {
        "success": True,
        "address": f"{int(cur if buf else start):08X}",
        "length": len(buf),
        "format": format,
        "timestamp": int(time.time() * 1000),
        "rawBytes": _b64.b64encode(bytes(buf)).decode("ascii"),
        "hexBytes": bytes(buf).hex(" ").upper(),
    }
    if crop_warn:
        agg.setdefault("warnings", []).append(crop_warn)

    # If nothing was read and we had an error, surface it
    if len(buf) == 0 and first_error:
        return first_error

    return agg


@mcp.tool()
def memory_read_ranges(
    ranges: Optional[List[Dict[str, Any]]] = None,
    format: str = "base64",
    port: Optional[int] = None,
    concat: bool = True,
    # Back-compat/adaptive inputs some agents incorrectly send:
    start: Optional[str] = None,
    end: Optional[str] = None,
    # Also accept explicit *_address synonyms used elsewhere
    start_address: Optional[str] = None,
    end_address: Optional[str] = None,
    address: Optional[str] = None,
    length: Optional[int] = None,
    # Output throttling:
    include_bytes: bool = True,
    include_hex: bool = False,
    max_segment_bytes: Optional[int] = None,
    max_concatenated_bytes: Optional[int] = None,
    # Provenance (optional, enforced via env):
    anchor: Optional[dict] = None,
) -> dict:
    """Read multiple ranges and optionally concatenate results in address order.

    Accepts any of:
      - ranges=[ { "start": "00420000", "end": "00420300" }, ... ] (inclusive)
      - ranges=[ { "address": "00420000", "length": 768 }, ... ]
      - ranges={single dict in either of the above forms}
      - start="00420000", end="00420300" (single range)
      - address="00420000", length=768 (single range)

    Returns: {
      success, segments: [{ address, length, rawBytes?, hexBytes? }...],
      concatenatedRaw?: base64, warnings?: [str]
    }
    """
    # Normalize inputs to a list of dicts.
    norm_input: List[Dict[str, Any]] = []
    if ranges is None:
        # Try top-level single range forms (support snake_case synonyms)
        a_start = start or start_address or address
        a_end = end or end_address
        a_len = length

        if a_start and a_end:
            norm_input = [{"start": a_start, "end": a_end}]
        elif a_start and a_len:
            norm_input = [{"address": a_start, "length": a_len}]
        elif a_end and a_len:
            # Compute start from end - length + 1
            try:
                # parse end as hex/dec
                e_s = str(a_end)
                e = int(e_s, 16) if e_s.lower().startswith("0x") or any(c in e_s.lower() for c in list("abcdef")) else int(e_s, 10)
                l = int(a_len)  # length already numeric in typical calls
                if l > 0:
                    s = max(0, e - (l - 1))
                    norm_input = [{"start": f"{s:08X}", "end": f"{e:08X}"}]
            except Exception:
                pass
        elif address and a_len:
            norm_input = [{"address": address, "length": a_len}]
        else:
            return {"success": False, "error": {"code": "MISSING_PARAMETER", "message": "Provide 'ranges' or top-level start/end or address/length or start/length or end/length"}, "timestamp": int(time.time() * 1000)}
    elif isinstance(ranges, dict):  # type: ignore[unreachable]
        # Some agents might pass a single dict instead of list
        norm_input = [ranges]  # type: ignore[list-item]
    elif isinstance(ranges, list):
        norm_input = [r for r in ranges if isinstance(r, dict)]
    else:
        return {"success": False, "error": {"code": "INVALID_PARAMETER", "message": "ranges must be a list of dicts or a single dict"}, "timestamp": int(time.time() * 1000)}

    if not norm_input:
        return {"success": False, "error": {"code": "MISSING_PARAMETER", "message": "ranges must contain at least one entry"}, "timestamp": int(time.time() * 1000)}

    # Defer optional anchor enforcement until after input normalization

    warnings: List[str] = []
    segs: List[Dict[str, Any]] = []

    # Normalize items into (address_hex, length)
    norm: List[Dict[str, Any]] = []
    def _get_first_key(d: Dict[str, Any], keys: List[str]) -> Optional[Any]:
        for k in keys:
            if k in d:
                return d[k]
        return None
    def _parse_addr(v: Any) -> Optional[int]:
        try:
            if v is None:
                return None
            if isinstance(v, int):
                return int(v)
            if isinstance(v, dict):
                nested = _get_first_key(
                    v,
                    [
                        "start_address",
                        "startAddress",
                        "end_address",
                        "endAddress",
                        "address",
                        "addr",
                        "value",
                        "start",
                        "end",
                    ],
                )
                return _parse_addr(nested)
            s = str(v).strip()
            # Try hex first (accept optional 0x)
            if s.lower().startswith("0x"):
                return int(s, 16)
            # If string contains hex letters, treat as hex
            if any(c in s.lower() for c in list("abcdef")):
                return int(s, 16)
            # Fallback: decimal
            return int(s, 10)
        except Exception:
            return None
    def _parse_len(v: Any) -> Optional[int]:
        try:
            if v is None:
                return None
            if isinstance(v, int):
                return v if v > 0 else None
            if isinstance(v, dict):
                nested = _get_first_key(v, ["length", "len", "size", "count", "bytes"])
                return _parse_len(nested)
            s = str(v).strip()
            if s.lower().startswith("0x"):
                n = int(s, 16)
            else:
                n = int(s, 10)
            return n if n > 0 else None
        except Exception:
            return None
    for r in norm_input:
        if not isinstance(r, dict):
            continue
        # Accept both snake_case and camelCase keys
        s_val = _get_first_key(r, ["start", "start_address", "startAddress"])  # type: ignore
        e_val = _get_first_key(r, ["end", "end_address", "endAddress"])      # type: ignore
        if s_val is not None and e_val is not None:
            try:
                s_parsed = _parse_addr(s_val)
                e_parsed = _parse_addr(e_val)
                if s_parsed is None or e_parsed is None:
                    raise ValueError("bad addr")
                s = int(s_parsed)
                e = int(e_parsed)
                if e < s:
                    s, e = e, s
                l = (e - s) + 1
                norm.append({"address": f"{s:08X}", "length": int(l)})
            except Exception:
                continue
            continue

        # Address + length style (support aliases)
        a_val = _get_first_key(r, ["address", "addr", "start", "start_address", "startAddress"])  # last three as fallback
        l_val = _get_first_key(r, ["length", "len", "size"])
        if a_val is not None and l_val is not None:
            try:
                s_parsed = _parse_addr(a_val)
                l_parsed = _parse_len(l_val)
                if s_parsed is None or l_parsed is None or l_parsed <= 0:
                    continue
                norm.append({"address": f"{int(s_parsed):08X}", "length": int(l_parsed)})
            except Exception:
                continue
    if not norm:
        return {"success": False, "error": {"code": "INVALID_PARAMETER", "message": "ranges contain no valid entries"}, "timestamp": int(time.time() * 1000)}

    # Optional anchor enforcement with auto-synthesis now that we have normalized input
    p = _get_instance_port(port)
    if str(os.environ.get("GHIDRA_ENFORCE_ANCHORED_READS", "0")).strip().lower() not in ("0", "false", "no", "off"):
        if not isinstance(anchor, dict) or not anchor.get("type"):
            try:
                a0_i = int(norm[0]["address"], 16)
                l0 = int(norm[0]["length"])
                auto = _infer_anchor_for_addr(p, a0_i, l0)
                if auto is not None:
                    anchor = auto
                if not isinstance(anchor, dict) or not anchor.get("type"):
                    err = _guard_require_anchor({"anchor": None})
                    if err:
                        return err
            except Exception:
                err = _guard_require_anchor({"anchor": None})
                if err:
                    return err

    # Sort by address
    norm.sort(key=lambda x: int(x["address"], 16))

    # Acquire each segment using memory_read_range (handles paging at 1024 bytes)
    for n in norm:
        # Guard header overlap before issuing read
        try:
            addr_i = int(str(n["address"]), 16)
        except Exception:
            addr_i = None
        # Guard-aware cropping per segment
        if addr_i is not None:
            new_start, new_len, crop_warn = _crop_away_header_guard(p, addr_i, int(n["length"]))
            if crop_warn:
                warnings.append(crop_warn.replace("region", f"region at {n['address']}"))
            if new_len <= 0:
                continue
            n_to_read = {"address": f"{int(new_start):08X}", "length": int(new_len)}
        else:
            n_to_read = n
        res = memory_read_range(address=n_to_read["address"], length=n_to_read["length"], format=format, port=port, anchor=anchor)  # type: ignore
        if not res or not res.get("success", False):
            warnings.append(f"Failed to read {n['address']} len {n['length']}")
            continue
        seg = {"address": res.get("address", n["address"]), "length": res.get("length", n["length"]) }
        # Optionally include bytes/hex with truncation
        try:
            import base64 as _b64
            # Always prefer using rawBytes if present; otherwise derive from hexBytes if needed
            rb = res.get("rawBytes")
            hb = res.get("hexBytes")

            if include_bytes:
                if rb is not None:
                    if isinstance(max_segment_bytes, int) and max_segment_bytes > 0:
                        try:
                            b = _b64.b64decode(rb)
                            if len(b) > max_segment_bytes:
                                seg["rawBytesPreview"] = _b64.b64encode(b[:max_segment_bytes]).decode("ascii")
                                seg["rawBytesTotal"] = len(b)
                            else:
                                seg["rawBytes"] = rb
                            # Correct length if the server's length metadata is inconsistent
                            try:
                                seg["length"] = int(len(b))
                            except Exception:
                                pass
                        except Exception:
                            warnings.append(f"base64 decode failed at {seg['address']}")
                    else:
                        seg["rawBytes"] = rb
                        # Correct length based on bytes when possible
                        try:
                            b = _b64.b64decode(rb)
                            seg["length"] = int(len(b))
                        except Exception:
                            pass
                elif isinstance(hb, str):
                    # Fall back: derive raw from hex
                    try:
                        b = bytes.fromhex(hb)
                        if isinstance(max_segment_bytes, int) and max_segment_bytes > 0 and len(b) > max_segment_bytes:
                            seg["rawBytesPreview"] = _b64.b64encode(b[:max_segment_bytes]).decode("ascii")
                            seg["rawBytesTotal"] = len(b)
                        else:
                            seg["rawBytes"] = _b64.b64encode(b).decode("ascii")
                        try:
                            seg["length"] = int(len(b))
                        except Exception:
                            pass
                    except Exception:
                        warnings.append(f"hex->raw fallback failed at {seg['address']}")

            if include_hex:
                if isinstance(hb, str):
                    if isinstance(max_segment_bytes, int) and max_segment_bytes > 0:
                        max_hex = max_segment_bytes * 2
                        if len(hb) > max_hex:
                            seg["hexBytesPreview"] = hb[:max_hex]
                            seg["hexBytesTotal"] = (len(hb) // 2)
                        else:
                            seg["hexBytes"] = hb
                    else:
                        seg["hexBytes"] = hb
                elif rb is not None:
                    # Fall back: derive hex from raw
                    try:
                        b = _b64.b64decode(rb)
                        h = b.hex().upper()
                        if isinstance(max_segment_bytes, int) and max_segment_bytes > 0 and len(b) > max_segment_bytes:
                            seg["hexBytesPreview"] = h[: max_segment_bytes * 2]
                            seg["hexBytesTotal"] = len(b)
                        else:
                            seg["hexBytes"] = h
                    except Exception:
                        warnings.append(f"raw->hex fallback failed at {seg['address']}")
        except Exception as _:
            warnings.append(f"bytes preview failed at {seg['address']}")
        segs.append(seg)

    out: Dict[str, Any] = {"success": True, "segments": segs, "timestamp": int(time.time() * 1000)}

    # Optional concatenation
    if concat and (include_bytes or include_hex) and segs:
        try:
            import base64 as _b64
            cat = bytearray()
            last_end = None
            for seg in segs:
                rb = seg.get("rawBytes")
                hb = seg.get("hexBytes")
                if rb:
                    b = _b64.b64decode(rb)
                elif isinstance(hb, str):
                    b = bytes.fromhex(hb)
                else:
                    b = b""
                # Track contiguity
                addr = int(seg["address"], 16)
                if last_end is not None and addr > last_end:
                    warnings.append(f"Gap detected between segments at 0x{last_end:08X} -> 0x{addr:08X}")
                # next expected start after this segment
                last_end = addr + int(seg["length"])
                if isinstance(max_concatenated_bytes, int) and max_concatenated_bytes > 0:
                    remaining = max_concatenated_bytes - len(cat)
                    if remaining <= 0:
                        continue
                    cat.extend(b[:remaining])
                else:
                    cat.extend(b)
            # Emit concatenated outputs based on include flags
            if include_bytes:
                out["concatenatedRaw"] = _b64.b64encode(bytes(cat)).decode("ascii")
            if include_hex:
                out["concatenatedHex"] = bytes(cat).hex().upper()
            if warnings:
                out["warnings"] = warnings
        except Exception as e:
            out.setdefault("warnings", []).append(f"concat failed: {e}")
    else:
        if warnings:
            out["warnings"] = warnings

    return out


# Lightweight range scanner that summarizes pages without returning bytes
def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126)
    return printable / max(1, len(data))


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from math import log2
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c / n
            ent -= p * log2(p)
    return ent


@mcp.tool()
def memory_scan_range(
    start_address: str,
    end_address: str,
    page_size: int = 65536,
    stride: Optional[int] = None,
    max_pages: Optional[int] = 512,
    port: Optional[int] = None,
) -> dict:
    """Summarize a large range by scanning it in pages and returning only stats per page.

    Returns: { success, pages: [ { address, length, printable_ratio, shannon_entropy }... ], warnings? }
    """
    if not start_address or not end_address:
        return {"success": False, "error": {"code": "MISSING_PARAMETER", "message": "start_address and end_address are required"}, "timestamp": int(time.time() * 1000)}
    try:
        start = int(start_address, 16)
        end = int(end_address, 16)
    except Exception:
        return {"success": False, "error": {"code": "INVALID_ADDRESS", "message": "Addresses must be hex"}, "timestamp": int(time.time() * 1000)}
    if end < start:
        start, end = end, start
    if page_size <= 0:
        page_size = 65536
    if stride is None or stride <= 0:
        stride = page_size
    warnings: List[str] = []
    pages: List[Dict[str, Any]] = []
    cur = start
    scanned = 0
    p = _get_instance_port(port)
    while cur <= end:
        length = min(page_size, (end - cur) + 1)
        # Crop away header-guard overlap instead of skipping entire page
        try:
            rd_start, rd_len, crop_warn = _crop_away_header_guard(p, int(cur), int(length))
        except Exception:
            rd_start, rd_len, crop_warn = int(cur), int(length), None
        if crop_warn:
            warnings.append(f"{crop_warn} at 0x{cur:08X}")
        if rd_len <= 0:
            # Nothing to read after cropping; advance
            cur += stride
            scanned += 1
            if isinstance(max_pages, int) and max_pages > 0 and scanned >= max_pages:
                warnings.append("max_pages reached; truncated")
                break
            continue
        # Use range reader (paginates internally at 1024) for robustness
        res = memory_read_range(address=f"{rd_start:08X}", length=int(rd_len), format="base64", port=port)  # type: ignore
        if not res or not res.get("success", False):
            # enrich warning with any error info
            try:
                err = res.get("error") if isinstance(res, dict) else None
                if isinstance(err, dict):
                    code = err.get("code")
                    msg = err.get("message")
                    if code or msg:
                        warnings.append(f"read failed at 0x{cur:08X}: {code or ''} {msg or ''}".strip())
                    else:
                        warnings.append(f"read failed at 0x{cur:08X}")
                else:
                    warnings.append(f"read failed at 0x{cur:08X}")
            except Exception:
                warnings.append(f"read failed at 0x{cur:08X}")
        else:
            try:
                import base64 as _b64
                b = _b64.b64decode(res.get("rawBytes") or res.get("concatenatedRaw") or b"")
                pages.append({
                    "address": f"{rd_start:08X}",
                    "length": int(len(b) if isinstance(b, (bytes, bytearray)) else rd_len),
                    "printable_ratio": _printable_ratio(b if isinstance(b, (bytes, bytearray)) else b""),
                    "shannon_entropy": _shannon_entropy(b if isinstance(b, (bytes, bytearray)) else b""),
                })
            except Exception:
                warnings.append(f"decode failed at 0x{cur:08X}")
        scanned += 1
        if isinstance(max_pages, int) and max_pages > 0 and scanned >= max_pages:
            warnings.append("max_pages reached; truncated")
            break
        cur += stride
    out: Dict[str, Any] = {"success": True, "pages": pages, "timestamp": int(time.time() * 1000)}
    if warnings:
        out["warnings"] = warnings
    return out


@mcp.tool()
def patch_int3_ret_to_call_eax(
    start_address: str,
    end_address: str,
    port: Optional[int] = None,
) -> dict:
    """Scan a memory range and patch occurrences of 'int3; ret' (CC C3) to 'call eax' (FF D0).

    Inputs:
      - start_address, end_address: inclusive hex addresses (e.g., "00420000").
        Note: section aliases like "+.text" are not supported here; resolve to hex first.
    Returns:
      { success, scanned_bytes, patches_applied, details: [ { address, old, new }... ] }
    """
    # Parse and normalize addresses
    try:
        s = int(start_address, 16)
        e = int(end_address, 16)
    except Exception:
        return {"success": False, "error": {"code": "INVALID_ADDRESS", "message": "start_address and end_address must be hex"}, "timestamp": int(time.time() * 1000)}
    if e < s:
        s, e = e, s
    length = (e - s) + 1

    # Read the full range once in base64
    rd = memory_read(address=f"{s:08X}", length=length, format="base64", port=port)  # type: ignore
    if not rd or not rd.get("success", False):
        return {"success": False, "error": {"code": "READ_FAILED", "message": str(rd)}, "timestamp": int(time.time() * 1000)}
    import base64 as _b64
    raw_b64 = rd.get("rawBytes")
    if not raw_b64:
        return {"success": False, "error": {"code": "NO_DATA", "message": "No bytes returned for range"}, "timestamp": int(time.time() * 1000)}
    try:
        buf = _b64.b64decode(raw_b64)
    except Exception:
        return {"success": False, "error": {"code": "DECODE_FAILED", "message": "Unable to decode base64"}, "timestamp": int(time.time() * 1000)}
    if not isinstance(buf, (bytes, bytearray)):
        return {"success": False, "error": {"code": "DECODE_FAILED", "message": "Decoded data not bytes"}, "timestamp": int(time.time() * 1000)}

    # Scan for CC C3 and patch each with D0 FF
    start = s
    total = len(buf)
    target = b"\xCC\xC3"
    repl = b"\xFF\xD0"  # call eax: opcode FF D0
    patches: List[Dict[str, Any]] = []
    i = 0
    while i + 1 < total:
        if buf[i:i+2] == target:
            # Compute address for this occurrence
            addr = start + i
            # Write the two-byte replacement at addr
            resp = memory_write(f"{addr:08X}", repl.hex(), format="hex", port=port)  # type: ignore
            if resp and resp.get("success", False):
                patches.append({"address": f"0x{addr:08X}", "old": "CCC3", "new": "FFD0"})
            i += 2
            continue
        i += 1

    return {
        "success": True,
        "scanned_bytes": total,
        "patches_applied": len(patches),
        "details": patches,
        "timestamp": int(time.time() * 1000),
    }

# Xrefs tools
@mcp.tool()
def xrefs_list(to_addr: Optional[str] = None, from_addr: Optional[str] = None, type: Optional[str] = None,
              offset: int = 0, limit: int = 100, port: Optional[int] = None) -> dict:
    """List cross-references with filtering and pagination
    
    Args:
        to_addr: Filter references to this address (hexadecimal)
        from_addr: Filter references from this address (hexadecimal)  
        type: Filter by reference type (e.g. "CALL", "READ", "WRITE")
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: Cross-references matching the filters
    """
    # At least one of the address parameters must be provided
    if not to_addr and not from_addr:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER", 
                "message": "Either to_addr or from_addr parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    params: Dict[str, Any] = {
        "offset": offset,
        "limit": limit
    }
    if to_addr:
        params["to_addr"] = to_addr
    if from_addr:
        params["from_addr"] = from_addr
    if type:
        params["type"] = type

    response = safe_get(port, "xrefs", params)
    simplified = simplify_response(response)
    
    # Ensure we maintain pagination metadata
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    
    return simplified

# Data tools
@mcp.tool()
def data_list(offset: int = 0, limit: int = 100, addr: Optional[str] = None,
            name: Optional[str] = None, name_contains: Optional[str] = None, type: Optional[str] = None,
            port: Optional[int] = None) -> dict:
    """List defined data items with filtering and pagination
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        addr: Filter by address (hexadecimal)
        name: Exact name match filter (case-sensitive)
        name_contains: Substring name filter (case-insensitive)
        type: Filter by data type (e.g. "string", "dword")
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: Data items matching the filters
    """
    port = _get_instance_port(port)
    
    params: Dict[str, Any] = {
        "offset": offset,
        "limit": limit
    }
    if addr:
        params["addr"] = addr
    if name:
        params["name"] = name
    if name_contains:
        params["name_contains"] = name_contains
    if type:
        params["type"] = type

    response = safe_get(port, "data", params)
    simplified = simplify_response(response)
    
    # Ensure we maintain pagination metadata
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    
    return simplified

@mcp.tool()
def data_create(address: str, data_type: str, size: Optional[int] = None, port: Optional[int] = None) -> dict:
    """Define a new data item at the specified address
    
    Args:
        address: Memory address in hex format
        data_type: Data type (e.g. "string", "dword", "byte")
        size: Optional size in bytes for the data item
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the created data information
    """
    if not address or not data_type:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address and data_type parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload: Dict[str, Any] = {
        "address": address,
        "type": data_type
    }
    
    if size is not None:
        payload["size"] = size
    
    response = safe_post(port, "data", payload)
    return simplify_response(response)

@mcp.tool()
def data_update(address: str, data_type: Optional[str] = None, size: Optional[int] = None, port: Optional[int] = None) -> dict:
    """Update an existing data item (type and/or size) at the specified address.

    Notes:
        Some HATEOAS plugin builds support an explicit update endpoint. If not available,
        this may return an error. Prefer data_create_smart for robust behavior.

    Args:
        address: Memory address in hex format (e.g. "0055b7c4")
        data_type: Optional new data type (e.g. "string", "undefined1")
        size: Optional size in bytes
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result
    """
    if not address:
        return {
            "success": False,
            "error": {"code": "MISSING_PARAMETER", "message": "Address is required"},
            "timestamp": int(time.time() * 1000),
        }
    port = _get_instance_port(port)
    payload: Dict[str, Any] = {"address": address}
    if data_type is not None:
        payload["type"] = data_type
    if size is not None:
        payload["size"] = size
    response = safe_post(port, "data/update", payload)
    return simplify_response(response)

@mcp.tool()
def data_list_strings(offset: int = 0, limit: int = 2000, filter: Optional[str] = None, port: Optional[int] = None) -> dict:
    """List all defined strings in the binary with their memory addresses
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum strings to return (default: 2000)
        filter: Optional string content filter
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: List of string data with addresses, values, and metadata
    """
    port = _get_instance_port(port)
    
    params: Dict[str, Any] = {
        "offset": offset,
        "limit": limit
    }
    
    if filter:
        params["filter"] = filter
    
    response = safe_get(port, "strings", params)
    # Some plugin versions throw INTERNAL_ERROR when offset exceeds available items:
    # e.g., "Error listing strings: fromIndex(50) > toIndex(14)". Treat this as end-of-results.
    try:
        if isinstance(response, dict) and (not response.get("success", True)):
            err = ""
            try:
                err_obj = response.get("error") or {}
                err = str(err_obj.get("message") or "")
            except Exception:
                err = ""
            if "fromIndex(" in err and ") > toIndex(" in err:
                import time as _t
                # Synthesize an empty page response to allow clients to stop paginating gracefully
                safe_empty = {
                    "id": response.get("id", f"mcp-bridge-{int(_t.time()*1000)}"),
                    "instance": response.get("instance"),
                    "success": True,
                    "result": [],
                    "size": 0,
                    "offset": offset,
                    "limit": limit,
                    "timestamp": int(_t.time()*1000),
                }
                return simplify_response(safe_empty)
    except Exception:
        # Fallback to normal simplification path if inspection fails
        pass
    return simplify_response(response)

@mcp.tool()
def data_rename(address: str, name: str, port: Optional[int] = None) -> dict:
    """Rename a data item
    
    Args:
        address: Memory address in hex format
        name: New name for the data item
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the updated data information
    """
    if not address or not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address and name parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload = {
        "address": address,
        "newName": name
    }
    
    response = safe_post(port, "data", payload)
    return simplify_response(response)

@mcp.tool()
def data_delete(address: str, port: Optional[int] = None) -> dict:
    """Delete data at the specified address
    
    Args:
        address: Memory address in hex format
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload = {
        "address": address,
        "action": "delete"
    }
    
    response = safe_post(port, "data/delete", payload)
    return simplify_response(response)

@mcp.tool()
def data_delete_range(start: str, size: Optional[int] = None, end: Optional[str] = None, port: Optional[int] = None) -> dict:
    """Delete any data definitions overlapping the [start, end] range.

    This issues best-effort deletes at each byte in the span to clear conflicting items
    when the plugin does not expose a single range-clear operation.

    Args:
        start: Start address (hex string like "12345678" or "0x12345678")
        size: Optional size in bytes (inclusive span = size)
        end: Optional end address (hex string); if provided, overrides size
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Summary with cleared_count and last_result
    """
    if not start:
        return {"success": False, "error": {"code": "MISSING_PARAMETER", "message": "Start address is required"}, "timestamp": int(time.time() * 1000)}
    if size is None and end is None:
        return {"success": False, "error": {"code": "MISSING_PARAMETER", "message": "Provide size or end"}, "timestamp": int(time.time() * 1000)}

    def _to_int(addr: str) -> int:
        s = addr.lower().strip()
        if s.startswith("0x"):
            return int(s, 16)
        return int(s, 16)  # assume hex without 0x

    start_i = _to_int(start)
    if end is not None:
        end_i = _to_int(end)
    else:
        end_i = start_i + max(1, int(size)) - 1
    if end_i < start_i:
        start_i, end_i = end_i, start_i

    port_resolved = _get_instance_port(port)
    cleared = 0
    last = None
    for addr in range(start_i, end_i + 1):
        a = f"{addr:08X}"
        payload = {"address": a, "action": "delete"}
        last = safe_post(port_resolved, "data/delete", payload)
        # Count success even if item was already not defined; rely on API message if needed
        try:
            if isinstance(last, dict) and last.get("success"):
                cleared += 1
        except Exception:
            pass
    return simplify_response({
        "id": f"mcp-bridge-{int(time.time()*1000)}",
        "instance": f"http://localhost:{port_resolved}",
        "success": True,
        "result": {"start": f"{start_i:08X}", "end": f"{end_i:08X}", "cleared_count": cleared, "last_result": last},
        "timestamp": int(time.time()*1000),
    })

@mcp.tool()
def data_set_type(address: str, data_type: str, port: Optional[int] = None) -> dict:
    """Set the data type of a data item
    
    Args:
        address: Memory address in hex format
        data_type: Data type name (e.g. "uint32_t", "char[10]")
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the updated data information
    """
    if not address or not data_type:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address and data_type parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload = {
        "address": address,
        "type": data_type
    }
    
    response = safe_post(port, "data/type", payload)
    return simplify_response(response)

@mcp.tool()
def data_create_smart(address: str, data_type: str, size: Optional[int] = None, port: Optional[int] = None, clear_on_conflict: bool = True) -> dict:
    """Create data with an automatic conflict fallback: clear the span then retry.

    This mirrors the Ghidra error guidance: "Use update_data or delete_data first".
    If the initial create fails and size is provided, it will delete the entire
    [address, address+size-1] span byte-by-byte and then attempt the create again.

    Args:
        address: Start address (hex)
        data_type: Data type to create
        size: Optional size in bytes
        port: Specific Ghidra instance port (optional)
        clear_on_conflict: Whether to auto-clear and retry on conflict

    Returns:
        dict: Final operation result; includes meta about any clearing performed
    """
    if not address or not data_type:
        return {
            "success": False,
            "error": {"code": "MISSING_PARAMETER", "message": "Address and data_type are required"},
            "timestamp": int(time.time() * 1000),
        }
    p = _get_instance_port(port)
    payload: Dict[str, Any] = {"address": address, "type": data_type}
    if size is not None:
        payload["size"] = size
    first = safe_post(p, "data", payload)
    # If first attempt succeeded or we cannot compute a span, return now
    try:
        if isinstance(first, dict) and first.get("success"):
            return simplify_response(first)
    except Exception:
        pass
    if not clear_on_conflict or size is None:
        return simplify_response(first)

    # Clear the intended span and retry once
    try:
        _ = data_delete_range(address, size=size, port=p)  # type: ignore
    except Exception:
        # Proceed to retry regardless
        pass
    second = safe_post(p, "data", payload)
    # Annotate that we cleared-on-conflict
    if isinstance(second, dict):
        second.setdefault("meta", {})
        try:
            second["meta"]["cleared_on_conflict"] = True
            second["meta"]["cleared_size"] = size
        except Exception:
            pass
    return simplify_response(second)

# Analysis tools
@mcp.tool()
def analysis_run(port: Optional[int] = None, analysis_options: Optional[dict] = None) -> dict:
    """Run analysis on the current program
    
    Args:
        analysis_options: Dictionary of analysis options to enable/disable
                         (e.g. {"functionRecovery": True, "dataRefs": False})
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: Analysis operation result with status
    """
    port = _get_instance_port(port)
    response = safe_post(port, "analysis", analysis_options or {})
    return simplify_response(response)

# Sections/tools additions
@mcp.tool()
def sections_list(port: Optional[int] = None) -> dict:
    """List memory blocks/sections with start/end/size/permissions.

    Tries the HATEOAS endpoint programs/current/memory/blocks if present; if not,
    falls back to heuristics using program info where available.
    """
    p = _get_instance_port(port)
    
    # Try various endpoints for memory blocks/sections
    endpoints = [
        "programs/current/memory/blocks",
        "memory/blocks",
        "blocks",
        "programs/current/blocks",
        "programs/current/sections",
        "sections",
        "memory/sections",
        "program/memory/blocks",
        "program/blocks",
        "program/sections"
    ]
    
    for endpoint in endpoints:
        resp = safe_get(p, endpoint)
        if isinstance(resp, dict) and resp.get("success") and isinstance(resp.get("result"), list):
            blocks = resp.get("result")
            # Filter out empty or invalid blocks
            valid_blocks = []
            for block in blocks:
                if isinstance(block, dict) and (block.get("size", 0) > 0 or block.get("end", "0") != block.get("start", "1")):
                    valid_blocks.append(block)
            if valid_blocks:
                return {"success": True, "result": valid_blocks, "timestamp": int(time.time() * 1000)}
    
    # Try /program endpoint and look for various block fields
    prog = safe_get(p, "program")
    if isinstance(prog, dict) and prog.get("success"):
        res = prog.get("result", {}) or {}
        # Try various field names
        for field in ["memoryBlocks", "memory_blocks", "blocks", "sections", "memoryMap", "memory_map"]:
            blocks = res.get(field)
            if isinstance(blocks, list) and blocks:
                return {"success": True, "result": blocks, "timestamp": int(time.time() * 1000)}
    
    # Try getting program info endpoint
    prog_info = safe_get(p, "programs/current")
    if isinstance(prog_info, dict) and prog_info.get("success"):
        res = prog_info.get("result", {}) or {}
        for field in ["memoryBlocks", "memory_blocks", "blocks", "sections"]:
            blocks = res.get(field)
            if isinstance(blocks, list) and blocks:
                return {"success": True, "result": blocks, "timestamp": int(time.time() * 1000)}
    
    # Last resort: return base+size only
    base = _get_program_base_address(p)
    if base is not None:
        return {
            "success": True,
            "result": [
                {"name": "image_base", "start": f"{int(base):08X}", "end": f"{int(base):08X}", "size": 0, "permissions": "R--"}
            ],
            "timestamp": int(time.time() * 1000)
        }
    return {"success": False, "error": {"code": "NO_SECTIONS", "message": "No sections information available"}, "timestamp": int(time.time() * 1000)}

@mcp.tool()
def section_read_by_name(section_name: str, format: str = "base64", port: Optional[int] = None) -> dict:
    """Read entire section data by section name (e.g., '.rdata', '.data').
    
    Args:
        section_name: Name of the section to read (e.g., '.text', '.rdata', '.data')
        format: Output format - 'base64', 'hex', or 'string' (default: base64)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: { success, section_info: {name, start, end, size}, data: (in requested format) }
    """
    p = _get_instance_port(port)
    
    # First, get the list of sections
    sections_resp = sections_list(port=p)
    if not (isinstance(sections_resp, dict) and sections_resp.get("success")):
        return {
            "success": False,
            "error": {"code": "SECTIONS_LIST_FAILED", "message": "Failed to retrieve sections list"},
            "timestamp": int(time.time() * 1000)
        }
    
    sections = sections_resp.get("result", [])
    if not isinstance(sections, list):
        return {
            "success": False,
            "error": {"code": "INVALID_SECTIONS", "message": "Invalid sections list format"},
            "timestamp": int(time.time() * 1000)
        }
    
    # Find the requested section
    target_section = None
    for section in sections:
        if not isinstance(section, dict):
            continue
        # Match section name (case-insensitive, handle with/without dot prefix)
        sec_name = str(section.get("name", "")).lower()
        search_name = section_name.lower()
        if not search_name.startswith('.'):
            search_name = '.' + search_name
        if sec_name == search_name or sec_name.endswith(search_name):
            target_section = section
            break
    
    if not target_section:
        return {
            "success": False,
            "error": {"code": "SECTION_NOT_FOUND", "message": f"Section '{section_name}' not found"},
            "timestamp": int(time.time() * 1000)
        }
    
    # Extract section bounds
    start_str = target_section.get("start") or target_section.get("address")
    end_str = target_section.get("end")
    size = target_section.get("size")
    
    # If we don't have end but have size, calculate it
    if start_str and not end_str and isinstance(size, (int, str)):
        try:
            start_addr = int(str(start_str), 16) if isinstance(start_str, str) else int(start_str)
            size_int = int(size) if isinstance(size, (int, str)) else 0
            if size_int > 0:
                end_addr = start_addr + size_int - 1
                end_str = f"{end_addr:08X}"
        except Exception:
            pass
    
    if not start_str or not end_str:
        return {
            "success": False,
            "error": {"code": "INVALID_SECTION_BOUNDS", "message": "Section has invalid or missing bounds"},
            "timestamp": int(time.time() * 1000)
        }
    
    # Read the section data using memory_read_range
    read_resp = memory_read_range(
        start_address=str(start_str),
        end_address=str(end_str),
        format=format,
        port=p
    )
    
    if not (isinstance(read_resp, dict) and read_resp.get("success")):
        return {
            "success": False,
            "error": {"code": "MEMORY_READ_FAILED", "message": "Failed to read section memory"},
            "timestamp": int(time.time() * 1000)
        }
    
    # Prepare the response
    result = {
        "section_info": {
            "name": target_section.get("name"),
            "start": start_str,
            "end": end_str,
            "size": size or 0,
            "permissions": target_section.get("permissions", "")
        }
    }
    
    # Add data in requested format
    # memory_read_range returns data directly in the response, not under 'result'
    if format == "base64":
        result["data"] = read_resp.get("rawBytes", "")
    elif format == "hex":
        result["data"] = read_resp.get("hexBytes", "")
    elif format == "string":
        result["data"] = read_resp.get("asciiString", "")
    else:
        result["data"] = read_resp.get("rawBytes", "")
    
    return {
        "success": True,
        "result": result,
        "timestamp": int(time.time() * 1000)
    }

@mcp.tool()
def section_scan_patterns(section_name: str, pattern_hints: Optional[List[str]] = None, min_chunk_size: int = 50, port: Optional[int] = None) -> dict:
    """Scan section for potential encrypted chunks based on entropy and patterns.
    
    This tool helps identify potential encrypted string chunks in a section by looking for:
    - High entropy regions (indicating encryption)
    - Specific byte patterns if provided
    - Chunk boundaries based on null bytes or size patterns
    
    Args:
        section_name: Name of the section to scan (e.g., '.rdata')
        pattern_hints: Optional list of patterns to look for (e.g., ['40_bytes_key', 'rc4_chunks'])
        min_chunk_size: Minimum size for a chunk to be considered (default: 50 bytes)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: { success, potential_chunks: [{offset, size, entropy, pattern_match, preview}] }
    """
    p = _get_instance_port(port)
    
    # First read the section data
    section_data_resp = section_read_by_name(section_name=section_name, format="base64", port=p)
    if not (isinstance(section_data_resp, dict) and section_data_resp.get("success")):
        return section_data_resp  # Pass through the error
    
    result = section_data_resp.get("result", {})
    section_info = result.get("section_info", {})
    data_b64 = result.get("data", "")
    
    if not data_b64:
        return {
            "success": False,
            "error": {"code": "NO_DATA", "message": "Section contains no data"},
            "timestamp": int(time.time() * 1000)
        }
    
    # Decode the base64 data
    try:
        import base64
        data = base64.b64decode(data_b64)
    except Exception as e:
        return {
            "success": False,
            "error": {"code": "DECODE_ERROR", "message": f"Failed to decode section data: {str(e)}"},
            "timestamp": int(time.time() * 1000)
        }
    
    # Calculate base address
    try:
        base_addr = int(section_info.get("start", "0"), 16)
    except Exception:
        base_addr = 0
    
    # Scan for potential chunks
    potential_chunks = []
    i = 0
    
    while i < len(data):
        # Skip null bytes
        while i < len(data) and data[i] == 0:
            i += 1
        
        if i >= len(data):
            break
        
        # Find the end of the current chunk (next sequence of nulls or end of data)
        chunk_start = i
        # Look for at least 4 consecutive null bytes as chunk delimiter
        while i < len(data):
            if i + 4 <= len(data) and data[i:i+4] == b'\x00\x00\x00\x00':
                break
            i += 1
        
        chunk_end = i
        chunk_size = chunk_end - chunk_start
        
        # Only consider chunks above minimum size
        if chunk_size >= min_chunk_size:
            chunk_data = data[chunk_start:chunk_end]
            entropy = _shannon_entropy(chunk_data)
            
            # Check for specific patterns
            pattern_match = None
            if pattern_hints:
                for hint in pattern_hints:
                    hint_lower = hint.lower()
                    if "40_bytes_key" in hint_lower or "40_byte_key" in hint_lower or "rc4" in hint_lower or "dridex" in hint_lower:
                        # For Dridex-style RC4: first 40 bytes are key (reversed), rest is encrypted
                        if chunk_size > 40:
                            # High entropy after the first 40 bytes suggests encryption
                            encrypted_part = chunk_data[40:]
                            enc_entropy = _shannon_entropy(encrypted_part)
                            if enc_entropy > 6.0:  # Encrypted data typically has entropy > 6
                                pattern_match = "rc4_40_byte_key"
                    elif "xor" in hint_lower:
                        # XOR encrypted data often has moderate to high entropy
                        if 5.0 < entropy < 7.5:
                            pattern_match = "possible_xor"
            
            # Preview: show first 16 bytes as hex
            preview_hex = chunk_data[:16].hex()
            if len(chunk_data) > 16:
                preview_hex += "..."
            
            # Add chunk if it has high entropy or matches patterns
            if entropy > 5.0 or pattern_match:
                potential_chunks.append({
                    "offset": chunk_start,  # Section-relative offset as integer
                    "address": f"{base_addr + chunk_start:08X}",  # Hex address as string
                    "file_offset": chunk_start,
                    "size": chunk_size,
                    "entropy": round(entropy, 2),
                    "pattern_match": pattern_match,
                    "preview": preview_hex
                })
        
        # Move past the null bytes
        i = chunk_end
    
    # Sort by offset
    potential_chunks.sort(key=lambda x: x["file_offset"])
    
    return {
        "success": True,
        "result": {
            "section": section_name,
            "section_info": section_info,
            "total_chunks_found": len(potential_chunks),
            "potential_chunks": potential_chunks
        },
        "timestamp": int(time.time() * 1000)
    }

def _rc4_crypt(data: bytes, key: bytes) -> bytes:
    """Simple RC4 implementation for Dridex decryption"""
    if not key:
        raise ValueError("RC4 key must not be empty")
    
    # Initialize S-box
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    # Generate keystream and decrypt
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    
    return bytes(out)

def _extract_strings_from_decrypted(data: bytes) -> list:
    """Extract ASCII and UTF-16 strings from decrypted data"""
    strings = []
    
    # Extract ASCII strings
    current = []
    for b in data:
        if 32 <= b <= 126:  # Printable ASCII
            current.append(chr(b))
        else:
            if len(current) >= 3:
                strings.append(''.join(current))
            current = []
    if len(current) >= 3:
        strings.append(''.join(current))
    
    # Extract UTF-16 strings
    i = 0
    while i < len(data) - 1:
        if data[i+1] == 0 and 32 <= data[i] <= 126:
            chars = []
            while i < len(data) - 1 and data[i+1] == 0 and 32 <= data[i] <= 126:
                chars.append(chr(data[i]))
                i += 2
            if len(chars) >= 3:
                strings.append(''.join(chars))
        else:
            i += 1
    
    return strings

@mcp.tool()
def dridex_extract_rc4_chunks(section_name: str = ".rdata", min_chunk_size: int = 50, port: Optional[int] = None) -> dict:
    """Extract and decrypt Dridex RC4-encrypted strings automatically.
    
    This tool finds Dridex-style encrypted chunks and decrypts them immediately:
    - First 40 bytes are the RC4 key (stored in reverse order)
    - Remaining bytes are RC4-encrypted configuration strings
    - Each chunk is decrypted individually to avoid context window overflow
    
    Args:
        section_name: Section to scan (default: ".rdata")
        min_chunk_size: Minimum chunk size to consider (default: 50 bytes)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Contains all decrypted strings, URLs, and IOCs extracted from Dridex chunks
    """
    port = _get_instance_port(port)
    
    # Normalize common section name variations
    if section_name and not section_name.startswith('.'):
        section_name = '.' + section_name
    
    # First scan for high-entropy chunks using the same pattern as the working demo
    scan_result = section_scan_patterns(section_name, ["rc4_40_byte_key"], min_chunk_size, port)
    
    if not scan_result.get("success") or not scan_result.get("result"):
        return scan_result
    
    result = scan_result["result"]
    chunks = result.get("potential_chunks", [])
    
    # Filter chunks like the working demo does - only process RC4 40-byte key chunks
    rc4_chunks = [c for c in chunks if c.get("pattern_match") == "rc4_40_byte_key"]
    
    # Process chunks to extract RC4 structure
    dridex_chunks = []
    
    # Read section data for processing
    section_info = result.get("section_info", {})
    if not section_info:
        return {
            "success": False,
            "error": {
                "code": "SECTION_NOT_FOUND",
                "message": f"Section {section_name} not found"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    # Read the section data
    read_result = section_read_by_name(section_name, format="base64", port=port)
    if not read_result.get("success"):
        return read_result
    
    section_data_b64 = read_result.get("result", {}).get("data")
    if not section_data_b64:
        return {
            "success": False,
            "error": {
                "code": "READ_ERROR",
                "message": "Failed to read section data"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    # Decode the base64 data
    try:
        if not isinstance(section_data_b64, str):
            return {
                "success": False,
                "error": {
                    "code": "DECODE_ERROR",
                    "message": f"Section data is not a string: {type(section_data_b64)}"
                },
                "timestamp": int(time.time() * 1000)
            }
        section_data = base64.b64decode(section_data_b64)
    except Exception as e:
        return {
            "success": False,
            "error": {
                "code": "DECODE_ERROR",
                "message": f"Failed to decode section data: {str(e)} (data type: {type(section_data_b64)}, length: {str(len(section_data_b64)) if isinstance(section_data_b64, str) else 'N/A'})"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    # Process each RC4 chunk
    for chunk in rc4_chunks:
        offset_in_section = chunk.get("offset", 0)  # This is offset within the section
        size = chunk.get("size", 0)
        
        # Check if chunk is large enough for RC4 (40 byte key + data)
        if size > 40:
            # Extract the chunk data using section-relative offset
            chunk_data = section_data[offset_in_section:offset_in_section + size]
            
            # First 40 bytes are the RC4 key (in reverse order)
            key_bytes = chunk_data[:40]
            encrypted_data = chunk_data[40:]
            
            # Check entropy of encrypted portion
            enc_entropy = _shannon_entropy(encrypted_data)
            
            # Only consider if encrypted part has high entropy
            if enc_entropy > 6.0:
                # Decrypt this chunk immediately using RC4 with reversed key
                try:
                    reversed_key = key_bytes[::-1]  # Reverse the key
                    decrypted_data = _rc4_crypt(encrypted_data, reversed_key)
                    
                    # Extract strings from decrypted data
                    extracted_strings = _extract_strings_from_decrypted(decrypted_data)
                    
                    # Only add chunk if we extracted meaningful strings
                    if extracted_strings:
                        dridex_chunks.append({
                            "offset": int(chunk.get("offset", 0)),
                            "address": chunk.get("address", ""),
                            "file_offset": int(chunk.get("file_offset", 0)),
                            "total_size": int(size),
                            "key_preview": (key_bytes[:8].hex() + "...") if len(key_bytes) > 0 else "empty",
                            "decrypted_strings": extracted_strings,
                            "string_count": len(extracted_strings),
                            "encrypted_entropy": round(float(enc_entropy), 2),
                            "status": "decrypted_successfully"
                        })
                except Exception as decrypt_err:
                    # Log failed decryption but continue processing other chunks
                    dridex_chunks.append({
                        "offset": int(chunk.get("offset", 0)),
                        "address": chunk.get("address", ""),
                        "status": f"decryption_failed: {str(decrypt_err)}"
                    })
    
    # Collect all decrypted strings for summary
    all_strings = []
    successful_decryptions = 0
    for chunk in dridex_chunks:
        if chunk.get("status") == "decrypted_successfully":
            successful_decryptions += 1
            all_strings.extend(chunk.get("decrypted_strings", []))
    
    return {
        "success": True,
        "result": {
            "section": section_name,
            "section_info": section_info,
            "total_chunks_found": len(chunks),
            "rc4_pattern_matches": len(rc4_chunks),
            "chunks_processed": len(dridex_chunks),
            "successful_decryptions": successful_decryptions,
            "total_strings_extracted": len(all_strings),
            "decrypted_chunks": dridex_chunks,
            "all_strings": list(set(all_strings)),  # Deduplicated strings
            "status": "complete - strings extracted and decrypted inline"
        },
        "timestamp": int(time.time() * 1000)
    }

@mcp.tool()
def functions_callsites(name: Optional[str] = None, address: Optional[str] = None, offset: int = 0, limit: int = 200, port: Optional[int] = None) -> dict:
    """List callsites referring to a function by name or address.

    Uses xrefs_list(to_addr=func_addr, type="CALL"). If only name is provided, resolves it first.
    """
    if not name and not address:
        return {"success": False, "error": {"code": "MISSING_PARAMETER", "message": "Provide name or address"}, "timestamp": int(time.time() * 1000)}
    p = _get_instance_port(port)
    target_addr: Optional[str] = None
    if address:
        target_addr = address
    else:
        info = functions_get(name=name, port=p)
        if isinstance(info, dict) and info.get("success"):
            res = info.get("result", {}) or {}
            a = res.get("entry", res.get("address", res.get("addr")))
            if isinstance(a, str) and a:
                target_addr = a
    if not target_addr:
        return {"success": False, "error": {"code": "RESOLVE_FAILED", "message": "Could not resolve function address"}, "timestamp": int(time.time() * 1000)}
    xr = xrefs_list(to_addr=target_addr, type="CALL", offset=offset, limit=limit, port=p)
    return xr if isinstance(xr, dict) else {"success": False, "error": {"code": "XREFS_ERROR", "message": "Unexpected response"}, "timestamp": int(time.time() * 1000)}

@mcp.tool()
def analysis_get_callgraph(name: Optional[str] = None, address: Optional[str] = None, max_depth: int = 3, port: Optional[int] = None) -> dict:
    """Get function call graph visualization data
    
    Args:
        name: Starting function name (mutually exclusive with address)
        address: Starting function address (mutually exclusive with name)
        max_depth: Maximum call depth to analyze (default: 3)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Graph data with nodes and edges
    """
    port = _get_instance_port(port)
    
    params: Dict[str, Any] = {"max_depth": max_depth}
    
    # Explicitly pass either name or address parameter based on what was provided
    if address:
        params["address"] = address
    elif name:
        params["name"] = name
    # If neither is provided, the Java endpoint will use the entry point
    
    response = safe_get(port, "analysis/callgraph", params)
    return simplify_response(response)

@mcp.tool()
def analysis_get_dataflow(address: str, direction: str = "forward", max_steps: int = 50, port: Optional[int] = None) -> dict:
    """Perform data flow analysis from an address
    
    Args:
        address: Starting address in hex format
        direction: "forward" or "backward" (default: "forward")
        max_steps: Maximum analysis steps (default: 50)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Data flow analysis results
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    params = {
        "address": address,
        "direction": direction,
        "max_steps": max_steps
    }
    
    response = safe_get(port, "analysis/dataflow", params)
    return simplify_response(response)

@mcp.tool()
def ui_get_current_address(port: Optional[int] = None) -> dict:
    """Get the address currently selected in Ghidra's UI

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        Dict containing address information or error
    """
    port = _get_instance_port(port)
    response = safe_get(port, "address")
    return simplify_response(response)

@mcp.tool()
def ui_get_current_function(port: Optional[int] = None) -> dict:
    """Get the function currently selected in Ghidra's UI

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        Dict containing function information or error
    """
    port = _get_instance_port(port)
    response = safe_get(port, "function")
    return simplify_response(response)

@mcp.tool()
def comments_set(address: str, comment: str = "", comment_type: str = "plate", port: Optional[int] = None) -> dict:
    """Set a comment at the specified address

    Args:
        address: Memory address in hex format
        comment: Comment text (empty string removes comment)
        comment_type: Type of comment - "plate", "pre", "post", "eol", "repeatable" (default: "plate")
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    payload = {
        "comment": comment
    }

    response = safe_post(port, f"memory/{address}/comments/{comment_type}", payload)
    return simplify_response(response)

@mcp.tool()
def functions_set_comment(address: str, comment: str = "", port: Optional[int] = None) -> dict:
    """Set a decompiler-friendly comment (tries function comment, falls back to pre-comment)

    Args:
        address: Memory address in hex format (preferably function entry point)
        comment: Comment text (empty string removes comment)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port_to_use = _get_instance_port(port)

    # Try setting as a function comment first using PATCH
    try:
        func_patch_payload = {
            "comment": comment
        }
        patch_response = safe_patch(port_to_use, f"functions/{address}", func_patch_payload)
        if patch_response.get("success", False):
            return simplify_response(patch_response) # Success setting function comment
        else:
             print(f"Note: Failed to set function comment via PATCH on {address}, falling back. Error: {patch_response.get('error')}", file=sys.stderr)
    except Exception as e:
        print(f"Exception trying function comment PATCH: {e}. Falling back.", file=sys.stderr)
        # Fall through to set pre-comment if PATCH fails

    # Fallback: Set as a "pre" comment using the comments_set tool
    print(f"Falling back to setting 'pre' comment for address {address}", file=sys.stderr)
    return comments_set(address=address, comment=comment, comment_type="pre", port=port_to_use)

# ================= Advanced Network Configuration Discovery =================

# Generic byte-patterns for locating a network configuration parsing routine.
# Patterns capture two 4-byte little-endian immediates that are used as
# addresses: one points to a 2-byte identifier, the other to a table whose
# layout is: count (1 byte) followed by count entries of (IPv4(4 bytes) + Port(2 bytes LE)).
# These patterns are derived from observed instruction sequences but are kept
# family-agnostic by design.
NETWORK_CONFIG_PARSER_PATTERNS: List[bytes] = [
    b'0fb70d([a-f0-9]{8})a3[a-f0-9]{8}a1[a-f0-9]{8}8908803d([a-f0-9]{8})0a77[a-f0-9]{2}a0[a-f0-9]{8}5?7?33ff803d[a-f0-9]{8}00',
    b'0fb7[a-f0-9]{2}([a-f0-9]{8})89[a-f0-9]{2}0fb[a-f0-9]{3}([a-f0-9]{8})89[a-f0-9]{10}83[a-f0-9]{2}0a',
    b'66a1([a-f0-9]{8})8b[a-f0-9]{10}0fb7[a-f0-9]{2}89[a-f0-9]{2}a0([a-f0-9]{8})3c0a77[a-f0-9]{2}8a',
    b'66a1([a-f0-9]{8})8b0d[a-f0-9]{8}0fb7c08901a0([a-f0-9]{8})3c0a77[a-f0-9]{2}a0[a-f0-9]{8}',
]

def _hex_le_immediate_to_int(hex_bytes_ascii: bytes) -> int:
    """Convert 8 ASCII hex nybbles (little-endian dword as it appears in code) to int."""
    try:
        import binascii
        b = binascii.unhexlify(hex_bytes_ascii)
        return int.from_bytes(b[::-1], 'big')
    except Exception:
        return -1

def _memory_read_bytes(addr: int, length: int, port: int) -> Optional[bytes]:
    """Best-effort raw bytes fetch via existing memory_read tool."""
    try:
        # memory_read expects hex string without 0x
        resp = memory_read(address=f"{addr:08X}", length=length, format="hex", port=port)
        if not (isinstance(resp, dict) and resp.get("success")):
            return None
        hx = resp.get("hexBytes", "").replace(" ", "")
        if not hx:
            return None
        import binascii
        return binascii.unhexlify(hx)
    except Exception:
        return None

def _try_parse_table(id_addr: int, table_addr: int, port: int) -> Optional[dict]:
    """Attempt to parse identifier (2 bytes) + table at table_addr.

    Returns dict on success: {identifier, endpoints:[{ip,port}], count}
    or None if layout invalid.
    """
    id_bytes = _memory_read_bytes(id_addr, 2, port)
    table_head = _memory_read_bytes(table_addr, 1, port)
    if id_bytes is None or table_head is None:
        return None
    identifier = int.from_bytes(id_bytes[::-1], 'big')  # little-endian 2 bytes
    count = table_head[0]
    if count == 0 or count > 64:  # impose sane upper bound
        return None
    needed = 1 + count * 6
    table_bytes = _memory_read_bytes(table_addr, needed, port)
    if table_bytes is None or len(table_bytes) < needed:
        return None
    endpoints = []
    off = 1
    for _ in range(count):
        if off + 6 > len(table_bytes):
            return None
        ip_raw = table_bytes[off:off+4]
        port_raw = table_bytes[off+4:off+6]
        off += 6
        # Basic validation
        if ip_raw == b'\x00\x00\x00\x00':
            return None
        ip = '.'.join(str(b) for b in ip_raw)
        port_val = int.from_bytes(port_raw[::-1], 'big')
        if port_val == 0 or port_val > 65535:
            return None
        endpoints.append({"ip": ip, "port": port_val})
    if not endpoints:
        return None
    return {"identifier": identifier, "endpoints": endpoints, "count": count}

@mcp.tool()
def network_config_discover(max_matches: int = 1, port: Optional[int] = None, include_patterns: bool = False) -> dict:
    """Discover and parse a compact network configuration table in the current program.

    The extractor scans executable/code sections for known instruction byte-patterns
    that reference two distinct addresses: one holding a 2-byte identifier and the
    other pointing to a table: count(1) + entries(count * (IPv4(4)+Port(2))).

    It returns the first successful parse by default. Heuristic—relies on patterns
    matching compiled instruction sequences. Designed to remain family-agnostic.

    Args:
        max_matches: Stop after this many successful parsed configs (default 1)
        port: Optional analysis instance port
        include_patterns: If True, include which pattern index matched

    Returns:
        dict: { success, results: [ {identifier, endpoints:[{ip,port}], metadata:{...}} ] }
    """
    p = _get_instance_port(port)
    results = []
    warnings: List[str] = []
    base_addr = _get_program_base_address(p)
    try:
        # Get sections and select executable/code sections
        secs_resp = sections_list(port=p)
        if not (isinstance(secs_resp, dict) and secs_resp.get("success")):
            return {"success": False, "error": {"code": "SECTIONS_UNAVAILABLE", "message": "Cannot enumerate sections"}, "timestamp": int(time.time()*1000)}
        sections = secs_resp.get("result", []) or []
        exec_sections = []
        for s in sections:
            try:
                name = str(s.get("name", ""))
                perms = str(s.get("permissions") or s.get("flags") or "").lower()
                if ("x" in perms) or any(tok in name.lower() for tok in [".text", "code"]):
                    exec_sections.append(s)
            except Exception:
                continue
        if not exec_sections:
            warnings.append("No executable sections identified; scanning all sections as fallback")
            exec_sections = sections

        import base64, binascii, re as _re
        compiled = [(_re.compile(pat), idx) for idx, pat in enumerate(NETWORK_CONFIG_PARSER_PATTERNS)]

        for sec in exec_sections:
            if max_matches and len(results) >= max_matches:
                break
            sec_name = sec.get("name")
            # Read section as base64
            read = section_read_by_name(section_name=sec_name, format="base64", port=p)
            if not (isinstance(read, dict) and read.get("success")):
                continue
            data_b64 = read.get("result", {}).get("data")
            if not data_b64:
                continue
            try:
                sec_bytes = base64.b64decode(data_b64)
            except Exception:
                continue
            hx = binascii.hexlify(sec_bytes)  # lowercase bytes
            for regex, pat_index in compiled:
                if max_matches and len(results) >= max_matches:
                    break
                try:
                    matches = regex.findall(hx)
                except Exception:
                    continue
                if not matches:
                    continue
                # Each match returns tuple of two capture groups
                for groups in matches:
                    if max_matches and len(results) >= max_matches:
                        break
                    if not isinstance(groups, (list, tuple)) or len(groups) != 2:
                        continue
                    raw_a = _hex_le_immediate_to_int(groups[0])
                    raw_b = _hex_le_immediate_to_int(groups[1])
                    if raw_a <= 0 or raw_b <= 0:
                        continue
                    addr_variants: List[Tuple[int,int,str]] = []
                    # Treat captured as absolute first
                    addr_variants.append((raw_a, raw_b, "absolute"))
                    if base_addr is not None:
                        # If both fall below base, treat as RVA
                        if raw_a < base_addr and raw_b < base_addr:
                            addr_variants.append((base_addr + raw_a, base_addr + raw_b, "rva+base"))
                        else:
                            # Individually adjust if one looks like RVA
                            if raw_a < base_addr:
                                addr_variants.append((base_addr + raw_a, raw_b, "mixed_a_rva"))
                            if raw_b < base_addr:
                                addr_variants.append((raw_a, base_addr + raw_b, "mixed_b_rva"))
                    successful = False
                    for va_a, va_b, mode in addr_variants:
                        if successful:
                            break
                        # Try (a=id, b=table) then swap
                        parse = _try_parse_table(va_a, va_b, p)
                        layout = {"id_address": f"{va_a:08X}", "table_address": f"{va_b:08X}", "address_mode": mode}
                        if not parse:
                            parse = _try_parse_table(va_b, va_a, p)
                            if parse:
                                layout = {"id_address": f"{va_b:08X}", "table_address": f"{va_a:08X}", "address_mode": mode, "swapped": True}
                        if not parse:
                            continue
                        successful = True
                        metadata = {
                            "pattern_index": pat_index if include_patterns else None,
                            "section": sec_name,
                            "count": parse["count"],
                            "addresses": layout,
                        }
                        result_obj = {
                            "identifier": parse["identifier"],
                            "endpoints": parse["endpoints"],
                            "metadata": metadata,
                        }
                        results.append(result_obj)
                    # end variants loop
        if not results:
            return {"success": False, "error": {"code": "NOT_FOUND", "message": "No network configuration pattern matched"}, "warnings": warnings, "timestamp": int(time.time()*1000)}
        return {"success": True, "results": results, "warnings": warnings, "timestamp": int(time.time()*1000)}
    except Exception as e:
        return {"success": False, "error": {"code": "DISCOVERY_ERROR", "message": str(e)}, "warnings": warnings, "timestamp": int(time.time()*1000)}

@mcp.tool()
def network_config_extract(port: Optional[int] = None) -> dict:
    """High-level wrapper to discover a network configuration and emit streamlined artifacts.

    Returns a simplified structure suitable for agent evidence JSON population.
    Attempts one discovery pass; if multiple configs present, returns the first.
    """
    p = _get_instance_port(port)
    discovery = network_config_discover(max_matches=1, port=p, include_patterns=True)
    if not (isinstance(discovery, dict) and discovery.get("success")):
        return {
            "success": False,
            "error": discovery.get("error") if isinstance(discovery, dict) else {"code": "DISCOVERY_FAILED", "message": "Unknown failure"},
            "timestamp": int(time.time() * 1000)
        }
    res_list = discovery.get("results", []) or []
    if not res_list:
        return {
            "success": False,
            "error": {"code": "NO_RESULTS", "message": "Discovery returned no results"},
            "timestamp": int(time.time() * 1000)
        }
    cfg = res_list[0]
    identifier = cfg.get("identifier")
    endpoints_struct = cfg.get("endpoints", [])
    endpoints_flat = [f"{e.get('ip')}:{e.get('port')}" for e in endpoints_struct if isinstance(e, dict) and e.get('ip') and e.get('port') is not None]
    artifacts = {
        "iocs": [{"type": "network_endpoint", "value": ep} for ep in endpoints_flat],
        "other": [
            {"key": "network_identifier", "value": identifier},
            {"key": "network_endpoint_count", "value": len(endpoints_flat)}
        ]
    }
    return {
        "success": True,
        "identifier": identifier,
        "endpoints": endpoints_flat,
        "raw_endpoints": endpoints_struct,
        "metadata": cfg.get("metadata", {}),
        "artifacts": artifacts,
        "timestamp": int(time.time() * 1000)
    }

# ================= Startup =================

if __name__ == "__main__":
    register_instance(DEFAULT_GHIDRA_PORT,
                      f"http://{ghidra_host}:{DEFAULT_GHIDRA_PORT}")

    # Use quick discovery on startup
    _discover_instances(QUICK_DISCOVERY_RANGE)

    # Start background discovery thread
    discovery_thread = threading.Thread(
        target=periodic_discovery,
        daemon=True,
        name="GhydraMCP-Discovery"
    )
    discovery_thread.start()

    signal.signal(signal.SIGINT, handle_sigint)
    mcp.run(transport="stdio")