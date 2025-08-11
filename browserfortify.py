#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BrowserFortify - Cross-platform browser security remediation & hardening
Target OS: Windows, macOS, Linux
Target browsers: Chrome/Chromium (incl. Edge), Firefox, Safari (assistive guidance)
"""

import argparse
import ctypes
import datetime as dt
import getpass
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import hashlib
import urllib.request
import ssl

APP_NAME = "BrowserFortify"
VERSION = "1.1.0"
LOG_DIR = Path.home() / f"{APP_NAME}-logs"
LOG_FILE = LOG_DIR / f"{APP_NAME}-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
DRY_RUN_PREFIX = "[DRY-RUN] "

SUSPICIOUS_PERMISSIONS = {
    "tabs","history","webRequest","webRequestBlocking","cookies","downloads",
    "browsingData","nativeMessaging","clipboardRead","clipboardWrite","privacy",
    "proxy","pageCapture","debugger","certificateProvider","dns","management",
    "sessions","<all_urls>"
}

KNOWN_MALICIOUS_CHROME_EXTENSIONS = {
    "iabflonngmpkalkpbjonemaamlgdghea",
    "jiaopkfkampgnnkckajcbdgannoipcne",
}

def log(msg: str):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{stamp} | {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def warn(msg: str):
    log("WARN  " + msg)

def err(msg: str):
    log("ERROR " + msg)

def is_windows_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def reexec_with_admin_windows():
    params = " ".join([f'"{a}"' for a in sys.argv])
    ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    if ret <= 32:
        err("Elevation rejected or failed.")
        sys.exit(1)
    sys.exit(0)

def is_root() -> bool:
    return os.name != "nt" and os.geteuid() == 0

def ensure_privileges(auto=True):
    if os.name == "nt":
        if not is_windows_admin():
            if auto:
                log("Requesting administrative privileges on Windows…")
                reexec_with_admin_windows()
            else:
                warn("Not elevated — some actions may fail.")
    else:
        if not is_root():
            warn("Not running as root. Some system-level actions may require sudo.")

class OSInfo:
    def __init__(self):
        self.system = platform.system().lower()
    @property
    def is_windows(self): return self.system == "windows"
    @property
    def is_macos(self): return self.system == "darwin"
    @property
    def is_linux(self): return self.system == "linux"

OS = OSInfo()

def terminate_processes(names: List[str], force=False, dry=False):
    log(f"{'Forcing' if force else 'Terminating'} processes: {', '.join(names)}")
    if dry:
        log(DRY_RUN_PREFIX + "Skipping kill in dry-run.")
        return
    if OS.is_windows:
        for n in names:
            flags = "/IM " + n + (" /F /T" if force else "")
            subprocess.run(["taskkill", *flags.split()], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        for n in names:
            if force:
                subprocess.run(["pkill", "-9", n])
            else:
                subprocess.run(["pkill", n])
    time.sleep(1)

class BrowserPaths:
    def __init__(self):
        self.chrome_paths = []      # (binary_path, user_data_root)
        self.edge_paths = []        # (binary_path, user_data_root)
        self.firefox_paths = []     # (binary_path, profiles_root)
        self.safari_present = False

def pfx(rel: str, *bases: Path) -> Optional[Path]:
    for b in bases:
        candidate = b / rel
        if candidate.exists():
            return candidate
    return None

def detect_browsers() -> 'BrowserPaths':
    bp = BrowserPaths()
    user_home = Path.home()
    if OS.is_windows:
        pf = Path(os.environ.get("ProgramFiles", "C:\\Program Files"))
        pf86 = Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"))
        localapp = Path(os.environ.get("LOCALAPPDATA", ""))

        chrome_bin = pf / "Google/Chrome/Application/chrome.exe"
        chrome_ud = localapp / "Google/Chrome/User Data"
        if chrome_bin.exists() and chrome_ud.exists():
            bp.chrome_paths.append((chrome_bin, chrome_ud))

        edge_bin = pfx("Microsoft/Edge/Application/msedge.exe", pf, pf86)
        edge_ud = localapp / "Microsoft/Edge/User Data"
        if edge_bin and edge_ud.exists():
            bp.edge_paths.append((edge_bin, edge_ud))

        fx_bin = pf / "Mozilla Firefox/firefox.exe"
        fx_prof = Path(os.environ.get("APPDATA", "")) / "Mozilla/Firefox"
        if fx_bin.exists() and fx_prof.exists():
            bp.firefox_paths.append((fx_bin, fx_prof))

        bp.safari_present = False

    elif OS.is_macos:
        chrome_bin = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        chrome_ud = user_home / "Library/Application Support/Google/Chrome"
        if chrome_bin.exists() and chrome_ud.exists():
            bp.chrome_paths.append((chrome_bin, chrome_ud))

        edge_bin = Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge")
        edge_ud = user_home / "Library/Application Support/Microsoft Edge"
        if edge_bin.exists() and edge_ud.exists():
            bp.edge_paths.append((edge_bin, edge_ud))

        fx_bin = Path("/Applications/Firefox.app/Contents/MacOS/firefox")
        fx_prof = user_home / "Library/Application Support/Firefox"
        if fx_bin.exists() and fx_prof.exists():
            bp.firefox_paths.append((fx_bin, fx_prof))

        bp.safari_present = Path("/Applications/Safari.app").exists()

    else:  # Linux
        for candidate in ["/usr/bin/google-chrome", "/usr/bin/chromium", "/snap/bin/chromium", "/usr/bin/google-chrome-stable"]:
            c = Path(candidate)
            if c.exists():
                ud = Path.home() / (".config/google-chrome" if "chrome" in candidate else ".config/chromium")
                if ud.exists():
                    bp.chrome_paths.append((c, ud))
        edge_bin = Path("/usr/bin/microsoft-edge")
        edge_ud = Path.home() / ".config/microsoft-edge"
        if edge_bin.exists() and edge_ud.exists():
            bp.edge_paths.append((edge_bin, edge_ud))
        fx_bin = Path("/usr/bin/firefox")
        fx_prof = Path.home() / ".mozilla/firefox"
        if fx_bin.exists() and fx_prof.exists():
            bp.firefox_paths.append((fx_bin, fx_prof))
        bp.safari_present = False
    return bp

def app_state_dir() -> Path:
    if OS.is_windows:
        root = Path(os.environ.get("PROGRAMDATA", r"C:\\ProgramData"))
        return root / APP_NAME
    elif OS.is_macos:
        return Path("/Library/Application Support") / APP_NAME
    else:
        return Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / APP_NAME

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_download(url: str, dest: Path, expected_sha256: Optional[str] = None, timeout: int = 15) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/{VERSION}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r, open(tmp, "wb") as out:
            shutil.copyfileobj(r, out)
        if expected_sha256:
            actual = sha256_file(tmp)
            if actual.lower() != expected_sha256.lower():
                warn(f"SHA256 mismatch for {url}: expected {expected_sha256}, got {actual}")
                tmp.unlink(missing_ok=True)
                return False
        tmp.replace(dest)
        return True
    except Exception as e:
        warn(f"Download failed: {url} -> {e}")
        try: tmp.unlink(missing_ok=True)
        except Exception: pass
        return False

def load_json(p: Path) -> Optional[dict]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

INTEL_CACHE_FILE = app_state_dir() / "intel.json"

def merge_intel(intel: dict):
    global KNOWN_MALICIOUS_CHROME_EXTENSIONS, SUSPICIOUS_PERMISSIONS
    ids = set(intel.get("known_malicious_chrome_extensions", []))
    perms = set(intel.get("suspicious_permissions", []))
    if ids:
        KNOWN_MALICIOUS_CHROME_EXTENSIONS.update(ids)
        log(f"Merged {len(ids)} malicious Chrome extension IDs from intel")
    if perms:
        SUSPICIOUS_PERMISSIONS.update(perms)
        log(f"Merged {len(perms)} suspicious permissions from intel")

def update_intel_from_manifest(manifest_url: str, timeout: int = 15) -> bool:
    state = app_state_dir()
    state.mkdir(parents=True, exist_ok=True)
    manifest_path = state / "intel-manifest.json"
    if not safe_download(manifest_url, manifest_path, expected_sha256=None, timeout=timeout):
        return False
    manifest = load_json(manifest_path) or {}
    intel_url = manifest.get("intel_url")
    sha = manifest.get("sha256")
    if not intel_url or not sha:
        warn("Intel manifest missing required fields.")
        return False
    if not safe_download(intel_url, INTEL_CACHE_FILE, expected_sha256=sha, timeout=timeout):
        return False
    data = load_json(INTEL_CACHE_FILE)
    if not data:
        warn("Downloaded intel json unreadable.")
        return False
    merge_intel(data)
    log(f"Intel updated to {manifest.get('intel_version', 'unknown')}")
    return True

def load_cached_intel_if_any():
    if INTEL_CACHE_FILE.exists():
        data = load_json(INTEL_CACHE_FILE)
        if data: merge_intel(data)

def check_binary_update(manifest_url: str) -> Tuple[bool, dict]:
    state = app_state_dir()
    mf = state / "update-manifest.json"
    if not safe_download(manifest_url, mf):
        return (False, {})
    m = load_json(mf) or {}
    latest = m.get("latest_version")
    if not latest: return (False, {})
    newer = latest.strip() != VERSION.strip()
    return (newer, m)

def stage_binary_update(update_manifest: dict, apply_now: bool=False) -> Optional[Path]:
    plat = "windows" if OS.is_windows else ("macos" if OS.is_macos else "linux")
    asset = (update_manifest.get("assets") or {}).get(plat)
    if not asset:
        warn("No asset for this platform in update manifest.")
        return None
    url = asset.get("url"); sha = asset.get("sha256")
    if not url or not sha:
        warn("Asset missing url/sha256.")
        return None
    state = app_state_dir()
    dl = state / ("BrowserFortify-staged.exe" if OS.is_windows else "BrowserFortify-staged")
    if not safe_download(url, dl, expected_sha256=sha, timeout=20):
        return None
    if OS.is_macos or OS.is_linux:
        try: dl.chmod(dl.stat().st_mode | 0o111)
        except Exception: pass
    log(f"Staged new binary at {dl}")
    if apply_now:
        try:
            current = Path(sys.argv[0]).resolve()
            if OS.is_windows:
                warn("On Windows, replace the binary after exit (file is locked while running).")
            else:
                backup = current.with_suffix(".old")
                shutil.copy2(current, backup)
                shutil.copy2(dl, current)
                log(f"Replaced {current} (backup at {backup})")
            return dl
        except Exception as e:
            warn(f"Could not apply binary update automatically: {e}")
    return dl

def check_chrome_policies_windows() -> Dict[str, Optional[str]]:
    keys = [
        r"HKCU\Software\Google\Chrome",
        r"HKCU\Software\Policies\Google\Chrome",
        r"HKLM\Software\Google\Chrome",
        r"HKLM\Software\Policies\Google\Chrome",
        r"HKLM\Software\Policies\Google\Update",
        r"HKLM\Software\WOW6432Node\Google\Enrollment",
        r"HKLM\Software\WOW6432Node\Google\Update\ClientState\{430FD4D0-B729-4F61-AA34-91526481799D}",
    ]
    result = {}
    for k in keys:
        try:
            out = subprocess.check_output(["reg", "query", k], stderr=subprocess.STDOUT, text=True)
            result[k] = out.strip()
        except subprocess.CalledProcessError:
            result[k] = None
    return result

def delete_chrome_policies_windows(dry=False):
    to_delete = [
        r"HKCU\Software\Policies\Google\Chrome",
        r"HKLM\Software\Policies\Google\Chrome",
        r"HKLM\Software\Policies\Google\Update",
        r"HKLM\Software\WOW6432Node\Google\Enrollment",
        r"HKLM\Software\WOW6432Node\Google\Update\ClientState\{430FD4D0-B729-4F61-AA34-91526481799D}",
    ]
    backup_dir = Path(tempfile.mkdtemp(prefix="bf-reg-backup-"))
    for key in to_delete:
        try:
            backup_file = backup_dir / (re.sub(r"[^A-Za-z0-9_-]+", "_", key) + ".reg")
            if not dry:
                subprocess.run(["reg", "export", key, str(backup_file), "/y"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            log(f"Backed up registry key {key} -> {backup_file}")
        except Exception as e:
            warn(f"Registry backup failed for {key}: {e}")
    for key in to_delete:
        log(f"Deleting registry path {key}")
        if dry:
            log(DRY_RUN_PREFIX + "Skipping reg delete.")
            continue
        subprocess.run(["reg", "delete", key, "/f"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pol_dir = Path(os.environ.get("ProgramFiles(x86)", r"C:\\Program Files (x86)")) / "Google/Policies"
    if pol_dir.exists():
        log(f"Deleting policy cache directory: {pol_dir}")
        if not dry:
            shutil.rmtree(pol_dir, ignore_errors=True)

def check_chrome_policies_macos() -> Dict[str, List[str]]:
    findings = {}
    system_plist = Path("/Library/Preferences/com.google.Chrome.plist")
    managed_plist = Path("/Library/Managed Preferences/com.google.Chrome.plist")
    cloud_enroll = Path.home() / "Library/Application Support/Google/Chrome Cloud Enrollment"
    for p in [system_plist, managed_plist]:
        if p.exists():
            findings[str(p)] = ["present"]
    if cloud_enroll.exists():
        findings[str(cloud_enroll)] = [f.name for f in cloud_enroll.glob("*")]
    return findings

def remove_chrome_policies_macos(dry=False):
    system_plist = Path("/Library/Preferences/com.google.Chrome.plist")
    managed_plist = Path("/Library/Managed Preferences/com.google.Chrome.plist")
    cloud_enroll = Path.home() / "Library/Application Support/Google/Chrome Cloud Enrollment"
    for plist in [system_plist, managed_plist]:
        if plist.exists():
            log(f"Removing plist: {plist}")
            if not dry:
                backup = plist.with_suffix(plist.suffix + ".bak")
                try:
                    shutil.copy2(plist, backup)
                    os.remove(plist)
                except Exception as e:
                    warn(f"Could not remove {plist}: {e}")
    if cloud_enroll.exists():
        log(f"Clearing cloud enrollment directory: {cloud_enroll}")
        if not dry:
            shutil.rmtree(cloud_enroll, ignore_errors=True)

def check_chrome_policies_linux() -> Dict[str, bool]:
    dirs = [
        Path("/etc/opt/chrome/policies"),
        Path("/etc/opt/chrome/policies/managed"),
        Path("/etc/opt/chrome/policies/recommended"),
    ]
    return {str(d): d.exists() for d in dirs}

def remove_chrome_policies_linux(dry=False):
    for d in [
        Path("/etc/opt/chrome/policies"),
        Path("/etc/opt/chrome/policies/managed"),
        Path("/etc/opt/chrome/policies/recommended"),
    ]:
        if d.exists():
            log(f"Removing {d}")
            if not dry:
                subprocess.run(["sudo", "rm", "-rf", str(d)])

def list_chromium_extensions(user_data_root: Path) -> List[Dict]:
    results = []
    profile_dirs = [p for p in user_data_root.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile"))]
    for prof in profile_dirs:
        ext_root = prof / "Extensions"
        if not ext_root.exists():
            continue
        for ext_id_dir in ext_root.iterdir():
            if not ext_id_dir.is_dir():
                continue
            for ver_dir in ext_id_dir.iterdir():
                manifest = ver_dir / "manifest.json"
                if manifest.exists():
                    try:
                        data = json.loads(manifest.read_text(encoding="utf-8", errors="ignore"))
                    except Exception:
                        data = {}
                    perms = set(data.get("permissions", []))
                    opt_perms = set(data.get("optional_permissions", []))
                    suspicious = bool(perms & SUSPICIOUS_PERMISSIONS or opt_perms & SUSPICIOUS_PERMISSIONS)
                    known_bad = ext_id_dir.name in KNOWN_MALICIOUS_CHROME_EXTENSIONS
                    results.append({
                        "profile": prof.name,
                        "id": ext_id_dir.name,
                        "version": ver_dir.name,
                        "name": data.get("name"),
                        "permissions": list(perms),
                        "optional_permissions": list(opt_perms),
                        "suspicious": suspicious,
                        "known_bad": known_bad,
                        "path": str(ver_dir),
                    })
    return results

def list_firefox_extensions(profiles_root: Path) -> List[Dict]:
    results = []
    prof_ini = profiles_root / "profiles.ini"
    candidate_profiles = []
    if prof_ini.exists():
        content = prof_ini.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r"^Path=(.+)$", content, flags=re.MULTILINE):
            rel = m.group(1).strip()
            candidate_profiles.append((profiles_root / rel).resolve())
    if not candidate_profiles:
        candidate_profiles = [p for p in profiles_root.iterdir() if p.is_dir() and (p.name.endswith(".default") or p.name.endswith(".default-release"))]
    for prof in candidate_profiles:
        ext_json = prof / "extensions.json"
        if ext_json.exists():
            try:
                data = json.loads(ext_json.read_text(encoding="utf-8", errors="ignore"))
                addons = data.get("addons", [])
            except Exception:
                addons = []
            for a in addons:
                perms = set(a.get("userPermissions", {}).get("permissions", []))
                suspicious = bool(perms & SUSPICIOUS_PERMISSIONS)
                results.append({
                    "profile": prof.name,
                    "id": a.get("id"),
                    "name": a.get("defaultLocale", {}).get("name") or a.get("name"),
                    "version": a.get("version"),
                    "permissions": list(perms),
                    "suspicious": suspicious,
                    "path": str(prof),
                })
    return results

def is_suspicious_url(u: str) -> bool:
    u = u.lower()
    suspect = ["search-redirect.", "searchredirect", "findqu", "myz", "wow-search", "smashapps", "tab", "feed", "/redirect?", "tracking", "click", "ad."]
    return any(s in u for s in suspect) and not any(g in u for g in ["google.", "bing.", "duckduckgo.", "yahoo."])

def detect_chromium_hijack_indicators(user_data_root: Path) -> Dict[str, List[str]]:
    findings = {"suspicious_search_engines": [], "startup_pages": [], "homepage_overrides": []}
    for prof in [p for p in user_data_root.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile"))]:
        pref_file = prof / "Preferences"
        if pref_file.exists():
            try:
                prefs = json.loads(pref_file.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            se = prefs.get("default_search_provider", {})
            name = se.get("name") or ""
            url = se.get("search_url") or se.get("search_url_post_params") or ""
            if url and not any(x in (url or "") for x in ["google.", "bing.", "duckduckgo.", "yahoo."]):
                findings["suspicious_search_engines"].append(f"{prof.name}: {name} -> {url}")
            on_start = prefs.get("session", {}).get("startup_urls") or prefs.get("session", {}).get("urls_to_restore_on_startup") or []
            for u in on_start:
                if is_suspicious_url(u):
                    findings["startup_pages"].append(f"{prof.name}: {u}")
            hp = prefs.get("homepage", "")
            if hp and is_suspicious_url(hp):
                findings["homepage_overrides"].append(f"{prof.name}: {hp}")
    return findings

def detect_firefox_hijack_indicators(profiles_root: Path) -> Dict[str, List[str]]:
    findings = {"suspicious_search_engines": [], "startup_pages": [], "homepage_overrides": []}
    for prof in profiles_root.iterdir():
        if not prof.is_dir(): continue
        prefs_js = prof / "prefs.js"
        if not prefs_js.exists(): continue
        try:
            content = prefs_js.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for m in re.finditer(r'user_pref\("browser\.startup\.homepage",\s*"([^"]+)"\);', content):
            u = m.group(1)
            if is_suspicious_url(u):
                findings["homepage_overrides"].append(f"{prof.name}: {u}")
        for m in re.finditer(r'user_pref\("browser\.search\.defaultenginename",\s*"([^"]+)"\);', content):
            name = m.group(1)
            if name and name.lower() not in ("google", "bing", "duckduckgo", "yahoo"):
                findings["suspicious_search_engines"].append(f"{prof.name}: {name}")
    return findings

def profile_integrity_check(path: Path) -> List[str]:
    issues = []
    must_have = ["Preferences", "Secure Preferences", "History", "Bookmarks"]
    present = [p.name for p in path.iterdir()] if path.exists() else []
    for m in must_have:
        if m not in present:
            issues.append(f"Missing: {m}")
    for p in path.glob("*"):
        try:
            if p.is_file() and p.stat().st_size > 512 * 1024 * 1024:
                issues.append(f"Unusual large file: {p.name} ({p.stat().st_size/1024/1024:.1f} MB)")
        except Exception:
            pass
    return issues

def backup_profile_dir(src: Path, dst_root: Path, dry=False) -> Path:
    dst_root.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = dst_root / f"{src.name}-backup-{ts}"
    log(f"Backing up profile: {src} -> {dst}")
    if dry:
        log(DRY_RUN_PREFIX + "Skipping copy in dry-run.")
        return dst
    try:
        shutil.copytree(src, dst)
        return dst
    except Exception as e:
        err(f"Backup failed: {e}")
        return dst

def rename_profile_dir(src: Path, dry=False) -> Optional[Path]:
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = src.with_name(src.name + f".old-{ts}")
    log(f"Renaming profile: {src} -> {dst}")
    if dry:
        log(DRY_RUN_PREFIX + "Skipping rename in dry-run.")
        return dst
    try:
        src.rename(dst)
        return dst
    except Exception as e:
        err(f"Rename failed: {e}")
        return None

def clear_chromium_browsing_data(profile_dir: Path, dry=False):
    targets = [
        "Cache", "Code Cache", "GPUCache", "Service Worker/CacheStorage",
        "Storage/ext", "IndexedDB", "Session Storage",
        "Cookies", "History", "History Provider Cache", "Network Action Predictor",
        "Top Sites", "Visited Links", "Shortcuts", "Favicons", "Login Data", "Web Data",
        "AutofillStrikeDatabase", "TransportSecurity",
    ]
    for t in targets:
        p = profile_dir / t
        if p.exists():
            log(f"Deleting {p}")
            if not dry:
                try:
                    if p.is_dir():
                        shutil.rmtree(p, ignore_errors=True)
                    else:
                        p.unlink(missing_ok=True)
                except Exception as e:
                    warn(f"Failed to remove {p}: {e}")

def uninstall_chromium_extension(ext_id: str, user_data_root: Path, dry=False):
    for prof in [p for p in user_data_root.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile"))]:
        ext_root = prof / "Extensions" / ext_id
        if ext_root.exists():
            log(f"Removing extension {ext_id} from {prof.name}")
            if not dry:
                shutil.rmtree(ext_root, ignore_errors=True)

def uninstall_firefox_extension(addon_id: str, profiles_root: Path, dry=False):
    for prof in profiles_root.iterdir():
        if not prof.is_dir(): continue
        ext_dir = prof / "extensions"
        if ext_dir.exists():
            for item in ext_dir.iterdir():
                if addon_id and addon_id in item.name:
                    log(f"Removing Firefox extension {addon_id} in {prof.name}")
                    if not dry:
                        if item.is_dir():
                            shutil.rmtree(item, ignore_errors=True)
                        else:
                            item.unlink(missing_ok=True)

def summarize_findings(findings: Dict) -> str:
    return json.dumps(findings, indent=2, ensure_ascii=False)

def write_report(title: str, content: Dict, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "title": title,
        "generated_at": dt.datetime.now().isoformat(),
        "host": platform.node(),
        "user": getpass.getuser(),
        "version": VERSION,
        "content": content
    }
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log(f"Report written to {path}")

def phase1_scan(bp: 'BrowserPaths') -> Dict:
    log("=== Phase 1: Initial System Scan and Diagnosis ===")
    findings = {
        "os": platform.platform(),
        "browsers": {"chrome": [], "edge": [], "firefox": [], "safari_present": bp.safari_present},
        "policies": {},
        "extensions": {"chromium": [], "firefox": []},
        "hijack_indicators": {"chromium": {}, "firefox": {}},
        "profile_integrity": {}
    }
    if OS.is_windows:
        findings["policies"]["windows_chrome"] = check_chrome_policies_windows()
    elif OS.is_macos:
        findings["policies"]["macos_chrome"] = check_chrome_policies_macos()
    else:
        findings["policies"]["linux_chrome"] = check_chrome_policies_linux()

    for (binp, ud) in bp.chrome_paths + bp.edge_paths:
        findings["browsers"]["chrome" if "Chrome" in str(binp) or "google-chrome" in str(binp) else "edge"].append({
            "binary": str(binp), "user_data": str(ud),
        })
        findings["extensions"]["chromium"].extend(list_chromium_extensions(ud))
        findings["hijack_indicators"]["chromium"][str(ud)] = detect_chromium_hijack_indicators(ud)
        for prof in [p for p in ud.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile"))]:
            issues = profile_integrity_check(prof)
            if issues:
                findings["profile_integrity"][str(prof)] = issues

    for (binp, pr) in bp.firefox_paths:
        findings["browsers"]["firefox"].append({"binary": str(binp), "profiles_root": str(pr)})
        findings["extensions"]["firefox"].extend(list_firefox_extensions(pr))
        findings["hijack_indicators"]["firefox"][str(pr)] = detect_firefox_hijack_indicators(pr)

    return findings

def phase2_remediate(bp: 'BrowserPaths', args, scan_findings: Dict):
    log("=== Phase 2: Automated Remediation ===")
    if not args.yes:
        resp = input("Proceed with remediation? This may close browsers, remove policies, clear data, and rename profiles. [yes/NO]: ").strip().lower()
        if resp not in ("y", "yes"):
            log("Remediation aborted by user.")
            return
    terminate_processes(
        names=["chrome.exe", "msedge.exe", "firefox.exe"] if OS.is_windows else ["google-chrome", "chromium", "microsoft-edge", "firefox"],
        force=args.force_kill, dry=args.dry_run
    )
    backup_root = Path(args.backup_dir).expanduser().resolve() if args.backup_dir else (LOG_DIR / "backups")
    for (_, ud) in bp.chrome_paths + bp.edge_paths:
        for prof in [p for p in ud.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile"))]:
            if args.backup:
                backup_profile_dir(prof, backup_root, dry=args.dry_run)

    if OS.is_windows:
        delete_chrome_policies_windows(dry=args.dry_run)
    elif OS.is_macos:
        remove_chrome_policies_macos(dry=args.dry_run)
    else:
        remove_chrome_policies_linux(dry=args.dry_run)

    for (_, ud) in bp.chrome_paths + bp.edge_paths:
        ext_list = list_chromium_extensions(ud)
        for e in ext_list:
            if e["known_bad"] or (e["suspicious"] and args.remove_suspicious):
                uninstall_chromium_extension(e["id"], ud, dry=args.dry_run)
        if args.reset_profiles:
            for prof in [p for p in ud.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile"))]:
                rename_profile_dir(prof, dry=args.dry_run)
        else:
            for prof in [p for p in ud.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile"))]:
                if args.clear_data:
                    clear_chromium_browsing_data(prof, dry=args.dry_run)

    for (_, pr) in bp.firefox_paths:
        ext_list = list_firefox_extensions(pr)
        for e in ext_list:
            if e["suspicious"] and args.remove_suspicious:
                if e.get("id"):
                    uninstall_firefox_extension(e["id"], pr, dry=args.dry_run)
        if args.reset_profiles:
            for prof in pr.iterdir():
                if prof.is_dir() and (prof.name.endswith(".default") or prof.name.endswith(".default-release") or prof.name.startswith("Profile")):
                    rename_profile_dir(prof, dry=args.dry_run)

    if bp.safari_present:
        log("Safari detected. Automated remediation limited.")
        log("Manual: Safari > Settings > Extensions (disable/uninstall unknown).")
        log("Check System Settings > Privacy & Security > Profiles for unwanted profiles.")

def phase3_verify_and_harden(bp: 'BrowserPaths', pre_findings: Dict, args) -> Dict:
    log("=== Phase 3: Post-Remediation Verification & Hardening ===")
    post = phase1_scan(bp)
    summary = {
        "pre_summary": {
            "chromium_extensions_flagged": sum(1 for e in pre_findings["extensions"]["chromium"] if e["known_bad"] or e["suspicious"]),
            "firefox_extensions_flagged": sum(1 for e in pre_findings["extensions"]["firefox"] if e["suspicious"]),
        },
        "post_summary": {
            "chromium_extensions_flagged": sum(1 for e in post["extensions"]["chromium"] if e["known_bad"] or e["suspicious"]),
            "firefox_extensions_flagged": sum(1 for e in post["extensions"]["firefox"] if e["suspicious"]),
        },
        "policy_check_post": post.get("policies", {}),
        "hijack_indicators_post": post.get("hijack_indicators", {}),
    }
    guidance = [
        "Enable MFA on browser-associated accounts.",
        "Review installed extensions; remove unused or invasive ones.",
        "Restrict site permissions for location, camera, mic, notifications.",
        "Disable ad personalization; prefer privacy-friendly defaults.",
        "Ensure automatic browser updates are enabled.",
        "Enterprise: verify patch management for rapid browser updates across fleet.",
        "Run a full system scan with reputable anti-malware (e.g., Malwarebytes, Sophos Scan & Clean).",
        "If a profile was renamed, create a fresh one and import bookmarks only. Prefer password sync; avoid CSV unless necessary (securely delete afterward).",
    ]
    result = {"verification": summary, "guidance": guidance}
    write_report("BrowserFortify Post-Remediation", result, LOG_DIR / "post-remediation-report.json")
    return result

def main():
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description=f"{APP_NAME} v{VERSION} — Cross-platform browser security remediation & hardening"
    )
    parser.add_argument("--scan-only", action="store_true", help="Run only Phase 1 scan and report.")
    parser.add_argument("--remediate", action="store_true", help="Run Phase 2 remediation.")
    parser.add_argument("--verify", action="store_true", help="Run Phase 3 verification & guidance.")
    parser.add_argument("--backup", action="store_true", help="Backup profiles before changes.")
    parser.add_argument("--backup-dir", type=str, help="Backup destination directory.")
    parser.add_argument("--clear-data", action="store_true", help="Clear caches/history/cookies/autofill (non-destructive).")
    parser.add_argument("--reset-profiles", action="store_true", help="Rename profiles to .old-<timestamp> for clean start.")
    parser.add_argument("--remove-suspicious", action="store_true", help="Also remove extensions with suspicious permissions (not only known malicious).")
    parser.add_argument("--force-kill", action="store_true", help="Force-terminate browser processes.")
    parser.add_argument("--dry-run", action="store_true", help="Show actions without making changes.")
    parser.add_argument("-y", "--yes", action="store_true", help="Assume yes for prompts.")
    parser.add_argument("--require-admin", action="store_true", help="Exit if not elevated/root.")
    parser.add_argument("--update-intel", action="store_true", help="Fetch and merge latest threat-intel (malicious IDs & permissions).")
    parser.add_argument("--intel-manifest", type=str, help="HTTPS URL to intel manifest json.")
    parser.add_argument("--check-binary-update", action="store_true", help="Check if a newer BrowserFortify binary is available.")
    parser.add_argument("--update-manifest", type=str, help="HTTPS URL to update manifest json.")
    parser.add_argument("--apply-binary-update", action="store_true", help="Attempt to replace binary after staging (POSIX only).")
    args = parser.parse_args()

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log(f"{APP_NAME} v{VERSION} starting as user {getpass.getuser()} on {platform.platform()}")

    ensure_privileges(auto=not args.require_admin)
    if args.require_admin:
        if OS.is_windows and not is_windows_admin():
            err("Administrative privileges required. Re-run elevated.")
            sys.exit(1)
        if not OS.is_windows and not is_root():
            err("Root privileges required. Re-run with sudo.")
            sys.exit(1)

    load_cached_intel_if_any()
    if args.update_intel:
        if not args.intel_manifest:
            err("--update-intel requires --intel-manifest <URL>")
            sys.exit(2)
        if update_intel_from_manifest(args.intel_manifest):
            log("Threat-intel updated successfully.")
        else:
            warn("Threat-intel update failed; proceeding with built-in + cached intel.")

    if args.check_binary_update:
        if not args.update_manifest:
            err("--check-binary-update requires --update-manifest <URL>")
            sys.exit(2)
        newer, m = check_binary_update(args.update_manifest)
        if newer:
            log(f"New version available: {m.get('latest_version')} (you are on {VERSION})")
            log(f"Release notes: {m.get('notes', 'n/a')}")
            if args.apply_binary_update:
                staged = stage_binary_update(m, apply_now=True)
                log(f"Update staged at: {staged}" if staged else "Staging failed.")
            else:
                staged = stage_binary_update(m, apply_now=False)
                log(f"Update staged at: {staged}. Replace the current binary after exit.")
        else:
            log("No newer binary available.")

    bp = detect_browsers()
    log(f"Detected browsers -> Chrome: {len(bp.chrome_paths)} | Edge: {len(bp.edge_paths)} | Firefox: {len(bp.firefox_paths)} | Safari: {bp.safari_present}")

    findings = phase1_scan(bp)
    write_report("BrowserFortify Initial Scan", findings, LOG_DIR / "initial-scan-report.json")

    if args.scan_only and not args.remediate and not args.verify:
        log("Scan-only complete.")
        return

    if args.remediate:
        phase2_remediate(bp, args, findings)

    if args.verify or (args.remediate and not args.scan_only):
        phase3_verify_and_harden(bp, findings, args)

    log(f"{APP_NAME} finished. Logs: {LOG_FILE}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        warn("Interrupted by user.")
    except Exception as e:
        err(f"Unhandled error: {e}")
        raise
