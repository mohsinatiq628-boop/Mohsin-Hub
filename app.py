"""
Mohsin Automation Hub
Production-ready, mobile-accessible Streamlit cloud automation agent.

Core Capabilities:
1. Gmail & Social Cookie Persistence (Gmail, TikTok, Instagram, YouTube)
2. Error-Handled Content & Link Fetcher (Video URLs & Live Streams)
3. Campaign Auto-Submission Workflow & Log Viewer (Gaming Clip Rewards)
4. Mobile-Responsive Light-Themed UI with Crash-Proof Error Handling
"""

from __future__ import annotations

import json
import os
import re
import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import pandas as pd
import requests
import streamlit as st
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import yt_dlp  # type: ignore
except ImportError:  # pragma: no cover
    yt_dlp = None

try:
    from cryptography.fernet import Fernet, InvalidToken  # type: ignore
except ImportError:  # pragma: no cover
    Fernet = None
    InvalidToken = Exception


# ---------------------------------------------------------------------------
# Configuration & Storage Paths
# ---------------------------------------------------------------------------

APP_NAME = "Mohsin Automation Hub"
DATA_DIR = Path(os.getenv("HUB_DATA_DIR", "./hub_storage")).resolve()
SESSIONS_DIR = DATA_DIR / "sessions"
CAMPAIGNS_FILE = DATA_DIR / "campaigns.json"
LOGS_FILE = DATA_DIR / "activity_logs.json"

PLATFORMS: Dict[str, Dict[str, str]] = {
    "gmail": {
        "label": "Gmail",
        "login_url": "https://accounts.google.com/",
        "domain": "google.com",
    },
    "youtube": {
        "label": "YouTube",
        "login_url": "https://www.youtube.com/",
        "domain": "youtube.com",
    },
    "tiktok": {
        "label": "TikTok",
        "login_url": "https://www.tiktok.com/login",
        "domain": "tiktok.com",
    },
    "instagram": {
        "label": "Instagram",
        "login_url": "https://www.instagram.com/accounts/login/",
        "domain": "instagram.com",
    },
}

DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
}


def ensure_storage() -> None:
    """Ensure local persistence directories exist safely."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class LogEntry:
    timestamp: str
    level: str  # INFO | SUCCESS | WARNING | ERROR
    module: str
    message: str
    details: str = ""


@dataclass
class MediaResult:
    source_url: str
    title: str = "Untitled Media"
    platform: str = "Web"
    author: str = "Unknown"
    duration_seconds: Optional[int] = None
    is_live: bool = False
    thumbnail_url: str = ""
    direct_streams: List[Dict[str, str]] = field(default_factory=list)
    extractor: str = "html-fallback"
    http_status: int = 200
    error: str = ""


@dataclass
class CampaignItem:
    id: str
    campaign_name: str
    game_title: str
    platform: str
    clip_url: str
    direct_media_url: str
    submission_endpoint: str
    reward_account: str
    caption: str
    status: str = "Queued"  # Queued | Submitted | Failed | Dry-Run OK
    last_response: str = ""
    updated_at: str = ""


# ---------------------------------------------------------------------------
# Persistent Log Manager
# ---------------------------------------------------------------------------


class LogManager:
    """Thread-safe local JSON activity log manager."""

    MAX_LOGS = 500

    @staticmethod
    def _read_raw() -> List[Dict[str, Any]]:
        ensure_storage()
        if not LOGS_FILE.exists():
            return []
        try:
            data = json.loads(LOGS_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except Exception:
            return []

    @staticmethod
    def _write_raw(entries: List[Dict[str, Any]]) -> None:
        ensure_storage()
        LOGS_FILE.write_text(
            json.dumps(entries[: LogManager.MAX_LOGS], indent=2),
            encoding="utf-8",
        )

    @classmethod
    def log(cls, level: str, module: str, message: str, details: str = "") -> None:
        try:
            entries = cls._read_raw()
            entry = LogEntry(
                timestamp=utc_now_iso(),
                level=level.upper(),
                module=module,
                message=message,
                details=details[:2000],
            )
            entries.insert(0, asdict(entry))
            cls._write_raw(entries)
        except Exception:
            # Logging must never crash the main application.
            pass

    @classmethod
    def get_logs(cls, level_filter: str = "ALL") -> List[Dict[str, Any]]:
        entries = cls._read_raw()
        if level_filter != "ALL":
            return [e for e in entries if e.get("level") == level_filter]
        return entries

    @classmethod
    def clear_logs(cls) -> None:
        try:
            cls._write_raw([])
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Capability 1: Gmail & Social Cookie / Session Persistence Vault
# ---------------------------------------------------------------------------


class SessionVault:
    """
    Saves and loads browser cookies & Playwright storage_state locally so
    Gmail, YouTube, TikTok, and Instagram sessions persist without repeated OTPs.
    Supports optional Fernet encryption when HUB_VAULT_KEY is set.
    """

    @staticmethod
    def _get_cipher() -> Optional[Any]:
        key = os.getenv("HUB_VAULT_KEY", "").strip()
        if key and Fernet is not None:
            try:
                return Fernet(key.encode("utf-8"))
            except Exception:
                LogManager.log(
                    "WARNING",
                    "SessionVault",
                    "Invalid HUB_VAULT_KEY format; falling back to plain JSON.",
                )
        return None

    @staticmethod
    def _session_path(platform: str) -> Path:
        safe_name = re.sub(r"[^a-z0-9_-]", "", platform.lower())
        return SESSIONS_DIR / f"{safe_name}_session.json"

    @classmethod
    def parse_cookie_input(cls, raw_text: str, default_domain: str) -> List[Dict[str, Any]]:
        """
        Parse either Playwright/EditThisCookie JSON array, storage_state JSON
        ({'cookies': [...]}), or Netscape cookies.txt text into normalized cookies.
        """
        cleaned = raw_text.strip()
        if not cleaned:
            raise ValueError("Cookie input is empty.")

        # Try JSON formats first
        if cleaned.startswith("{") or cleaned.startswith("["):
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict) and "cookies" in parsed:
                cookies = parsed["cookies"]
            elif isinstance(parsed, list):
                cookies = parsed
            elif isinstance(parsed, dict):
                # Simple key:value cookie map
                cookies = [
                    {
                        "name": str(k),
                        "value": str(v),
                        "domain": f".{default_domain}",
                        "path": "/",
                        "secure": True,
                        "httpOnly": False,
                    }
                    for k, v in parsed.items()
                ]
            else:
                raise ValueError("Unsupported JSON cookie format.")

            normalized: List[Dict[str, Any]] = []
            for item in cookies:
                if not isinstance(item, dict) or "name" not in item:
                    continue
                normalized.append(
                    {
                        "name": str(item.get("name", "")),
                        "value": str(item.get("value", "")),
                        "domain": str(item.get("domain") or f".{default_domain}"),
                        "path": str(item.get("path") or "/"),
                        "expires": item.get("expires") or item.get("expirationDate"),
                        "httpOnly": bool(item.get("httpOnly", False)),
                        "secure": bool(item.get("secure", True)),
                        "sameSite": str(item.get("sameSite") or "Lax"),
                    }
                )
            if not normalized:
                raise ValueError("No valid cookie entries found in JSON.")
            return normalized

        # Try Netscape cookies.txt format
        netscape_cookies: List[Dict[str, Any]] = []
        for line in cleaned.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 7:
                netscape_cookies.append(
                    {
                        "name": parts[5],
                        "value": parts[6],
                        "domain": parts[0],
                        "path": parts[2],
                        "expires": int(parts[4]) if parts[4].isdigit() else None,
                        "httpOnly": False,
                        "secure": parts[3].upper() == "TRUE",
                        "sameSite": "Lax",
                    }
                )
        if netscape_cookies:
            return netscape_cookies

        raise ValueError(
            "Unrecognized cookie payload. Paste JSON cookies, Playwright storage_state, or Netscape cookies.txt."
        )

    @classmethod
    def save_browser_cookies(
        cls,
        platform: str,
        cookies: List[Dict[str, Any]],
        account_label: str = "",
        origins: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bool, str]:
        """Persist browser cookies and storage_state locally."""
        try:
            ensure_storage()
            payload = {
                "platform": platform.lower(),
                "account_label": account_label.strip() or f"{platform}_default",
                "saved_at": utc_now_iso(),
                "cookies": cookies,
                "origins": origins or [],
            }
            raw_bytes = json.dumps(payload, indent=2).encode("utf-8")

            cipher = cls._get_cipher()
            if cipher is not None:
                envelope = {
                    "encrypted": True,
                    "token": cipher.encrypt(raw_bytes).decode("utf-8"),
                }
                cls._session_path(platform).write_text(
                    json.dumps(envelope, indent=2), encoding="utf-8"
                )
            else:
                cls._session_path(platform).write_text(
                    raw_bytes.decode("utf-8"), encoding="utf-8"
                )

            LogManager.log(
                "SUCCESS",
                "SessionVault",
                f"Saved {len(cookies)} cookies for {platform.title()}.",
                f"Account: {payload['account_label']}",
            )
            return True, f"Saved {len(cookies)} cookies for {platform.title()}."
        except Exception as exc:
            LogManager.log(
                "ERROR",
                "SessionVault",
                f"Failed to save cookies for {platform}.",
                str(exc),
            )
            return False, f"Save failed: {exc}"

    @classmethod
    def load_browser_cookies(cls, platform: str) -> Optional[Dict[str, Any]]:
        """Load persisted browser session data from local disk."""
        path = cls._session_path(platform)
        if not path.exists():
            return None
        try:
            raw_text = path.read_text(encoding="utf-8")
            parsed = json.loads(raw_text)
            if isinstance(parsed, dict) and parsed.get("encrypted"):
                cipher = cls._get_cipher()
                if cipher is None:
                    raise RuntimeError(
                        "Session is encrypted, but HUB_VAULT_KEY is not set."
                    )
                decrypted = cipher.decrypt(parsed["token"].encode("utf-8"))
                return json.loads(decrypted.decode("utf-8"))
            return parsed
        except (InvalidToken, Exception) as exc:
            LogManager.log(
                "ERROR",
                "SessionVault",
                f"Could not load session for {platform}.",
                str(exc),
            )
            return None

    @classmethod
    def export_requests_cookie_jar(cls, platform: str) -> requests.cookies.RequestsCookieJar:
        """Convert stored session cookies into a requests CookieJar."""
        jar = requests.cookies.RequestsCookieJar()
        session_data = cls.load_browser_cookies(platform)
        if not session_data:
            return jar
        for cookie in session_data.get("cookies", []):
            name = cookie.get("name")
            value = cookie.get("value")
            if name and value is not None:
                jar.set(
                    name=name,
                    value=value,
                    domain=cookie.get("domain", ""),
                    path=cookie.get("path", "/"),
                )
        return jar

    @classmethod
    def write_netscape_cookies_txt(cls, platform: str) -> Optional[Path]:
        """Write temporary Netscape cookies.txt for yt-dlp authentication."""
        session_data = cls.load_browser_cookies(platform)
        if not session_data or not session_data.get("cookies"):
            return None
        ensure_storage()
        out_path = SESSIONS_DIR / f"{platform.lower()}_cookies.txt"
        lines = ["# Netscape HTTP Cookie File", "# Generated by Mohsin Automation Hub"]
        now_ts = int(time.time()) + 86400 * 30
        for c in session_data["cookies"]:
            domain = c.get("domain") or f".{PLATFORMS.get(platform, {}).get('domain', 'example.com')}"
            include_sub = "TRUE" if domain.startswith(".") else "FALSE"
            path = c.get("path") or "/"
            secure = "TRUE" if c.get("secure", True) else "FALSE"
            expires = c.get("expires")
            exp_int = int(expires) if isinstance(expires, (int, float)) and expires > 0 else now_ts
            lines.append(
                f"{domain}\t{include_sub}\t{path}\t{secure}\t{exp_int}\t{c.get('name', '')}\t{c.get('value', '')}"
            )
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return out_path

    @classmethod
    def get_session_status(cls, platform: str) -> Dict[str, Any]:
        """Inspect local session health, expiry counts, and metadata."""
        data = cls.load_browser_cookies(platform)
        if not data:
            return {
                "connected": False,
                "account_label": "Not connected",
                "cookie_count": 0,
                "expired_count": 0,
                "saved_at": "—",
            }
        cookies = data.get("cookies", [])
        now_ts = time.time()
        expired = sum(
            1
            for c in cookies
            if isinstance(c.get("expires"), (int, float))
            and 0 < float(c["expires"]) < now_ts
        )
        return {
            "connected": len(cookies) > 0,
            "account_label": data.get("account_label", "Saved Profile"),
            "cookie_count": len(cookies),
            "expired_count": expired,
            "saved_at": data.get("saved_at", "—"),
        }

    @classmethod
    def clear_session(cls, platform: str) -> Tuple[bool, str]:
        try:
            for target in (
                cls._session_path(platform),
                SESSIONS_DIR / f"{platform.lower()}_cookies.txt",
            ):
                if target.exists():
                    target.unlink()
            LogManager.log(
                "INFO",
                "SessionVault",
                f"Cleared local session for {platform.title()}.",
            )
            return True, f"Session cleared for {platform.title()}."
        except Exception as exc:
            return False, f"Failed to clear session: {exc}"

    @classmethod
    def launch_interactive_playwright_capture(
        cls, platform: str, account_label: str = "", timeout_seconds: int = 90
    ) -> Tuple[bool, str]:
        """
        Optional desktop-host helper: opens a headed Chromium Playwright browser
        with existing storage_state so the user signs in once (handling 2FA/OTP),
        then automatically persists the resulting cookies & storage_state locally.
        """
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except ImportError:
            return (
                False,
                "Playwright is not installed. Run `playwright install chromium` or paste cookies manually.",
            )

        meta = PLATFORMS.get(platform.lower())
        if not meta:
            return False, f"Unsupported platform: {platform}"

        try:
            existing = cls.load_browser_cookies(platform)
            storage_state_arg = None
            if existing and existing.get("cookies"):
                storage_state_arg = {
                    "cookies": existing["cookies"],
                    "origins": existing.get("origins", []),
                }

            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=False)
                context = browser.new_context(storage_state=storage_state_arg)
                page = context.new_page()
                page.goto(meta["login_url"], wait_until="domcontentloaded", timeout=30000)

                deadline = time.time() + timeout_seconds
                while time.time() < deadline:
                    if page.is_closed():
                        break
                    time.sleep(1.0)

                state = context.storage_state()
                browser.close()

            return cls.save_browser_cookies(
                platform=platform,
                cookies=state.get("cookies", []),
                account_label=account_label,
                origins=state.get("origins", []),
            )
        except Exception as exc:
            msg = (
                "Headed browser capture unavailable in headless cloud environment. "
                f"Import JSON/cookies.txt instead. ({exc})"
            )
            LogManager.log("WARNING", "SessionVault", msg)
            return False, msg


# ---------------------------------------------------------------------------
# Capability 2: Error-Handled Content & Link Fetcher Module
# ---------------------------------------------------------------------------


def build_resilient_http_session(platform_hint: Optional[str] = None) -> requests.Session:
    """Create a requests Session with retry policy, browser headers, and optional cookies."""
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    retry = Retry(
        total=2,
        backoff_factor=0.6,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if platform_hint:
        jar = SessionVault.export_requests_cookie_jar(platform_hint)
        if len(jar) > 0:
            session.cookies.update(jar)

    return session


def infer_platform_from_url(url: str) -> str:
    host = urlparse(url).netloc.lower()
    if "youtube.com" in host or "youtu.be" in host:
        return "youtube"
    if "tiktok.com" in host:
        return "tiktok"
    if "instagram.com" in host:
        return "instagram"
    if "twitch.tv" in host:
        return "twitch"
    return "web"


class MediaFetcher:
    """Safely extracts video/live-stream metadata and direct media URLs."""

    @staticmethod
    def _validate_url(url: str) -> str:
        cleaned = url.strip()
        parsed = urlparse(cleaned)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("Please enter a valid http:// or https:// URL.")
        return cleaned

    @classmethod
    def fetch(cls, raw_url: str, use_saved_cookies: bool = True) -> MediaResult:
        try:
            target_url = cls._validate_url(raw_url)
        except ValueError as exc:
            return MediaResult(source_url=raw_url, error=str(exc), http_status=400)

        platform_hint = infer_platform_from_url(target_url)

        # Direct media file shortcut (.mp4, .webm, .m3u8)
        lower_path = urlparse(target_url).path.lower()
        if any(lower_path.endswith(ext) for ext in (".mp4", ".webm", ".mov", ".m3u8")):
            is_live = lower_path.endswith(".m3u8")
            result = MediaResult(
                source_url=target_url,
                title=Path(lower_path).name or "Direct Stream",
                platform=platform_hint.title(),
                is_live=is_live,
                extractor="direct-url",
                direct_streams=[
                    {
                        "quality": "Direct Source",
                        "ext": lower_path.rsplit(".", 1)[-1],
                        "url": target_url,
                    }
                ],
            )
            LogManager.log("SUCCESS", "MediaFetcher", f"Resolved direct media link: {target_url}")
            return result

        # Primary extractor: yt-dlp (supports YouTube, TikTok, Instagram, Twitch, etc.)
        if yt_dlp is not None:
            ydl_result = cls._extract_with_ytdlp(target_url, platform_hint, use_saved_cookies)
            if ydl_result and not ydl_result.error:
                LogManager.log(
                    "SUCCESS",
                    "MediaFetcher",
                    f"Extracted media via yt-dlp: {ydl_result.title}",
                    target_url,
                )
                return ydl_result

        # Fallback extractor: resilient HTML/OpenGraph scraper
        html_result = cls._extract_with_http_fallback(target_url, platform_hint, use_saved_cookies)
        if html_result.error:
            LogManager.log(
                "WARNING",
                "MediaFetcher",
                f"Media fetch handled error ({html_result.http_status}): {html_result.error}",
                target_url,
            )
        else:
            LogManager.log(
                "SUCCESS",
                "MediaFetcher",
                f"Extracted page media via HTML parser: {html_result.title}",
                target_url,
            )
        return html_result

    @classmethod
    def _extract_with_ytdlp(
        cls, url: str, platform_hint: str, use_saved_cookies: bool
    ) -> Optional[MediaResult]:
        cookie_file: Optional[Path] = None
        if use_saved_cookies and platform_hint in PLATFORMS:
            cookie_file = SessionVault.write_netscape_cookies_txt(platform_hint)

        ydl_opts: Dict[str, Any] = {
            "quiet": True,
            "no_warnings": True,
            "skip_download": True,
            "noplaylist": True,
            "socket_timeout": 12,
            "http_headers": DEFAULT_HEADERS,
        }
        if cookie_file and cookie_file.exists():
            ydl_opts["cookiefile"] = str(cookie_file)

        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=False)
                if not info:
                    return None

                streams: List[Dict[str, str]] = []
                for fmt in info.get("formats", []) or []:
                    fmt_url = fmt.get("url")
                    if not fmt_url:
                        continue
                    vcodec = fmt.get("vcodec", "none")
                    acodec = fmt.get("acodec", "none")
                    if vcodec == "none" and acodec == "none":
                        continue
                    streams.append(
                        {
                            "quality": str(
                                fmt.get("format_note")
                                or fmt.get("resolution")
                                or fmt.get("format_id")
                                or "stream"
                            ),
                            "ext": str(fmt.get("ext") or "mp4"),
                            "url": str(fmt_url),
                        }
                    )

                if not streams and info.get("url"):
                    streams.append(
                        {
                            "quality": "Default",
                            "ext": str(info.get("ext") or "mp4"),
                            "url": str(info["url"]),
                        }
                    )

                # Keep top 8 clearest stream entries (preferring mp4/hls)
                deduped: List[Dict[str, str]] = []
                seen_urls = set()
                for s in reversed(streams):
                    if s["url"] not in seen_urls:
                        seen_urls.add(s["url"])
                        deduped.append(s)
                    if len(deduped) >= 8:
                        break

                return MediaResult(
                    source_url=url,
                    title=str(info.get("title") or "Extracted Video"),
                    platform=str(info.get("extractor_key") or platform_hint.title()),
                    author=str(info.get("uploader") or info.get("channel") or "Unknown"),
                    duration_seconds=info.get("duration"),
                    is_live=bool(info.get("is_live", False)),
                    thumbnail_url=str(info.get("thumbnail") or ""),
                    direct_streams=deduped,
                    extractor="yt-dlp",
                    http_status=200,
                )
        except Exception as exc:
            err_str = str(exc)
            status = 403 if "403" in err_str or "Forbidden" in err_str else 500
            return MediaResult(
                source_url=url,
                platform=platform_hint.title(),
                extractor="yt-dlp",
                http_status=status,
                error=f"Extractor notice: {err_str[:220]}",
            )

    @classmethod
    def _extract_with_http_fallback(
        cls, url: str, platform_hint: str, use_saved_cookies: bool
    ) -> MediaResult:
        session = build_resilient_http_session(platform_hint if use_saved_cookies else None)
        try:
            resp = session.get(url, timeout=12, allow_redirects=True)
            if resp.status_code == 403:
                return MediaResult(
                    source_url=url,
                    platform=platform_hint.title(),
                    http_status=403,
                    error=(
                        "Target server returned HTTP 403 Forbidden. Load fresh session "
                        "cookies for this platform in the Sessions tab and retry."
                    ),
                )
            if resp.status_code >= 400:
                return MediaResult(
                    source_url=url,
                    platform=platform_hint.title(),
                    http_status=resp.status_code,
                    error=f"HTTP {resp.status_code}: {resp.reason}",
                )

            soup = BeautifulSoup(resp.text, "html.parser")
            title_tag = soup.find("meta", property="og:title") or soup.find("title")
            title = (
                title_tag.get("content", "").strip()
                if title_tag and title_tag.has_attr("content")
                else (title_tag.get_text(strip=True) if title_tag else "Web Media")
            )

            thumb_tag = soup.find("meta", property="og:image")
            thumb_url = (
                urljoin(url, thumb_tag["content"])
                if thumb_tag and thumb_tag.get("content")
                else ""
            )

            streams: List[Dict[str, str]] = []
            seen = set()

            for meta_prop in ("og:video:secure_url", "og:video:url", "og:video", "twitter:player:stream"):
                tag = soup.find("meta", property=meta_prop) or soup.find(
                    "meta", attrs={"name": meta_prop}
                )
                if tag and tag.get("content"):
                    resolved = urljoin(url, tag["content"].strip())
                    if resolved not in seen:
                        seen.add(resolved)
                        streams.append({"quality": meta_prop, "ext": "stream", "url": resolved})

            for video_tag in soup.find_all(["video", "source"]):
                src = video_tag.get("src")
                if src:
                    resolved = urljoin(url, src.strip())
                    if resolved not in seen:
                        seen.add(resolved)
                        streams.append({"quality": "HTML5 Media", "ext": "mp4", "url": resolved})

            # Regex fallback for embedded mp4 / m3u8 links inside page payload
            for match in re.findall(r"https?://[^\s\"'<>]+\.(?:mp4|m3u8)(?:\?[^\s\"'<>]*)?", resp.text):
                if match not in seen:
                    seen.add(match)
                    ext = "m3u8" if ".m3u8" in match.lower() else "mp4"
                    streams.append({"quality": "Embedded Stream", "ext": ext, "url": match})
                if len(streams) >= 8:
                    break

            return MediaResult(
                source_url=url,
                title=title or "Extracted Page",
                platform=platform_hint.title(),
                is_live=any(s["ext"] == "m3u8" for s in streams),
                thumbnail_url=thumb_url,
                direct_streams=streams,
                extractor="html-fallback",
                http_status=resp.status_code,
                error="" if streams else "Page loaded (200 OK), but no public direct video stream tags were exposed.",
            )
        except requests.exceptions.Timeout:
            return MediaResult(
                source_url=url,
                platform=platform_hint.title(),
                http_status=408,
                error="Request timed out after 12 seconds.",
            )
        except requests.exceptions.RequestException as exc:
            return MediaResult(
                source_url=url,
                platform=platform_hint.title(),
                http_status=502,
                error=f"Network error handled safely: {exc}",
            )


# ---------------------------------------------------------------------------
# Capability 3: Campaign Auto-Submission Manager
# ---------------------------------------------------------------------------


class CampaignManager:
    """Manages gaming-reward clip campaigns and executes safe submissions."""

    @staticmethod
    def load_campaigns() -> List[Dict[str, Any]]:
        ensure_storage()
        if not CAMPAIGNS_FILE.exists():
            seed = [
                {
                    "id": "cmp-001",
                    "campaign_name": "Valorant Clutch Weeklies",
                    "game_title": "Valorant",
                    "platform": "tiktok",
                    "clip_url": "https://www.tiktok.com/@example/video/7000000000000000000",
                    "direct_media_url": "",
                    "submission_endpoint": "https://httpbin.org/post",
                    "reward_account": "mohsinatiq628@gmail.com",
                    "caption": "Ace clutch on Ascent #Valorant #GamingRewards",
                    "status": "Queued",
                    "last_response": "Ready for dry-run or live submission",
                    "updated_at": utc_now_iso(),
                }
            ]
            CAMPAIGNS_FILE.write_text(json.dumps(seed, indent=2), encoding="utf-8")
            return seed
        try:
            data = json.loads(CAMPAIGNS_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except Exception:
            return []

    @staticmethod
    def save_campaigns(campaigns: List[Dict[str, Any]]) -> None:
        ensure_storage()
        CAMPAIGNS_FILE.write_text(json.dumps(campaigns, indent=2), encoding="utf-8")

    @classmethod
    def add_campaign(cls, item: CampaignItem) -> None:
        campaigns = cls.load_campaigns()
        campaigns.insert(0, asdict(item))
        cls.save_campaigns(campaigns)
        LogManager.log(
            "INFO",
            "CampaignManager",
            f"Queued campaign clip: {item.campaign_name} ({item.game_title})",
            item.clip_url,
        )

    @classmethod
    def submit_campaign(cls, campaign_id: str, dry_run: bool = True) -> Tuple[bool, str]:
        campaigns = cls.load_campaigns()
        target = next((c for c in campaigns if c.get("id") == campaign_id), None)
        if not target:
            return False, "Campaign entry not found."

        platform = str(target.get("platform", "gmail")).lower()
        payload = {
            "campaign_name": target.get("campaign_name"),
            "game_title": target.get("game_title"),
            "platform": platform,
            "clip_url": target.get("clip_url"),
            "direct_media_url": target.get("direct_media_url"),
            "reward_account": target.get("reward_account"),
            "caption": target.get("caption"),
            "submitted_at": utc_now_iso(),
        }

        if dry_run:
            target["status"] = "Dry-Run OK"
            target["last_response"] = "Validated payload & local session cookies (no external POST sent)."
            target["updated_at"] = utc_now_iso()
            cls.save_campaigns(campaigns)
            LogManager.log(
                "SUCCESS",
                "CampaignManager",
                f"Dry-run passed for {target['campaign_name']}",
                json.dumps(payload),
            )
            return True, target["last_response"]

        endpoint = str(target.get("submission_endpoint", "")).strip()
        if not endpoint.startswith(("http://", "https://")):
            target["status"] = "Failed"
            target["last_response"] = "Invalid submission endpoint URL."
            target["updated_at"] = utc_now_iso()
            cls.save_campaigns(campaigns)
            return False, target["last_response"]

        session = build_resilient_http_session(platform)
        # Attach Gmail cookies as secondary identity context if available
        gmail_jar = SessionVault.export_requests_cookie_jar("gmail")
        if len(gmail_jar) > 0:
            session.cookies.update(gmail_jar)

        try:
            resp = session.post(endpoint, json=payload, timeout=15)
            if resp.status_code == 403:
                target["status"] = "Failed"
                target["last_response"] = "403 Forbidden from campaign endpoint. Refresh cookies or verify endpoint."
                target["updated_at"] = utc_now_iso()
                cls.save_campaigns(campaigns)
                LogManager.log("ERROR", "CampaignManager", target["last_response"], endpoint)
                return False, target["last_response"]

            if resp.ok:
                target["status"] = "Submitted"
                target["last_response"] = f"HTTP {resp.status_code} Accepted"
                target["updated_at"] = utc_now_iso()
                cls.save_campaigns(campaigns)
                LogManager.log(
                    "SUCCESS",
                    "CampaignManager",
                    f"Submitted {target['campaign_name']} -> HTTP {resp.status_code}",
                    endpoint,
                )
                return True, target["last_response"]

            target["status"] = "Failed"
            target["last_response"] = f"HTTP {resp.status_code}: {resp.text[:160]}"
            target["updated_at"] = utc_now_iso()
            cls.save_campaigns(campaigns)
            LogManager.log("WARNING", "CampaignManager", target["last_response"], endpoint)
            return False, target["last_response"]
        except requests.exceptions.RequestException as exc:
            target["status"] = "Failed"
            target["last_response"] = f"Request error handled safely: {exc}"
            target["updated_at"] = utc_now_iso()
            cls.save_campaigns(campaigns)
            LogManager.log("ERROR", "CampaignManager", target["last_response"], endpoint)
            return False, target["last_response"]


# ---------------------------------------------------------------------------
# Capability 4: Mobile-Responsive Light-Themed Streamlit UI
# ---------------------------------------------------------------------------


def inject_mobile_light_theme_css() -> None:
    """Apply clean, fast, light-themed mobile-responsive styling."""
    st.markdown(
        """
        <style>
        :root {
            --hub-bg: #F8FAFC;
            --hub-surface: #FFFFFF;
            --hub-border: #E2E8F0;
            --hub-text: #0F172A;
            --hub-muted: #475569;
            --hub-accent: #2563EB;
        }
        .stApp {
            background-color: var(--hub-bg);
            color: var(--hub-text);
        }
        .block-container {
            padding-top: 1.25rem;
            padding-bottom: 2.5rem;
            max-width: 1120px;
        }
        div[data-testid="stMetric"] {
            background: var(--hub-surface);
            border: 1px solid var(--hub-border);
            border-radius: 12px;
            padding: 14px 16px;
        }
        .hub-card {
            background: var(--hub-surface);
            border: 1px solid var(--hub-border);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 12px;
        }
        .stButton > button, .stDownloadButton > button {
            min-height: 44px;
            border-radius: 10px;
            font-weight: 600;
        }
        .stTextInput input, .stTextArea textarea, .stSelectbox select {
            min-height: 44px;
            border-radius: 10px;
        }
        /* Mobile viewport ergonomics */
        @media (max-width: 768px) {
            .block-container {
                padding-left: 0.85rem;
                padding-right: 0.85rem;
                padding-top: 0.75rem;
            }
            .stTabs [data-baseweb="tab-list"] {
                gap: 6px;
                overflow-x: auto;
                white-space: nowrap;
            }
            .stTabs [data-baseweb="tab"] {
                min-height: 44px;
                padding: 8px 12px;
                font-size: 0.88rem;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_sessions_tab() -> None:
    st.subheader("Gmail & Social Session Persistence")
    st.caption(
        "Save browser cookies or Playwright storage_state locally so Gmail, TikTok, "
        "Instagram, and YouTube stay authenticated without repeated OTP prompts."
    )

    cols = st.columns(4)
    for idx, (key, meta) in enumerate(PLATFORMS.items()):
        status = SessionVault.get_session_status(key)
        with cols[idx % 4]:
            state_label = "Connected" if status["connected"] else "Disconnected"
            st.metric(
                label=meta["label"],
                value=state_label,
                delta=f"{status['cookie_count']} cookies" if status["connected"] else "No cookies",
            )
            st.caption(f"Account: {status['account_label']}")

    st.divider()

    selected_platform = st.selectbox(
        "Target Platform",
        options=list(PLATFORMS.keys()),
        format_func=lambda k: PLATFORMS[k]["label"],
    )
    account_label = st.text_input(
        "Account Identifier",
        placeholder="e.g. mohsinatiq628@gmail.com or @creator_handle",
    )

    col_left, col_right = st.columns([2, 1])
    with col_left:
        cookie_payload = st.text_area(
            "Paste Cookies (JSON Array, Playwright storage_state.json, or Netscape cookies.txt)",
            height=160,
            placeholder='[{"name": "SID", "value": "...", "domain": ".google.com", "path": "/"}]',
        )
        uploaded = st.file_uploader(
            "Or Upload Cookie / storage_state File",
            type=["json", "txt"],
            key=f"upload_{selected_platform}",
        )
        if uploaded is not None:
            cookie_payload = uploaded.read().decode("utf-8", errors="replace")

    with col_right:
        st.markdown('<div class="hub-card">', unsafe_allow_html=True)
        st.markdown("**Actions**")
        if st.button("Save Session Cookies", type="primary", use_container_width=True):
            try:
                domain = PLATFORMS[selected_platform]["domain"]
                parsed = SessionVault.parse_cookie_input(cookie_payload, domain)
                ok, msg = SessionVault.save_browser_cookies(
                    platform=selected_platform,
                    cookies=parsed,
                    account_label=account_label,
                )
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)
            except Exception as exc:
                st.error(f"Could not parse or save cookies: {exc}")

        if st.button("Launch Browser Login (Desktop)", use_container_width=True):
            with st.spinner("Waiting for browser login capture..."):
                ok, msg = SessionVault.launch_interactive_playwright_capture(
                    platform=selected_platform,
                    account_label=account_label,
                )
            if ok:
                st.success(msg)
            else:
                st.warning(msg)

        if st.button("Clear Saved Session", use_container_width=True):
            ok, msg = SessionVault.clear_session(selected_platform)
            if ok:
                st.info(msg)
            else:
                st.error(msg)
        st.markdown("</div>", unsafe_allow_html=True)


def render_fetcher_tab() -> None:
    st.subheader("Content & Link Fetcher")
    st.caption(
        "Paste any target video URL or live stream. Built-in error handling prevents "
        "403 crashes and automatically attaches your saved platform cookies."
    )

    with st.form("media_fetcher_form", clear_on_submit=False):
        target_url = st.text_input(
            "Target Video or Live Stream URL",
            placeholder="https://www.youtube.com/watch?v=... or https://.../stream.m3u8",
        )
        use_cookies = st.checkbox(
            "Attach saved local session cookies for authenticated access",
            value=True,
        )
        submitted = st.form_submit_button("Fetch Media & Metadata", type="primary", use_container_width=True)

    if submitted:
        with st.spinner("Safely inspecting target URL..."):
            result = MediaFetcher.fetch(target_url, use_saved_cookies=use_cookies)
            st.session_state["last_media_result"] = asdict(result)

    saved_res = st.session_state.get("last_media_result")
    if saved_res:
        if saved_res.get("error"):
            st.warning(f"Handled Notice (HTTP {saved_res.get('http_status')}): {saved_res['error']}")

        st.markdown('<div class="hub-card">', unsafe_allow_html=True)
        c1, c2 = st.columns([2, 1])
        with c1:
            st.markdown(f"### {saved_res.get('title', 'Extracted Media')}")
            st.write(
                f"**Platform:** {saved_res.get('platform')} · "
                f"**Author:** {saved_res.get('author')} · "
                f"**Extractor:** `{saved_res.get('extractor')}`"
            )
            if saved_res.get("is_live"):
                st.info("Live Stream Detected")
            elif saved_res.get("duration_seconds"):
                st.caption(f"Duration: {saved_res['duration_seconds']} seconds")
        with c2:
            if saved_res.get("thumbnail_url"):
                st.image(saved_res["thumbnail_url"], use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

        streams = saved_res.get("direct_streams", [])
        if streams:
            st.markdown("**Extracted Direct Media / Stream Elements**")
            st.dataframe(pd.DataFrame(streams), use_container_width=True, hide_index=True)

            if st.button("Send First Stream to Campaign Queue", use_container_width=True):
                new_item = CampaignItem(
                    id=f"cmp-{int(time.time())}",
                    campaign_name="Fetched Clip Submission",
                    game_title="Gaming Rewards",
                    platform=infer_platform_from_url(saved_res["source_url"]),
                    clip_url=saved_res["source_url"],
                    direct_media_url=streams[0]["url"],
                    submission_endpoint="https://httpbin.org/post",
                    reward_account="mohsinatiq628@gmail.com",
                    caption=saved_res.get("title", "Clip Submission"),
                    updated_at=utc_now_iso(),
                )
                CampaignManager.add_campaign(new_item)
                st.success("Added extracted clip to Campaign Auto-Submit queue.")


def render_campaigns_tab() -> None:
    st.subheader("Campaign Auto-Submission")
    st.caption(
        "Manage gaming reward clip workflows, validate payloads in dry-run mode, "
        "or submit directly using persisted Gmail & social cookies."
    )

    with st.expander("Create New Campaign Submission", expanded=False):
        with st.form("new_campaign_form"):
            c1, c2 = st.columns(2)
            with c1:
                campaign_name = st.text_input("Campaign Name", value="Gaming Clip Rewards")
                game_title = st.text_input("Game Title", value="Valorant")
                platform = st.selectbox("Source Platform", options=["tiktok", "youtube", "instagram", "gmail"])
            with c2:
                clip_url = st.text_input("Clip URL", placeholder="https://www.tiktok.com/@user/video/...")
                endpoint = st.text_input("Campaign Webhook / Endpoint", value="https://httpbin.org/post")
                reward_account = st.text_input("Reward Email / Account ID", value="mohsinatiq628@gmail.com")
            caption = st.text_input("Submission Caption / Tags", value="Weekly highlight #GamingRewards")
            if st.form_submit_button("Queue Clip for Campaign", type="primary", use_container_width=True):
                if not clip_url.strip():
                    st.error("Clip URL is required.")
                else:
                    CampaignManager.add_campaign(
                        CampaignItem(
                            id=f"cmp-{int(time.time())}",
                            campaign_name=campaign_name.strip(),
                            game_title=game_title.strip(),
                            platform=platform,
                            clip_url=clip_url.strip(),
                            direct_media_url="",
                            submission_endpoint=endpoint.strip(),
                            reward_account=reward_account.strip(),
                            caption=caption.strip(),
                            updated_at=utc_now_iso(),
                        )
                    )
                    st.success("Campaign clip queued.")
                    st.rerun()

    campaigns = CampaignManager.load_campaigns()
    if not campaigns:
        st.info("No campaign entries yet. Queue a clip above or send one from Content Fetcher.")
        return

    dry_run_mode = st.toggle(
        "Dry-Run Mode (validate cookies & payload without external HTTP POST)",
        value=True,
    )

    for cmp_item in campaigns:
        with st.container():
            st.markdown('<div class="hub-card">', unsafe_allow_html=True)
            top_left, top_right = st.columns([3, 1])
            with top_left:
                st.markdown(f"**{cmp_item.get('campaign_name')}** · {cmp_item.get('game_title')}")
                st.caption(
                    f"Platform: {cmp_item.get('platform', '').title()} · "
                    f"Status: {cmp_item.get('status')} · Updated: {cmp_item.get('updated_at')}"
                )
                st.text(cmp_item.get("clip_url", ""))
                if cmp_item.get("last_response"):
                    st.caption(f"Last Result: {cmp_item['last_response']}")
            with top_right:
                if st.button(
                    "Run Submit",
                    key=f"submit_{cmp_item['id']}",
                    type="primary",
                    use_container_width=True,
                ):
                    ok, msg = CampaignManager.submit_campaign(cmp_item["id"], dry_run=dry_run_mode)
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)
                    st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)


def render_logs_tab() -> None:
    st.subheader("Automation Activity Logs")
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        level_filter = st.selectbox("Filter Log Level", ["ALL", "SUCCESS", "INFO", "WARNING", "ERROR"])
    logs = LogManager.get_logs(level_filter)
    with col2:
        if logs:
            csv_bytes = pd.DataFrame(logs).to_csv(index=False).encode("utf-8")
            st.download_button(
                "Export CSV",
                data=csv_bytes,
                file_name="mohsin_hub_logs.csv",
                mime="text/csv",
                use_container_width=True,
            )
    with col3:
        if st.button("Clear Logs", use_container_width=True):
            LogManager.clear_logs()
            st.rerun()

    if not logs:
        st.info("No activity logs recorded for this filter yet.")
        return

    st.dataframe(pd.DataFrame(logs), use_container_width=True, hide_index=True)


def main() -> None:
    st.set_page_config(
        page_title=APP_NAME,
        page_icon="⚡",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    ensure_storage()
    inject_mobile_light_theme_css()

    st.title(APP_NAME)
    st.caption("Mobile-accessible cloud automation agent · Persistent sessions, safe media fetching, and campaign workflows")

    tab_sessions, tab_fetcher, tab_campaigns, tab_logs = st.tabs(
        [
            "Sessions & Cookies",
            "Content Fetcher",
            "Campaign Auto-Submit",
            "Activity Logs",
        ]
    )

    for tab, renderer in (
        (tab_sessions, render_sessions_tab),
        (tab_fetcher, render_fetcher_tab),
        (tab_campaigns, render_campaigns_tab),
        (tab_logs, render_logs_tab),
    ):
        with tab:
            try:
                renderer()
            except Exception as exc:
                LogManager.log("ERROR", renderer.__name__, str(exc), traceback.format_exc())
                st.error(f"An unexpected error was safely caught: {exc}")


if __name__ == "__main__":
    main()
