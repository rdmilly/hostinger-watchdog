#!/usr/bin/env python3
"""Hostinger Watchdog — host-safety daemon for Millyweb VPS1/VPS2.

Runs every 30s via systemd timer. Samples host CPU/mem/load + disk + per-container
usage. Maintains a rolling 10-sample history for sustained-threshold detection.
Fires tiered responses (Warn / Act / Protect) with pre-announce-and-abort grace
windows via ntfy.sh.

See PRD at Working KB projects/hostinger-watchdog/PRD.md for full design.

Exit code 0 always (systemd-friendly). Errors surface to journal + events log.
"""
from __future__ import annotations

import datetime as dt
import fnmatch
import json
import logging
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

import psutil
import requests
import yaml

VERSION = "1.0.0"
CONFIG_PATH = Path(os.environ.get("WATCHDOG_CONFIG", "/opt/projects/hostinger-watchdog/config.yml"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s watchdog - %(message)s",
)
log = logging.getLogger("watchdog")


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        log.error("config not found at %s", CONFIG_PATH)
        sys.exit(2)
    with open(CONFIG_PATH) as f:
        cfg = yaml.safe_load(f)
    # Minimal validation: required fields.
    for key in ("thresholds", "safelist", "paths", "ntfy", "mode"):
        if key not in cfg:
            log.error("config missing required key: %s", key)
            sys.exit(2)
    if cfg["mode"] not in ("alert_only", "armed"):
        log.error("config mode must be alert_only or armed, got %r", cfg["mode"])
        sys.exit(2)
    if cfg.get("host", "auto") == "auto":
        cfg["host"] = socket.gethostname().split(".")[0]
    return cfg


# ---------------------------------------------------------------------------
# Persistent state (cool-downs, sample history, heartbeat)
# ---------------------------------------------------------------------------

def ensure_dirs(cfg: dict[str, Any]) -> None:
    for key in ("heartbeat", "cooldowns", "sample_history", "events_log"):
        Path(cfg["paths"][key]).parent.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default: Any) -> Any:
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    tmp.replace(path)


def append_event(events_log: Path, event: dict[str, Any]) -> None:
    event["ts"] = dt.datetime.now(dt.timezone.utc).isoformat()
    with open(events_log, "a") as f:
        f.write(json.dumps(event) + "\n")


# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------

def sample_host() -> dict[str, Any]:
    """One snapshot of host-level metrics."""
    # psutil.cpu_percent needs a baseline. Call with interval=None to diff
    # against previous call; first call returns 0.0. Caller keeps state.
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    load1, load5, load15 = psutil.getloadavg()
    ncpu = psutil.cpu_count() or 1
    return {
        "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
        "cpu_pct": round(cpu, 1),
        "mem_pct": round(mem.percent, 1),
        "mem_used_mb": round(mem.used / 1024 / 1024),
        "load_1": round(load1, 2),
        "load_normalized": round(load1 / ncpu, 2),
        "ncpu": ncpu,
    }


def sample_disks(partitions: list[str]) -> dict[str, dict[str, float]]:
    out = {}
    seen_devices = set()
    for p in partitions:
        try:
            u = psutil.disk_usage(p)
        except FileNotFoundError:
            continue
        # dedupe by underlying device
        try:
            dev = os.stat(p).st_dev
        except FileNotFoundError:
            continue
        if dev in seen_devices:
            continue
        seen_devices.add(dev)
        out[p] = {
            "pct": round(u.percent, 1),
            "used_gb": round(u.used / 1024**3, 1),
            "total_gb": round(u.total / 1024**3, 1),
        }
    return out


def sample_containers() -> list[dict[str, Any]]:
    """Per-container CPU% and memory via `docker stats --no-stream`.
    Returns list sorted by CPU% desc, then mem desc.
    """
    try:
        r = subprocess.run(
            ["docker", "stats", "--no-stream", "--format",
             "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}"],
            capture_output=True, text=True, timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.warning("docker stats failed: %s", e)
        return []
    out = []
    for line in r.stdout.strip().splitlines():
        try:
            name, cpu_s, mem_s, mempct_s = line.split("|")
            cpu = float(cpu_s.rstrip("%") or 0)
            # MemUsage like "579.3MiB / 4.395GiB"
            used_s = mem_s.split("/")[0].strip()
            used_mb = parse_mem_to_mb(used_s)
            out.append({
                "name": name,
                "cpu_pct": round(cpu, 1),
                "mem_mb": used_mb,
                "mem_pct": round(float(mempct_s.rstrip("%") or 0), 1),
            })
        except (ValueError, IndexError):
            continue
    out.sort(key=lambda c: (-c["cpu_pct"], -c["mem_mb"]))
    return out


def parse_mem_to_mb(s: str) -> float:
    """Parse '579.3MiB' or '4.395GiB' or '512KB' to MB (float)."""
    s = s.strip()
    if not s:
        return 0.0
    # extract number + unit
    n = ""
    i = 0
    while i < len(s) and (s[i].isdigit() or s[i] == "."):
        n += s[i]
        i += 1
    try:
        val = float(n)
    except ValueError:
        return 0.0
    unit = s[i:].strip().upper()
    if unit.startswith("GI") or unit == "GB":
        return round(val * 1024, 1)
    if unit.startswith("MI") or unit == "MB":
        return round(val, 1)
    if unit.startswith("KI") or unit == "KB":
        return round(val / 1024, 3)
    if unit.startswith("B"):
        return round(val / 1024 / 1024, 3)
    return round(val, 1)


# ---------------------------------------------------------------------------
# Tier evaluation
# ---------------------------------------------------------------------------

def eval_tier(value: float, thresholds: dict[str, float]) -> str:
    """Returns 'protect' | 'act' | 'warn' | 'ok'."""
    if value >= thresholds["protect"]:
        return "protect"
    if value >= thresholds["act"]:
        return "act"
    if value >= thresholds["warn"]:
        return "warn"
    return "ok"


TIER_RANK = {"ok": 0, "warn": 1, "act": 2, "protect": 3}


def worst_tier(*tiers: str) -> str:
    return max(tiers, key=lambda t: TIER_RANK[t])


def sustained_tier(history: list[dict[str, Any]], metric: str, thresholds: dict[str, float], window: int) -> str:
    """Return the highest tier that all N most-recent samples clear.
    i.e. the 'sustained' tier across `window` samples.
    """
    if len(history) < window:
        return "ok"
    recent = history[-window:]
    tiers = [eval_tier(s.get(metric, 0), thresholds) for s in recent]
    # sustained = the tier everyone met = min of tier ranks
    return min(tiers, key=lambda t: TIER_RANK[t])


# ---------------------------------------------------------------------------
# Safelist + offender selection
# ---------------------------------------------------------------------------

def is_safelisted(name: str, safelist: list[str]) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in safelist)


def top_cpu_offender(containers: list[dict[str, Any]], safelist: list[str], exclude_safelist: bool) -> Optional[dict[str, Any]]:
    for c in containers:
        if exclude_safelist and is_safelisted(c["name"], safelist):
            continue
        return c
    return None


# ---------------------------------------------------------------------------
# ntfy push + reply-to-abort
# ---------------------------------------------------------------------------

def _ascii_safe(s: str) -> str:
    """HTTP headers must be latin-1 encodable. Strip anything outside ASCII."""
    return s.encode("ascii", "ignore").decode("ascii")


def ntfy_push(cfg: dict[str, Any], title: str, message: str, priority: str, tags: list[str] | None = None) -> bool:
    topic = cfg["ntfy"]["topic"]
    if not topic:
        log.warning("ntfy topic is empty; set it in config.yml. Message was: %s | %s", title, message)
        return False
    url = f"{cfg['ntfy']['base_url'].rstrip('/')}/{topic}"
    headers = {
        "Title": _ascii_safe(title),
        "Priority": _ascii_safe(priority),
    }
    if tags:
        headers["Tags"] = _ascii_safe(",".join(tags))
    try:
        r = requests.post(url, data=message.encode("utf-8"), headers=headers, timeout=5)
        r.raise_for_status()
        return True
    except requests.RequestException as e:
        log.warning("ntfy push failed: %s", e)
        return False


def wait_for_abort(cfg: dict[str, Any], grace_seconds: int) -> bool:
    """Open an ntfy JSON-stream subscription for the grace window.
    Return True if any message starting with STOP arrives. Else False.
    """
    if not cfg["ntfy"].get("reply_abort_enabled", True):
        time.sleep(grace_seconds)
        return False
    topic = cfg["ntfy"]["topic"]
    if not topic:
        time.sleep(grace_seconds)
        return False
    url = f"{cfg['ntfy']['base_url'].rstrip('/')}/{topic}/json?poll=1&since={grace_seconds}s"
    # Simple approach: poll once at end of grace window.
    # For real-time abort we'd use the streaming endpoint with a thread; skipped
    # here because systemd oneshot pattern doesn't love long-running threads.
    time.sleep(grace_seconds)
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        for line in r.text.strip().splitlines():
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            body = (msg.get("message") or "").strip().upper()
            if body.startswith("STOP"):
                return True
    except requests.RequestException as e:
        log.warning("abort check failed: %s", e)
    return False


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def do_act_cap(cfg: dict[str, Any], container: dict[str, Any]) -> dict[str, Any]:
    """Tighten cap on a container to (current_usage * ratio), respecting floors."""
    new_cpu = max(
        cfg["act_cap_cpu_floor"],
        round((container["cpu_pct"] / 100.0) * cfg["act_cap_cpu_ratio"], 2),
    )
    new_mem_mb = max(
        cfg["act_cap_mem_floor_mb"],
        int(container["mem_mb"] * cfg["act_cap_mem_ratio"]),
    )
    cmd = [
        "docker", "update",
        "--cpus", str(new_cpu),
        "--memory", f"{new_mem_mb}m",
        "--memory-swap", f"{new_mem_mb}m",
        container["name"],
    ]
    result = {"container": container["name"], "new_cpu": new_cpu, "new_mem_mb": new_mem_mb}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        result["exit"] = r.returncode
        result["stdout"] = r.stdout.strip()[:500]
        result["stderr"] = r.stderr.strip()[:500]
    except subprocess.TimeoutExpired:
        result["exit"] = -1
        result["stderr"] = "docker update timed out"
    return result


def do_protect_stop(container: dict[str, Any]) -> dict[str, Any]:
    cmd = ["docker", "stop", "-t", "30", container["name"]]
    result = {"container": container["name"]}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        result["exit"] = r.returncode
        result["stdout"] = r.stdout.strip()[:500]
        result["stderr"] = r.stderr.strip()[:500]
    except subprocess.TimeoutExpired:
        result["exit"] = -1
        result["stderr"] = "docker stop timed out"
    return result


# ---------------------------------------------------------------------------
# Daily digest
# ---------------------------------------------------------------------------

def maybe_send_daily_digest(cfg: dict[str, Any], heartbeat: dict[str, Any]) -> bool:
    """Send once per UTC day when the clock crosses the configured time."""
    target = cfg["schedules"]["daily_digest_utc"]  # "15:00"
    now = dt.datetime.now(dt.timezone.utc)
    today = now.strftime("%Y-%m-%d")
    last_sent = heartbeat.get("last_daily_digest_date")
    if last_sent == today:
        return False
    hh, mm = target.split(":")
    target_dt = now.replace(hour=int(hh), minute=int(mm), second=0, microsecond=0)
    if now < target_dt:
        return False
    # Build digest from today's events.
    events_path = Path(cfg["paths"]["events_log"])
    counts = {"warn": 0, "act": 0, "protect": 0}
    peak_cpu = 0.0
    if events_path.exists():
        with open(events_path) as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if ev.get("ts", "").startswith(today):
                    lvl = ev.get("level")
                    if lvl in counts:
                        counts[lvl] += 1
                    peak_cpu = max(peak_cpu, ev.get("host_cpu_pct", 0))
    runs = heartbeat.get("runs_today", 0)
    expected = int(86400 / cfg["tick_seconds"])
    body = (
        f"Runs: {runs}/{expected} | Peak CPU: {peak_cpu}% | "
        f"{counts['warn']} warn, {counts['act']} act, {counts['protect']} protect"
    )
    host = cfg["host"]
    ntfy_push(cfg, f"[{host}] Daily digest - {today}", body, priority="min", tags=["bar_chart"])
    heartbeat["last_daily_digest_date"] = today
    return True


# ---------------------------------------------------------------------------
# Main tick
# ---------------------------------------------------------------------------

def main() -> int:
    cfg = load_config()
    ensure_dirs(cfg)
    paths = {k: Path(v) for k, v in cfg["paths"].items()}

    # Load persistent state
    history = load_json(paths["sample_history"], default=[])
    cooldowns = load_json(paths["cooldowns"], default={})
    heartbeat = load_json(paths["heartbeat"], default={
        "version": VERSION, "host": cfg["host"], "runs_today": 0,
        "current_tier": "ok", "last_action_taken": None,
        "last_daily_digest_date": None,
    })

    now_ts = time.time()
    today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    if heartbeat.get("runs_today_date") != today:
        heartbeat["runs_today"] = 0
        heartbeat["runs_today_date"] = today
    heartbeat["runs_today"] += 1

    # Sample
    host = sample_host()
    disks = sample_disks(cfg["partitions_watched"])
    containers = sample_containers()

    # Update rolling history
    history.append(host)
    if len(history) > 20:
        history = history[-20:]

    # Evaluate tiers (sustained). CPU and memory drive tiers.
    # Load is context-only: reported alongside but never solo-escalates,
    # because 1-min loadavg spikes hard under CPU steal / disk IO without
    # actually indicating our own sustained resource consumption.
    t_cpu = sustained_tier(history, "cpu_pct", cfg["thresholds"]["host_cpu_pct"], cfg["sustained_ticks"])
    t_mem = sustained_tier(history, "mem_pct", cfg["thresholds"]["host_mem_pct"], cfg["sustained_ticks"])
    t_load = sustained_tier(history, "load_normalized", cfg["thresholds"]["load_avg_normalized"], cfg["sustained_ticks"])  # context only
    # Disk is instantaneous
    t_disk = "ok"
    disk_offender = None
    for p, u in disks.items():
        dt_tier = eval_tier(u["pct"], cfg["thresholds"]["disk_pct"])
        if TIER_RANK[dt_tier] > TIER_RANK[t_disk]:
            t_disk = dt_tier
            disk_offender = p

    # overall = worst of CPU, MEM, DISK. LOAD is deliberately excluded.
    overall = worst_tier(t_cpu, t_mem, t_disk)
    heartbeat["current_tier"] = overall
    heartbeat["last_run_utc"] = host["ts"]
    heartbeat["last_host"] = host
    heartbeat["last_disks"] = disks
    heartbeat["last_top_containers"] = containers[:5]
    heartbeat["last_tiers"] = {"cpu": t_cpu, "mem": t_mem, "load": t_load, "disk": t_disk}

    # Always log the sample at info level (structured)
    append_event(paths["events_log"], {
        "level": "sample", "host": cfg["host"],
        "host_cpu_pct": host["cpu_pct"], "host_mem_pct": host["mem_pct"],
        "load_normalized": host["load_normalized"],
        "tiers": heartbeat["last_tiers"], "overall": overall,
    })

    # Dispatch tier actions
    if overall == "warn":
        handle_warn(cfg, host, disks, containers, t_cpu, t_mem, t_load, t_disk, disk_offender, cooldowns, paths)
    elif overall == "act":
        handle_act(cfg, host, containers, disk_offender, t_disk, cooldowns, paths, heartbeat, now_ts)
    elif overall == "protect":
        handle_protect(cfg, host, containers, cooldowns, paths, heartbeat, now_ts)

    # Daily digest
    try:
        maybe_send_daily_digest(cfg, heartbeat)
    except Exception as e:  # noqa: BLE001
        log.warning("daily digest failed: %s", e)

    # Persist state
    save_json(paths["sample_history"], history)
    save_json(paths["cooldowns"], cooldowns)
    save_json(paths["heartbeat"], heartbeat)

    # Verbose decision log: always written, so we can audit every tick.
    top3 = ", ".join(f"{c['name']}={c['cpu_pct']}%/{c['mem_mb']:.0f}MB" for c in containers[:3]) or "(none)"
    disk_s = " ".join(f"{p}={u['pct']}%" for p, u in disks.items())
    log.info(
        "tick: cpu=%.1f%% mem=%.1f%% load=%.2fx | tiers: cpu=%s mem=%s load=%s disk=%s | overall=%s | mode=%s | top: %s | disks: %s",
        host["cpu_pct"], host["mem_pct"], host["load_normalized"],
        t_cpu, t_mem, t_load, t_disk, overall, cfg["mode"], top3, disk_s,
    )
    return 0


# ---------------------------------------------------------------------------
# Tier handlers
# ---------------------------------------------------------------------------

def cooldown_active(cooldowns: dict[str, Any], key: str, now_ts: float) -> bool:
    return key in cooldowns and cooldowns[key] > now_ts


def set_cooldown(cooldowns: dict[str, Any], key: str, seconds: float) -> None:
    cooldowns[key] = time.time() + seconds


def handle_warn(cfg, host, disks, containers, t_cpu, t_mem, t_load, t_disk, disk_offender, cooldowns, paths):
    now_ts = time.time()
    key = f"warn:{max([(t_cpu,'cpu'),(t_mem,'mem'),(t_load,'load'),(t_disk,'disk')], key=lambda x: TIER_RANK[x[0]])[1]}"
    if cooldown_active(cooldowns, key, now_ts):
        return
    set_cooldown(cooldowns, key, cfg["cooldowns"]["warn_seconds"])
    top = containers[:3]
    top_s = ", ".join(f"{c['name']} ({c['cpu_pct']}% cpu, {c['mem_mb']}MB)" for c in top) or "(no container data)"
    msg = (
        f"CPU {host['cpu_pct']}% | Mem {host['mem_pct']}% | Load {host['load_normalized']}x"
        + (f" | Disk {disk_offender} {disks[disk_offender]['pct']}%" if disk_offender else "")
        + f"\nTop: {top_s}"
    )
    ntfy_push(cfg, f"[{cfg['host']}] WARN", msg, priority="default", tags=["warning"])
    append_event(paths["events_log"], {
        "level": "warn", "host": cfg["host"], "tiers": {"cpu": t_cpu, "mem": t_mem, "load": t_load, "disk": t_disk},
        "top_containers": top,
    })


def handle_act(cfg, host, containers, disk_offender, t_disk, cooldowns, paths, heartbeat, now_ts):
    offender = top_cpu_offender(containers, cfg["safelist"], exclude_safelist=False)
    if offender is None:
        return
    key = f"act:{offender['name']}"
    if cooldown_active(cooldowns, key, now_ts):
        return

    if cfg["mode"] == "alert_only":
        msg = (
            f"Would cap {offender['name']} (cpu={offender['cpu_pct']}%, mem={offender['mem_mb']}MB) if armed.\n"
            f"Host CPU {host['cpu_pct']}%. No action taken (alert-only mode)."
        )
    else:
        msg = (
            f"About to cap {offender['name']} (cpu={offender['cpu_pct']}%, mem={offender['mem_mb']}MB).\n"
            f"Host CPU {host['cpu_pct']}%. Reply STOP within {cfg['act_grace_seconds']}s to abort."
        )
    mode_prefix = "SIMULATED" if cfg["mode"] == "alert_only" else "PENDING"
    ntfy_push(cfg, f"[{cfg['host']}] ACT {mode_prefix}", msg, priority="high" if cfg["mode"] == "armed" else "default", tags=["hammer"])
    append_event(paths["events_log"], {
        "level": "act_pending", "host": cfg["host"], "offender": offender,
        "mode": cfg["mode"], "grace_seconds": cfg["act_grace_seconds"],
    })

    if cfg["mode"] == "alert_only":
        # Log what we WOULD have done, but don't execute.
        append_event(paths["events_log"], {
            "level": "act_skipped_alert_only", "host": cfg["host"], "offender": offender,
        })
        set_cooldown(cooldowns, key, cfg["cooldowns"]["action_seconds"])
        return

    aborted = wait_for_abort(cfg, cfg["act_grace_seconds"])
    if aborted:
        ntfy_push(cfg, f"[{cfg['host']}] ACT aborted", f"User cancelled cap on {offender['name']}.", priority="default")
        append_event(paths["events_log"], {"level": "abort", "host": cfg["host"], "action": "act", "offender": offender})
        set_cooldown(cooldowns, key, cfg["cooldowns"]["action_seconds"])
        return

    result = do_act_cap(cfg, offender)
    append_event(paths["events_log"], {"level": "act", "host": cfg["host"], "offender": offender, "result": result})
    set_cooldown(cooldowns, key, cfg["cooldowns"]["action_seconds"])
    heartbeat["last_action_taken"] = {"tier": "act", "container": offender["name"], "at": host["ts"], "result": result}
    ntfy_push(cfg, f"[{cfg['host']}] ACT done",
              f"Capped {offender['name']} to {result['new_cpu']}cpu / {result['new_mem_mb']}MB. exit={result.get('exit')}",
              priority="high", tags=["white_check_mark"])


def handle_protect(cfg, host, containers, cooldowns, paths, heartbeat, now_ts):
    offender = top_cpu_offender(containers, cfg["safelist"], exclude_safelist=True)
    if offender is None:
        ntfy_push(cfg, f"[{cfg['host']}] PROTECT but no non-safelist target",
                  f"Host CPU {host['cpu_pct']}%. Top offenders are all safelisted. Manual review needed.",
                  priority="urgent", tags=["no_entry"])
        append_event(paths["events_log"], {"level": "protect_no_target", "host": cfg["host"], "top": containers[:5]})
        return
    key = f"protect:{offender['name']}"
    if cooldown_active(cooldowns, key, now_ts):
        return

    if cfg["mode"] == "alert_only":
        msg = (
            f"Would stop {offender['name']} (cpu={offender['cpu_pct']}%, mem={offender['mem_mb']}MB) if armed.\n"
            f"Host CPU {host['cpu_pct']}%. No action taken (alert-only mode)."
        )
    else:
        msg = (
            f"About to STOP {offender['name']} (cpu={offender['cpu_pct']}%, mem={offender['mem_mb']}MB).\n"
            f"Host CPU {host['cpu_pct']}%. Reply STOP within {cfg['protect_grace_seconds']}s to abort.\n"
            f"Manual restart will be required after stop."
        )
    mode_prefix = "SIMULATED" if cfg["mode"] == "alert_only" else "PENDING"
    ntfy_push(cfg, f"[{cfg['host']}] PROTECT {mode_prefix}", msg, priority="urgent" if cfg["mode"] == "armed" else "default", tags=["rotating_light"])
    append_event(paths["events_log"], {
        "level": "protect_pending", "host": cfg["host"], "offender": offender, "mode": cfg["mode"],
    })

    if cfg["mode"] == "alert_only":
        append_event(paths["events_log"], {
            "level": "protect_skipped_alert_only", "host": cfg["host"], "offender": offender,
        })
        set_cooldown(cooldowns, key, cfg["cooldowns"]["action_seconds"])
        return

    aborted = wait_for_abort(cfg, cfg["protect_grace_seconds"])
    if aborted:
        ntfy_push(cfg, f"[{cfg['host']}] PROTECT aborted",
                  f"User cancelled stop on {offender['name']}.", priority="default")
        append_event(paths["events_log"], {"level": "abort", "host": cfg["host"], "action": "protect", "offender": offender})
        set_cooldown(cooldowns, key, cfg["cooldowns"]["action_seconds"])
        return

    result = do_protect_stop(offender)
    append_event(paths["events_log"], {"level": "protect", "host": cfg["host"], "offender": offender, "result": result})
    set_cooldown(cooldowns, key, cfg["cooldowns"]["action_seconds"])
    heartbeat["last_action_taken"] = {"tier": "protect", "container": offender["name"], "at": host["ts"], "result": result}
    ntfy_push(cfg, f"[{cfg['host']}] PROTECT done",
              f"Stopped {offender['name']}. Exit {result.get('exit')}. Manual restart required.",
              priority="urgent", tags=["octagonal_sign"])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        log.exception("watchdog tick failed: %s", e)
        # Write an error event if we can
        try:
            cfg = load_config()
            Path(cfg["paths"]["events_log"]).parent.mkdir(parents=True, exist_ok=True)
            with open(cfg["paths"]["events_log"], "a") as f:
                f.write(json.dumps({
                    "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "level": "error",
                    "error": f"{type(e).__name__}: {e}",
                }) + "\n")
        except Exception:
            pass
        sys.exit(0)  # always exit 0 so systemd timer keeps firing
