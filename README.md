# hostinger-watchdog

VPS health safety daemon for VPS1 and VPS2.
Runs every 30s via systemd timer. Samples CPU/mem/disk/load + per-container usage.
Fires tiered responses: Warn (ntfy alert) → Act (cap offender, 30s abort window) → Protect (auto-stop, 60s abort window).
Safelist prevents helix-*, postgres, redis, traefik, coolify from ever being stopped.

## Deploy

```bash
pip install -r requirements.txt
cp config.yml /opt/projects/hostinger-watchdog/
# Install systemd timer (see PRD)
```
