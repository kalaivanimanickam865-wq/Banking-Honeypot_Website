# Windows: "page not opening" checklist

If `python run.py` shows `Running on http://127.0.0.1:5000` but the
browser won't load the page, work through these in order.

## 1. Check for a Windows Defender Firewall popup
The very first time `python.exe` tries to open a network port, Windows
often shows a firewall permission popup ("Windows Defender Firewall
has blocked some features of this app"). If you clicked **Cancel** or
it appeared behind another window and you never answered it, the dev
server can be silently blocked from accepting connections.

**Fix:** Settings → Update & Security → Windows Security → Firewall &
network protection → Allow an app through firewall → find Python →
tick both Private and Public → OK. Then stop the server (Ctrl+C) and
run `python run.py` again.

## 2. Confirm the port is actually listening
In a **new** PowerShell window (leave the server running):
```powershell
Get-NetTCPConnection -LocalPort 5000
```
You should see a row with `State: Listen`. If this returns nothing,
the Flask process isn't actually bound to the port — check the first
terminal for a crash/error instead.

## 3. Test with PowerShell before the browser
```powershell
Invoke-WebRequest http://127.0.0.1:5000/
```
- **HTML content prints out** → server is fine, the problem is
  browser-specific (try a different browser, or disable extensions).
- **"Unable to connect" / timeout** → the server itself isn't
  reachable — go back to step 1, or check antivirus (see step 4).

## 4. Antivirus software
Some antivirus suites (Avast, Kaspersky, McAfee, some India-specific
AVs) intercept localhost traffic by default. Temporarily disable
real-time protection, retry, and if that fixes it, add an exception
for Python instead of leaving it off.

## 5. Something else already using port 5000
```powershell
Get-Process -Id (Get-NetTCPConnection -LocalPort 5000).OwningProcess
```
If another process owns port 5000, run on a different port instead:
```powershell
$env:PORT="5050"
python run.py
```
then visit `http://127.0.0.1:5050/`.

## 6. Typo checklist
- URL must be `http://` not `https://`
- `127.0.0.1:5000`, not `127.0.0.1:5000/login` (start at the root)
- No stray characters copy-pasted into the address bar

## Once it's loading
Log in once with `admin` / `Adm!n#2026Secure`, log in once more with a
wrong password on purpose, then verify both got logged:
```powershell
python -c "import sqlite3; c=sqlite3.connect('instance/honeypot.db'); cur=c.cursor(); cur.execute('SELECT id, username_attempted, login_status, ip_address FROM login_attempts'); [print(r) for r in cur.fetchall()]"
```
You can also just open `http://127.0.0.1:5000/api/login-attempts` in
the browser directly — it returns the same data as JSON.
