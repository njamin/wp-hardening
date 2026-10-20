# njamin/wp-hardening

A WordPress security baseline, loaded as a must-use plugin. It covers what a clean install leaves
open, and changes nothing a site's own code relies on.

- **Logins:** one generic error for an unknown user and a wrong password (REST and XML-RPC
  included); a lockout per username that a signed cookie lets the account's own device skip; a
  throttle per IP.
- **Lost password:** the same answer for an existing and an unknown account, including when the
  e-mail can't be sent; rate limited per IP.
- **Passwords:** a minimum length and a check against known breaches (Have I Been Pwned,
  k-anonymity: only 5 characters of a hash leave the server).
- **Two-factor authentication** enforced for the roles that need it, with the
  [Two Factor](https://wordpress.org/plugins/two-factor/) plugin.
- **Sessions:** shorter for administrators (12 h by default), ended on a password or role change.
- **Surface:** no user enumeration (REST, `?author=`), no pingbacks, no version in the HTML;
  uploads restricted to safe types, with SVG only when a sanitiser is configured.
- **Plugin guard:** plugins named in `BP_PROTECTED_PLUGINS` can't be deactivated from the admin.
- **Security events** (lockouts, throttles, failures) on the `bp/hardening/event` action, with
  users and IPs pseudonymised by an HMAC when `BP_LOG_KEY` is set.

## Requirements

WordPress 7.0 or later, PHP 8.3 or later.

## Install

```bash
composer require njamin/wp-hardening
```

Then load it from a must-use plugin, e.g. `wp-content/mu-plugins/bp-loader.php`:

```php
<?php
require_once dirname( __DIR__, 2 ) . '/vendor/autoload.php'; // wherever Composer's autoloader is
\BP\Hardening\Plugin::boot();
```

## Settings

Every setting is an optional constant in `wp-config.php`:

| Constant | Purpose |
|---|---|
| `BP_TRUSTED_PROXIES`, `BP_CLIENT_IP_HEADER` | The proxies (CIDRs) whose forwarded client IP header is believed, and which header that is |
| `BP_LOGIN_IP_LIMIT`, `BP_LOGIN_IP_WINDOW` | Failed logins allowed per IP, and over how many seconds |
| `BP_LOST_PASSWORD_LIMIT` | Lost-password requests per IP and hour (default 5) |
| `BP_PASSWORD_MIN_LENGTH`, `BP_BREACHED_PASSWORD_CHECK` | Password length, and the breach check on or off |
| `BP_2FA_ROLES`, `BP_2FA_EXEMPT_USERS` | Roles that must use 2FA; users exempt on a local environment only |
| `BP_ADMIN_SESSION_LIFETIME` | Administrator session length, in seconds |
| `BP_ALLOW_APPLICATION_PASSWORDS` | Application passwords stay off unless this is true |
| `BP_SVG_SANITISER` | Allows SVG uploads through the named sanitiser |
| `BP_PROTECTED_PLUGINS` | Plugins the admin can't deactivate |
| `BP_LOG_KEY` | Key of the HMAC that pseudonymises users and IPs in security events |
| `BP_DISABLE_HARDENING` | Kill switch, for an emergency: everything above stops |

## Tests

The integration suite boots a real WordPress: `BP_WP_LOAD=/path/to/wp-load.php vendor/bin/phpunit`.

## Security

Report a vulnerability privately through this repository's **Security → Report a
vulnerability**, not in a public issue.

## Licence

GPL-2.0-or-later. This repository is a read-only mirror: changes are made upstream and
published here with each release.
