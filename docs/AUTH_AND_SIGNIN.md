# Sign-in, 2FA and social login

Everything on this page is optional. The panel works with a username and
password alone; this is for people who want more than that.

Two features, often confused:

| | What it proves | Protects against |
|---|---|---|
| **Two-factor (2FA)** | you have your password **and** your phone | a stolen or guessed password |
| **Social login** | someone else already verified who you are | making users remember another password |

They work together. Turning on Google login does **not** weaken 2FA — if your
account has 2FA, signing in with Google still asks for the code.

---

## 1. Turn on two-factor for your account

1. Sign in, then go to **Profile → Two-Factor Authentication → Set up**.
   Direct link: `https://your-panel/settings/2fa`
2. Scan the QR code with an authenticator app — Google Authenticator, Aegis,
   1Password, Bitwarden, anything that speaks TOTP.
3. Type the 6-digit code the app shows and press **Enable**.
4. **Save the 10 recovery codes.** They are shown once and never again.

That's it. Next time you sign in, the panel asks for a code after your password.

> **Don't skip the recovery codes.** They are the only way back in if you lose
> your phone. If you lose both, an admin has to reset your 2FA for you.

### Using a recovery code

On the code screen, click **Lost your device? Use a recovery code** and type one
in. Codes look like `abcd-efgh`, spaces and capitals don't matter, and each one
works exactly once — it is deleted from the database the moment it's used.

### What happens when they run out

Signing in with a recovery code tells you how many are left. Below three, the
panel warns you. At zero, the Profile page shows a red banner.

Generate a fresh set any time: **Profile → Two-Factor → Generate new recovery
codes**. This **destroys the old set immediately** — print or save the new one.

---

## 2. Require 2FA for admins

Once you're running more than one admin account, you probably want 2FA to be
mandatory rather than optional.

**Admin → Settings → Sign-in → Require 2FA for admins**

When on:

- Admins and sub-admins who sign in **without** 2FA are sent to the setup page
  and cannot reach anything else until they finish.
- It is checked at login, so an admin cannot dodge it by skipping the page.

It only applies to `admin` and `subadmin` roles. Regular users enrol voluntarily.

---

## 3. Locked out? Reset someone's 2FA

Someone lost their phone *and* their recovery codes. They cannot sign in, and
you cannot send them their codes because nobody has them.

**Admin → Users → find the user → Reset 2FA**

Their second factor is cleared and they can sign in with just their password
again. The button only appears on accounts that have 2FA enabled.

Every reset is written to the activity log with your username against it, so
this is not a silent backdoor.

> An admin cannot reset their **own** 2FA this way — that would let a hijacked
> session strip its own protection. Admins change their own 2FA from their
> profile like everyone else.

### Last resort: from the server

If you are locked out and are the only admin, run this on the panel itself:

```bash
sudo -u tgvpanel sqlite3 /opt/tgvpanel/data/tgvpanel.db \
  "UPDATE users SET two_factor_enabled = 0, two_factor_secret_enc = NULL WHERE username = 'admin';"
sudo systemctl restart tgvpanel
```

Adjust the database path if yours differs (`grep TGVPANEL_DATA_DIR /etc/systemd/system/tgvpanel.service`).

---

## 4. Add Google sign-in

Google is the one most people want, because most people have a Gmail account.

### Step 1 — create the app at Google

1. Go to <https://console.cloud.google.com/apis/credentials>
2. Create a project if you don't have one (top bar → project selector → **New project**).
3. **Configure consent screen** → choose **External** → fill in app name and your
   support email → save. You can stay in **Testing** mode while you set things up.
4. **Credentials → Create credentials → OAuth client ID**
5. Application type: **Web application**
6. Under **Authorised redirect URIs**, add exactly:

   ```
   https://your-panel-domain.com/auth/google/callback
   ```

   `http://` only works for `localhost`. A real deployment needs `https://`.
7. Copy the **Client ID** and **Client secret**.

### Step 2 — paste them into the panel

**Admin → Settings → Sign-in → Google → Set up**, paste both values, tick
**Enable Google sign-in**, press **Save**.

The panel shows you the exact redirect URI to register — copy it from there
rather than typing it, since a single character off is the usual cause of
`redirect_uri_mismatch`.

### Step 3 — check it

Press **Test connection**. Then open the login page in a private window: a
**Continue with Google** button appears. If it doesn't, the provider isn't
enabled or a credential is missing.

> While your Google app is in **Testing** mode only accounts you added as test
> users can sign in. Publish the app when you're ready for everyone.

---

## 5. Add Discord sign-in

1. Go to <https://discord.com/developers/applications> → **New Application**.
2. **OAuth2** in the left sidebar.
3. Copy **Client ID** and **Client Secret** (`Reset Secret` if it's hidden).
4. Under **Redirects**, add:

   ```
   https://your-panel-domain.com/auth/discord/callback
   ```

5. Paste the credentials into **Admin → Settings → Sign-in → Discord** and enable.

Discord returns a verified email only for accounts that confirmed it. If
someone's Discord email isn't verified, the panel will not silently attach their
Discord login to an existing account — see [account linking](#7-how-accounts-get-linked).

---

## 6. Add GitHub sign-in

1. <https://github.com/settings/developers> → **New OAuth App**
2. Homepage URL: your panel URL.
3. **Authorization callback URL**:

   ```
   https://your-panel-domain.com/auth/github/callback
   ```

4. **Generate a new client secret**, then paste the Client ID and secret into
   **Admin → Settings → Sign-in → GitHub** and enable.

GitHub hides email addresses behind a separate scope; the panel already requests
`user:email` so it can read the primary verified address.

---

## 7. How accounts get linked

When someone signs in with Google for the first time, the panel has to decide:
is this a new person, or an existing account?

It checks, in order:

| Situation | What happens |
|---|---|
| This Google account is already linked to a user | Sign them in |
| Email matches an existing user **and** the provider says it's verified | Link automatically, sign them in |
| Email matches an existing user but **is not verified** | Ask them for that account's password first |
| No match, and sign-up is allowed | Create a new account |
| No match, and sign-up is **off** | Refuse, with a message |

The third row is the important one. An unverified email could belong to anyone,
so trusting it would let an attacker attach their Google account to your admin
account and walk in. Instead they must prove they own the existing account.

Two settings per provider control this:

- **Create an account automatically** — whether a stranger can sign up at all.
  Leave this **off** on a private panel.
- **Link to an existing account when the provider verifies the email** — leave on.

### Managing your own links

**Profile → Connected Sign-in Accounts** lists every provider and whether it's
connected. Connect or disconnect from there.

You cannot disconnect your last sign-in method if you have no password — that
would lock you out permanently. The panel refuses and tells you to set a
password first.

---

## 8. Security notes

The short version of what the implementation guarantees, so you know what you're
relying on:

- **Secrets are encrypted at rest.** Provider client secrets are encrypted with
  the panel's vault key, the same one used for node secrets. The API never
  returns them — the settings page only reports *whether* one is saved.
- **CSRF-protected.** Every OAuth callback validates a random `state` in constant
  time, and that value is single-use. A replayed or forged callback is rejected.
- **PKCE everywhere it's supported.** Google and Discord get S256 PKCE; GitHub
  doesn't support it, so it's omitted rather than faked.
- **Session ids are regenerated** on every successful sign-in, so a pre-login
  session id cannot be fixated into an authenticated one.
- **Recovery codes are hashed**, never stored in plaintext, and are single-use
  with an atomic check so two simultaneous requests can't both consume one.
- **TOTP codes cannot be replayed.** Each accepted code records its 30-second
  step; the same code is refused until the next one starts.
- **Turning 2FA off requires proof.** Even for admins — a hijacked session
  cannot quietly disable the second factor.

### What it does not do

- No email verification of its own. Trust is delegated to the provider.
- No SMS 2FA. SIM-swap attacks make it weaker than TOTP.
- No WebAuthn/passkeys yet.
- 2FA state is per-account, not per-device: one code succeeds for all sessions.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `redirect_uri_mismatch` | URI differs from what you registered | Copy it from the panel's settings page; check `http` vs `https` and trailing slashes |
| No button on the login page | Provider not enabled, or missing credential | Settings → Sign-in; check the dot is green |
| `Security check failed` | State expired (>10 min) or cookie lost | Retry; make sure cookies aren't blocked |
| `Sign-in took too long` | Sat on the consent screen too long | Retry |
| 2FA code always wrong | Device clock drifted | Enable automatic time on the phone; TOTP needs a clock within ~30 s |
| `This code has already been used` | Replay protection | Wait for the next code |
| Locked out entirely | Lost device and codes | Admin resets it, or the SQL in §3 |

### Checking the logs

```bash
sudo journalctl -u tgvpanel -n 100 --no-pager | grep -iE "oauth|2fa|auth"
```

Failed sign-ins, state mismatches and 2FA resets all appear there and in
**Admin → Activity**.
