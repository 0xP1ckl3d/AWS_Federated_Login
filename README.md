# Federated AWS Console Login

A Bash script that generates a federated AWS Console login URL from existing credentials (key/secret, environment file, profile, or session), suitable for cloud audits, penetration tests, or red team engagements, where AWS CLI Keys are accessible and console access is desired without password/MFA.

---

##  🔧 Features

- Generates a short-lived federated console session (up to 36 hours)
- Accepts credentials from:
  - Inline access key/secret
  - Environment file
  - AWS profile
  - Exported environment variables
  - Default AWS CLI config
- Supports:
  - Full-access or scoped **read-only** policy
  - Optional browser auto-launch
  - Verbose mode to show session JSON

---

## 🧪 Usage

```bash
./aws_federated_login.sh [options]
```

### Options:

| Option              | Description                                                       |
| ------------------- | ----------------------------------------------------------------- |
| `-h`, `--help`      | Show help message and exit                                        |
| `-t`, `--time`      | Session duration in hours (default: `1`, max: `36`)               |
| `-k`, `--key`       | AWS Access Key ID (must be used with `--secret`)                  |
| `-s`, `--secret`    | AWS Secret Access Key (must be used with `--key`)                 |
| `--profile`         | Use a named AWS CLI profile                                       |
| `--env`             | Load credentials from a `.env`-style file                         |
| `-r`, `--read-only` | Use scoped-down read-only permissions (recommended for audit use) |
| `-i`                | Automatically open the generated login URL in the default browser |
| `-v`, `--verbose`   | Output the session JSON used to generate the token                |

---

## ✅ Examples

**Using an AWS CLI profile:**

```bash
./aws_federated_login.sh --profile dev-account -t 4 -i
```

**Using a custom environment file:**

```bash
./aws_federated_login.sh --env creds.env -t 2
```

**Generating a read-only audit session:**

```bash
./aws_federated_login.sh --profile audit-role -r
```

---

## ⚠️ Permission Issues

If you are getting permission denied, but have `iam:AttachUserPolicy` or `iam:FullAccess`, you can assign yourself full admin aceess with the following and try again:

```bash
aws iam attach-user-policy \       
  --user-name <ACCOUNT_USER_NAME> \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Account username can be displayed with:

```bash
aws sts get-caller-identity
```

## ⚠️ Security Notes

- Avoid passing keys via CLI arguments on shared systems (`ps` visibility).
- Prefer profiles or environment files when possible.
- Full-access mode grants `*:*` permissions — use `--read-only` in audit contexts.
- Verbose mode (`-v`) prints credentials to screen — be cautious in shared terminals.

---

## 🗕️ Console Session Duration

The default session length is **1 hour**, and can be set up to **36 hours** depending on the IAM policy. The expiry time is shown after generation.

---

## 🧼 Cleanup

This script does not modify or persist credentials. It uses temporary STS federation tokens which automatically expire.

---
