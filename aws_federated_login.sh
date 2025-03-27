#!/usr/bin/env bash
set -euo pipefail

# Default values
DURATION_HOURS=1
AWS_KEY=""
AWS_SECRET=""
AWS_PROFILE=""
ENV_FILE=""
VERBOSE=false

# Usage/help message
show_help() {
  echo ""
  echo "Federated AWS Console Login"
  echo "---------------------------"
  echo "This script generates a temporary AWS Console login URL using federated credentials"
  echo "from your current AWS CLI session, credentials file, profile, or custom input."
  echo ""
  echo "Credential precedence (highest to lowest):"
  echo "  1. --key / --secret        Credentials passed as arguments"
  echo "  2. --env FILE              Environment file containing AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
  echo "  3. --profile NAME          Named AWS CLI profile from ~/.aws/credentials or ~/.aws/config"
  echo "  4. Exported environment    Already-exported AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
  echo "  5. Default AWS CLI config  ~/.aws/credentials or ~/.aws/config"
  echo ""
  echo "Options:"
  echo "  -h, --help              Show this help message and exit"
  echo "  -t, --time HOURS        Set session duration in hours (default: 1, max: 36 depending on policy)"
  echo "  -k, --key KEY           AWS Access Key ID (must be used with --secret)"
  echo "  -s, --secret SECRET     AWS Secret Access Key (must be used with --key)"
  echo "  --profile NAME          Use the specified AWS CLI profile"
  echo "  --env FILE              Load AWS credentials from a custom environment file"
  echo "  -r, --read-only         Use a scoped-down session (Describe/List/Get only)"
  echo "  -i                      Open login URL in default browser"
  echo "  -v, --verbose           Output the full session JSON block"
  echo ""
  echo "Example:"
  echo "  $0 -t 4 --profile dev-account -i"
  echo ""
  exit 0
}

OPEN_IN_BROWSER=false
READ_ONLY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) show_help ;;
    -t|--time) DURATION_HOURS="$2"; shift 2 ;;
    -k|--key) AWS_KEY="$2"; shift 2 ;;
    -s|--secret) AWS_SECRET="$2"; shift 2 ;;
    --profile) AWS_PROFILE="$2"; shift 2 ;;
    --env) ENV_FILE="$2"; shift 2 ;;
    -v|--verbose) VERBOSE=true; shift ;;
    -i) OPEN_IN_BROWSER=true; shift ;;
    -r|--read-only) READ_ONLY=true; shift ;;
    *) echo "❌ Unknown option: $1"; echo "Use --help to see available options."; exit 1 ;;
  esac
done

# Validate duration
if ! [[ "$DURATION_HOURS" =~ ^[0-9]+$ ]] || (( DURATION_HOURS < 1 || DURATION_HOURS > 36 )); then
  echo "❌ Invalid session duration: must be between 1 and 36 hours."
  exit 1
fi

# Validate key/secret usage
if [[ -n "$AWS_KEY" && -z "$AWS_SECRET" ]] || [[ -n "$AWS_SECRET" && -z "$AWS_KEY" ]]; then
  echo "❌ If you provide a key, you must also provide a secret (and vice versa)."
  exit 1
fi

# Apply credentials by priority
if [[ -n "$AWS_KEY" ]]; then
  export AWS_ACCESS_KEY_ID="$AWS_KEY"
  export AWS_SECRET_ACCESS_KEY="$AWS_SECRET"
  echo "🔐 Using credentials from --key/--secret: $AWS_ACCESS_KEY_ID"

elif [[ -n "$ENV_FILE" && -f "$ENV_FILE" ]]; then
  echo "📄 Loading credentials from environment file: $ENV_FILE"
  unset AWS_PROFILE
  unset AWS_ACCESS_KEY_ID
  unset AWS_SECRET_ACCESS_KEY
  unset AWS_SESSION_TOKEN
  set -a
  source "$ENV_FILE"
  set +a
  echo "🔐 Using credentials from env file: ${AWS_ACCESS_KEY_ID:-unset}"


elif [[ -n "$AWS_PROFILE" ]]; then
  unset AWS_ACCESS_KEY_ID
  unset AWS_SECRET_ACCESS_KEY
  unset AWS_SESSION_TOKEN
  export AWS_PROFILE
  echo "🔐 Using AWS CLI profile: $AWS_PROFILE"
  PROFILE_KEY=$(aws configure get aws_access_key_id --profile "$AWS_PROFILE" 2>/dev/null || echo "")
  echo "🔐 Resolved access key: ${PROFILE_KEY:-unset}"

elif [[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
  echo "🔐 Using already-exported credentials: $AWS_ACCESS_KEY_ID"

else
  echo "🔐 Falling back to default AWS CLI credentials (~/.aws/credentials or ~/.aws/config)"
fi


# Validate credentials and show account/user
if ! IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null); then
  echo "❌ AWS credentials are invalid, expired, not authorised, or not available!"
  echo "💡 Provide credentials via --key/--secret, --env, --profile, or export them."
  exit 1
fi

ACCOUNT=$(echo "$IDENTITY" | jq -r .Account)
ARN=$(echo "$IDENTITY" | jq -r .Arn)
USERNAME=$(basename "$ARN")

echo "✅ Authenticated as '$USERNAME' in account $ACCOUNT"

DURATION_SECONDS=$((DURATION_HOURS * 3600))
echo "🔐 Requesting federated session from STS for $DURATION_HOURS hour(s)..."

# Define policy
if $READ_ONLY; then
  echo "🔐 Using read-only policy for session"
  POLICY='{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:List*",
        "s3:Get*",
        "iam:List*",
        "iam:Get*",
        "cloudtrail:LookupEvents",
        "config:Describe*",
        "config:Get*",
        "logs:Describe*",
        "logs:Get*",
        "cloudwatch:Get*",
        "cloudwatch:Describe*",
        "kms:List*",
        "kms:Describe*",
        "kms:Get*"
      ],
      "Resource": "*"
    }]
  }'
else
  echo "⚠️  This session will grant FULL access to AWS services (*:*). Use with care."
  POLICY='{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }]
  }'
fi

# Request federated token
if ! CREDS=$(aws sts get-federation-token \
  --name "tempConsoleAccess" \
  --policy "$POLICY" \
  --duration-seconds "$DURATION_SECONDS" 2>&1); then
  echo "❌ Failed to get federated token:"
  echo "$CREDS"
  exit 1
fi

# Validate credentials were returned
if ! echo "$CREDS" | jq -e .Credentials.AccessKeyId >/dev/null 2>&1; then
  echo "❌ Unexpected response. Output was:"
  echo "$CREDS"
  exit 1
fi

echo "✅ Federated session token successfully obtained."

# Extract values
ACCESS_KEY=$(echo "$CREDS" | jq -r '.Credentials.AccessKeyId')
SECRET_KEY=$(echo "$CREDS" | jq -r '.Credentials.SecretAccessKey')
SESSION_TOKEN=$(echo "$CREDS" | jq -r '.Credentials.SessionToken')

# Create session JSON block
SESSION_JSON=$(jq -n \
  --arg sid "$ACCESS_KEY" \
  --arg sk "$SECRET_KEY" \
  --arg token "$SESSION_TOKEN" \
  '{sessionId: $sid, sessionKey: $sk, sessionToken: $token}')

# Verbose output
if $VERBOSE; then
  echo ""
  echo "🔎 Session JSON:"
  echo "$SESSION_JSON"
fi

echo "🌐 Requesting SigninToken from federation endpoint..."

# Get SigninToken from federation endpoint
SIGNIN_RESPONSE=$(curl -sS --fail \
  --data-urlencode "Action=getSigninToken" \
  --data-urlencode "Session=$(jq -c . <<< "$SESSION_JSON")" \
  "https://signin.aws.amazon.com/federation") || {
    echo "❌ Failed to retrieve SigninToken from federation endpoint."
    exit 1
}

SIGNIN_TOKEN=$(echo "$SIGNIN_RESPONSE" | jq -r .SigninToken)

if [[ -z "$SIGNIN_TOKEN" || "$SIGNIN_TOKEN" == "null" ]]; then
  echo "❌ Invalid SigninToken received. Check session JSON or network issues."
  exit 1
fi

# Generate login URL
LOGIN_URL="https://signin.aws.amazon.com/federation?Action=login&Issuer=&Destination=https%3A%2F%2Fconsole.aws.amazon.com%2F&SigninToken=$SIGNIN_TOKEN"

echo ""
echo "✅ Federated session ready."
echo "🔗 Login to the AWS Console here (valid for $DURATION_HOURS hour(s)):"
echo "$LOGIN_URL"
echo "🕒 Console access expires at: $(date -d "+$DURATION_HOURS hour" '+%Y-%m-%d %H:%M:%S')"
if ! $READ_ONLY; then
  echo "⚠️  This session will grant FULL access to AWS services (*:*). Use with care."
fi

if $OPEN_IN_BROWSER; then
  echo "🌐 Opening login URL in browser..."
  if command -v xdg-open &> /dev/null; then
    xdg-open "$LOGIN_URL" >/dev/null 2>&1 &
  elif command -v open &> /dev/null; then
    open "$LOGIN_URL" >/dev/null 2>&1 &
  elif grep -qEi 'microsoft|wsl' /proc/version &> /dev/null; then
    cmd.exe /C start "$LOGIN_URL"
  else
    echo "⚠️ Could not detect a compatible method to open the browser."
  fi
fi
