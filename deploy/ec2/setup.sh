#!/usr/bin/env bash
set -euo pipefail

APP_USER=ec2-user
APP_HOME="/home/$APP_USER"
REPO_DIR="$APP_HOME/trustvault"
NVM_VERSION=v0.40.3
COMPOSE_VERSION=v2.29.7

if [[ "$(id -un)" != "$APP_USER" ]]; then
  printf 'Run this script as %s, not root or another user.\n' "$APP_USER" >&2
  exit 1
fi
if [[ ! -f "$REPO_DIR/package.json" ]]; then
  printf 'Expected the repository at %s.\n' "$REPO_DIR" >&2
  exit 1
fi
cd "$REPO_DIR"

sudo dnf install -y docker curl git openssl
sudo systemctl enable --now docker
sudo usermod -aG docker "$APP_USER"

mkdir -p "$APP_HOME/.docker/cli-plugins"
case "$(uname -m)" in
  x86_64) compose_arch=x86_64; cloudflared_arch=amd64 ;;
  aarch64) compose_arch=aarch64; cloudflared_arch=arm64 ;;
  *)
    printf 'Unsupported machine architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac
curl -fsSL \
  "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-${compose_arch}" \
  -o "$APP_HOME/.docker/cli-plugins/docker-compose"
chmod 755 "$APP_HOME/.docker/cli-plugins/docker-compose"
sudo curl -fsSL \
  "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${cloudflared_arch}" \
  -o /usr/local/bin/cloudflared
sudo chmod 755 /usr/local/bin/cloudflared

export NVM_DIR="$APP_HOME/.nvm"
if [[ ! -s "$NVM_DIR/nvm.sh" ]]; then
  curl -fsSL "https://raw.githubusercontent.com/nvm-sh/nvm/${NVM_VERSION}/install.sh" | bash
fi
# shellcheck source=/dev/null
source "$NVM_DIR/nvm.sh"
nvm install 20
nvm use 20

if [[ ! -e "$REPO_DIR/.env" && ! -L "$REPO_DIR/.env" ]]; then
  migrator_password="$(openssl rand -hex 32)"
  app_password="$(openssl rand -hex 32)"
  master_key="$(openssl rand -hex 32)"
  audit_secret="$(openssl rand -hex 32)"
  session_secret="$(openssl rand -hex 32)"
  if ! (
    set -o noclobber
    umask 077
    {
      printf 'POSTGRES_MIGRATOR_PASSWORD=%s\n' "$migrator_password"
      printf 'POSTGRES_APP_PASSWORD=%s\n' "$app_password"
      printf 'DATABASE_URL=postgresql://trustvault_app:%s@127.0.0.1:5432/trustvault\n' "$app_password"
      printf 'DB_MIGRATION_URL=postgresql://trustvault_migrator:%s@127.0.0.1:5432/trustvault\n' "$migrator_password"
      printf 'MASTER_KEY=%s\n' "$master_key"
      printf 'AUDIT_HMAC_SECRET=%s\n' "$audit_secret"
      printf 'SESSION_SECRET=%s\n' "$session_secret"
    } > "$REPO_DIR/.env"
  ); then
    printf 'Refusing to overwrite an existing .env file.\n' >&2
    exit 1
  fi
  chmod 600 "$REPO_DIR/.env"
fi

sudo -u "$APP_USER" env DOCKER_CONFIG="$APP_HOME/.docker" \
  docker compose --profile local up -d db
npm ci
npm run build:all
npm run db:migrate
npm run seed

sudo install -m 644 "$REPO_DIR/deploy/ec2/trustvault.service" \
  /etc/systemd/system/trustvault.service
sudo install -m 644 "$REPO_DIR/deploy/ec2/trustvault-cloudflared.service" \
  /etc/systemd/system/trustvault-cloudflared.service
touch "$APP_HOME/tunnel.log"
chmod 600 "$APP_HOME/tunnel.log"
sudo systemctl daemon-reload
sudo systemctl enable --now trustvault.service
sudo systemctl enable --now trustvault-cloudflared.service

for _ in {1..30}; do
  if grep -Eq 'https://[[:alnum:]-]+\.trycloudflare\.com' "$APP_HOME/tunnel.log"; then
    break
  fi
  sleep 1
done
if ! grep -Eq 'https://[[:alnum:]-]+\.trycloudflare\.com' "$APP_HOME/tunnel.log"; then
  printf 'Cloudflare tunnel did not publish a trycloudflare.com link; inspect systemctl status and %s/tunnel.log.\n' "$APP_HOME" >&2
  exit 1
fi
