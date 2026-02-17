#!/bin/bash
set -e

mkdir -p tools_bin

echo "[*] Baixando Nuclei..."
curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /tmp/nuclei.zip
unzip -o /tmp/nuclei.zip -d /tmp/nuclei_extract/ 2>/dev/null || true
cp /tmp/nuclei_extract/nuclei tools_bin/nuclei 2>/dev/null || true

echo "[*] Baixando Gitleaks..."
GITLEAKS_URL=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep browser_download_url | grep linux_x64 | cut -d '"' -f 4)
if [ -n "$GITLEAKS_URL" ]; then
    curl -sL "$GITLEAKS_URL" -o /tmp/gitleaks.tar.gz
    tar xzf /tmp/gitleaks.tar.gz -C tools_bin/ gitleaks 2>/dev/null || true
fi

echo "[*] Baixando TruffleHog..."
TRUFFLEHOG_URL=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | grep browser_download_url | grep linux_amd64.tar.gz | head -1 | cut -d '"' -f 4)
if [ -n "$TRUFFLEHOG_URL" ]; then
    curl -sL "$TRUFFLEHOG_URL" -o /tmp/trufflehog.tar.gz
    tar xzf /tmp/trufflehog.tar.gz -C tools_bin/ trufflehog 2>/dev/null || true
fi

echo "[*] SQLMap instalado via pip (requirements.txt)"

chmod +x tools_bin/* 2>/dev/null || true
echo "[+] Ferramentas externas instaladas."
