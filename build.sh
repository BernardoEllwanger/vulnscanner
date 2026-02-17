#!/bin/bash
set -e

mkdir -p tools_bin

echo "[*] Baixando Nuclei..."
NUCLEI_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep browser_download_url | grep linux_amd64.zip | cut -d '"' -f 4)
if [ -n "$NUCLEI_URL" ]; then
    curl -sL "$NUCLEI_URL" -o /tmp/nuclei.zip
    unzip -o /tmp/nuclei.zip -d /tmp/nuclei_extract/ 2>/dev/null || true
    find /tmp/nuclei_extract/ -name "nuclei" -type f -exec cp {} tools_bin/nuclei \;
    echo "[+] Nuclei baixado"
else
    echo "[!] Nuclei URL nao encontrada"
fi

echo "[*] Baixando Gitleaks..."
GITLEAKS_URL=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep browser_download_url | grep linux_x64 | cut -d '"' -f 4)
if [ -n "$GITLEAKS_URL" ]; then
    curl -sL "$GITLEAKS_URL" -o /tmp/gitleaks.tar.gz
    tar xzf /tmp/gitleaks.tar.gz -C tools_bin/ gitleaks 2>/dev/null || true
    echo "[+] Gitleaks baixado"
fi

echo "[*] Baixando TruffleHog..."
TRUFFLEHOG_URL=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | grep browser_download_url | grep linux_amd64.tar.gz | head -1 | cut -d '"' -f 4)
if [ -n "$TRUFFLEHOG_URL" ]; then
    curl -sL "$TRUFFLEHOG_URL" -o /tmp/trufflehog.tar.gz
    mkdir -p /tmp/trufflehog_extract
    tar xzf /tmp/trufflehog.tar.gz -C /tmp/trufflehog_extract/ 2>/dev/null || true
    find /tmp/trufflehog_extract/ -name "trufflehog" -type f -exec cp {} tools_bin/trufflehog \;
    echo "[+] TruffleHog baixado"
else
    echo "[!] TruffleHog URL nao encontrada"
fi

echo "[*] SQLMap instalado via pip (requirements.txt)"

chmod +x tools_bin/* 2>/dev/null || true

echo ""
echo "[+] Ferramentas externas:"
ls -la tools_bin/ 2>/dev/null || true
echo ""
