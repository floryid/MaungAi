#!/usr/bin/env bash
set -euo pipefail

echo "[*] MaungAi Linux tool installer"
echo "[*] Target tools: subfinder httpx katana gau waybackurls gf uro nuclei"

if ! command -v go >/dev/null 2>&1; then
  echo "[!] Golang belum terpasang. Install Go terlebih dahulu: https://go.dev/dl/"
  exit 1
fi

if command -v apt >/dev/null 2>&1; then
  sudo apt update
  sudo apt install -y curl git wget unzip python3 python3-venv
fi

GOBIN_BIN="$(go env GOPATH)/bin"
mkdir -p "${GOBIN_BIN}"

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/s0md3v/uro@latest

if [ -d "${HOME}/.gf" ]; then
  echo "[*] Direktori gf patterns sudah ada"
else
  git clone https://github.com/1ndianl33t/Gf-Patterns "${HOME}/.gf"
fi

if ! grep -q "${GOBIN_BIN}" "${HOME}/.bashrc" 2>/dev/null; then
  echo "export PATH=\"\$PATH:${GOBIN_BIN}\"" >> "${HOME}/.bashrc"
fi

if ! grep -q "${GOBIN_BIN}" "${HOME}/.zshrc" 2>/dev/null; then
  echo "export PATH=\"\$PATH:${GOBIN_BIN}\"" >> "${HOME}/.zshrc"
fi

echo "[*] Update templates nuclei"
"${GOBIN_BIN}/nuclei" -update-templates || true

echo "[+] Selesai. Restart terminal lalu cek:"
echo "    subfinder -version"
echo "    httpx -version"
echo "    katana -version"
echo "    nuclei -version"
