#!/bin/bash
# INSTALLER IMXPLOIT PREDATOR
# TikTok: @lugowo.hy
# GitHub: https://github.com/lugowohy/imxploit-predator

MERAH='\033[0;31m'
HIJAU='\033[0;32m'
KUNING='\033[1;33m'
BIRU='\033[0;34m'
NC='\033[0m'

clear
echo -e "${BIRU}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         INSTALLER IMXPLOIT PREDATOR v15.0                 ║"
echo "║              TikTok: @lugowo.hy                           ║"
echo "║         GitHub: github.com/lugowohy/imxploit-predator     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

echo -e "${KUNING}[*] Memeriksa koneksi internet...${NC}"
if ! ping -c 1 google.com > /dev/null 2>&1; then
    echo -e "${MERAH}[!] Gagal! Periksa koneksi internet lo.${NC}"
    exit 1
fi
echo -e "${HIJAU}[✓] Koneksi OK${NC}"
sleep 1

echo -e "${KUNING}[*] Mengupdate package list...${NC}"
pkg update -y > /dev/null 2>&1
echo -e "${HIJAU}[✓] Update selesai${NC}"
sleep 1

echo -e "${KUNING}[*] Menginstall dependencies...${NC}"
pkg install -y curl wget git nano > /dev/null 2>&1
pkg install -y python python2 > /dev/null 2>&1
pkg install -y clang make cmake > /dev/null 2>&1
pkg install -y libxml2 libxslt > /dev/null 2>&1
echo -e "${HIJAU}[✓] Dependencies terinstall${NC}"
sleep 1

echo -e "${KUNING}[*] Menginstall module Python...${NC}"
pip install requests colorama bs4 > /dev/null 2>&1
pip install lxml beautifulsoup4 > /dev/null 2>&1
echo -e "${HIJAU}[✓] Module Python terinstall${NC}"
sleep 1

echo -e "${KUNING}[*] Memberi izin eksekusi...${NC}"
chmod +x predator.sh
echo -e "${HIJAU}[✓] Izin diberikan${NC}"
sleep 1

echo ""
echo -e "${HIJAU}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${HIJAU}║      INSTALLASI SELESAI!                                  ║${NC}"
echo -e "${HIJAU}╠════════════════════════════════════════════════════════════╣${NC}"
echo -e "${HIJAU}║  Jalankan tools dengan perintah:                          ║${NC}"
echo -e "${HIJAU}║      ./predator.sh                                        ║${NC}"
echo -e "${HIJAU}║                                                            ║${NC}"
echo -e "${HIJAU}║  ⚠️  Tools butuh LICENSE!                                  ║${NC}"
echo -e "${HIJAU}║  Beli di TikTok: @lugowo.hy                               ║${NC}"
echo -e "${HIJAU}║                                                            ║${NC}"
echo -e "${HIJAU}║  Harga:                                                   ║${NC}"
echo -e "${HIJAU}║  • Trial: GRATIS                                          ║${NC}"
echo -e "${HIJAU}║  • Basic: Rp 50.000 (14 hari)                             ║${NC}"
echo -e "${HIJAU}║  • Pro: Rp 150.000 (30 hari)                              ║${NC}"
echo -e "${HIJAU}║  • Premium: Rp 200.000 (60 hari)                          ║${NC}"
echo -e "${HIJAU}║  • Lifetime: Rp 500.000 (selamanya)                       ║${NC}"
echo -e "${HIJAU}╚════════════════════════════════════════════════════════════╝${NC}"