#!/bin/bash
# IMXPLOIT-PREDATOR-X v15.0 - GITHUB EDITION
# Created by: IMXploit
# CONTACT: TikTok @lugowo.hy
# GITHUB: https://github.com/lugowohy/imxploit-predator

BIRU='\033[0;34m'
MERAH='\033[0;31m'
HIJAU='\033[0;32m'
KUNING='\033[1;33m'
CYAN='\033[0;36m'
UNGU='\033[0;35m'
NC='\033[0m'

# ============== KONFIGURASI ==============
VERSION="15.0 GITHUB EDITION"
OWNER="IMXploit"
CONTACT_TIKTOK="@lugowo.hy"
GITHUB_REPO="https://github.com/lugowohy/imxploit-predator"

# File license lokal (dibikin pas aktivasi)
LICENSE_FILE="$HOME/.imxploit_license.dat"

# ============== CEK LICENSE TERSIMPAN ==============
check_saved_license() {
    if [[ -f "$LICENSE_FILE" ]]; then
        local expiry=$(cat "$LICENSE_FILE" | cut -d'|' -f2)
        local current_date=$(date +%Y-%m-%d)
        
        if [[ "$current_date" > "$expiry" ]]; then
            echo -e "${MERAH}[!] License expired!${NC}"
            echo -e "${KUNING}[i] Silahkan beli license baru di TikTok @lugowo.hy${NC}"
            rm -f "$LICENSE_FILE"
            sleep 3
            return 1
        else
            local days_left=$(( ( $(date -d "$expiry" +%s) - $(date +%s) ) / 86400 ))
            echo -e "${HIJAU}[✓] License valid!${NC}"
            echo -e "${HIJAU}[✓] Sisa masa aktif: $days_left hari${NC}"
            sleep 2
            return 0
        fi
    fi
    return 1
}

# ============== VALIDASI LICENSE ONLINE ==============
validate_license() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              AKTIVASI LICENSE IMXPLOIT                    ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║  Masukkan LICENSE KEY yang lo dapat dari admin:            ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${KUNING}LICENSE KEY: ${NC}"
    read license_key
    
    # Minta HWID
    local hwid=$(getprop ro.serialno 2>/dev/null | md5sum | cut -d' ' -f1)
    [[ -z "$hwid" ]] && hwid=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 16 | head -n 1)
    
    echo -e "${CYAN}[*] Mengaktifkan license...${NC}"
    sleep 2
    
    # Simulasi cek ke admin (sebenernya lo yang catat manual)
    # Disini tools cuma akan minta input dan nyimpen license
    # Lo sebagai admin yang catat siapa beli apa
    
    echo -e "${KUNING}[?] Pilih paket yang lo beli:${NC}"
    echo "    1. Trial (14 hari) - GRATIS"
    echo "    2. Basic (14 hari) - Rp 50.000"
    echo "    3. Pro (30 hari) - Rp 150.000"
    echo "    4. Premium (60 hari) - Rp 200.000"
    echo "    5. Lifetime (selamanya) - Rp 500.000"
    echo ""
    echo -ne "${KUNING}Pilih paket [1-5]: ${NC}"
    read paket
    
    case $paket in
        1) expiry=$(date -d "+14 days" +%Y-%m-%d);;
        2) expiry=$(date -d "+14 days" +%Y-%m-%d);;
        3) expiry=$(date -d "+30 days" +%Y-%m-%d);;
        4) expiry=$(date -d "+60 days" +%Y-%m-%d);;
        5) expiry="2099-12-31";;
        *) echo -e "${MERAH}Pilihan salah!${NC}"; sleep 2; return 1;;
    esac
    
    # Simpan license
    echo "$license_key|$expiry|$hwid" > "$LICENSE_FILE"
    
    echo ""
    echo -e "${HIJAU}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${HIJAU}║      AKTIVASI BERHASIL!                                   ║${NC}"
    echo -e "${HIJAU}║      License aktif sampai: $expiry               ║${NC}"
    echo -e "${HIJAU}╚════════════════════════════════════════════════════════════╝${NC}"
    sleep 3
    return 0
}

# ============== MENU BELI LICENSE ==============
buy_license() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              CARA BELI LICENSE                            ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║                                                            ║${NC}"
    echo -e "${CYAN}║  1. DM TikTok: ${HIJAU}$CONTACT_TIKTOK${NC}                        ║${NC}"
    echo -e "${CYAN}║  2. Bilang mau beli paket apa                              ║${NC}"
    echo -e "${CYAN}║  3. Transfer ke rek yang dikasih admin                     ║${NC}"
    echo -e "${CYAN}║  4. Kirim bukti transfer + minta LICENSE KEY               ║${NC}"
    echo -e "${CYAN}║  5. Masukin LICENSE KEY pas aktivasi                       ║${NC}"
    echo -e "${CYAN}║                                                            ║${NC}"
    echo -e "${CYAN}║  📦 PAKET TERSEDIA:                                        ║${NC}"
    echo -e "${CYAN}║  • Trial 2 minggu: ${HIJAU}GRATIS!${NC}                                ║${NC}"
    echo -e "${CYAN}║  • Basic 2 minggu: ${HIJAU}Rp 50.000${NC}                             ║${NC}"
    echo -e "${CYAN}║  • Pro 1 bulan: ${HIJAU}Rp 150.000${NC}                               ║${NC}"
    echo -e "${CYAN}║  • Premium 2 bulan: ${HIJAU}Rp 200.000${NC}                           ║${NC}"
    echo -e "${CYAN}║  • Lifetime (selamanya): ${HIJAU}Rp 500.000${NC}                      ║${NC}"
    echo -e "${CYAN}║                                                            ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${KUNING}Press Enter untuk kembali...${NC}"
    read
}

# ============== MENU UTAMA ==============
main_menu() {
    while true; do
        clear
        echo -e "${MERAH}"
        echo "    ╔════════════════════════════════════════════════════════════╗"
        echo "    ║     IMXPLOIT-PREDATOR-X v15.0 - GITHUB EDITION             ║"
        echo "    ║              Created by: IMXploit                          ║"
        echo "    ║              Contact: @lugowo.hy (TikTok)                   ║"
        echo "    ╚════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                    MAIN MENU                              ║${NC}"
        echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║  [1] Aktivasi License                                     ║${NC}"
        echo -e "${CYAN}║  [2] Cara Beli License                                    ║${NC}"
        echo -e "${CYAN}║  [3] Jalankan Tools (HARUS AKTIF)                         ║${NC}"
        echo -e "${CYAN}║  [4] Tentang Tools                                        ║${NC}"
        echo -e "${CYAN}║  [5] Keluar                                               ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -ne "${KUNING}Pilih menu [1-5]: ${NC}"
        read choice
        
        case $choice in
            1)
                validate_license
                ;;
            2)
                buy_license
                ;;
            3)
                if check_saved_license; then
                    # PANGGIL FUNGSI TOOLS UTAMA DI SINI
                    echo -e "${CYAN}[✓] Memulai tools...${NC}"
                    sleep 2
                    # TODO: Masukkan kode tools scanning lo di sini
                    echo -e "${HIJAU}[✓] Tools siap digunakan! (Demo)${NC}"
                    echo -ne "${KUNING}Press Enter...${NC}"
                    read
                else
                    echo -e "${MERAH}[!] License tidak aktif!${NC}"
                    sleep 2
                fi
                ;;
            4)
                echo ""
                echo -e "${CYAN}IMXploit Predator v$VERSION${NC}"
                echo -e "${CYAN}Created by: $OWNER${NC}"
                echo -e "${CYAN}📍 TikTok: @lugowo.hy${NC}"
                echo -e "${CYAN}📍 GitHub: $GITHUB_REPO${NC}"
                echo ""
                echo -ne "${KUNING}Press Enter...${NC}"
                read
                ;;
            5)
                echo -e "${HIJAU}Thanks for using IMXploit Predator!${NC}"
                exit 0
                ;;
            *)
                echo -e "${MERAH}Pilihan tidak valid!${NC}"
                sleep 1
                ;;
        esac
    done
}

# ============== MAIN ==============
main() {
    # Cek apakah udah pernah aktivasi
    if check_saved_license; then
        main_menu
    else
        # Belum pernah aktivasi, langsung ke menu utama
        # User bisa pilih aktivasi atau beli
        main_menu
    fi
}

main