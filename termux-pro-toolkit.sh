#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#   TERMUX PRO TOOLKIT  —  Legal Recon & Learning Suite
#   Modules: Link Inspector | Phone Analyzer | IP Recon Panel | Setup
#   Use only on your OWN links/devices/data or with permission.
# ============================================================

VERSION="1.0"
RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'
CYAN='\033[1;36m'; PURPLE='\033[1;35m'; WHITE='\033[1;37m'
BOLD='\033[1m'; RESET='\033[0m'

# ---------------- pretty print helpers ----------------
banner() {
    clear
    echo -e "${PURPLE}"
    echo "  ████████╗ ██████╗ ████████╗"
    echo "  ╚══██╔══╝██╔═══██╗╚══██╔══╝"
    echo "     ██║   ██║   ██║   ██║   "
    echo "     ██║   ██║   ██║   ██║   "
    echo "     ██║   ╚██████╔╝   ██║   "
    echo "     ╚═╝    ╚═════╝    ╚═╝   "
    echo -e "${RESET}"
    echo -e "${CYAN}  ╔══════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}  ║   ${WHITE}P R O   T O O L K I T${CYAN}  v${VERSION}          ║${RESET}"
    echo -e "${CYAN}  ║   ${YELLOW}100%% Legal  •  Ethical Use Only${CYAN}      ║${RESET}"
    echo -e "${CYAN}  ╚══════════════════════════════════════════╝${RESET}"
    echo ""
}

pause() { echo ""; read -rp "  Press ENTER to continue..." _; }

hr() { echo -e "${CYAN}  ────────────────────────────────────────────${RESET}"; }

check_deps() {
    local missing=()
    for pkg in curl jq python nmap whois; do
        command -v "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}  [*] Installing missing packages: ${missing[*]}${RESET}"
        pkg install -y "${missing[@]}" >/dev/null 2>&1
        pip install --quiet phonenumbers 2>/dev/null
    else
        python -c "import phonenumbers" 2>/dev/null || pip install --quiet phonenumbers 2>/dev/null
    fi
}

# ============================================================
#  MODULE 1 — LINK INFO INSPECTOR  (links you OWN / are allowed to test)
# ============================================================
link_inspector() {
    banner
    echo -e "${WHITE}${BOLD}  MODULE 1 › LINK INFO INSPECTOR${RESET}"
    echo -e "${YELLOW}  Only inspect links/sites you own or have permission to test.${RESET}"
    hr
    read -rp "  Enter URL (e.g. https://your-own-site.com): " URL
    [ -z "$URL" ] && { echo -e "${RED}  [!] No URL entered.${RESET}"; pause; return; }
    URL="${URL#http://}"; URL="${URL#https://}"; URL="https://$URL"
    HOST=$(echo "$URL" | sed -E 's|https?://([^/]+).*|\1|')

    echo -e "\n${CYAN}  [1] DNS / IP Address${RESET}"
    IP=$(getent hosts "$HOST" 2>/dev/null | awk '{print $1}' | head -1)
    [ -z "$IP" ] && IP=$(dig +short "$HOST" 2>/dev/null | grep -E '^[0-9]' | head -1)
    if [ -n "$IP" ]; then
        echo -e "      IP       : ${GREEN}$IP${RESET}"
        GEO=$(curl -s "http://ip-api.com/json/$IP?fields=status,country,regionName,city,isp,org,as" 2>/dev/null)
        if echo "$GEO" | jq -e . >/dev/null 2>&1 && [ "$(echo "$GEO" | jq -r .status)" = "success" ]; then
            echo -e "      Country  : $(echo "$GEO" | jq -r .country)"
            echo -e "      Region   : $(echo "$GEO" | jq -r .regionName), $(echo "$GEO" | jq -r .city)"
            echo -e "      ISP      : $(echo "$GEO" | jq -r .isp)"
            echo -e "      Org/AS   : $(echo "$GEO" | jq -r .as)"
        fi
    else
        echo -e "      ${RED}Could not resolve host.${RESET}"
    fi

    echo -e "\n${CYAN}  [2] Redirect Chain${RESET}"
    curl -s -o /dev/null -sL --max-time 15 -w "      %{url_effective}\n      HTTP code: %{http_code}\n      Redirects: %{num_redirects}\n" "$URL" 2>/dev/null | sed 's/^/      /'

    echo -e "\n${CYAN}  [3] Page Title & Server${RESET}"
    HEADERS=$(curl -sIL --max-time 15 "$URL" 2>/dev/null)
    TITLE=$(curl -sL --max-time 15 "$URL" 2>/dev/null | grep -oiE '<title[^>]*>[^<]*' | head -1 | sed 's/<title[^>]*>//i')
    [ -n "$TITLE" ] && echo -e "      Title    : ${GREEN}$TITLE${RESET}"
    echo "$HEADERS" | grep -iE '^(server|x-powered-by|content-type|strict-transport|cf-ray)' | head -6 | sed 's/^/      /'

    echo -e "\n${CYAN}  [4] Security Headers Check${RESET}"
    for h in "Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options"; do
        if echo "$HEADERS" | grep -qi "$h"; then
            echo -e "      ${GREEN}[✓]${RESET} $h present"
        else
            echo -e "      ${RED}[✗]${RESET} $h MISSING"
        fi
    done

    echo -e "\n${CYAN}  [5] SSL Certificate${RESET}"
    SSL=$(echo | timeout 10 openssl s_client -connect "$HOST:443" -servername "$HOST" 2>/dev/null | openssl x509 -noout -dates -subject 2>/dev/null)
    if [ -n "$SSL" ]; then
        echo "$SSL" | sed 's/^/      /'
    else
        echo -e "      ${YELLOW}No SSL info (site may not use HTTPS).${RESET}"
    fi

    echo -e "\n${CYAN}  [6] WHOIS (registration data)${RESET}"
    whois "$HOST" 2>/dev/null | grep -iE 'registrar:|creation date:|expiry' | head -4 | sed 's/^/      /'

    echo -e "\n${CYAN}  [7] Open Ports (basic scan — authorized targets only)${RESET}"
    nmap -Pn --top-ports 10 -T4 "$HOST" 2>/dev/null | grep -E '^[0-9]+/' | sed 's/^/      /' | head -10

    pause
}

# ============================================================
#  MODULE 2 — PHONE NUMBER ANALYZER  (public numbering data only)
# ============================================================
phone_analyzer() {
    banner
    echo -e "${WHITE}${BOLD}  MODULE 2 › PHONE NUMBER ANALYZER${RESET}"
    echo -e "${YELLOW}  Shows public numbering data: country, carrier type, region.${RESET}"
    hr
    read -rp "  Enter number with country code (e.g. +60123456789): " NUM
    [ -z "$NUM" ] && { echo -e "${RED}  [!] No number entered.${RESET}"; pause; return; }

    python3 - "$NUM" <<'PYEOF'
import sys, phonenumbers
from phonenumbers import geocoder, carrier, timezone

num = sys.argv[1].replace(" ", "").replace("-", "")
try:
    p = phonenumbers.parse(num)
except Exception:
    print("  [!] Invalid number format."); sys.exit(1)

if not phonenumbers.is_valid_number(p):
    print("  [!] Number is NOT valid in any country numbering plan.")
    sys.exit(1)

print(f"  {'Valid':<12}: YES")
print(f"  {'Country':<12}: {phonenumbers.region_code_for_number(p)}")
desc = geocoder.description_for_number(p, "en")
print(f"  {'Region':<12}: {desc or 'n/a'}")
c = carrier.name_for_number(p, "en")
print(f"  {'Carrier':<12}: {c or 'n/a (portable/VoIP)'}")
print(f"  {'Line type':<12}: ", end="")
n = p.national_number
print("Mobile (inferred from prefix block)" if phonenumbers.number_type(p) == phonenumbers.PhoneNumberType.MOBILE
      else {0:"Fixed line",1:"Fixed/Mobile",2:"Toll-free",3:"Premium rate",4:"Shared cost",5:"VoIP",6:"Personal",7:"Pager",8:"UAN",9:"Voicemail"}.get(phonenumbers.number_type(p), "Unknown"))
tzs = timezone.time_zones_for_number(p)
print(f"  {'Timezone(s)':<12}: {', '.join(tzs) if tzs else 'n/a'}")
fmt_int = phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
print(f"  {'Formatted':<12}: {fmt_int}")
PYEOF
    pause
}

# ============================================================
#  MODULE 3 — MY IP & DEVICE RECON PANEL  (your own data)
# ============================================================
ip_recon() {
    banner
    echo -e "${WHITE}${BOLD}  MODULE 3 › MY IP & DEVICE RECON PANEL${RESET}"
    echo -e "${YELLOW}  Shows what websites can see about YOUR connection.${RESET}"
    hr
    ME=$(curl -s "http://ip-api.com/json/?fields=status,query,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting" 2>/dev/null)
    if echo "$ME" | jq -e . >/dev/null 2>&1 && [ "$(echo "$ME" | jq -r .status)" = "success" ]; then
        echo -e "  ${CYAN}◆ Network${RESET}"
        echo -e "      Your IP      : ${GREEN}$(echo "$ME" | jq -r .query)${RESET}"
        echo -e "      Reverse DNS  : $(echo "$ME" | jq -r .reverse)"
        echo -e "      ISP          : $(echo "$ME" | jq -r .isp)"
        echo -e "      Org          : $(echo "$ME" | jq -r .org)"
        echo -e "      ASN          : $(echo "$ME" | jq -r .as)"
        echo -e "\n  ${CYAN}◆ Location (approx, from IP)${RESET}"
        echo -e "      Country      : $(echo "$ME" | jq -r .country) ($(echo "$ME" | jq -r .countryCode))"
        echo -e "      City/Region  : $(echo "$ME" | jq -r .city), $(echo "$ME" | jq -r .regionName)"
        echo -e "      Coordinates  : $(echo "$ME" | jq -r .lat), $(echo "$ME" | jq -r .lon)"
        echo -e "      Timezone     : $(echo "$ME" | jq -r .timezone)"
        echo -e "\n  ${CYAN}◆ Connection Flags${RESET}"
        echo "$ME" | jq -r '"      Mobile ISP : \(.mobile)   Proxy/VPN: \(.proxy)   Hosting: \(.hosting)"'
        echo -e "\n  ${CYAN}◆ Device Info (what your browser sends)${RESET}"
        UA=$(curl -s -A "Mozilla/5.0" https://api.myip.com 2>/dev/null >/dev/null; echo ok)
        echo -e "      User-Agent   : $HTTP_USER_AGENT"
        echo -e "      Device model : ${YELLOW}$ (run 'getprop ro.product.model' on Android)${RESET}"
        getprop ro.product.model 2>/dev/null | sed 's/^/      Model        : /'
        getprop ro.build.version.release 2>/dev/null | sed 's/^/      Android ver  : /'
    else
        echo -e "${RED}  [!] Could not reach IP lookup API. Check connection.${RESET}"
    fi
    echo ""
    echo -e "${PURPLE}  💡 Lesson: this is exactly the info ANY site you visit can see.${RESET}"
    echo -e "${PURPLE}     A VPN changes most of it — that's how exposure works.${RESET}"
    pause
}

# ============================================================
#  MODULE 4 — TERMUX PRO SETUP  (one-shot environment installer)
# ============================================================
termux_setup() {
    banner
    echo -e "${WHITE}${BOLD}  MODULE 4 › TERMUX PRO SETUP${RESET}"
    hr
    echo -e "  This installs: figlet, lolcat, jq, nmap, whois, openssl, python"
    echo -e "  + ${BOLD}phonenumbers${RESET} lib + colors + a custom login banner."
    echo ""
    read -rp "  Proceed with install? [y/N]: " ANS
    [[ "$ANS" =~ ^[Yy]$ ]] || { echo -e "  ${YELLOW}Cancelled.${RESET}"; pause; return; }

    echo -e "\n${CYAN}  [*] Updating Termux packages...${RESET}"
    pkg update -y >/dev/null 2>&1 && pkg upgrade -y >/dev/null 2>&1
    echo -e "${GREEN}  [✓] Packages updated${RESET}"

    echo -e "${CYAN}  [*] Installing core tools...${RESET}"
    pkg install -y figlet lolcat jq nmap whois openssl python curl git >/dev/null 2>&1
    echo -e "${GREEN}  [✓] Core tools installed${RESET}"

    echo -e "${CYAN}  [*] Installing Python phonenumbers lib...${RESET}"
    pip install --quiet phonenumbers
    echo -e "${GREEN}  [✓] phonenumbers ready${RESET}"

    echo -e "${CYAN}  [*] Creating custom banner in .bashrc...${RESET}"
    cat >> ~/.bashrc <<'BRC'

# ---- PRO TOOLKIT banner ----
clear
echo ""
figlet -f standard "PRO TOOLKIT" 2>/dev/null | lolcat 2>/dev/null || echo "PRO TOOLKIT"
echo -e "\033[1;36m  Ethical tools only. \033[1;33mRun: bash termux-pro-toolkit.sh\033[0m"
echo ""
BRC
    echo -e "${GREEN}  [✓] Banner added (activates on next Termux launch)${RESET}"

    echo -e "\n${GREEN}${BOLD}  ✔ SETUP COMPLETE!${RESET}"
    echo -e "  Launch the toolkit anytime with:"
    echo -e "  ${WHITE}bash termux-pro-toolkit.sh${RESET}"
    pause
}

# ============================================================
#  MAIN MENU
# ============================================================
main() {
    check_deps
    while true; do
        banner
        echo -e "${WHITE}  ┌─ MAIN MENU ──────────────────────────────┐${RESET}"
        echo -e "  │  ${GREEN}1${RESET}) 🔎 Link Info Inspector        (own/authorized sites)"
        echo -e "  │  ${GREEN}2${RESET}) 📱 Phone Number Analyzer      (public numbering data)"
        echo -e "  │  ${GREEN}3${RESET}) 🕵️  My IP & Device Recon      (your own exposure)"
        echo -e "  │  ${GREEN}4${RESET}) 🛠️  Termux Pro Setup           (install everything)"
        echo -e "  │  ${GREEN}5${RESET}) 📚 Ethical Use Guide"
        echo -e "  │  ${RED}0${RESET}) Exit"
        echo -e "${WHITE}  └──────────────────────────────────────────┘${RESET}"
        echo ""
        read -rp "  Select an option [0-5]: " CHOICE
        case "$CHOICE" in
            1) link_inspector ;;
            2) phone_analyzer ;;
            3) ip_recon ;;
            4) termux_setup ;;
            5) banner
               echo -e "${WHITE}${BOLD}  ETHICAL USE GUIDE${RESET}"; hr
               echo -e "  ✅ ALLOWED: your own sites, your own numbers, your own IP,"
               echo -e "     targets with written permission, learning in labs"
               echo -e "     (TryHackMe, HackTheBox, PortSwigger Academy)."
               echo ""
               echo -e "  ❌ NOT ALLOWED: scanning/harvesting other people, tracking"
               echo -e "     someone without consent, collecting personal data covertly."
               echo -e "     In Malaysia: PDPA 2010 + CMA 1998 make that a crime."
               pause ;;
            0) echo -e "\n${GREEN}  Stay legal, stay sharp. 👋${RESET}\n"; exit 0 ;;
            *) echo -e "${RED}  Invalid option.${RESET}"; sleep 1 ;;
        esac
    done
}

main "$@"
