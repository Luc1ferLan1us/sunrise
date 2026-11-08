#!/data/data/com.termux/files/usr/bin/bash
# auto_hunt_net.sh v4 — Full Network Pentest + HTML + Metasploit
# Usage: auto_hunt_net.sh [SUBNET] [quick|deep]

set -o pipefail

MODE="${2:-quick}"
OUT_DIR="$HOME/pentest_results"
TS=$(date +%Y%m%d_%H%M%S)
mkdir -p "$OUT_DIR"

# ---------- утилиты ----------
detect_my_ip() {
    local ip
    ip=$(termux-wifi-connectioninfo 2>/dev/null | python3 -c "
import sys,json
try: print(json.load(sys.stdin).get('ip',''))
except: print('')" 2>/dev/null)
    [ -z "$ip" ] && ip=$(ip -4 addr show wlan0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
    echo "$ip"
}

SUBNET="${1:-auto}"
[ "$SUBNET" = "auto" ] && SUBNET="$(detect_my_ip | awk -F. '{print $1"."$2"."$3".0/24"}')"
if [ -z "$SUBNET" ] || [ "$SUBNET" = ".0/24" ]; then
    echo "[!] Не удалось определить подсеть. Укажи вручную: 192.168.0.0/24"
    exit 1
fi
MY_IP=$(detect_my_ip)

REPORT="$OUT_DIR/net_${TS}.txt"
RAW="$OUT_DIR/net_${TS}.tsv"
HTML_OUT="$OUT_DIR/report_${TS}.html"

: > "$REPORT"
: > "$RAW"

log() { echo "$@" | tee -a "$REPORT"; }
sep() { log "════════════════════════════════════════════════════════"; }

sep
log "=== NET PENTEST $SUBNET @ $(date '+%F %T') ==="
log "Mode: $MODE | My IP: $MY_IP"
sep

# ---------- 1. DISCOVERY ----------
log "[*] Discovery (-sn)..."
DISC="$OUT_DIR/disc_${TS}.xml"
nmap -sn --unprivileged -oX "$DISC" "$SUBNET" >/dev/null 2>&1

LIVE_IPS=$(grep -oP '<host[^>]*>\s*<status state="up".*?<address addr="\K[0-9.]+' "$DISC" 2>/dev/null | sort -u)
[ -z "$LIVE_IPS" ] && LIVE_IPS=$(grep -oP '<address addr="\K[0-9.]+' "$DISC" 2>/dev/null | sort -u)

HOST_COUNT=$(echo "$LIVE_IPS" | grep -c '.')
if [ "$HOST_COUNT" -eq 0 ]; then
    log "[!] Живых хостов нет."
    termux-notification --title "Net pentest $SUBNET" --content "Хостов нет" 2>/dev/null
    exit 0
fi
log "[+] Живых хостов: $HOST_COUNT"
sep

# ---------- 2. СКАН ----------
FAST_PORTS="21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,1521,2049,2375,2376,3000,3306,3389,5000,5173,5432,5900,5985,5986,6379,6443,8000,8008,8080,8081,8088,8432,8443,8888,9000,9050,9090,9150,9200,9443,11211,27017"

parse_xml_to_tsv() {
    local xml="$1" ip="$2"
    python3 - "$xml" "$ip" <<'PYEOF' >> "$RAW"
import sys, xml.etree.ElementTree as ET
try:
    root = ET.parse(sys.argv[1]).getroot()
except Exception:
    sys.exit(0)
ip = sys.argv[2]
for port in root.iter('port'):
    st = port.find('state')
    if st is None or st.get('state') != 'open':
        continue
    portid = port.get('portid')
    svc = port.find('service')
    name = prod = ver = ''
    if svc is not None:
        name = svc.get('name','')
        prod = svc.get('product','')
        ver = svc.get('version','')
    ver_str = (prod + ' ' + ver).strip()
    print(f"port\t{ip}\t{portid}\t{name}|{ver_str}|")
PYEOF
}

N=0; TOTAL_FINDINGS=0
for ip in $LIVE_IPS; do
    N=$((N+1))
    [ "$ip" = "$MY_IP" ] && { log ""; log "[skip] $ip — свой IP"; continue; }

    log ""
    log "[$N/$HOST_COUNT] ─── $ip ───"
    XML="$OUT_DIR/h_${ip//./_}_${TS}.xml"

    if [ "$MODE" = "deep" ]; then
        log "  [*] Глубокий (-p-)..."
        nmap -sT --unprivileged -Pn -p- --min-rate 500 -sV -oX "$XML" "$ip" >/dev/null 2>&1
    else
        log "  [*] Быстрый..."
        nmap -sT --unprivileged -Pn -p "$FAST_PORTS" --min-rate 500 -sV -oX "$XML" "$ip" >/dev/null 2>&1
    fi

    if [ ! -s "$XML" ]; then log "  [!] Nmap не справился"; continue; fi

    PORTS=$(grep -oP '<port[^>]*portid="\K[0-9]+(?="[^>]*>\s*<state[^>]*state="open")' "$XML" 2>/dev/null | sort -un)
    if [ -z "$PORTS" ]; then log "  [-] Открытых портов нет"; continue; fi
    log "  [+] Порты: $(echo "$PORTS" | tr '\n' ' ')"

    parse_xml_to_tsv "$XML" "$ip"

    # EDB по версиям из Nmap
    EDB_JSON="$OUT_DIR/edb_${ip//./_}_${TS}.json"
    searchsploit --nmap "$XML" --json > "$EDB_JSON" 2>/dev/null
    EDB_N=$(python3 -c "
import json
try: print(len(json.load(open('$EDB_JSON')).get('RESULTS_EXPLOIT',[])))
except: print(0)" 2>/dev/null)
    if [ "$EDB_N" -gt 0 ]; then
        log "  [🔥] EDB по версиям: $EDB_N совпадений"
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + EDB_N))
        python3 - "$EDB_JSON" "$ip" <<'PYEOF' >> "$RAW"
import json,sys
try: d=json.load(open(sys.argv[1]))
except: sys.exit(0)
ip=sys.argv[2]
for e in d.get('RESULTS_EXPLOIT',[])[:10]:
    title=e.get('Title','?'); path=e.get('Path','?')
    print(f"finding\t{ip}\t-\thigh\tEDB: {title}  [{path}]")
PYEOF
    fi

    # HTTP Fingerprinting
    for p in $PORTS; do
        HEADERS=$(curl -s -m 4 -k -I "http://$ip:$p" 2>/dev/null)
        [ -z "$HEADERS" ] && HEADERS=$(curl -s -m 4 -k -I "https://$ip:$p" 2>/dev/null)

        if [ -z "$HEADERS" ]; then
            BANNER=$(echo "" | timeout 3 nc -w 2 "$ip" "$p" 2>/dev/null | head -1)
            if [ -n "$BANNER" ]; then
                printf 'finding\t%s\t%s\tinfo\tBanner: %s\n' "$ip" "$p" "$BANNER" >> "$RAW"
                TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
            fi
            continue
        fi

        SERVER=$(echo "$HEADERS" | awk -F': ' 'tolower($1)=="server"{print $2; exit}' | tr -d '\r')
        POWERED=$(echo "$HEADERS" | awk -F': ' 'tolower($1)=="x-powered-by"{print $2; exit}' | tr -d '\r')
        
        # EDB по токенам Server / X-Powered-By
        for tok in $(echo "$SERVER $POWERED" | tr ' /:;()' '\n\n\n\n\n\n' | grep -E '^[A-Za-z0-9._-]{3,}$' | grep -viE '^(the|and|for|with|python|debian|ubuntu|linux|http|https|server)$' | sort -u); do
            RES=$(searchsploit "$tok" 2>/dev/null | grep -E '^[A-Za-z]' | grep -viE 'Exploit Title|Shellcodes|No Results|^[-=]+$' | head -3)
            if [ -n "$RES" ]; then
                while IFS= read -r line; do
                    [ -z "$line" ] && continue
                    printf 'finding\t%s\t%s\thigh\tEDB: %s\n' "$ip" "$p" "$line" >> "$RAW"
                    TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
                done <<< "$RES"
            fi
        done

        # Проверка чувствительных путей
        PATHS="admin login api docs swagger openapi.json graphql .git/HEAD .env server-status robots.txt"
        echo "$SERVER $POWERED" | grep -qi 'werkzeug\|flask'                          && PATHS="$PATHS console __debugger__"
        echo "$SERVER $POWERED" | grep -qi 'granian\|fastapi\|uvicorn\|starlette'    && PATHS="$PATHS redoc health"

        for path in $PATHS; do
            CODE=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -k "http://$ip:$p/$path" 2>/dev/null)
            case "$CODE" in
                200)
                    case "$path" in
                        .env|.git/HEAD|console|__debugger__|admin|phpinfo.php|server-status) SEV="crit" ;;
                        login|api|docs|redoc|openapi.json|graphql|swagger) SEV="high" ;;
                        *) SEV="info" ;;
                    esac
                    printf 'finding\t%s\t%s\t%s\t/%s → 200\n' "$ip" "$p" "$SEV" "$path" >> "$RAW"
                    TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
                    ;;
                401|403)
                    if [ "$SERVER" = "nginx" ] && [ "$CODE" = "403" ]; then continue; fi
                    printf 'finding\t%s\t%s\tlow\t/%s → %s\n' "$ip" "$p" "$CODE" "$path" "$CODE" >> "$RAW"
                    TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
                    ;;
            esac
        done
    done
done

# ---------- 2.5. METASPLOIT SEARCH ----------
if command -v msfrpcd >/dev/null 2>&1; then
    sep
    log "[*] Поиск в Metasploit (может занять время)..."
    
    for ip in $(cut -f2 "$RAW" | grep -v '^-' | sort -u); do
        TERMS=$(awk -F'\t' -v ip="$ip" '
            $2==ip && $1=="port" { print $4 }
            $2==ip && $1=="finding" { print $5 }
        ' "$RAW" | grep -oiE 'CVE-[0-9]{4}-[0-9]+|apache|nginx|tomcat|openssh|werkzeug|granian|flask|fastapi' | sort -u | paste -sd, -)
        
        if [ -n "$TERMS" ]; then
            log "  [MSF] Анализ $ip по ключам: $TERMS"
            SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
            MSF_RES=$(python3 "$SCRIPT_DIR/sunrise_msf.py" "$ip" "$TERMS" 2>/dev/null)
            
            if echo "$MSF_RES" | grep -q 'MSF:'; then
                echo "$MSF_RES" >> "$RAW"
                COUNT=$(echo "$MSF_RES" | grep -c 'MSF:')
                log "    [🔥] Найдено $COUNT модулей Metasploit!"
                TOTAL_FINDINGS=$((TOTAL_FINDINGS + COUNT))
            fi
        fi
    done
fi

# ---------- 3. ИТОГ ----------
sep
log "  NET SCAN DONE. Находок: $TOTAL_FINDINGS"

# ---------- 4. РЕНДЕР HTML ----------
python3 - "$RAW" "$HTML_OUT" "$SUBNET" <<'PYEOF'
import sys, html
from collections import OrderedDict
from datetime import datetime

raw_path, out_path, subnet = sys.argv[1], sys.argv[2], sys.argv[3]
hosts = OrderedDict()
for line in open(raw_path):
    parts = line.rstrip('\n').split('\t')
    if len(parts) < 4: continue
    typ = parts[0]
    if typ == 'port':
        ip, port, data = parts[1], parts[2], parts[3]
        svc, ver, banner = (data.split('|') + ['','',''])[:3]
        hosts.setdefault(ip, {'ports': OrderedDict()})
        hosts[ip]['ports'][port] = {'service': svc, 'version': ver, 'banner': banner, 'findings': []}
    elif typ == 'finding':
        ip, port, sev, msg = parts[1], parts[2], parts[3], parts[4] if len(parts) > 4 else ''
        hosts.setdefault(ip, {'ports': OrderedDict()})
        if port == '-':
            hosts[ip].setdefault('global_findings', []).append({'sev': sev, 'msg': msg})
        else:
            hosts[ip]['ports'].setdefault(port, {'service':'','version':'','banner':'','findings':[]})
            hosts[ip]['ports'][port]['findings'].append({'sev': sev, 'msg': msg})

SEV_ORDER = {'crit': 0, 'high': 1, 'med': 2, 'low': 3, 'info': 4}
def all_findings():
    for ip, h in hosts.items():
        for gf in h.get('global_findings', []): yield gf
        for p, pd in h['ports'].items():
            for f in pd['findings']: yield f

counts = {'crit':0,'high':0,'med':0,'low':0,'info':0}
for f in all_findings(): counts[f['sev']] = counts.get(f['sev'], 0) + 1
total = sum(counts.values())
def sev_badge(sev): return f'<span class="badge badge-{sev}">{sev.upper()}</span>'

CSS = """
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--muted:#8b949e;--crit:#f85149;--high:#ffa657;--med:#d29922;--low:#79c0ff;--info:#8b949e;--ok:#3fb950;--accent:#58a6ff}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.5;padding:16px;max-width:1200px;margin:0 auto;font-size:15px}
h1{font-size:1.6em;margin-bottom:6px;color:var(--accent)}
.subtitle{color:var(--muted);font-size:.9em;margin-bottom:20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:20px 0}
.stat{background:var(--card);border:1px solid var(--border);padding:14px;border-radius:8px;text-align:center}
.stat .num{font-size:1.9em;font-weight:700;line-height:1.1}
.stat .label{color:var(--muted);font-size:.72em;text-transform:uppercase;letter-spacing:.5px;margin-top:4px}
.stat.crit .num{color:var(--crit)}.stat.high .num{color:var(--high)}.stat.med .num{color:var(--med)}.stat.total .num{color:var(--accent)}.stat.hosts .num{color:var(--ok)}
.toc{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:20px}
.toc-title{color:var(--muted);font-size:.8em;text-transform:uppercase;margin-bottom:8px}
.toc a{color:var(--accent);text-decoration:none;font-family:monospace;margin-right:14px;display:inline-block;padding:3px 0}
.host{background:var(--card);border:1px solid var(--border);border-radius:8px;margin-bottom:16px;overflow:hidden}
.host-header{display:flex;justify-content:space-between;align-items:center;padding:14px 18px;border-bottom:1px solid var(--border);background:#1c2128}
.host-ip{font-family:monospace;font-size:1.15em;color:var(--ok);font-weight:600}
.host-meta{color:var(--muted);font-size:.85em}
.host-body{padding:14px 18px}
.port{margin-bottom:12px;padding:12px;background:#0d1117;border-radius:6px;border-left:3px solid var(--border)}
.port.has-crit{border-left-color:var(--crit)}.port.has-high{border-left-color:var(--high)}
.port-header{display:flex;gap:10px;align-items:center;margin-bottom:8px;flex-wrap:wrap}
.port-num{background:var(--border);padding:2px 9px;border-radius:4px;font-family:monospace;font-weight:700;color:var(--text)}
.port-service{color:var(--low);font-weight:600;font-family:monospace}
.port-version{color:var(--muted);font-size:.85em;font-family:monospace}
.banner{font-family:monospace;font-size:.82em;color:var(--muted);padding:7px 10px;background:#161b22;border-radius:4px;margin-bottom:8px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.finding{padding:8px 12px;margin:5px 0;border-radius:4px;font-family:monospace;font-size:.87em;display:flex;gap:10px;align-items:flex-start}
.finding .badge{flex-shrink:0;font-size:.7em;padding:2px 6px;border-radius:3px;font-weight:700;letter-spacing:.5px}
.badge-crit{background:var(--crit);color:#fff}.badge-high{background:var(--high);color:#000}.badge-med{background:var(--med);color:#000}.badge-low{background:var(--low);color:#000}.badge-info{background:var(--info);color:#fff}
.finding.sev-crit{background:rgba(248,81,73,.12);color:#ffa198}.finding.sev-high{background:rgba(255,166,87,.10);color:#ffcb8a}.finding.sev-med{background:rgba(210,153,34,.10);color:#e3b341}.finding.sev-low{background:rgba(121,192,255,.08);color:var(--low)}.finding.sev-info{background:rgba(139,148,158,.08);color:var(--muted)}
.finding .msg{flex:1}
.no-ports{color:var(--muted);font-style:italic;padding:10px;text-align:center}
.footer{text-align:center;color:var(--muted);margin-top:40px;padding-top:20px;border-top:1px solid var(--border);font-size:.82em}
.filter-bar{margin-bottom:16px;display:flex;gap:8px;flex-wrap:wrap}
.filter-btn{background:var(--card);border:1px solid var(--border);color:var(--text);padding:6px 14px;border-radius:6px;cursor:pointer;font-size:.85em;font-family:inherit}
.filter-btn:hover{border-color:var(--accent)}.filter-btn.active{background:var(--accent);color:#0d1117;border-color:var(--accent);font-weight:600}
@media(max-width:600px){body{padding:10px}h1{font-size:1.3em}.stats{grid-template-columns:repeat(2,1fr)}}
"""
JS = """
function setFilter(sev){document.querySelectorAll('.filter-btn').forEach(b=>b.classList.toggle('active',b.dataset.sev===sev));document.querySelectorAll('.host').forEach(h=>{let showHost=false;h.querySelectorAll('.finding').forEach(f=>{const show=sev==='all'||f.classList.contains('sev-'+sev);f.style.display=show?'flex':'none';if(show)showHost=true;});h.style.display=showHost?'block':'none';});}
"""

P = []
P.append(f'''<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pentest Report — {html.escape(subnet)}</title><style>{CSS}</style></head><body>
<h1>🔍 Pentest Report</h1>
<div class="subtitle mono">{html.escape(subnet)} · {datetime.now().strftime("%Y-%m-%d %H:%M")} · rootless + MSF</div>
<div class="stats">
<div class="stat hosts"><div class="num">{len(hosts)}</div><div class="label">хостов</div></div>
<div class="stat crit"><div class="num">{counts["crit"]}</div><div class="label">критичных</div></div>
<div class="stat high"><div class="num">{counts["high"]}</div><div class="label">высоких</div></div>
<div class="stat total"><div class="num">{total}</div><div class="label">всего</div></div>
</div>
<div class="filter-bar">
<button class="filter-btn active" data-sev="all" onclick="setFilter('all')">Все ({total})</button>
<button class="filter-btn" data-sev="crit" onclick="setFilter('crit')">🔴 Crit ({counts["crit"]})</button>
<button class="filter-btn" data-sev="high" onclick="setFilter('high')">🟠 High ({counts["high"]})</button>
<button class="filter-btn" data-sev="info" onclick="setFilter('info')">⚪ Info ({counts["info"]})</button>
</div>''')

if hosts:
    P.append('<div class="toc"><div class="toc-title">Хосты</div>')
    for ip in hosts: P.append(f'<a href="#host-{ip.replace(".","-")}">{html.escape(ip)}</a>')
    P.append('</div>')

for ip, h in hosts.items():
    ports = h['ports']
    P.append(f'<div class="host" id="host-{ip.replace(".","-")}">')
    P.append(f'<div class="host-header"><span class="host-ip">{html.escape(ip)}</span><span class="host-meta">{len(ports)} портов</span></div>')
    P.append('<div class="host-body">')
    for gf in h.get('global_findings', []):
        P.append(f'<div class="finding sev-{gf["sev"]}">{sev_badge(gf["sev"])}<span class="msg">{html.escape(gf["msg"])}</span></div>')
    if not ports: P.append('<div class="no-ports">Открытых портов нет</div>')
    for p, pd in ports.items():
        worst = 'none'
        for f in pd['findings']:
            if SEV_ORDER[f['sev']] < SEV_ORDER.get(worst, 99): worst = f['sev']
        cls = 'has-crit' if worst == 'crit' else ('has-high' if worst == 'high' else '')
        P.append(f'<div class="port {cls}"><div class="port-header">')
        P.append(f'<span class="port-num">{html.escape(p)}</span>')
        if pd['service']: P.append(f'<span class="port-service">{html.escape(pd["service"])}</span>')
        if pd['version']: P.append(f'<span class="port-version">{html.escape(pd["version"])}</span>')
        P.append('</div>')
        if pd['banner']: P.append(f'<div class="banner">{html.escape(pd["banner"])}</div>')
        for f in sorted(pd['findings'], key=lambda x: SEV_ORDER.get(x['sev'], 99)):
            P.append(f'<div class="finding sev-{f["sev"]}">{sev_badge(f["sev"])}<span class="msg">{html.escape(f["msg"])}</span></div>')
        P.append('</div>')
    P.append('</div></div>')

P.append(f'<div class="footer">Auto-generated · {html.escape(subnet)} · {datetime.now().isoformat(timespec="seconds")}</div>')
P.append(f'<script>{JS}</script></body></html>')
open(out_path, 'w', encoding='utf-8').write('\n'.join(P))
PYEOF

# ---------- 5. АВТО-ОТКРЫТИЕ ----------
if [ -f "$HTML_OUT" ]; then
    pkill -f "http.server 8080" 2>/dev/null
    sleep 0.5
    (cd "$OUT_DIR" && nohup python3 -m http.server 8080 >/dev/null 2>&1 &)
    sleep 1.5
    URL="http://127.0.0.1:8080/$(basename "$HTML_OUT")"
    termux-open-url "$URL" 2>/dev/null || am start -a android.intent.action.VIEW -d "$URL" 2>/dev/null || log "[!] Открой вручную: $URL"
fi

termux-notification --title "🔥 $SUBNET: $TOTAL_FINDINGS находок" --content "Отчёт готов" --priority high 2>/dev/null
exit 0
