#!/usr/bin/env python3
import sys
import subprocess
import time
from pymetasploit3.msfrpc import MsfRpcClient

RPC_PASSWORD = "termux_msf_pass"
RPC_PORT = 55553

def start_rpc():
    # Пытаемся подключиться к уже запущенному серверу
    try:
        return MsfRpcClient(RPC_PASSWORD, port=RPC_PORT, ssl=False)
    except:
        pass
    
    print("[*] Запускаю RPC-сервер Metasploit...")
    # Запускаем в фоне
    subprocess.Popen(["msfrpcd", "-P", RPC_PASSWORD, "-S", "-p", str(RPC_PORT)], 
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Ждем запуска (на Termux это может занять время)
    time.sleep(10)
    try:
        return MsfRpcClient(RPC_PASSWORD, port=RPC_PORT, ssl=False)
    except Exception as e:
        print(f"[!] Ошибка RPC: {e}")
        return None

def main():
    if len(sys.argv) < 3:
        print("Usage: msf_search.py <IP> <TERM1,TERM2,...>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    terms = sys.argv[2].split(',')
    
    client = start_rpc()
    if not client:
        sys.exit(1)
        
    seen_modules = set()
    
    for term in terms:
        term = term.strip()
        if len(term) < 3: continue
        
        print(f"[*] Metasploit search: {term}")
        try:
            # Ищем модули
            res = client.modules.search(term)
            for mod in res:
                if mod.get('type') == 'exploit':
                    fullname = mod.get('fullname')
                    if fullname in seen_modules:
                        continue
                    seen_modules.add(fullname)
                    rank = mod.get('rank', 'normal')
                    
                    # Выводим в формате TSV для нашего Bash-скрипта
                    print(f"finding\t{target_ip}\t-\tinfo\tMSF: {fullname} (Rank: {rank})")
        except Exception as e:
            print(f"[!] Ошибка поиска '{term}': {e}")

if __name__ == "__main__":
    main()
