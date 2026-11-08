# 🌅 Sunrise

Дисклеймер

Инструмент создан исключительно для легального тестирования безопасности собственных сетей и в образовательных целях. Автор не несет ответственности за любой ущерб, причиненный использованием данного ПО.

**Sunrise** — это автономный инструмент для пентеста локальной сети прямо с Android-устройства. Работает без root-прав, использует Termux, Nmap, Exploit-DB и Metasploit Framework.

## Возможности

- Обнаружение живых хостов в подсети (Nmap).
- TCP-сканирование портов без root (`-sT --unprivileged`).
- Определение баннеров и версий сервисов (HTTP Fingerprinting).
- Поиск чувствительных путей (`/.env`, `/.git/HEAD`, `/admin` и др.).
- Автоматический поиск эксплойтов в Exploit-DB (`searchsploit`).
- Интеграция с Metasploit Framework через RPC.
- Генерация красивого HTML-отчета (Dark Theme, GitHub-style) с фильтрами по уровню критичности.
- Автоматический запуск по триггеру (Wi-Fi) через MacroDroid + Termux:Tasker.

## Требования

- Android 7.0+
- [Termux](https://f-droid.org/packages/com.termux/) (F-Droid)
- Termux:API, Termux:Tasker
- Установленный Nmap, Python, Ruby, PostgreSQL, Metasploit Framework
- Установленный `searchsploit`

## Установка

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/ВАШ_НИК/sunrise.git
   cd sunrise```
2. Установите зависимости для Python:
```
 pip install pymetasploit3
```
Сделайте скрипты исполняемыми:

```
 chmod +x sunrise.sh sunrise_msf.py
```
3. Использование

Запуск сканирования всей сети (автоопределение подсети):
bash
```
./sunrise.sh
```
Запуск сканирования конкретной подсети:
bash
```
./sunrise.sh 192.168.0.0/24
```
Глубокое сканирование (все 65535 портов, медленно):
bash
```
./sunrise.sh 192.168.0.0/24 deep
```
Результаты сохраняются в ~/pentest_results/. HTML-отчет автоматически открывается в браузере через локальный сервер.
