# infotecs_TI_automation

**TODO:** *запуск из под sudo*, *установка под разные дистрибутивы*, *проблема с рваными файлами при самбе*

Этот проект включает в себя разработку автоматизированного решения по обработке множества PCAP-файлов захвата траффика с помощью привлечения Threat Intelligence. За основу взяты open-source фреймворки Zeek и RITA. 

Целью данного проекта является автоматизированные:
1. Обработка PCAP-файлов, поступающих в рабочую директорию.
2. Анализ файлов с помощью фреймворка [Zeek](https://github.com/zeek/zeek) и генерация отчетов.
3. Формирование белого списка доменов при помощи репозитория [AdGuard](https://github.com/AdguardTeam/AdGuardHome/blob/master/client/src/helpers/trackers/trackers.json)..
4. Построение отчетов в виде веб-страниц с помощью фреймворка [RITA](https://github.com/activecm/rita/tree/master).
5. Отдача отчетов через веб-сервер NGINX. 
## Описание this_script.sh

Скрипт this_script.sh аггрегирует весь процесс по установке и настройке необходимых компонентов, а также автоматизированный анализ дампов траффика и генерации отчетов в виде веб-страниц.

### Использование

Работа проекта протестирована и подходит под: Kali, Ubuntu и Debian. Временно работа скрипта возможно только из под root.

Для работы скрипта:

```
git clone https://github.com/wellafl3x/infotecs_TI_automation.git
cd infotecs_TI_automation
chmod +x ./this_script.sh
source ./vars
PATH_TO=$PWD WHITELIST=./templates/whitelists/results.txt \
DOMAINS=./templates/whitelists/domains.txt ./this_script.sh -smb \
```

Переменные PATH_TO, WHITELIST и DOMAINS служат для обозначения рабочей директории, указания на файл с белым списком IP-адресов, на файл с белым списков доменов.

Доступные флаги:

- -h --help          — Отображает справку.
- -smb --samba       - Конфигурация рабочей директории для доступа по SMB
- -g --generate      - Генерация белых списков (может занять до 15 минут, невозможно использование при явном указании черех переменные)
- --disable-zeek     — Отключает автоматическую установку Zeek
- --disable-rita     — Отключает автоматическую установку RITA
- --disable-mongo    — Отключает автоматическую установку MongoDB
- --disable-all      — Отключает автоматическую установку всех компонентов

После запуска, создаются директории PCAPS и REPORTS, согласно определенной переменной PATH_TO. При успешном выполнении подготовительных инструкций скрипт будет выполнять мониторинг директории PCAPS, куда необходимо помещать дампы траффика для анализа. При перемещении туда файлов, они автоматически будут анализироваться, а затем перемещаться по пути REPORTS/pcaps. В папке REPORTS будут находится отчеты по каждому файлу. Также, эти отчеты будут представлены через веб-сервер NGINX и доступны при обращении по 80 порту.

> ВАЖНО! Использование scp не рекомендуется из-за поточной и нецелостной передачи файлов, используйте rsync.

### Структурная схема

```mermaid
graph TD;
    A[Запуск скрипта администратором, 
    проверка на root, отображение заставки] --> B[Установка зависимостей и необходимых компонентов];
    B --> C[Создание директорий PCAPS, REPORTS, 
    временных директорий для NGINX, ZEEK];
    C -->  D[Конфигурация файлов  веб-сервера];
    D --> E[Установка Zeek, RITA, MongoDB ];
    E --> F[Мониторинг рабочей директории с помощью inotify];
    F --> |При появлении PCAP файлов| G[Автоматический анализ файлов с помощью Zeek, 
    генерация отчетов Zeek в /tmp];
    G --> H[На основе отчетов Zeek генерация отчетов RITA
    с применением фильтрации белых списков];
    H --> I[Вывод отчетов через веб-сервер NGINX]
    I --> F;

```
При наличии определенных флагов некоторые из описанных этапов могут быть пропущены.

## Описание main.py

Cкрипт main.py генерирует белый список доменов на базе репозитория [AdGuard](https://github.com/AdguardTeam/AdGuardHome/blob/master/client/src/helpers/trackers/trackers.json).

### Структурная схема
```mermaid
graph TD;
    A[Запуск скрипта] -->|Загрузка JSON| B[Извлечение нужных записей];
    B --> |Поиск совпадении в секции trackerDomains| C[Список доменов];
    C --> |Резолв DNS| D[Список IP-адресов];
    D --> |Очистка дубликатов| E[Получение AS для IP-адресов];
    E --> |Очистка дубликатов| F[Получение пулов IP для каждой AS];
    F --> G[Файл results.txt];
    C --> H[Файл domains.txt];
```

Необходимый тип записей определяется в [данной строке](https://github.com/wellafl3x/infotecs_TI_automation/blob/main/main.py#L20) в соответствии с секцией [trackers](https://github.com/AdguardTeam/AdGuardHome/blob/master/client/src/helpers/trackers/trackers.json#L3).
