# infotecs_script
Script for automation analyze of network traffic and detect C2 exploitation with Zeek and RITA framework

# Описание

Cкрипт main.py генерирует белый список доменов на базе репозитория [AdGuard](https://github.com/AdguardTeam/AdGuardHome/blob/master/client/src/helpers/trackers/trackers.json).

# Структурная схема
```mermaid
graph TD;
    A[Запуск скрипта] -->|Загрузка JSON| B[Извлечение нужных записей];
    B --> |Поиск совпадении в секции trackerDomains| C[Список доменов];
    C --> |Резолв DNS| D[Список IP-адресов];
    D --> |Очистка дубликатов| E[Получение AS для IP-адресов];
    E --> |Очистка дубликатов| F[Получение пулов IP для каждой AS];
    F --> G[Файл results.txt];
```

Необходимый тип записей определяется в [данной строке](https://github.com/wellafl3x/infotecs_TI_automation/blob/main/main.py#L20) в соответствии с секцией [trackers](https://github.com/AdguardTeam/AdGuardHome/blob/master/client/src/helpers/trackers/trackers.json#L3).
