import json
import requests
import socket
import ipaddress
import urllib.request
from bs4 import BeautifulSoup
from ipwhois.net import Net
from ipwhois.asn import IPASN

url = "https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/client/src/helpers/trackers/trackers.json"
with urllib.request.urlopen(url) as urls:
    ag_list = json.load(urls)

# categories = ag_list["categories"]
trackers = ag_list["trackers"]
trackerDomains = ag_list["trackerDomains"]
ag_list.clear()
# Извлечение записей
records = []
for x in trackers:
    if trackers[x]["categoryId"] == 9 or trackers[x]["categoryId"] == 7 or trackers[x]["categoryId"] == 6:
        if trackers[x]["companyId"] is None:
            records.append(x)
        else:
            records.append(x)
            records.append(trackers[x]["companyId"])
print("Извлечено "+str(len(records))+" записей")

# Извлечение доменов
domains = []
for x in records:
    for k, v in trackerDomains.items():
        if v == x:
            domains.append(k)
records.clear()
trackers.clear()
trackerDomains.clear()
print("Получено "+str(len(domains))+" доменов")

# Разрешение доменов для получения хостов
ip = []
for x in domains:
    try:
        host = socket.gethostbyname(x)
        if not ipaddress.ip_address(host).is_private:
            ip.append(host)
    except:
        pass
print("Получено "+str(len(ip))+" IP-адресов")

# Запрос ASN для IP-адресов
asn = []
for x in ip:
    net = Net(x)
    obj = IPASN(net)
    result = obj.lookup()
    if " " in result["asn"]:
        tmp = result["asn"].split(" ")
        asn.extend(tmp)
    if result["asn"] != "NA" and not " " in result["asn"]:
        asn.append(result["asn"])
# Удаление дубликатов
asn = list(set(asn))
ip.clear()
print("IP-адресам соответствует "+str(len(asn))+" автономных систем")

# Получение пулов IP для каждой ASN
cnt = 0
session = requests.Session()
subnet_all = []
for x in asn:
    try:
        url = "https://bgp.he.net/AS" + x + "#_prefixes"
        page = session.get(url).text
        soup = BeautifulSoup(page, "html.parser")
        table = soup.find("table", {"id": "table_prefixes4"})
        for row in table.findAll("tr"):
            columns = row.findAll("td")
            if len(columns) > 0:
                pool = columns[0].get_text().strip()
                cnt += 1
                subnet_all.append(pool)
    except:
        url = "https://ip.guide/AS" + x
        print(x)
        response = requests.get(url)
        ip_pool = response.json()
        pool = ip_pool["routes"]["v4"]
        cnt += len(pool)
        subnet_all.append(pool)

with open('domains.txt', 'a') as f:
    f.writelines(f"    - {item}\n" for item in domains)
domains.clear()

with open('results.txt', 'a') as f:
    f.writelines(f"    - {item}\n" for item in subnet_all)
subnet_all.clear()
print("В файл results.txt записано "+str(cnt)+" строк.")
