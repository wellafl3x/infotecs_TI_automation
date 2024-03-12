import json
import requests
import socket
import ipaddress
import urllib.request
from lxml import html
from bs4 import BeautifulSoup

url = "https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/client/src/helpers/trackers/trackers.json"
with urllib.request.urlopen(url) as urls:
    ag_list = json.load(urls)

#categories = ag_list["categories"]
trackers = ag_list["trackers"]
trackerDomains = ag_list["trackerDomains"]
ag_list.clear()
# Извлечение записей
records = []
for x in trackers:
    if trackers[x]["categoryId"] == 9:
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
    except:
        pass
    if not ipaddress.ip_address(host).is_private:
        ip.append(host)
domains.clear()
print("Получено "+str(len(ip))+" IP-адресов")

# Запрос ASN для IP-адресов
asn = []
session = requests.Session()
for x in ip:
    url = "https://bgp.he.net/ip/"+x
    response = session.get(url)
    asnum = html.fromstring(response.text)
    result = asnum.xpath("/html/body/div/div[2]/div[2]/div[2]/table/tbody/tr/td[1]/a")
    asn.append(result[0].text)
# Удаление дубликатов
asn = list(set(asn))
ip.clear()
print("IP-адресам соответствует "+str(len(asn))+" автономных систем")

# Получение пулов IP для каждой ASN
f = open("results.txt", "a")
cnt = 0
for x in asn:
    url = "https://bgp.he.net/"+x+"#_prefixes"
    page = session.get(url).text
    soup = BeautifulSoup(page, "html.parser")
    table = soup.find("table", {"id":"table_prefixes4"})
    for row in table.findAll("tr"):
        columns = row.findAll("td")
        if len(columns) > 0:
            pool = columns[0].get_text().strip()
            f.write("   - "+pool+"\n")
            cnt += 1
print("В файл results.txt записано "+str(cnt)+" строк.")
