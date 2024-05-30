import ipaddress
import re
import pymongo
import argparse

# __parse func provides parsing of ET log files and write to dict external IPs and highest threat priority
def __parse(file_path):
    ip_pattern = r"((([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])[ (\[]?(\.|dot)[ )\]]?){3}([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5]))"
    priority_pattern = r"\[Priority: (\d+)\]"
    internal_subnet = "192.168.0.0/16"
    duck = {}

    with open(file_path, 'r') as file:
        for line in file:
            priority_match = re.search(priority_pattern, line)
            priority_value = priority_match.group(1)
            ips = [match[0] for match in re.findall(ip_pattern, line) if ipaddress.ip_address(match[0]) not in ipaddress.ip_network(internal_subnet)]
            for ip in ips:
                if ip in duck:
                    if priority_value < duck[ip]:
                        duck[ip] = priority_value
                else:
                    duck[ip] = priority_value    
    return duck
                 
def __duration_to_score_correlation(db_name, dbhost):
    client = pymongo.MongoClient(f"mongodb://{dbhost}:27017/")
    db = client[db_name]
    collections = db.list_collection_names()
    max_dur = float()
    for col_name in collections:
        if "uconn" in col_name:
            collection = db[col_name]
            for document in collection.find():
                if "tdur" in document:
                    max_dur = max(max_dur, document["tdur"])
    max_dur = round(max_dur, 3)
    print (max_dur)
    for col_name in collections:
        if "uconn" in col_name:
            collection = db[col_name]
            for document in collection.find():
                if "tdur" in document:
                    res = round(document["tdur"] / max_dur, 3)
                    collection.update_one({"_id": document["_id"]}, {"$set": {"tdur": res}})

def __change_scores(db_name, dbhost, ip_address, priority):
    client = pymongo.MongoClient(f"mongodb://{dbhost}:27017/")
    db = client[db_name]

    collections = db.list_collection_names()    

    for col_name in collections:
        collection = db[col_name]
        documents = collection.find({ "dst": f"{ip_address}" })
        documents_list = list(documents)
        if documents_list:
            for document in collection.find({ "dst": f"{ip_address}" }):
                if "score" in document:
                    # результат алгоритма в переменную new_value
                    new_value = priority + 1
                    collection.update_one({"_id": document["_id"]}, {"$set": {"score": new_value}}) 
                if "tdur" in document:
                    # результат алгоритма в переменную new_value
                    new_value = priority + 1 
                    collection.update_one({"_id": document["_id"]}, {"$set": {"tdur": new_value}})



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, help="Choose which db you want to modify")
    parser.add_argument("--dbhost", required=True, help="Provides an IP address to DB host")
    args = parser.parse_args()
    file_path = "./ET.log" # change
    result = __parse(file_path)
    __duration_to_score_correlation(args.database, args.dbhost)
    for ip_address in result.keys():
        priority = result[ip_address]
        __change_scores(args.database, args.dbhost, ip_address, priority)

if __name__ == '__main__':
    main()