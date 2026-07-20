import os
import urllib.request
import ipaddress
import collections
from concurrent.futures import ThreadPoolExecutor
import router_pb2

SOURCES = {
    "Client-Flavor-geosite": "https://github.com/bratishkadrugoimamysynishka/geogaga-client-flavor/raw/release/geosite.dat",
    "Client-Flavor-geoip": "https://github.com/bratishkadrugoimamysynishka/geogaga-client-flavor/raw/release/geoip.dat",
    "Loyalsoldier-geosite": "https://github.com/Loyalsoldier/v2ray-rules-dat/raw/release/geosite.dat",
    "Loyalsoldier-geoip": "https://github.com/Loyalsoldier/v2ray-rules-dat/raw/release/geoip.dat",
    "roscomvpn-geosite": "https://github.com/hydraponique/roscomvpn-geosite/raw/release/geosite.dat",
    "roscomvpn-geoip": "https://github.com/hydraponique/roscomvpn-geoip/raw/release/geoip.dat",
    "runetfreedom-geosite": "https://github.com/runetfreedom/russia-v2ray-rules-dat/raw/release/geosite.dat",
    "runetfreedom-geoip": "https://github.com/runetfreedom/russia-v2ray-rules-dat/raw/release/geoip.dat",
    "b4-geoip": "https://github.com/DanielLavrushin/b4geoip/releases/latest/download/geoip.dat"
}

OUTPUT_DIR = "parser-tmp"

def get_domain_type_str(d_type):
    if d_type == 0: return "ключевое_слово"
    if d_type == 1: return "регулярное_выражение"
    if d_type == 2: return "домен"
    if d_type == 3: return "полное_совпадение"
    return "неизвестно"

def format_domain(d):
    prefix = get_domain_type_str(d.type)
    return f"{prefix}:{d.value}" if prefix != "неизвестно" else d.value

def format_cidr(c):
    try:
        addr = ipaddress.ip_address(c.ip)
        return f"{addr}/{c.prefix}", "IPv4" if isinstance(addr, ipaddress.IPv4Address) else "IPv6"
    except Exception:
        return f"НЕКОРРЕКТНЫЙ_IP/{c.prefix}", "некорректный"

def process_single_source(folder_name, url):
    print(f"Запуск обработки: {folder_name}")
    
    target_folder = os.path.join(OUTPUT_DIR, folder_name)
    os.makedirs(target_folder, exist_ok=True)
    
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req) as response:
            data = response.read()
    except Exception as e:
        print(f"❌ Не удалось загрузить {folder_name}: {e}")
        return

    is_geoip = "geoip" in folder_name.lower() or "geoip" in url.lower()
    
    try:
        if is_geoip:
            parsed_list = router_pb2.GeoIPList.FromString(data)
            attr_name = "cidr"
        else:
            parsed_list = router_pb2.GeoSiteList.FromString(data)
            attr_name = "domain"
    except Exception as e:
        print(f"❌ Не удалось распарсить protobuf для {folder_name}: {e}")
        return

    total_elements = 0
    total_categories = len(parsed_list.entry)
    summary_lines = []
    
    global_type_counts = collections.Counter()

    for entry in parsed_list.entry:
        cat_name = entry.country_code
        safe_cat_name = "".join([c for c in cat_name if c.isalpha() or c.isdigit() or c in ('-', '_')]).rstrip()
        items = getattr(entry, attr_name)
        
        elements_count = len(items)
        total_elements += elements_count
        
        cat_type_counts = collections.Counter()
        lst_lines = []
        
        for item in items:
            if is_geoip:
                cidr_str, ip_type = format_cidr(item)
                lst_lines.append(cidr_str)
                cat_type_counts[ip_type] += 1
                global_type_counts[ip_type] += 1
            else:
                t_str = get_domain_type_str(item.type)
                lst_lines.append(format_domain(item))
                cat_type_counts[t_str] += 1
                global_type_counts[t_str] += 1

        type_details = ", ".join([f"{k}: {v}" for k, v in cat_type_counts.items()])
        summary_lines.append(f"- {cat_name}: {elements_count} элементов ({type_details})")
        
        lst_path = os.path.join(target_folder, f"{safe_cat_name}.lst")
        with open(lst_path, "w", encoding="utf-8") as f:
            f.write("
".join(lst_lines) + "
")

    summary_path = os.path.join(target_folder, "_summary.txt")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(f"=== СВОДКА: {folder_name} ===\n")
        f.write(f"Всего категорий: {total_categories}\n")
        f.write(f"Всего элементов: {total_elements}\n\n")
        
        f.write("Всего элементов по типам данных:\n")
        for k, v in global_type_counts.items():
            f.write(f"  {k}: {v}\n")
        f.write("\n")
        
        f.write("Детализация по категориям:\n")
        f.write("\n".join(summary_lines) + "\n")
        
    print(f"✓ Завершено: {folder_name}")

def parse_and_dump_parallel():
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(lambda item: process_single_source(*item), SOURCES.items())

if __name__ == "__main__":
    parse_and_dump_parallel()
    print("Все задачи парсинга выполнены.")
