import os
import json
import urllib.request
import ipaddress
import collections
from concurrent.futures import ThreadPoolExecutor
import router_pb2
from common import (
    parse_json_source_geoip, parse_json_source_geosite,
    parse_lst_source_geoip, parse_lst_source_geosite,
    get_item_key
)

OUTPUT_DIR = "parser-tmp"

def get_safe_name(url):
    import hashlib
    base = url.split('/')[-1].split('.')[0] or 'source'
    hash_part = hashlib.md5(url.encode()).hexdigest()[:8]
    return f"{base}_{hash_part}"

def download_data(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    except Exception as e:
        print(f"❌ Ошибка загрузки {url}: {e}")
        return None

def process_source(source, is_geoip):
    url = source['url']
    print(f"Обработка источника: {url}")

    data_bytes = download_data(url)
    if data_bytes is None:
        return

    url_lower = url.lower()
    folder_name = get_safe_name(url)
    target_folder = os.path.join(OUTPUT_DIR, folder_name)
    os.makedirs(target_folder, exist_ok=True)

    if url_lower.endswith('.json'):
        try:
            data = json.loads(data_bytes.decode('utf-8'))
        except Exception as e:
            print(f"❌ Ошибка парсинга JSON {url}: {e}")
            return
        for rule in source['rules']:
            src_cats = {c.upper() for c in rule['src']}
            dst_cat = rule['dst'].upper()
            if is_geoip:
                items_with_cat = parse_json_source_geoip(data, src_cats)
                items = [i for i, _ in items_with_cat]
            else:
                items_with_cat = parse_json_source_geosite(data, src_cats)
                items = [i for i, _ in items_with_cat]
            write_lst_file(target_folder, dst_cat, items, is_geoip)

    elif url_lower.endswith('.lst') or url_lower.endswith('.txt'):
        data_str = data_bytes.decode('utf-8', errors='ignore')
        for rule in source['rules']:
            dst_cat = rule['dst'].upper()
            if is_geoip:
                items = parse_lst_source_geoip(data_str)
            else:
                items = parse_lst_source_geosite(data_str)
            write_lst_file(target_folder, dst_cat, items, is_geoip)

    else:  # .dat
        try:
            if is_geoip:
                parsed = router_pb2.GeoIPList.FromString(data_bytes)
                attr_name = "cidr"
            else:
                parsed = router_pb2.GeoSiteList.FromString(data_bytes)
                attr_name = "domain"
        except Exception as e:
            print(f"❌ Ошибка распаковки protobuf {url}: {e}")
            return

        for rule in source['rules']:
            src_cats = {c.upper() for c in rule['src']}
            dst_cat = rule['dst'].upper()
            items = []
            for entry in parsed.entry:
                current_cat = entry.country_code.upper()
                if "*" in src_cats or current_cat in src_cats:
                    items.extend(getattr(entry, attr_name))
            write_lst_file(target_folder, dst_cat, items, is_geoip)

def write_lst_file(folder, category, items, is_geoip):
    if not items:
        print(f"  ⚠️ Категория {category} пуста, файл не создан.")
        return
    safe_name = "".join([c for c in category if c.isalpha() or c.isdigit() or c in ('-', '_')]).rstrip()
    filename = f"{safe_name}.lst"
    filepath = os.path.join(folder, filename)

    lines = []
    for item in items:
        if is_geoip:
            try:
                addr = ipaddress.ip_address(item.ip)
                lines.append(f"{addr}/{item.prefix}")
            except Exception:
                lines.append(f"INVALID_IP/{item.prefix}")
        else:
            type_map = {0: "keyword", 1: "regex", 2: "domain", 3: "full"}
            prefix = type_map.get(item.type, "unknown")
            lines.append(f"{prefix}:{item.value}" if prefix != "unknown" else item.value)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  ✅ Создан {filename} ({len(lines)} элементов)")

def main():
    if os.path.exists(OUTPUT_DIR):
        import shutil
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    config_path = "config.json"
    if not os.path.exists(config_path):
        print("❌ config.json не найден!")
        sys.exit(1)

    with open(config_path, 'r') as f:
        config = json.load(f)

    if 'geosite' in config:
        print("=== Обработка geosite ===")
        with ThreadPoolExecutor(max_workers=4) as executor:
            executor.map(lambda src: process_source(src, False), config['geosite'])

    if 'geoip' in config:
        print("=== Обработка geoip ===")
        with ThreadPoolExecutor(max_workers=4) as executor:
            executor.map(lambda src: process_source(src, True), config['geoip'])

    print("✅ Все задачи парсинга завершены.")

if __name__ == "__main__":
    import sys
    main()
