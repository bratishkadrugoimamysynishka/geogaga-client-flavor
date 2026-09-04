import os
import sys
import json
import urllib.request
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
import router_pb2
from common import (
    parse_json_source_geoip, parse_json_source_geosite,
    parse_lst_source_geoip, parse_lst_source_geosite,
    get_item_key, fetch_asn
)

OUTPUT_DIR = "parser-tmp"

def download_file(url, dest):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=60) as resp:
            with open(dest, 'wb') as f:
                f.write(resp.read())
        return dest
    except Exception as e:
        print(f"❌ Ошибка скачивания {url}: {e}")
        return None

def get_repo_name(url):
    match = re.search(r'github\.com/([^/]+/[^/]+)', url)
    return match.group(1) if match else None

def get_folder_name(url, is_geoip):
    repo = get_repo_name(url)
    if repo:
        suffix = 'geoip' if is_geoip else 'geosite'
        return f"{repo.replace('/', '-')}-{suffix}"
    parts = url.split('/')
    name = parts[-1].split('.')[0] if parts else 'unknown'
    return f"{name}-{'geoip' if is_geoip else 'geosite'}"

def download_data(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    except Exception as e:
        print(f"❌ Ошибка загрузки {url}: {e}")
        return None

def write_lst_file(folder, category, items, is_geoip):
    if not items:
        print(f"  ⚠️ Категория {category} пуста, файл не создан.")
        return
    safe_name = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in category.upper())
    filename = f"{safe_name}.LST"
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

def process_dat(data_bytes, is_geoip, target_folder):
    try:
        if is_geoip:
            parsed = router_pb2.GeoIPList.FromString(data_bytes)
            attr = 'cidr'
        else:
            parsed = router_pb2.GeoSiteList.FromString(data_bytes)
            attr = 'domain'
    except Exception as e:
        print(f"❌ Ошибка распаковки protobuf: {e}")
        return

    for entry in parsed.entry:
        country = entry.country_code.upper()
        if not country:
            continue
        items = getattr(entry, attr)
        if not items:
            continue
        write_lst_file(target_folder, country, items, is_geoip)

def process_json_geoip(data, target_folder):
    for provider, info in data.items():
        items = []
        cidrs = info.get("cidrs", []) or info.get("ips", []) or []
        for c in cidrs:
            if isinstance(c, str) and '/' in c:
                try:
                    net = ipaddress.ip_network(c.strip(), strict=False)
                    cidr_proto = router_pb2.CIDR()
                    cidr_proto.ip = net.network_address.packed
                    cidr_proto.prefix = net.prefixlen
                    items.append(cidr_proto)
                except Exception:
                    continue

        asns = info.get("asns", []) or []
        for asn in asns:
            if isinstance(asn, str):
                asn_digits = "".join(filter(str.isdigit, asn))
                if asn_digits:
                    prefixes = fetch_asn(asn_digits)
                    for p_str in prefixes:
                        try:
                            net = ipaddress.ip_network(p_str, strict=False)
                            cidr_proto = router_pb2.CIDR()
                            cidr_proto.ip = net.network_address.packed
                            cidr_proto.prefix = net.prefixlen
                            items.append(cidr_proto)
                        except Exception:
                            continue

        if items:
            write_lst_file(target_folder, provider, items, is_geoip=True)

def process_json_geosite(data, target_folder):
    type_mapping = {
        "plain": router_pb2.Domain.Plain,
        "keyword": router_pb2.Domain.Plain,
        "regex": router_pb2.Domain.Regex,
        "domain": router_pb2.Domain.Domain,
        "full": router_pb2.Domain.Full
    }

    for category, content in data.items():
        items = []
        if isinstance(content, list):
            for item in content:
                if not isinstance(item, str):
                    continue
                d_type = router_pb2.Domain.Domain
                d_value = item.strip()
                if ":" in d_value:
                    prefix, value = d_value.split(":", 1)
                    if prefix.lower() in type_mapping:
                        d_type = type_mapping[prefix.lower()]
                        d_value = value.strip()
                if d_value:
                    d_proto = router_pb2.Domain()
                    d_proto.type = d_type
                    d_proto.value = d_value
                    items.append(d_proto)
        elif isinstance(content, dict):
            for t_key, v_list in content.items():
                if t_key.lower() in type_mapping and isinstance(v_list, list):
                    d_type = type_mapping[t_key.lower()]
                    for item in v_list:
                        if isinstance(item, str) and item.strip():
                            d_proto = router_pb2.Domain()
                            d_proto.type = d_type
                            d_proto.value = item.strip()
                            items.append(d_proto)

        if items:
            write_lst_file(target_folder, category, items, is_geoip=False)

def process_source(source, is_geoip):
    url = source['url']
    if "custom-additions" in url:
        print(f"⏩ Пропускаем custom-additions: {url}")
        return

    print(f"Обработка источника: {url}")
    data_bytes = download_data(url)
    if data_bytes is None:
        return

    folder_name = get_folder_name(url, is_geoip)
    target_folder = os.path.join(OUTPUT_DIR, folder_name)
    os.makedirs(target_folder, exist_ok=True)

    url_lower = url.lower()
    if url_lower.endswith('.json'):
        try:
            data = json.loads(data_bytes.decode('utf-8'))
        except Exception as e:
            print(f"❌ Ошибка парсинга JSON {url}: {e}")
            return

        if is_geoip:
            process_json_geoip(data, target_folder)
        else:
            process_json_geosite(data, target_folder)

    elif url_lower.endswith('.lst') or url_lower.endswith('.txt'):
        data_str = data_bytes.decode('utf-8', errors='ignore')
        if is_geoip:
            items = parse_lst_source_geoip(data_str)
        else:
            items = parse_lst_source_geosite(data_str)
        write_lst_file(target_folder, "all", items, is_geoip)

    else:
        process_dat(data_bytes, is_geoip, target_folder)

def parse_geogaga_dat(filepath, is_geoip):
    with open(filepath, 'rb') as f:
        data = f.read()
    if is_geoip:
        parsed = router_pb2.GeoIPList.FromString(data)
        attr = 'cidr'
    else:
        parsed = router_pb2.GeoSiteList.FromString(data)
        attr = 'domain'

    folder = 'geogaga-client-flavor-geosite' if not is_geoip else 'geogaga-client-flavor-geoip'
    target_folder = os.path.join(OUTPUT_DIR, folder)
    os.makedirs(target_folder, exist_ok=True)

    for entry in parsed.entry:
        country = entry.country_code.upper()
        if not country:
            continue
        items = getattr(entry, attr)
        if not items:
            continue
        write_lst_file(target_folder, country, items, is_geoip)

def process_geogaga_dat():
    branch = os.environ.get('GITHUB_REF_NAME', '')
    geosite_path = None
    geoip_path = None

    if branch == 'main':
        print("🔍 Ветка main: скачиваем geodata из release...")
        geosite_path = download_file(
            'https://raw.githubusercontent.com/bratishkadrugoimamysynishka/geogaga-client-flavor/release/geosite.dat',
            'geosite_release.dat'
        )
        geoip_path = download_file(
            'https://raw.githubusercontent.com/bratishkadrugoimamysynishka/geogaga-client-flavor/release/geoip.dat',
            'geoip_release.dat'
        )
    elif branch == 'test':
        print("🔍 Ветка test: берём geodata из result/...")
        if os.path.exists('result/geosite.dat'):
            geosite_path = 'result/geosite.dat'
        if os.path.exists('result/geoip.dat'):
            geoip_path = 'result/geoip.dat'
    else:
        print("🔍 Неизвестная ветка или ручной запуск: ищем geodata в текущей папке...")
        if os.path.exists('geosite.dat'):
            geosite_path = 'geosite.dat'
        if os.path.exists('geoip.dat'):
            geoip_path = 'geoip.dat'

    if geosite_path:
        print("🔄 Обработка geogaga geosite.dat...")
        parse_geogaga_dat(geosite_path, is_geoip=False)
    else:
        print("⚠️ geosite.dat не найден, пропускаем.")

    if geoip_path:
        print("🔄 Обработка geogaga geoip.dat...")
        parse_geogaga_dat(geoip_path, is_geoip=True)
    else:
        print("⚠️ geoip.dat не найден, пропускаем.")

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

    process_geogaga_dat()

    print("✅ Все задачи парсинга завершены.")

if __name__ == "__main__":
    main()
