import sys
import json
import urllib.request
import collections
import ipaddress
import os
from concurrent.futures import ThreadPoolExecutor
import router_pb2
from common import (
    log_to_review, get_item_key, get_item_display_str,
    parse_json_source_geoip, parse_json_source_geosite,
    parse_lst_source_geoip, parse_lst_source_geosite,
    optimize_domains, optimize_ips,
    filter_and_log_geoip_items,
    parse_exclude_list, check_exclusions
)

def download_and_parse(source, list_class):
    print(f"Загрузка: {source['url']}")
    try:
        req = urllib.request.Request(source['url'], headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
            data = response.read()

        url_lower = source['url'].lower()
        if url_lower.endswith('.json'):
            return source, json.loads(data.decode('utf-8'))
        elif url_lower.endswith('.lst') or url_lower.endswith('.txt'):
            return source, data.decode('utf-8')
        else:
            parsed_list = list_class.FromString(data)
            return source, parsed_list
    except Exception as e:
        msg = f"Ошибка загрузки или обработки источника {source['url']}: {e}"
        print(f"❌ {msg}")
        log_to_review(f"[ОШИБКА ЗАГРУЗКИ] {msg}")
        return source, None

def process_dat(config, list_class, attr_name):
    category_items = collections.defaultdict(list)

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda src: download_and_parse(src, list_class), config))

    upstream_keys_map = collections.defaultdict(list)
    for source, parsed_data in results:
        if parsed_data is None or "custom-additions" in source['url']:
            continue

        url_lower = source['url'].lower()
        if url_lower.endswith('.json'):
            for rule in source['rules']:
                src_cats = {c.upper() for c in rule['src']}
                fetched = parse_json_source_geoip(parsed_data, src_cats) if attr_name == "cidr" else parse_json_source_geosite(parsed_data, src_cats)
                for item, cat in fetched:
                    k = get_item_key(item, attr_name)
                    upstream_keys_map[k].append((source['url'], cat))
        elif url_lower.endswith('.lst') or url_lower.endswith('.txt'):
            fetched = parse_lst_source_geoip(parsed_data) if attr_name == "cidr" else parse_lst_source_geosite(parsed_data)
            for item in fetched:
                k = get_item_key(item, attr_name)
                upstream_keys_map[k].append((source['url'], "RAW_LST"))
        else:
            for rule in source['rules']:
                src_cats = {c.upper() for c in rule['src']}
                for entry in parsed_data.entry:
                    current_cat = entry.country_code.upper()
                    if "*" in src_cats or current_cat in src_cats:
                        for item in getattr(entry, attr_name):
                            k = get_item_key(item, attr_name)
                            upstream_keys_map[k].append((source['url'], current_cat))

    for source, parsed_data in results:
        if parsed_data is None:
            continue

        url = source['url']
        url_lower = url.lower()
        is_custom = "custom-additions" in url

        if url_lower.endswith('.json'):
            if attr_name == "cidr":
                # Обработка geoip с новой фильтрацией (только CIDR и ASN)
                for rule in source['rules']:
                    src_cats = {c.upper() for c in rule['src']}
                    dst_cat = rule['dst'].upper()
                    exclude_list = rule.get('exclude', [])

                    fetched = parse_json_source_geoip(parsed_data, src_cats)
                    filtered_items = filter_and_log_geoip_items(
                        fetched, exclude_list, url, rule['src'], dst_cat
                    )

                    category_items[dst_cat].extend(filtered_items)
                    print(f"[СБОРЩИК] Интегрировано {len(filtered_items)} IP-префиксов в категорию {dst_cat} из JSON")
                    if is_custom:
                        check_and_log_duplicates(filtered_items, url, attr_name, upstream_keys_map)
            else:
                # geosite (домены)
                for rule in source['rules']:
                    src_cats = {c.upper() for c in rule['src']}
                    dst_cat = rule['dst'].upper()
                    exclude_keys = parse_exclude_list(rule.get('exclude', []), attr_name)

                    fetched = parse_json_source_geosite(parsed_data, src_cats)
                    all_items = [i for i, _ in fetched]
                    all_keys = {get_item_key(item, attr_name) for item in all_items}
                    check_exclusions(exclude_keys, all_keys, url, rule.get('dst'), rule.get('src'), attr_name)
                    items = [item for item in all_items if get_item_key(item, attr_name) not in exclude_keys]
                    category_items[dst_cat].extend(items)
                    print(f"[СБОРЩИК] Интегрировано {len(items)} правил в категорию {dst_cat} из JSON")
                    if is_custom:
                        check_and_log_duplicates(items, url, attr_name, upstream_keys_map)

        elif url_lower.endswith('.lst') or url_lower.endswith('.txt'):
            for rule in source['rules']:
                dst_cat = rule['dst'].upper()
                exclude_keys = parse_exclude_list(rule.get('exclude', []), attr_name)

                if attr_name == "cidr":
                    all_items = parse_lst_source_geoip(parsed_data)
                else:
                    all_items = parse_lst_source_geosite(parsed_data)

                all_keys = {get_item_key(item, attr_name) for item in all_items}
                check_exclusions(exclude_keys, all_keys, url, rule.get('dst'), rule.get('src'), attr_name)
                items = [item for item in all_items if get_item_key(item, attr_name) not in exclude_keys]
                category_items[dst_cat].extend(items)
                print(f"[СБОРЩИК] Интегрировано {len(items)} элементов в категорию {dst_cat} из LST")
                if is_custom:
                    check_and_log_duplicates(items, url, attr_name, upstream_keys_map)

        else:  # .dat
            for rule in source['rules']:
                src_cats = {c.upper() for c in rule['src']}
                dst_cat = rule['dst'].upper()
                exclude_keys = parse_exclude_list(rule.get('exclude', []), attr_name)

                all_items = []
                for entry in parsed_data.entry:
                    current_cat = entry.country_code.upper()
                    if "*" in src_cats or current_cat in src_cats:
                        target = current_cat if dst_cat == "*" else dst_cat
                        all_items.extend(getattr(entry, attr_name))

                all_keys = {get_item_key(item, attr_name) for item in all_items}
                check_exclusions(exclude_keys, all_keys, url, rule.get('dst'), rule.get('src'), attr_name)
                items = [item for item in all_items if get_item_key(item, attr_name) not in exclude_keys]
                category_items[target].extend(items)
                if is_custom:
                    check_and_log_duplicates(items, url, attr_name, upstream_keys_map)

    out_list = list_class()
    for cat, items in category_items.items():
        entry = out_list.entry.add()
        entry.country_code = cat.upper()
        target_list = getattr(entry, attr_name)

        if cat.upper().startswith("GEOGAGA-"):
            optimized_items = optimize_domains(items) if attr_name == "domain" else optimize_ips(items)
            target_list.extend(optimized_items)
        else:
            seen = set()
            for item in items:
                s = item.SerializeToString()
                if s not in seen:
                    seen.add(s)
                    target_list.append(item)

    return out_list

def check_and_log_duplicates(items, url, attr_name, upstream_map):
    for item in items:
        k = get_item_key(item, attr_name)
        if k in upstream_map:
            url_to_cats = collections.defaultdict(set)
            for up_url, up_cat in upstream_map[k]:
                url_to_cats[up_url].add(up_cat)

            upstream_lines = []
            for up_url in sorted(url_to_cats.keys()):
                cats_str = ", ".join(sorted(list(url_to_cats[up_url])))
                upstream_lines.append(f"    • {up_url} [Категории: {cats_str}]")

            upstream_str = "\n".join(upstream_lines)

            msg = (
                f"[ДУБЛИКАТ ОБНАРУЖЕН]\n"
                f"  Кастомный источник : {url}\n"
                f"  Элемент            : {get_item_display_str(item, attr_name)}\n"
                f"  Апстрим-источники  :\n{upstream_str}\n"
                f"{'-'*70}"
            )
            log_to_review(msg)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python builder.py config.json")
        sys.exit(1)

    os.makedirs("tools", exist_ok=True)
    with open("tools/review.log", "w", encoding="utf-8") as f:
        f.write("")

    with open(sys.argv[1], 'r') as f:
        config = json.load(f)

    if 'geosite' in config:
        geosite = process_dat(config['geosite'], router_pb2.GeoSiteList, "domain")
        with open("geosite.dat", "wb") as f:
            f.write(geosite.SerializeToString())
        print("[УСПЕХ] Файл geosite.dat успешно сгенерирован.")

    if 'geoip' in config:
        geoip = process_dat(config['geoip'], router_pb2.GeoIPList, "cidr")
        with open("geoip.dat", "wb") as f:
            f.write(geoip.SerializeToString())
        print("[УСПЕХ] Файл geoip.dat успешно сгенерирован.")

    print("Сборка успешно завершена.")
