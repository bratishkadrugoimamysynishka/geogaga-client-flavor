import sys
import json
import urllib.request
import collections
import ipaddress
import os
from concurrent.futures import ThreadPoolExecutor
import router_pb2

def log_to_review(message):
    os.makedirs("tools", exist_ok=True)
    with open("tools/review.log", "a", encoding="utf-8") as f:
        f.write(message + "\n")

def get_item_key(item, attr_name):
    if attr_name == "domain":
        return (item.type, item.value)
    return (item.ip, item.prefix)

def get_item_display_str(item, attr_name):
    if attr_name == "domain":
        type_str = {0: "keyword", 1: "regex", 2: "domain", 3: "full"}.get(item.type, str(item.type))
        return f"[{type_str}] {item.value}"
    else:
        try:
            addr = ipaddress.ip_address(item.ip)
            return f"{addr}/{item.prefix}"
        except Exception:
            return f"неизвестно/{item.prefix}"

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

def optimize_domains(domains_list):
    dom_map = {}
    full_map = {}
    plains = []
    regexes = []
    others = []

    for d in domains_list:
        if d.type == 0: 
            plains.append(d)
        elif d.type == 1: 
            regexes.append(d)
        elif d.type == 2:
            if d.value not in dom_map or len(d.attribute) > len(dom_map[d.value].attribute):
                dom_map[d.value] = d
        elif d.type == 3:
            if d.value not in full_map or len(d.attribute) > len(full_map[d.value].attribute):
                full_map[d.value] = d
        else:
            others.append(d)

    plain_values = [p.value for p in plains]

    final_doms = set()
    sorted_dom_keys = sorted(dom_map.keys(), key=len)
    
    for d_val in sorted_dom_keys:
        parts = d_val.split('.')
        is_subdomain = False
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in final_doms:
                is_subdomain = True
                break
                
        if is_subdomain:
            continue

        if any(p_val in d_val for p_val in plain_values):
            continue

        final_doms.add(d_val)

    final_fulls = set()
    for f_val in full_map.keys():
        parts = f_val.split('.')
        
        is_covered_by_domain = False
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
            if parent in final_doms:
                is_covered_by_domain = True
                break
                
        if is_covered_by_domain:
            continue

        if any(p_val in f_val for p_val in plain_values):
            continue

        final_fulls.add(f_val)

    optimized = []
    optimized.extend(plains)
    optimized.extend(regexes)
    for d_val in final_doms: 
        optimized.append(dom_map[d_val])
    for f_val in final_fulls: 
        optimized.append(full_map[f_val])
    optimized.extend(others)
    
    return optimized

def optimize_ips(cidr_list):
    ipv4_nets = []
    ipv6_nets = []
    for c in cidr_list:
        try:
            addr = ipaddress.ip_address(c.ip)
            net = ipaddress.ip_network(f"{addr}/{c.prefix}", strict=False)
            if isinstance(net, ipaddress.IPv4Network): 
                ipv4_nets.append(net)
            else: 
                ipv6_nets.append(net)
        except Exception:
            pass
            
    opt_v4 = list(ipaddress.collapse_addresses(ipv4_nets))
    opt_v6 = list(ipaddress.collapse_addresses(ipv6_nets))

    optimized = []
    for net in opt_v4 + opt_v6:
        c = router_pb2.CIDR()
        c.ip = net.network_address.packed
        c.prefix = net.prefixlen
        optimized.append(c)
    return optimized

def fetch_asn_prefixes(all_asns):
    def fetch_asn(asn):
        prefixes = []
        asn_url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        try:
            req = urllib.request.Request(asn_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as resp:
                res_data = json.loads(resp.read().decode('utf-8'))
                for item in res_data.get("data", {}).get("prefixes", []):
                    p = item.get("prefix")
                    if p:
                        prefixes.append(p)
        except Exception as e:
            msg = f"Предупреждение при получении данных для AS{asn}: {e}"
            print(f"⚠️ {msg}")
            log_to_review(f"[ОШИБКА RIPE] {msg}")
        return prefixes

    all_cidrs = set()
    if all_asns:
        print(f"[АСН-РЕЗОЛВЕР] Найдено {len(all_asns)} ASN для обработки. Запуск резолва через RIPE...")
        with ThreadPoolExecutor(max_workers=15) as executor:
            for chunk in executor.map(fetch_asn, all_asns):
                all_cidrs.update(chunk)
    return all_cidrs

def parse_json_source_geoip(data, allowed_cats_set):
    provider_cidrs = []
    asn_to_providers = collections.defaultdict(set)
    
    for provider, info in data.items():
        prov_upper = provider.upper()
        if prov_upper not in allowed_cats_set:
            continue
            
        cidrs = info.get("cidrs", []) or info.get("ips", []) or []
        for c in cidrs:
            if isinstance(c, str) and '/' in c:
                try:
                    net = ipaddress.ip_network(c.strip(), strict=False)
                    cidr_proto = router_pb2.CIDR()
                    cidr_proto.ip = net.network_address.packed
                    cidr_proto.prefix = net.prefixlen
                    provider_cidrs.append((cidr_proto, prov_upper))
                except Exception:
                    continue

        asns = info.get("asns", []) or []
        for asn in asns:
            if isinstance(asn, str):
                asn_digits = "".join(filter(str.isdigit, asn))
                if asn_digits:
                    asn_to_providers[asn_digits].add(prov_upper)

    def fetch_asn(asn):
        import time
        prefixes = []
        asn_url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        
        max_retries = 3
        backoff = 2
        
        for attempt in range(max_retries):
            try:
                req = urllib.request.Request(asn_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=25) as resp:
                    res_data = json.loads(resp.read().decode('utf-8'))
                    for item in res_data.get("data", {}).get("prefixes", []):
                        p = item.get("prefix")
                        if p:
                            prefixes.append(p)
                return asn, prefixes
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(backoff)
                    backoff *= 2
                else:
                    msg = f"Ошибка получения префиксов для AS{asn} после {max_retries} попыток: {e}"
                    print(f"❌ {msg}")
                    log_to_review(f"[ОШИБКА RIPE] {msg}")
        return asn, []

    if asn_to_providers:
        print(f"[JSON-IP] Найдено {len(asn_to_providers)} ASN для обработки. Запуск резолва через RIPE...")
        with ThreadPoolExecutor(max_workers=5) as executor:
            for asn, prefixes in executor.map(fetch_asn, asn_to_providers.keys()):
                providers = asn_to_providers[asn]
                for p_str in prefixes:
                    try:
                        net = ipaddress.ip_network(p_str, strict=False)
                        cidr_proto = router_pb2.CIDR()
                        cidr_proto.ip = net.network_address.packed
                        cidr_proto.prefix = net.prefixlen
                        for prov in providers:
                            provider_cidrs.append((cidr_proto, prov))
                    except Exception:
                        continue

    return provider_cidrs

def parse_json_source_geosite(data, allowed_cats_set):
    proto_domains = []
    
    type_mapping = {
        "plain": router_pb2.Domain.Plain,
        "keyword": router_pb2.Domain.Plain,
        "regex": router_pb2.Domain.Regex,
        "domain": router_pb2.Domain.Domain,
        "full": router_pb2.Domain.Full
    }

    for category, content in data.items():
        cat_upper = category.upper()
        if cat_upper not in allowed_cats_set:
            continue
            
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
                    proto_domains.append((d_proto, cat_upper))
                    
        elif isinstance(content, dict):
            for t_key, v_list in content.items():
                if t_key.lower() in type_mapping and isinstance(v_list, list):
                    d_type = type_mapping[t_key.lower()]
                    for item in v_list:
                        if isinstance(item, str) and item.strip():
                            d_proto = router_pb2.Domain()
                            d_proto.type = d_type
                            d_proto.value = item.strip()
                            proto_domains.append((d_proto, cat_upper))
                            
    return proto_domains

def parse_lst_source_geoip(data_str):
    all_cidrs = set()
    all_asns = set()

    for line in data_str.splitlines():
        line = line.split('#')[0].strip()
        if not line:
            continue

        if line.upper().startswith("AS") or line.isdigit():
            asn_digits = "".join(filter(str.isdigit, line))
            if asn_digits:
                all_asns.add(asn_digits)
        else:
            if '/' not in line:
                try:
                    addr = ipaddress.ip_address(line)
                    prefix = 32 if addr.version == 4 else 128
                    all_cidrs.add(f"{addr}/{prefix}")
                except ValueError:
                    continue
            else:
                all_cidrs.add(line)

    if all_asns:
        all_cidrs.update(fetch_asn_prefixes(all_asns))

    proto_cidrs = []
    for c_str in all_cidrs:
        try:
            net = ipaddress.ip_network(c_str, strict=False)
            cidr_proto = router_pb2.CIDR()
            cidr_proto.ip = net.network_address.packed
            cidr_proto.prefix = net.prefixlen
            proto_cidrs.append(cidr_proto)
        except Exception:
            continue
            
    return proto_cidrs

def parse_lst_source_geosite(data_str):
    proto_domains = []
    type_mapping = {
        "plain": router_pb2.Domain.Plain,
        "keyword": router_pb2.Domain.Plain,
        "regex": router_pb2.Domain.Regex,
        "domain": router_pb2.Domain.Domain,
        "full": router_pb2.Domain.Full
    }

    for line in data_str.splitlines():
        line = line.split('#')[0].strip()
        if not line:
            continue

        d_type = router_pb2.Domain.Domain
        d_value = line

        if ":" in d_value:
            prefix, value = d_value.split(":", 1)
            if prefix.lower() in type_mapping:
                d_type = type_mapping[prefix.lower()]
                d_value = value.strip()

        if d_value:
            d_proto = router_pb2.Domain()
            d_proto.type = d_type
            d_proto.value = d_value
            proto_domains.append(d_proto)

    return proto_domains

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
            for rule in source['rules']:
                src_cats = {c.upper() for c in rule['src']}
                dst_cat = rule['dst'].upper()
                
                if attr_name == "cidr":
                    fetched = parse_json_source_geoip(parsed_data, src_cats)
                    items = [i for i, c in fetched]
                    category_items[dst_cat].extend(items)
                    print(f"[СБОРЩИК] Интегрировано {len(items)} IP-префиксов в категорию {dst_cat} из JSON")
                    if is_custom:
                        check_and_log_duplicates(items, url, attr_name, upstream_keys_map)
                elif attr_name == "domain":
                    fetched = parse_json_source_geosite(parsed_data, src_cats)
                    items = [i for i, c in fetched]
                    category_items[dst_cat].extend(items)
                    print(f"[СБОРЩИК] Интегрировано {len(items)} правил в категорию {dst_cat} из JSON")
                    if is_custom:
                        check_and_log_duplicates(items, url, attr_name, upstream_keys_map)
        
        elif url_lower.endswith('.lst') or url_lower.endswith('.txt'):
            for rule in source['rules']:
                dst_cat = rule['dst'].upper()
                
                if attr_name == "cidr":
                    fetched_cidrs = parse_lst_source_geoip(parsed_data)
                    category_items[dst_cat].extend(fetched_cidrs)
                    print(f"[СБОРЩИК] Интегрировано {len(fetched_cidrs)} IP-префиксов в категорию {dst_cat} из LST")
                    if is_custom:
                        check_and_log_duplicates(fetched_cidrs, url, attr_name, upstream_keys_map)
                elif attr_name == "domain":
                    fetched_domains = parse_lst_source_geosite(parsed_data)
                    category_items[dst_cat].extend(fetched_domains)
                    print(f"[СБОРЩИК] Интегрировано {len(fetched_domains)} правил в категорию {dst_cat} из LST")
                    if is_custom:
                        check_and_log_duplicates(fetched_domains, url, attr_name, upstream_keys_map)
                    
        else:
            for rule in source['rules']:
                src_cats = {c.upper() for c in rule['src']}
                dst_cat = rule['dst'].upper()
                
                for entry in parsed_data.entry:
                    current_cat = entry.country_code.upper()
                    if "*" in src_cats or current_cat in src_cats:
                        target = current_cat if dst_cat == "*" else dst_cat
                        items = getattr(entry, attr_name)
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
