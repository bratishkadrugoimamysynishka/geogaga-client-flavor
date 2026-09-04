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
            return prefixes
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(backoff)
                backoff *= 2
            else:
                msg = f"Ошибка получения префиксов для AS{asn} после {max_retries} попыток: {e}"
                print(f"❌ {msg}")
                log_to_review(f"[ОШИБКА RIPE] {msg}")
    return prefixes

def fetch_asn_prefixes(all_asns):
    all_cidrs = set()
    if all_asns:
        print(f"[АСН-РЕЗОЛВЕР] Найдено {len(all_asns)} ASN для обработки. Запуск резолва через RIPE...")
        with ThreadPoolExecutor(max_workers=15) as executor:
            for chunk in executor.map(fetch_asn, all_asns):
                all_cidrs.update(chunk)
    return all_cidrs

def parse_json_source_geoip(data, allowed_cats_set):
    provider_items = []
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
                    provider_items.append((cidr_proto, prov_upper, None))
                except Exception:
                    continue

        asns = info.get("asns", []) or []
        for asn in asns:
            if isinstance(asn, str):
                asn_digits = "".join(filter(str.isdigit, asn))
                if asn_digits:
                    asn_to_providers[asn_digits].add(prov_upper)

    if asn_to_providers:
        print(f"[JSON-IP] Найдено {len(asn_to_providers)} ASN для обработки. Запуск резолва через RIPE...")
        with ThreadPoolExecutor(max_workers=5) as executor:
            for asn, prefixes in executor.map(lambda a: (a, fetch_asn(a)), asn_to_providers.keys()):
                providers = asn_to_providers[asn]
                for p_str in prefixes:
                    try:
                        net = ipaddress.ip_network(p_str, strict=False)
                        cidr_proto = router_pb2.CIDR()
                        cidr_proto.ip = net.network_address.packed
                        cidr_proto.prefix = net.prefixlen
                        for prov in providers:
                            provider_items.append((cidr_proto, prov, asn))
                    except Exception:
                        continue

    return provider_items

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

def filter_and_log_geoip_items(items, exclude_list, url, rule_src, rule_dst):
    if not exclude_list:
        return [item[0] for item in items]

    cidrs_to_exclude = set()
    asns_to_exclude = set()
    invalid_exclusions = []

    for excl in exclude_list:
        excl_upper = excl.upper()
        if excl_upper.startswith("AS") or excl_upper.isdigit():
            asn_digits = "".join(filter(str.isdigit, excl_upper))
            if asn_digits:
                asns_to_exclude.add(asn_digits)
            else:
                invalid_exclusions.append(excl)
        else:
            try:
                net = ipaddress.ip_network(excl, strict=False)
                cidr_proto = router_pb2.CIDR()
                cidr_proto.ip = net.network_address.packed
                cidr_proto.prefix = net.prefixlen
                cidrs_to_exclude.add(get_item_key(cidr_proto, "cidr"))
            except Exception:
                invalid_exclusions.append(excl)

    if invalid_exclusions:
        msg = (f"[ИСКЛЮЧЕНИЯ-НЕВЕРНЫЙ ФОРМАТ]\n"
               f"  Источник: {url}\n"
               f"  Правило: src={rule_src}, dst={rule_dst}\n"
               f"  Следующие значения не являются ни CIDR, ни ASN: {', '.join(invalid_exclusions)}\n"
               f"{'-'*70}")
        log_to_review(msg)

    all_cidr_keys = {get_item_key(item[0], "cidr") for item in items}
    all_asn_keys = {item[2] for item in items if item[2]}

    missing_asns = asns_to_exclude - all_asn_keys
    if missing_asns:
        msg = (f"[ИСКЛЮЧЕНИЯ-ASN НЕ НАЙДЕНЫ В ДАННЫХ]\n"
               f"  Источник: {url}\n"
               f"  Правило: src={rule_src}, dst={rule_dst}\n"
               f"  Отсутствуют: {', '.join(missing_asns)}\n"
               f"{'-'*70}")
        log_to_review(msg)

    missing_cidrs = set()
    for cidr_key in cidrs_to_exclude:
        try:
            addr = ipaddress.ip_address(cidr_key[0])
            cidr_str = f"{addr}/{cidr_key[1]}"
        except:
            cidr_str = f"INVALID/{cidr_key[1]}"
        if cidr_key not in all_cidr_keys:
            missing_cidrs.add(cidr_str)
    if missing_cidrs:
        msg = (f"[ИСКЛЮЧЕНИЯ-CIDR НЕ НАЙДЕНЫ В ДАННЫХ]\n"
               f"  Источник: {url}\n"
               f"  Правило: src={rule_src}, dst={rule_dst}\n"
               f"  Отсутствуют: {', '.join(missing_cidrs)}\n"
               f"{'-'*70}")
        log_to_review(msg)

    filtered = []
    for cidr_proto, provider, asn in items:
        if get_item_key(cidr_proto, "cidr") in cidrs_to_exclude:
            continue
        if asn and asn in asns_to_exclude:
            continue
        filtered.append(cidr_proto)

    return filtered

def parse_exclude_list(exclude_list, attr_name):
    keys = set()
    if not exclude_list:
        return keys

    if attr_name == "domain":
        type_mapping = {
            "plain": router_pb2.Domain.Plain,
            "keyword": router_pb2.Domain.Plain,
            "regex": router_pb2.Domain.Regex,
            "domain": router_pb2.Domain.Domain,
            "full": router_pb2.Domain.Full
        }
        for line in exclude_list:
            line = line.strip()
            if not line:
                continue
            d_type = router_pb2.Domain.Domain
            d_value = line
            if ":" in line:
                prefix, value = line.split(":", 1)
                if prefix.lower() in type_mapping:
                    d_type = type_mapping[prefix.lower()]
                    d_value = value.strip()
            if d_value:
                d_proto = router_pb2.Domain()
                d_proto.type = d_type
                d_proto.value = d_value
                keys.add(get_item_key(d_proto, "domain"))
    else:
        for line in exclude_list:
            line = line.strip()
            if not line:
                continue
            try:
                if '/' in line:
                    net = ipaddress.ip_network(line, strict=False)
                else:
                    addr = ipaddress.ip_address(line)
                    prefix = 32 if addr.version == 4 else 128
                    net = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
                cidr_proto = router_pb2.CIDR()
                cidr_proto.ip = net.network_address.packed
                cidr_proto.prefix = net.prefixlen
                keys.add(get_item_key(cidr_proto, "cidr"))
            except Exception:
                continue
    return keys

def check_exclusions(exclude_keys, all_keys, source_url, rule_dst, rule_src, attr_name):
    missing = []
    for key in exclude_keys:
        if key not in all_keys:
            missing.append(key)
    if missing:
        msg = f"[ИСКЛЮЧЕНИЯ НЕ НАЙДЕНЫ В ДАННЫХ]\n  Источник: {source_url}\n  Правило: src={rule_src}, dst={rule_dst}\n  Следующие исключения отсутствуют в данных:\n"
        for k in missing:
            if attr_name == "domain":
                type_str = {0: "plain", 1: "regex", 2: "domain", 3: "full"}.get(k[0], str(k[0]))
                msg += f"    - {type_str}:{k[1]}\n"
            else:
                try:
                    addr = ipaddress.ip_address(k[0])
                    msg += f"    - {addr}/{k[1]}\n"
                except:
                    msg += f"    - INVALID_IP/{k[1]}\n"
        msg += "-" * 70
        log_to_review(msg)
