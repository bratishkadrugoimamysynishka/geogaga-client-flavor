<div align="center">

<table width="100%">
<tr>
<td align="center"><a href="https://github.com/bratishkadrugoimamysynishka/geogaga-client-flavor"><b>🔵 GeoGaga - Client Flavor</b></a></td>
<td align="center"><a href="https://github.com/bratishkadrugoimamysynishka/geogaga-server-flavor">🟢 Geogaga - Server Flavor</a></td>
</tr>
</table>

</div>

<p align="center">
  <img src="banner.svg" alt="GeoGaga - Client Flavor Banner" width="100%">
</p>

# GeoGaga — Client Flavor

**GeoGaga - Client Flavor** — это автоматически собираемые файлы данных `geoip.dat` и `geosite.dat`, специально оптимизированные для настройки умной **клиентской** маршрутизации трафика. Сборка предназначена для использования на конечных устройствах: смартфонах, персональных компьютерах, а также на домашних роутерах (Keenetic, OpenWrt и др.) с поддержкой VPN-клиентов на базе ядер Xray / V2Ray.

Главная особенность клиентской версии — точечная агрегация, очистка от дубликатов и перепаковка строго определенных апстрим-категорий в три единые группы правил с префиксом `geogaga`. Это позволяет существенно разгрузить центральный процессор конечного устройства (как при работе через домашнего провайдера интернета, так и через оператора мобильной связи) за счет отсутствия громоздких цепочек правил и снижения количества проверок при обработке сетевых пакетов.

---

## 📥 Скачивание баз данных (geodata)

Вы всегда можете скачать самые свежие, автоматически скомпилированные бинарные базы данных напрямую по ссылкам:

* 🌐 **Geosite (`geosite.dat`)** — [Скачать](https://raw.githack.com/bratishkadrugoimamysynishka/geogaga-client-flavor/release/geosite.dat)
* 🗺️ **Geoip (`geoip.dat`)** — [Скачать](https://raw.githack.com/bratishkadrugoimamysynishka/geogaga-client-flavor/release/geoip.dat)

> 💡 **Альтернативный вариант:** вы также можете загрузить актуальные файлы баз данных и их контрольные суммы SHA256 напрямую из раздела **[Releases](https://github.com/bratishkadrugoimamysynishka/geogaga-client-flavor/releases)** репозитория.

---

## 🚀 Готовые профили маршрутизации

Для популярных VPN-клиентов **Incy** и **Happ** реализован **автоматизированный механизм генерации** конфигурационных файлов и ссылок для импорта. 

### Как работает механизм:
* **Генерация на лету:** скрипт-сборщик при каждой компиляции баз данных автоматически формирует актуальные файлы правил маршрутизации (`.json`) и готовые ссылки для импорта (`.link`).
* **Полная синхронизация:** ссылки и JSON-конфигурации генерируются динамически. Правила внутри них всегда строго соответствуют обновленным тегам категорий (`geogaga-direct`, `geogaga-proxy`, `geogaga-block`), исключая ошибки ручной настройки.
* **Автообновление:** импорт по ссылкам `.link` позволяет вашим клиентам на лету подтягивать свежие списки правил без необходимости повторного импорта конфигурации вручную.

Вы можете использовать готовые ссылки для импорта или скачать JSON-файлы вручную:

| Клиент | 🔗 Ссылка для импорта | 📝 Содержимое ссылки | 📄 JSON-конфиг |
| :---: | :--- | :--- | :--- |
| **Incy** | [geogaga-incy.rf.gd](https://geogaga-incy.rf.gd) | [Смотреть](https://raw.githack.com/bratishkadrugoimamysynishka/geogaga-client-flavor/release/routing/incy.link) | [Смотреть](https://raw.githack.com/bratishkadrugoimamysynishka/geogaga-client-flavor/release/routing/incy.json) |
| **Happ** | [geogaga-happ.rf.gd](https://geogaga-happ.rf.gd/) | [Смотреть](https://raw.githack.com/bratishkadrugoimamysynishka/geogaga-client-flavor/release/routing/happ.link) | [Смотреть](https://raw.githack.com/bratishkadrugoimamysynishka/geogaga-client-flavor/release/routing/happ.json) |

---

## 🛠 Рекомендуемый порядок правил в клиенте

Для достижения максимального быстродействия и правильной логики распределения трафика рекомендуется выстраивать правила маршрутизации в клиенте в следующем порядке:

1. **Блокировка (`Block`)** ➡️ Сюда отправляется реклама, трекеры и скам. Соединение сбрасывается моментально.
2. **Напрямую (`Direct`)** ➡️ Трафик к российским государственным сервисам, банкам, локальным ресурсам, а также выбранным игровым и системным сервисам, которые должны идти через основного провайдера или мобильного оператора.
3. **Через VPN (`Proxy`)** ➡️ Заблокированные ресурсы, пулы CDN, списки обхода блокировок и зарубежные хостинг-провайдеры.
4. **Финальное правило (По умолчанию)** ➡️ **Напрямую (`Direct`)**. Весь остальной трафик, не попавший в предыдущие списки, должен идти через вашего текущего провайдера интернета или оператора связи.

### Пример структуры в конфигурации Xray JSON:

```json
"routing": {
  "domainStrategy": "IPIfNonMatch",
  "rules": [
    {
      "type": "field",
      "outboundTag": "block",
      "domain": [
        "geosite:geogaga-block"
      ]
    },
    {
      "type": "field",
      "outboundTag": "direct",
      "domain": [
        "geosite:geogaga-direct"
      ]
    },
    {
      "type": "field",
      "outboundTag": "direct",
      "ip": [
        "geoip:geogaga-direct"
      ]
    },
    {
      "type": "field",
      "outboundTag": "proxy",
      "domain": [
        "geosite:geogaga-proxy"
      ]
    },
    {
      "type": "field",
      "outboundTag": "proxy",
      "ip": [
        "geoip:geogaga-proxy"
      ]
    },
    {
      "type": "field",
      "outboundTag": "direct",
      "ip": [
        "0.0.0.0/0",
        "::/0"
      ]
    }
  ]
}
```

---

## 📦 Описание категорий GeoSite (`geosite.dat`)

Файл `geosite.dat` содержит доменные имена, ключевые слова и регулярные выражения, распределенные по трем целевым группам:

### 🚫 `geosite:geogaga-block`
Предназначена для жесткой блокировки рекламы, трекеров и телеметрии на уровне клиента.
* **Включает в себя категории:**
  * Из репозитория *runetfreedom/russia-v2ray-rules-dat*:
    * `category-ads` — база рекламных сетей и систем аналитики.
    * `win-spy` — домены сбора телеметрии ОС Windows.
  * Из локального репозитория *custom-additions/geosite-block.lst*:
    * `*` — персональные доменные имена для блокировки.

### 🟢 `geosite:geogaga-direct`
Обширный белый список ресурсов, которые работают исключительно напрямую через домашнего интернет-провайдера или оператора мобильной связи.
* **Включает в себя категории:**
  * Из репозитория *hydraponique/roscomvpn-geosite*:
    * `whitelist`, `category-ru`, `private` — государственные сайты, российские банки, платежные системы и локальные приватные сети.
    * `apple`, `microsoft` — официальные домены вендоров для бесперебойного обновления ПО и работы внутренних облачных сервисов экосистем.
    * `steam`, `epicgames`, `riot`, `escapefromtarkov`, `faceit` — игровые лаунчеры, CDN игровых дистрибутивов и игровые сервера для обеспечения минимального пинга напрямую.
    * `twitch`, `pinterest` — медиаплатформы, требующие прямой маршрутизации.
    * `torrent` — популярные торрент-трекеры и анонсеры для предотвращения забивания VPN-канала тяжелым P2P-трафиком.
  * Из репозитория *runetfreedom/russia-v2ray-rules-dat*:
    * `ru-available-only-inside` — российские ресурсы, доступные только с IP-адресов РФ.
  * Из репозитория *Loyalsoldier/v2ray-rules-dat*:
    * `category-ip-geo-detect`, `test-ipv6` — служебные домены определения IP-адресов и тестирования IPv6.
  * Из локального репозитория *custom-additions/geosite-direct.lst*:
    * `*` — персональные доменные имена для прямого соединения.

### 🔵 `geosite:geogaga-proxy`
Основной список доменов для пуска через VPN.
* **Включает в себя категории:**
  * Из репозитория *runetfreedom/russia-v2ray-rules-dat*:
    * `ru-blocked` — регулярно обновляемый список заблокированных на территории РФ доменов, формируемый на основе выгрузок РКН и баз данных Antifilter / Re:filter.
  * Из репозитория *hydraponique/roscomvpn-geosite*:
    * `category-geoblock-ru` — доменные имена зарубежных ресурсов, заблокировавших доступ для пользователей из РФ.
    * `twitch-ads` — домены рекламной сети Twitch.
  * Из локального репозитория *custom-additions/geosite-proxy.lst*:
    * `*` — персональные доменные имена для маршрутизации через VPN.

---

## 🌐 Описание категорий GeoIP (`geoip.dat`)

Файл `geoip.dat` оперирует массивами IP-адресов и CIDR-подсетей (IPv4 и IPv6).

### 🟢 `geoip:geogaga-direct`
Пул адресов для прямого соединения через инфраструктуру локального оператора связи или домашнего провайдера без использования VPN.
* **Включает в себя категории:**
  * Из репозитория *hydraponique/roscomvpn-geoip*:
    * `direct` — подсети российских операторов связи и локальных автономных систем.
    * `whitelist` — доверенные IP-адреса критической инфраструктуры.
    * `private` — диапазоны частных адресов (RFC 1918) для корректного доступа к локальной сети роутера.
  * Из репозитория *runetfreedom/russia-v2ray-rules-dat*:
    * `ru-whitelist` — доверенные российские IP-адреса.
  * Из локального репозитория *custom-additions/geoip-direct.lst*:
    * `*` — персональные IP-адреса и CIDR для прямой маршрутизации.

### 🔵 `geoip:geogaga-proxy`
Сетевые диапазоны, маршрутируемые строго через VPN.
* **Включает в себя категории:**
  * Из репозитория *runetfreedom/russia-v2ray-rules-dat*:
    * `ru-blocked-community` — адреса, заблокированные или замедленные по решениям ведомств, включая пулы серверов Telegram и публичные прокси.
    * `re-filter` — подсети из списка оптимизации проекта Re:filter.
  * Из репозитория *DanielLavrushin/b4geoip*:
    * Диапазоны глобальных хостингов и CDN для обхода DPI-замедлений и точечных блокировок по IP: `aeza`, `akamai`, `amazon`, `belcloud`, `buyvm`, `cdn77`, `cloudflare`, `cogent`, `constant`, `contabo`, `datacamp`, `digitalocean`, `digitalone`, `fastly`, `gcore`, `glesys`, `gthost`, `hetzner`, `meganz`, `melbicom`, `oracle`, `ovh`, `scalaxy`, `scaleway`, `zerocdn`.
  * Из репозитория *PentiumB/CDN-RuleSet*:
    * Дополнительные диапазоны IP-адресов крупных CDN-сетей: `amazon`, `cloudflare`, `fastly`, `akamai`, `datacamp`, `oracle`.
  * Из репозитория *mansourjabin/cdn-ip-database* (файл `resolved_ips.json`):
    * Динамически разрешаемые базы IP-адресов для популярных сетей доставки контента:
      `Akamai`, `Alibaba Cloud CDN`, `ArvanCloud`, `Azion`, `BaishanCloud`, `BelugaCDN`, `Bunny`, `CDN77`, `CDNetworks`, `CDNsun`, `CacheFly`, `ChinaCache (QUANTIL)`, `CloudFront`, `Cloudflare`, `Derak Cloud`, `EdgeNext`, `Edgecast`, `Edgio`, `F5`, `Fastly`, `Gcore`, `Google Cloud`, `Huawei Cloud CDN`, `Imperva`, `IranServer`, `KeyCDN`, `Leaseweb`, `Limelight`, `Medianova`, `Microsoft Azure`, `OVHcloud CDN`, `ParsPack`, `Qrator`, `StackPath`, `StormWall`, `Sucuri`, `Tencent Cloud CDN`, `X4B`.
  * Из локального репозитория *custom-additions/geoip-proxy.lst*:
    * `*` — персональные IP-адреса и CIDR для направления в VPN.

---

## 👥 Источники данных

Сборка компилируется благодаря автоматическому слиянию данных из следующих специализированных репозиториев:

| Репозиторий | Описание вклада в GeoGaga |
| :--- | :--- |
| [hydraponique/roscomvpn-geosite](https://github.com/hydraponique/roscomvpn-geosite) | Белые списки, игровые категории, реклама, медиасервисы |
| [hydraponique/roscomvpn-geoip](https://github.com/hydraponique/roscomvpn-geoip) | Российские подсети, приватные диапазоны, списки исключений IP |
| [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat) | Списки заблокированных доменов, выгрузки IP, инфраструктура мессенджеров, Re:filter |
| [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) | Категории IP Geo Detect и тестирование IPv6-соединений |
| [DanielLavrushin/b4geoip](https://github.com/DanielLavrushin/b4geoip) | Пулы CIDR-адресов крупнейших мировых облачных хостингов и CDN |
| [PentiumB/CDN-RuleSet](https://github.com/PentiumB/CDN-RuleSet) | Расширенные диапазоны IP от глобальных CDN |
| [mansourjabin/cdn-ip-database](https://github.com/mansourjabin/cdn-ip-database) | Динамически разрешаемые базы IP-адресов для более чем 30 CDN-сетей |
| **Локальные дополнения** | Пользовательские списки и ручные корректировки (`custom-additions`) |

---

## 🔄 Автоматическое обновление

Сборка полностью автономна и обновляется 4 раза в сутки (каждые 6 часов) с помощью **GitHub Actions**.

В процессе работы автоматического сценария (`builder.py`):
* Все дубликаты доменов и подсетей оптимизируются (включая автоматическую проверку вхождения поддоменов в родительские зоны и пересечения IP-диапазонов).
* Осуществляется автоматический многопоточный резолв анонсированных префиксов для автономных систем (ASN) через публичный API RIPE Stat.
* Имена всех категорий внутри компилируемых бинарных файлов принудительно переводятся в верхний регистр (`UPPERCASE`) для обеспечения стопроцентной совместимости со всеми версиями клиентских приложений и ядер.
* Финальный результат упаковывается в оптимизированный бинарный формат Protobuf.

### 📄 Текстовые списки (LST)
С частотой в 6 часов отдельный парсер распаковывает готовые бинарные базы и выкладывает их в виде простых текстовых `.lst` файлов в отдельную ветку **[`lists`](https://github.com/bratishkadrugoimamysynishka/geogaga-client-flavor/tree/lists)**. Эти файлы отлично подойдут для интеграции в сторонние фаерволы, роутеры или скрипты без поддержки формата Protobuf.
> 💡 **Дополнительно:** также в этой ветке в виде lst-файлов доступны и списки всех источников данных.
