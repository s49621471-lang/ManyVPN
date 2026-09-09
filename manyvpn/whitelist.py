DOMAINS = {
    "gosuslugi.ru", "mail.ru", "vk.com", "vk.ru", "vk.me", "userapi.com", "vk-cdn.net",
    "vkuser.net", "vkuservideo.net", "mycdn.me", "ok.ru", "odnoklassniki.ru",
    "yandex.ru", "yandex.net", "ya.ru", "yastatic.net", "yandexcloud.net",
    "dzen.ru", "kinopoisk.ru", "rutube.ru", "smotrim.ru", "1tv.ru", "vgtrk.ru",
    "sberbank.ru", "sber.ru", "sberbank.com", "tinkoff.ru", "tbank.ru", "vtb.ru",
    "alfabank.ru", "gazprombank.ru", "raiffeisen.ru", "psbank.ru",
    "mos.ru", "nalog.ru", "nalog.gov.ru", "pfr.gov.ru", "gov.ru", "kremlin.ru",
    "rt.ru", "mts.ru", "megafon.ru", "beeline.ru", "tele2.ru", "rostelecom.ru",
    "avito.ru", "wildberries.ru", "wbbasket.ru", "ozon.ru", "ozone.ru",
    "dns-shop.ru", "mvideo.ru", "citilink.ru", "lenta.com", "magnit.ru",
    "gismeteo.ru", "2gis.ru", "2gis.com", "rambler.ru", "lenta.ru", "ria.ru",
    "tass.ru", "rbc.ru", "kommersant.ru", "aif.ru", "kp.ru",
    "hh.ru", "sravni.ru", "domclick.ru", "cian.ru", "auto.ru", "drom.ru",
    "cdnvideo.ru", "ngenix.net", "vkvideo.ru", "vkplay.ru", "max.ru",
    "gosuslugi.gov.ru", "edu.gov.ru", "rkn.gov.ru", "sberdevices.ru",
    "russianpost.ru", "pochta.ru", "rzd.ru", "aeroflot.ru", "s7.ru",
    "sportmaster.ru", "eldorado.ru", "petrovich.ru", "leroymerlin.ru",
}

MARKERS = ("white", "whitelist", "white-list", "белы", "белый список", "wl-", "-wl", "_wl", "wlist")


def _suffix_match(host):
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False
    parts = host.split(".")
    for index in range(len(parts) - 1):
        if ".".join(parts[index:]) in DOMAINS:
            return True
    return False


def detect(node):
    if node.whitelist:
        return True
    spec = node.spec
    tls = spec.get("tls") or {}
    if _suffix_match(tls.get("server_name", "")):
        return True
    transport = spec.get("transport") or {}
    host = transport.get("host")
    if isinstance(host, list):
        host = host[0] if host else ""
    if _suffix_match(host or ""):
        return True
    headers = transport.get("headers") or {}
    if _suffix_match(headers.get("Host", "")):
        return True
    if _suffix_match(node.server):
        return True
    lowered = (node.remark or "").lower()
    source = (node.source or "").lower()
    if any(marker in lowered for marker in MARKERS):
        return True
    if any(marker in source for marker in MARKERS):
        return True
    return False


def apply(nodes):
    for node in nodes:
        node.whitelist = detect(node)
    return nodes
