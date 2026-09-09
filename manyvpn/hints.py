import re

from . import countries

FLAG_RE = re.compile("[\U0001F1E6-\U0001F1FF]{2}")
CODE_RE = re.compile(r"(?:^|[^A-Za-z])([A-Z]{2})(?:[^A-Za-z]|$)")

WORDS = {
    "netherlands": "NL", "nederland": "NL", "нидерланды": "NL", "holland": "NL", "amsterdam": "NL",
    "germany": "DE", "deutschland": "DE", "германия": "DE", "frankfurt": "DE",
    "usa": "US", "united states": "US", "америка": "US", "сша": "US",
    "united kingdom": "GB", "england": "GB", "london": "GB", "британия": "GB",
    "france": "FR", "франция": "FR", "paris": "FR",
    "finland": "FI", "финляндия": "FI", "helsinki": "FI",
    "sweden": "SE", "швеция": "SE", "stockholm": "SE",
    "poland": "PL", "польша": "PL", "warsaw": "PL",
    "russia": "RU", "россия": "RU", "moscow": "RU",
    "japan": "JP", "япония": "JP", "tokyo": "JP",
    "singapore": "SG", "сингапур": "SG",
    "canada": "CA", "канада": "CA",
    "turkey": "TR", "турция": "TR", "istanbul": "TR",
    "switzerland": "CH", "швейцария": "CH",
    "austria": "AT", "австрия": "AT",
    "italy": "IT", "италия": "IT",
    "spain": "ES", "испания": "ES",
    "estonia": "EE", "эстония": "EE",
    "latvia": "LV", "латвия": "LV",
    "lithuania": "LT", "литва": "LT",
    "norway": "NO", "норвегия": "NO",
    "denmark": "DK", "дания": "DK",
    "ireland": "IE", "ирландия": "IE",
    "romania": "RO", "румыния": "RO",
    "bulgaria": "BG", "болгария": "BG",
    "czech": "CZ", "чехия": "CZ",
    "hungary": "HU", "венгрия": "HU",
    "ukraine": "UA", "украина": "UA",
    "kazakhstan": "KZ", "казахстан": "KZ",
    "armenia": "AM", "армения": "AM",
    "india": "IN", "индия": "IN",
    "iran": "IR", "иран": "IR",
    "china": "CN", "китай": "CN",
    "hong kong": "HK", "гонконг": "HK",
    "taiwan": "TW", "тайвань": "TW",
    "korea": "KR", "корея": "KR",
    "australia": "AU", "австралия": "AU",
    "brazil": "BR", "бразилия": "BR",
    "argentina": "AR", "аргентина": "AR",
    "israel": "IL", "израиль": "IL",
    "emirates": "AE", "dubai": "AE", "оаэ": "AE",
    "moldova": "MD", "молдова": "MD",
    "serbia": "RS", "сербия": "RS",
    "belarus": "BY", "беларусь": "BY",
    "vietnam": "VN", "вьетнам": "VN",
    "indonesia": "ID", "индонезия": "ID",
    "malaysia": "MY", "малайзия": "MY",
    "mexico": "MX", "мексика": "MX",
    "chile": "CL", "чили": "CL",
    "south africa": "ZA", "юар": "ZA",
    "portugal": "PT", "португалия": "PT",
    "greece": "GR", "греция": "GR",
    "cyprus": "CY", "кипр": "CY",
    "iceland": "IS", "исландия": "IS",
    "luxembourg": "LU", "люксембург": "LU",
    "belgium": "BE", "бельгия": "BE",
    "slovakia": "SK", "словакия": "SK",
    "slovenia": "SI", "словения": "SI",
    "croatia": "HR", "хорватия": "HR",
    "georgia": "GE", "грузия": "GE",
}


def _from_flag(text):
    match = FLAG_RE.search(text)
    if not match:
        return ""
    pair = match.group(0)
    code = chr(ord(pair[0]) - 0x1F1E6 + 65) + chr(ord(pair[1]) - 0x1F1E6 + 65)
    return countries.normalize(code)


def guess(text):
    if not text:
        return ""
    code = _from_flag(text)
    if code:
        return code
    lowered = text.lower()
    for word, value in WORDS.items():
        if word in lowered:
            return value
    for match in CODE_RE.finditer(text):
        code = countries.normalize(match.group(1))
        if code and countries.known(code):
            return code
    return ""
