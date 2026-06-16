#!/usr/bin/env python3
"""
보안 아침 브리핑 봇 (실무 브리핑 v9)
대상: 모의해킹/정보보안 실무자의 '오늘 어떤 CVE를 먼저 봐야 하는가' 판단용.

=== v9 신규 ===
[그룹] 🚨KEV(실제악용) / 🔗공급망 / ⚠️위협동향 / 📰일반  (4단)
[상단] 'TL;DR' 라벨 → '오늘의 요약' + '오늘 우선 확인' 통계(KEV/Critical/CVSS9+/공급망/랜섬웨어)
[2단 본문] 운영(심각도/CWE/분류/EPSS/KEV/핵심/즉시조치) + 🔬분석(원리/IoC/ATT&CK/출처)
[EPSS] 확률 + 백분위(percentile) 동시 표기  (예: 0.5% · 95퍼센타일)
[KEV] 등록일(dateAdded) + 랜섬웨어 악용 여부(공식 필드) + Exploitation Status(🟢🟡🔴)
[분류] CVE 항목은 NVD의 CWE→유형 매핑으로 생성(환각 제거), 그 외만 LLM
[영향제품] CVE 항목은 NVD CPE에서 벤더/제품 추출(코드)
[CVE多] 한 기사 CVE 10개+면 대표 3개 + N more
[폴백] 429는 재시도 없이 즉시 폴백, 3모델 다 막히면 '요약 생략 모드'
       (제목+제품+CVSS+EPSS+KEV+링크만) → 브리핑은 매일 도착
[병합] 같은 CVE 포함 OR 제목 유사도≥0.82
[IoC] 더미 + 단어형 비-IoC(멀웨어/그룹명) 필터
[날짜] KST 기준
"""
import os
import re
import html
import json
import time
import datetime
import difflib

import feedparser
import requests
import trafilatura

KST = datetime.timezone(datetime.timedelta(hours=9))

# ── 설정 ──────────────────────────────────────────────
FEEDS = {
    "The Hacker News":   ("https://feeds.feedburner.com/TheHackersNews", True),
    "BleepingComputer":  ("https://www.bleepingcomputer.com/feed/", True),
    "Krebs on Security": ("https://krebsonsecurity.com/feed/", True),
    "The Record":        ("https://therecord.media/feed/", True),
    "보안뉴스":          ("https://www.boannews.com/media/news_rss.xml", True),
    "CISA Advisories":   ("https://www.cisa.gov/cybersecurity-advisories/all.xml", True),
    "KISA 보안공지":     ("https://www.boho.or.kr/kr/rss.do?bbsId=B0000133", False),
}

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
NVD_CACHE_FILE = "nvd_cache.json"
NVD_CACHE_TTL = 24 * 3600

HOURS = 24
MAX_CANDIDATES_RSS = 14
ARTICLE_CHARS = 4000
MAX_ITEMS = 8
MAX_CVE_PER_ITEM = 3       # 한 항목에 표시할 대표 CVE 수
DEDUP_RATIO = 0.82

GEMINI_MODELS = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-flash-latest"]
MAX_RETRIES_503 = 2        # 503/타임아웃만 짧게 재시도(429는 재시도 안 함)
RETRYABLE_STATUS = (500, 502, 503, 504)   # 429 제외!

UA = {"User-Agent": "Mozilla/5.0 (compatible; secnews-digest/4.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
TG_LIMIT = 3500


# ── CWE → 침투/실무 분류 매핑 ─────────────────────────
CWE_TO_CLASS = {
    "CWE-22": "Path Traversal", "CWE-23": "Path Traversal", "CWE-35": "Path Traversal",
    "CWE-78": "Command Injection", "CWE-77": "Command Injection",
    "CWE-89": "SQL Injection", "CWE-79": "XSS", "CWE-80": "XSS",
    "CWE-918": "SSRF", "CWE-352": "CSRF",
    "CWE-287": "Authentication Bypass", "CWE-306": "Authentication Bypass",
    "CWE-288": "Authentication Bypass", "CWE-294": "Authentication Bypass",
    "CWE-347": "Auth/Signature Bypass", "CWE-345": "Auth/Signature Bypass",
    "CWE-862": "Authorization (Missing)", "CWE-863": "Authorization (Incorrect)",
    "CWE-269": "Privilege Escalation", "CWE-250": "Privilege Escalation",
    "CWE-502": "Insecure Deserialization",
    "CWE-434": "File Upload", "CWE-61": "Symlink Following", "CWE-59": "Link Following",
    "CWE-94": "Code Injection", "CWE-95": "Code Injection", "CWE-1336": "Template Injection",
    "CWE-74": "Injection", "CWE-20": "Improper Input Validation",
    "CWE-200": "Information Disclosure", "CWE-209": "Information Disclosure",
    "CWE-798": "Hard-coded Credentials", "CWE-522": "Weak Credential Mgmt",
    "CWE-416": "Use After Free", "CWE-787": "Out-of-bounds Write",
    "CWE-125": "Out-of-bounds Read", "CWE-119": "Memory Corruption",
    "CWE-190": "Integer Overflow", "CWE-400": "DoS / Resource Exhaustion",
    "CWE-611": "XXE", "CWE-918 ": "SSRF", "CWE-420": "Missing Auth (Critical Resource)",
    "CWE-732": "Incorrect Permission", "CWE-276": "Incorrect Default Permission",
}
CWE_LABEL = {  # 분석 섹션에 코드+영문명
    "CWE-306": "Missing Authentication", "CWE-287": "Improper Authentication",
    "CWE-89": "SQL Injection", "CWE-79": "XSS", "CWE-78": "OS Command Injection",
    "CWE-22": "Path Traversal", "CWE-352": "CSRF", "CWE-918": "SSRF",
    "CWE-502": "Insecure Deserialization", "CWE-434": "Unrestricted File Upload",
    "CWE-862": "Missing Authorization", "CWE-863": "Incorrect Authorization",
    "CWE-269": "Improper Privilege Mgmt", "CWE-416": "Use After Free",
    "CWE-787": "Out-of-bounds Write", "CWE-94": "Code Injection", "CWE-77": "Command Injection",
    "CWE-347": "Improper Verification of Signature", "CWE-61": "UNIX Symlink Following",
    "CWE-420": "Unprotected Alternate Channel", "CWE-74": "Injection",
    "CWE-200": "Information Exposure", "CWE-798": "Hard-coded Credentials",
}


# ── 유틸 ──────────────────────────────────────────────
def _clean(s: str) -> str:
    return re.sub(r"<[^>]+>", "", html.unescape(s or "")).strip()


def _norm_title(t):
    t = re.sub(r"[^0-9a-z가-힣 ]", " ", (t or "").lower())
    return re.sub(r"\s+", " ", t).strip()


def fetch_article_text(url: str):
    if not url:
        return None
    try:
        resp = requests.get(url, timeout=15, headers=UA)
        if resp.status_code != 200:
            return None
        text = trafilatura.extract(resp.text, include_comments=False, include_tables=False)
        if text and len(text.strip()) >= 200:
            return text.strip()[:ARTICLE_CHARS]
    except Exception:
        pass
    return None


def collect_rss_candidates():
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=HOURS)
    cands, ok, fail, skip = [], [], [], []
    for src, (url, verified) in FEEDS.items():
        try:
            feed = feedparser.parse(url, request_headers=UA)
            if feed.bozo and not feed.entries:
                raise RuntimeError(getattr(feed, "bozo_exception", "파싱 실패/빈 피드"))
            n = 0
            for e in feed.entries:
                pub = e.get("published_parsed") or e.get("updated_parsed")
                if not pub:
                    continue
                dt = datetime.datetime(*pub[:6], tzinfo=datetime.timezone.utc)
                if dt >= cutoff:
                    cands.append({
                        "source": src,
                        "title": _clean(e.get("title", "")),
                        "summary": _clean(e.get("summary", ""))[:600],
                        "link": e.get("link", ""),
                        "published": dt.strftime("%Y-%m-%d"),
                        "dt": dt,
                    })
                    n += 1
            ok.append(f"{src}({n})")
        except Exception as ex:
            (fail if verified else skip).append(f"{src}: {ex}")
    print("RSS 수집 성공:", ", ".join(ok) or "없음")
    if fail:
        print("RSS 실패(검증 소스):", " | ".join(fail))
    if skip:
        print("RSS 스킵(미검증):", " | ".join(skip))
    cands.sort(key=lambda x: x["dt"], reverse=True)
    return dedup_candidates(cands[:MAX_CANDIDATES_RSS])


def dedup_candidates(cands):
    """같은 CVE 포함 OR 제목 유사도≥0.82면 병합."""
    kept = []
    for c in cands:
        nt = _norm_title(c["title"])
        c_cves = {m.upper() for m in CVE_RE.findall(c["title"] + " " + c.get("summary", ""))}
        dup = False
        for k in kept:
            k_cves = k.setdefault("_cves", {m.upper() for m in
                     CVE_RE.findall(k["title"] + " " + k.get("summary", ""))})
            same_cve = bool(c_cves & k_cves)
            sim = difflib.SequenceMatcher(None, nt, _norm_title(k["title"])).ratio()
            if same_cve or sim >= DEDUP_RATIO:
                k.setdefault("also", []).append(c["source"])
                dup = True
                break
        if not dup:
            kept.append(c)
    for k in kept:
        k.pop("_cves", None)
    if len(kept) != len(cands):
        print(f"기사 중복 병합: {len(cands)} → {len(kept)}")
    return kept


def enrich_with_body(cands):
    full, snip = 0, 0
    for it in cands:
        body = fetch_article_text(it["link"])
        if body:
            it["content"], it["content_type"] = body, "fulltext"
            full += 1
        else:
            it["content"], it["content_type"] = it.get("summary", ""), "snippet"
            snip += 1
        it.pop("dt", None)
    print(f"본문 추출: 성공 {full} / snippet {snip}")
    return cands


def fetch_kev():
    """KEV 로드 → (신규항목, {CVE: {added, ransomware}})."""
    try:
        data = requests.get(KEV_URL, timeout=30, headers=UA).json()
    except Exception as ex:
        print("KEV 수집 실패:", ex)
        return [], {}
    meta = {}
    for v in data.get("vulnerabilities", []):
        cid = v.get("cveID", "").upper()
        meta[cid] = {
            "added": v.get("dateAdded", ""),
            "ransomware": (v.get("knownRansomwareCampaignUse", "Unknown") or "").lower() == "known",
        }
    cutoff = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
    out = []
    for v in data.get("vulnerabilities", []):
        if v.get("dateAdded", "") >= cutoff:
            out.append({
                "source": "CISA KEV (실제 악용중)",
                "title": f'{v.get("cveID", "")} - {v.get("vulnerabilityName", "")}',
                "content": v.get("shortDescription", ""),
                "content_type": "kev",
                "published": v.get("dateAdded", ""),
                "link": f'https://nvd.nist.gov/vuln/detail/{v.get("cveID", "")}',
            })
    print(f"KEV 신규 {len(out)}건 / KEV 전체 {len(meta)}개")
    return out, meta


# ── NVD 캐시 ──────────────────────────────────────────
def _load_cache():
    try:
        with open(NVD_CACHE_FILE, encoding="utf-8") as f:
            c = json.load(f)
        if time.time() - c.get("_ts", 0) < NVD_CACHE_TTL:
            return c.get("data", {})
    except Exception:
        pass
    return {}


def _save_cache(d):
    try:
        with open(NVD_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"_ts": time.time(), "data": d}, f)
    except Exception:
        pass


def nvd_lookup(cve, cache):
    if cve in cache:
        return cache[cve]
    result = None
    try:
        headers = dict(UA)
        key = os.environ.get("NVD_API_KEY")
        if key:
            headers["apiKey"] = key
        r = requests.get(NVD_API, params={"cveId": cve}, headers=headers, timeout=30)
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            if vulns:
                obj = vulns[0]["cve"]
                metrics = obj.get("metrics", {})
                score, sev = None, ""
                for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(mk):
                        cd = metrics[mk][0]["cvssData"]
                        score = cd.get("baseScore")
                        sev = (cd.get("baseSeverity") or metrics[mk][0].get("baseSeverity") or "").title()
                        break
                cwe = ""
                for w in obj.get("weaknesses", []):
                    for d in w.get("description", []):
                        if d.get("value", "").startswith("CWE-"):
                            cwe = d["value"]
                            break
                    if cwe:
                        break
                # CPE에서 벤더/제품(대표 1개)
                product = ""
                try:
                    for cfg in obj.get("configurations", []):
                        for node in cfg.get("nodes", []):
                            for m in node.get("cpeMatch", []):
                                parts = m.get("criteria", "").split(":")
                                if len(parts) > 5 and parts[3] != "*":
                                    vend = parts[3].replace("_", " ").title()
                                    prod = parts[4].replace("_", " ").title()
                                    product = f"{vend} {prod}".strip()
                                    break
                            if product:
                                break
                        if product:
                            break
                except Exception:
                    pass
                result = {"score": score, "severity": sev, "cwe": cwe, "product": product,
                          "in_nvd": True}
        elif r.status_code == 404:
            result = {"in_nvd": False}
    except Exception:
        pass
    cache[cve] = result
    return result


def epss_lookup_bulk(cves):
    """{CVE: (확률%, 백분위)} 반환."""
    if not cves:
        return {}
    try:
        r = requests.get(EPSS_API, params={"cve": ",".join(sorted(cves))}, headers=UA, timeout=30)
        if r.status_code != 200:
            return {}
        out = {}
        for d in r.json().get("data", []):
            try:
                pct = float(d.get("epss", 0)) * 100
                perc = float(d.get("percentile", 0)) * 100
                out[d.get("cve", "").upper()] = (f"{pct:.1f}%", f"{perc:.0f}퍼센타일")
            except Exception:
                pass
        return out
    except Exception:
        return {}


def enrich_cve_facts(items, kev_meta):
    per_item, all_cves = [], set()
    for it in items:
        found = sorted({m.upper() for m in CVE_RE.findall(f"{it.get('title','')} {it.get('content','')}")})
        per_item.append(found)
        all_cves.update(found)
    if not all_cves:
        print("본문 내 CVE 0개")
        return

    epss = epss_lookup_bulk(all_cves)
    cache = _load_cache()
    miss = [c for c in sorted(all_cves) if c not in cache]
    for i, cve in enumerate(miss):
        nvd_lookup(cve, cache)
        if i < len(miss) - 1:
            time.sleep(0.8)
    _save_cache(cache)

    for it, cves in zip(items, per_item):
        cves = cves[:MAX_CVE_PER_ITEM + 5]  # 너무 많으면 뒤에서 자름
        recs = []
        cls_set, cwe_disp, prod_set = [], [], []
        kev_added, ransomware = "", False
        for cve in cves:
            nv = cache.get(cve) or {}
            rec = {"cve": cve, "in_nvd": nv.get("in_nvd", None),
                   "score": nv.get("score"), "severity": nv.get("severity", "")}
            if cve in epss:
                rec["epss"], rec["percentile"] = epss[cve]
            if cve in kev_meta:
                rec["kev"] = True
                kev_added = kev_added or kev_meta[cve]["added"]
                ransomware = ransomware or kev_meta[cve]["ransomware"]
            if nv.get("cwe"):
                c = CWE_TO_CLASS.get(nv["cwe"])
                if c:
                    cls_set.append(c)
                lab = CWE_LABEL.get(nv["cwe"], "")
                cwe_disp.append(nv["cwe"] + (f" {lab}" if lab else ""))
            if nv.get("product"):
                prod_set.append(nv["product"])
            recs.append(rec)
        it["_cve_recs"] = recs
        it["_total_cves"] = len(set(cves))
        if cls_set:
            it["_cwe_class"] = " / ".join(dict.fromkeys(cls_set))
        if cwe_disp:
            it["_cwes"] = list(dict.fromkeys(cwe_disp))
        if prod_set:
            it["_products"] = list(dict.fromkeys(prod_set))
        if kev_added:
            it["_kev_added"] = kev_added
        it["_ransomware"] = ransomware
    print(f"CVE 사실 주입 완료 / 대상 {len(all_cves)}개 (NVD 신규 {len(miss)})")


# ── IoC 필터 ──────────────────────────────────────────
DUMMY_PATTERNS = [
    re.compile(r"^(aa:bb:cc|00:11:22|11:22:33|de:ad:be)", re.I),
    re.compile(r"example\.(com|org|net)", re.I),
    re.compile(r"(LAPTOP|DESKTOP|GP-CLIENT|WINDOWS-LAPTOP|HOSTNAME)-?\d*$", re.I),
    re.compile(r"^(1\.2\.3\.4|0\.0\.0\.0|127\.0\.0\.1|192\.168\.|10\.0\.0\.|x\.x\.x\.x)", re.I),
    re.compile(r"^(domain|hostname|ip[-_]?addr|user_info)", re.I),
]
# IoC처럼 보이는지(IP/도메인/해시/URL/이메일/파일명/CVE) — 단어형 멀웨어/그룹명 배제
IOC_SHAPE = re.compile(
    r"""(
    \b\d{1,3}(\.\d{1,3}){3}\b           # IPv4
    | \b[a-f0-9]{32,64}\b               # MD5/SHA
    | \b[\w.-]+\.[a-z]{2,}\b            # 도메인/호스트
    | https?://\S+                      # URL
    | \b[\w.+-]+@[\w.-]+\.\w+\b         # 이메일
    | \b[\w-]+\.(exe|dll|js|php|war|jsp|sh|ps1|bin|py|jar|bat|dmp)\b  # 파일명
    | CVE-\d{4}-\d{4,7}
    )""", re.I | re.X)


def clean_iocs(ioc_str):
    if not ioc_str:
        return ""
    keep = []
    for tok in re.split(r"[,\n]", ioc_str):
        t = tok.strip()
        if not t or t in ("원문 확인", "없음", "N/A", "-"):
            continue
        cmp = t.replace("[.]", ".").replace("[:]", ":").replace("(.)", ".")
        if any(p.search(cmp) for p in DUMMY_PATTERNS):
            continue
        if not IOC_SHAPE.search(cmp):   # IP/도메인/해시/URL/이메일/파일/CVE 형태가 아니면 제외
            continue
        keep.append(t)
    return ", ".join(keep)


# ── [C] 수치 환각 검증 ────────────────────────────────
def verify_numbers(text, source_text):
    if not text or not source_text:
        return False
    src = source_text.lower().replace(",", "")
    for m in re.findall(r"(\d[\d,]{2,})\s*(만|억|million|billion)?", text):
        num = m[0].replace(",", "")
        if len(num) < 3:
            continue
        if num in src:
            continue
        return True
    return False


# ── 요약 프롬프트(분류/IoC 최소화, 서술 중심) ─────────
PROMPT = """아래는 지난 24시간 보안 소스에서 수집한 원자료(JSON)다.
content는 기사 본문(fulltext)/요약(snippet)/CISA 권고(kev) 중 하나다.
너는 모의해킹·정보보안 실무자를 위한 한국어 아침 브리핑 편집자다.

[정확성 규칙 — 가장 중요]
- 오직 제공된 content의 사실만 사용. 없으면 그 필드에 "원문 확인".
- CVSS·심각도·CWE·EPSS·KEV·제품명은 적지 마라(시스템이 공식 API로 채운다).
  severity, category는 항상 빈 문자열("").
- 숫자는 content에 적힌 그대로, 단위 바꾸지 마라(설치수↔사이트수 금지). 불확실하면 생략.
- IoC는 content에 실제 존재하는 '기술적 지표'만(IP/도메인/해시/URL/이메일/악성파일명).
  멀웨어 이름·그룹명·제품명 같은 일반 단어는 IoC가 아니므로 넣지 마라. 없으면 "".
- 추측·과장 금지.

[선별] 같은 사건은 병합, 중요도순 최대 8개. content_type=kev 최우선.

[출력] 아래 JSON만(코드펜스/설명 금지). 한국어(기술용어 영문 병기 가능).
summary/principle/action은 각각 1~2문장. 마크다운 기호(*, **, #, _) 금지.

{
  "tldr": "오늘 전체 위협 흐름 2~3문장(아래 통계와 중복되지 않게 '맥락' 위주)",
  "items": [
    {
      "title": "제목 또는 CVE",
      "severity": "",
      "category": "",
      "summary": "무슨 일인지 1~2문장(재작성)",
      "action": "지금 당장 할 조치 1~2문장(패치 버전/완화/차단). 없으면 원문 확인",
      "impact_extra": "제품 외 추가 영향(대상 범위 등). 없으면 빈 문자열",
      "principle": "왜 통하는지 1~2문장(근거 없으면 원문 확인)",
      "ioc": "기술적 IoC만 쉼표로(없으면 빈 문자열)",
      "attack": "근거 있으면 ATT&CK ID 쉼표구분(없으면 빈 문자열)",
      "published": "published 값 그대로",
      "source": "원문 URL"
    }
  ]
}

원자료:
"""


def _call_gemini(model, payload, use_json_mime=True):
    api_key = os.environ["GEMINI_API_KEY"]
    url = (f"https://generativelanguage.googleapis.com/v1beta/"
           f"models/{model}:generateContent?key={api_key}")
    body = {"contents": [{"parts": [{"text": PROMPT + payload}]}]}
    if use_json_mime:
        body["generationConfig"] = {"response_mime_type": "application/json"}
    r = requests.post(url, json=body, timeout=180)
    if r.status_code == 429:
        raise QuotaError()                       # 한도 → 재시도 금지
    if r.status_code in RETRYABLE_STATUS:
        raise requests.exceptions.HTTPError(f"{r.status_code} 일시 오류")
    if r.status_code == 400 and use_json_mime:
        raise ValueError("400-json-mime")
    r.raise_for_status()
    return r.json()["candidates"][0]["content"]["parts"][0]["text"]


class QuotaError(Exception):
    pass


def summarize(items):
    slim = [{k: it[k] for k in ("source", "title", "content", "content_type", "published", "link") if k in it}
            for it in items]
    payload = json.dumps(slim, ensure_ascii=False, indent=2)
    for model in GEMINI_MODELS:
        use_json = True
        attempt = 0
        while attempt <= MAX_RETRIES_503:
            try:
                raw = _call_gemini(model, payload, use_json_mime=use_json)
                if parse_digest(raw):
                    return raw
                print(f"[{model}] JSON 파싱 실패 → 재요청")
                attempt += 1
                continue
            except QuotaError:
                print(f"[{model}] 429 한도 → 재시도 없이 다음 모델")
                break                              # 즉시 다음 모델
            except ValueError:
                print(f"[{model}] json_mime 미지원 → 옵션 제거 재시도")
                use_json = False
                continue
            except requests.exceptions.RequestException as e:
                wait = (2 ** attempt) * 5
                print(f"[{model}] 일시 오류({e}) → {wait}s 후 재시도")
                time.sleep(wait)
                attempt += 1
        # 다음 모델로
    print("모든 모델 실패 → 요약 생략 모드")
    return None


def parse_digest(raw):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        m = re.search(r"\{.*\}", raw, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return None
        return None


# ── 코드 주입 사실을 LLM 결과에 매칭 ──────────────────
def merge_facts(data, src_items):
    by_cve = {}
    for it in src_items:
        for c in {m.upper() for m in CVE_RE.findall(f"{it.get('title','')} {it.get('content','')}")}:
            by_cve.setdefault(c, it)
    for out in data.get("items", []):
        text = f"{out.get('title','')} {out.get('summary','')}"
        cves = sorted({m.upper() for m in CVE_RE.findall(text)})
        src = next((by_cve[c] for c in cves if c in by_cve), None)
        if src:
            for key in ("_cve_recs", "_cwe_class", "_cwes", "_products",
                        "_kev_added", "_ransomware", "_total_cves"):
                if key in src:
                    out[key] = src[key]
            body = src.get("content", "")
            out["_unverified_num"] = verify_numbers(out.get("impact_extra", ""), body) if body else False
    return data


def _esc(s):
    return html.escape(str(s or "").strip(), quote=False)


_BLANK = ("", "원문 확인", "없음", "N/A", "-", "확인 필요")


def _sev_icon(sev):
    s = (sev or "").lower()
    if "crit" in s: return "\U0001f534"
    if "high" in s: return "\U0001f7e0"
    if "med" in s or "mod" in s: return "\U0001f7e1"
    if "low" in s: return "\U0001f7e2"
    return "\u26aa"


def _max_score(it):
    best = -1.0
    for r in it.get("_cve_recs", []):
        if r.get("score") is not None:
            best = max(best, float(r["score"]))
    return best


def _is_kev(it):
    return any(r.get("kev") for r in it.get("_cve_recs", []))


def _exploit_status(it):
    """🔴 실제악용(KEV) / 🟡 ... / 🟢 ... — 무료 공식근거 기반."""
    if _is_kev(it):
        return "\U0001f534 실제 악용 확인(KEV)"
    return ""   # PoC 미수집이라 그 외 단계는 표시 안 함(과표기 방지)


def _is_supply(it):
    t = (it.get("title", "") + it.get("summary", "")).lower()
    return any(w in t for w in ("supply chain", "공급망", "cdn", "plugin", "플러그인",
                                "npm", "pypi", "유포 채널", "library", "라이브러리"))


def _is_trend(it):
    t = (it.get("title", "") + it.get("summary", "")).lower()
    return any(w in t for w in ("피싱", "phishing", "campaign", "캠페인", "apt", "그룹",
                                "actor", "해커", "스미싱", "유출", "breach", "ransom", "랜섬"))


def _group_of(it):
    if _is_kev(it) or _max_score(it) >= 9.0:
        return "kev"
    if _is_supply(it):
        return "supply"
    if _is_trend(it):
        return "trend"
    return "normal"


NUM = ["1\ufe0f\u20e3", "2\ufe0f\u20e3", "3\ufe0f\u20e3", "4\ufe0f\u20e3", "5\ufe0f\u20e3",
       "6\ufe0f\u20e3", "7\ufe0f\u20e3", "8\ufe0f\u20e3", "9\ufe0f\u20e3", "\U0001f51f"]

GROUPS = [("kev", "\U0001f6a8 즉시 패치 (KEV/Critical)"),
          ("supply", "\U0001f517 공급망 공격"),
          ("trend", "\u26a0\ufe0f 위협 동향"),
          ("normal", "\U0001f4f0 일반")]


def _short_label(it):
    """목차용 짧은 라벨: 제품/핵심 키워드 + 태그."""
    prod = it.get("_products", [])
    if prod:
        base = prod[0]
    else:
        # 제목 앞부분에서 회사/제품 추정(첫 3단어)
        base = " ".join(_esc(it.get("title", "")).split()[:4])
    tag = " KEV" if _is_kev(it) else ""
    sc = _max_score(it)
    if not tag and sc >= 9.0:
        tag = " Critical"
    return f"{base}{tag}"


def _cve_line(it):
    """CVE 한 줄: CVE · CVSS · EPSS(percentile) · KEV."""
    out = []
    for r in it.get("_cve_recs", [])[:MAX_CVE_PER_ITEM]:
        seg = [f"<code>{_esc(r['cve'])}</code>"]
        if r.get("in_nvd") is False:
            seg.append("NVD 분석 대기")
        elif r.get("score") is not None:
            seg.append(f"CVSS {r['score']} {_sev_icon(r.get('severity'))}")
        if r.get("epss"):
            seg.append(f"EPSS {r['epss']}·{r.get('percentile','')}")
        if r.get("kev"):
            seg.append("\U0001f534KEV")
        out.append(" · ".join(seg))
    extra = it.get("_total_cves", 0) - MAX_CVE_PER_ITEM
    tail = f"  (+{extra} more)" if extra > 0 else ""
    return ("\n".join(f"  • {o}" for o in out) + tail) if out else ""


def _item_block(idx, it):
    n = NUM[idx] if idx < len(NUM) else f"{idx + 1}."
    kev = _is_kev(it)
    title = f"{n} <b>{_esc(it.get('title'))}</b>"
    if kev:
        title += "  \U0001f6a8"
    lines = [title]

    # 운영 영역
    sc = _max_score(it)
    if sc >= 0:
        # 대표 심각도(최고 점수)
        sev = ""
        for r in it.get("_cve_recs", []):
            if r.get("score") == sc:
                sev = r.get("severity", "")
                break
        lines.append(f"{_sev_icon(sev)} <b>심각도</b>: {_esc(sev)} (CVSS {sc}) <i>(NVD)</i>")
    cls = it.get("_cwe_class") or it.get("category")
    if cls and _esc(cls) not in _BLANK:
        lines.append(f"\U0001f3f7 <b>분류</b>: {_esc(cls)}")
    if it.get("_products"):
        lines.append(f"\U0001f3af <b>영향 제품</b>: {_esc(', '.join(it['_products'][:4]))}")
    exp = _exploit_status(it)
    if exp:
        extra = []
        if it.get("_kev_added"):
            extra.append(f"등록 {it['_kev_added']}")
        if it.get("_ransomware"):
            extra.append("\U0001f480랜섬웨어 악용")
        lines.append(f"\U0001f6a8 <b>상태</b>: {exp}" + (f" ({', '.join(extra)})" if extra else ""))
    cve_line = _cve_line(it)
    if cve_line:
        lines.append("\U0001f522 <b>CVE</b>:\n" + cve_line)
    if it.get("summary"):
        lines.append(f"\U0001f4cc <b>핵심</b>: {_esc(it['summary'])}")
    if it.get("impact_extra") and _esc(it["impact_extra"]) not in _BLANK:
        warn = "  \u26a0\ufe0f<i>수치 미검증</i>" if it.get("_unverified_num") else ""
        lines.append(f"\U0001f4a5 <b>영향</b>: {_esc(it['impact_extra'])}{warn}")
    if it.get("action") and _esc(it["action"]) not in _BLANK:
        lines.append(f"\U0001f6a8 <b>즉시 조치</b>: {_esc(it['action'])}")

    # 🔬 분석 영역
    ana = []
    if it.get("principle") and _esc(it["principle"]) not in _BLANK:
        ana.append(f"\U0001f50d <b>원리</b>: {_esc(it['principle'])}")
    if it.get("_cwes"):
        ana.append(f"\U0001f9ea <b>CWE</b>: {_esc(', '.join(it['_cwes']))}")
    ioc = clean_iocs(it.get("ioc", ""))
    if ioc:
        ana.append(f"\U0001f9e9 <b>IoC</b>: <code>{_esc(ioc)}</code>")
    atk = _esc(it.get("attack"))
    if atk and atk not in _BLANK:
        ana.append(f"\U0001f3af <b>ATT&amp;CK</b>: {atk} <i>(AI 추정·미검증)</i>")
    pub = _esc(it.get("published"))
    if pub and pub not in _BLANK:
        ana.append(f"\U0001f5d3 <b>게시일</b>: {pub}")
    if it.get("source"):
        ana.append(f"\U0001f517 {_esc(it['source'])}")
    if ana:
        lines.append("\n\U0001f52c <b>분석</b>")
        lines.extend(ana)
    return "\n".join(lines)


def format_blocks(data, today):
    items = data.get("items", [])[:MAX_ITEMS]
    groups = {k: [] for k, _ in GROUPS}
    for it in items:
        groups[_group_of(it)].append(it)

    def sk(it):
        return (0 if _is_kev(it) else 1, -_max_score(it))
    for g in groups:
        groups[g].sort(key=sk)
    ordered = sum((groups[k] for k, _ in GROUPS), [])

    # 통계
    n_kev = sum(1 for it in ordered if _is_kev(it))
    n_crit = sum(1 for it in ordered if _max_score(it) >= 9.0)
    n_c9 = sum(1 for it in ordered if _max_score(it) >= 9.0)
    n_supply = len(groups["supply"])
    n_ransom = sum(1 for it in ordered if it.get("_ransomware"))

    head = f"\U0001f6e1\ufe0f <b>보안 아침 브리핑</b> \u2014 {today}  (총 {len(ordered)}건)"
    # 오늘 우선 확인(1초 판단)
    stat = []
    if n_kev: stat.append(f"실제 악용(KEV) {n_kev}")
    if n_crit: stat.append(f"Critical {n_crit}")
    if n_supply: stat.append(f"공급망 {n_supply}")
    if n_ransom: stat.append(f"\U0001f480랜섬웨어 {n_ransom}")
    if stat:
        head += "\n\U0001f6a8 <b>오늘 우선 확인</b> \u2014 " + " · ".join(stat)

    kev_cves = sorted({r["cve"] for it in ordered for r in it.get("_cve_recs", []) if r.get("kev")})
    if kev_cves:
        head += "\n\U0001f534 <b>KEV</b>: " + ", ".join(f"<code>{_esc(c)}</code>" for c in kev_cves)

    # 요약 문단(라벨 한글)
    tldr = _esc(data.get("tldr"))
    if tldr:
        head += f"\n\n\U0001f4f0 <b>오늘의 요약</b>\n{tldr}"

    # 목차(짧은 라벨)
    toc = ["\n\U0001f4d1 <b>목차</b>"]
    pos = 0
    for key, lab in GROUPS:
        if not groups[key]:
            continue
        toc.append(f"<b>{lab}</b> ({len(groups[key])})")
        for it in groups[key]:
            num = NUM[pos] if pos < len(NUM) else f"{pos+1}."
            toc.append(f"{num} {_short_label(it)}")
            pos += 1
    head += "\n" + "\n".join(toc)

    blocks = [head]
    pos = 0
    for key, lab in GROUPS:
        if not groups[key]:
            continue
        blocks.append(f"<b>{lab}</b>")
        for it in groups[key]:
            blocks.append(_item_block(pos, it))
            pos += 1

    blocks.append(
        "\u2139\ufe0f <i>심각도·CWE·분류·EPSS·KEV·제품·랜섬웨어는 NVD/FIRST/CISA 공식 데이터. "
        "핵심·원리·조치·ATT&amp;CK는 AI 요약/추정이므로 대응 전 출처 원문 확인.</i>"
    )
    return blocks


# ── 요약 생략 모드(한도 초과) ─────────────────────────
def fallback_blocks(items, today):
    blocks = [f"\U0001f6e1\ufe0f <b>보안 아침 브리핑</b> \u2014 {today}\n"
              f"\u26a0\ufe0f <b>요약 서비스(Gemini) 한도/오류</b> \u2014 제목·공식수치·링크만 제공"]
    # CVE 있는 항목 위주로 최소 정보
    shown = 0
    body = []
    for it in items:
        if shown >= MAX_ITEMS:
            break
        recs = it.get("_cve_recs", [])
        line = [f"\u2022 <b>{_esc(it.get('title'))}</b>"]
        if it.get("_products"):
            line.append(f"  제품: {_esc(', '.join(it['_products'][:3]))}")
        for r in recs[:MAX_CVE_PER_ITEM]:
            seg = [f"<code>{_esc(r['cve'])}</code>"]
            if r.get("score") is not None:
                seg.append(f"CVSS {r['score']}")
            elif r.get("in_nvd") is False:
                seg.append("NVD 대기")
            if r.get("epss"):
                seg.append(f"EPSS {r['epss']}·{r.get('percentile','')}")
            if r.get("kev"):
                seg.append("\U0001f534KEV")
            line.append("  " + " · ".join(seg))
        if it.get("link"):
            line.append(f"  \U0001f517 {_esc(it['link'])}")
        body.append("\n".join(line))
        shown += 1
    blocks.append("\n\n".join(body) if body else "표시할 항목이 없습니다.")
    return blocks


def _chunk(blocks):
    sep = "\n\n\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n\n"
    chunks, cur = [], ""
    for b in blocks:
        if not cur:
            cur = b
        elif len(cur) + len(sep) + len(b) <= TG_LIMIT:
            cur += sep + b
        else:
            chunks.append(cur)
            cur = b
    if cur:
        chunks.append(cur)
    return chunks


def send_telegram_blocks(blocks):
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id = os.environ["TELEGRAM_CHAT_ID"]
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    for c in _chunk(blocks):
        requests.post(url, data={"chat_id": chat_id, "text": c, "parse_mode": "HTML",
                                 "disable_web_page_preview": "true"}, timeout=30).raise_for_status()


def main():
    today = datetime.datetime.now(KST).strftime("%Y-%m-%d")
    kev_items, kev_meta = fetch_kev()
    rss = enrich_with_body(collect_rss_candidates())
    items = kev_items + rss
    print(f"총 후보 {len(items)} (KEV {len(kev_items)} + RSS {len(rss)})")

    if not items:
        send_telegram_blocks([f"\U0001f6e1\ufe0f <b>보안 아침 브리핑</b> \u2014 {today}\n\n지난 24시간 내 신규 보안 항목이 없습니다."])
        return

    enrich_cve_facts(items, kev_meta)
    raw = summarize(items)
    data = parse_digest(raw)

    if not data or "items" not in data:
        print("요약 생략 모드로 발송")
        send_telegram_blocks(fallback_blocks(items, today))
        return

    data = merge_facts(data, items)
    send_telegram_blocks(format_blocks(data, today))
    print("발송 완료")


if __name__ == "__main__":
    main()
