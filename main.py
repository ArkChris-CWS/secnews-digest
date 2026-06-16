#!/usr/bin/env python3
"""
보안 아침 브리핑 봇 (정확도+가독성 풀버전 v8)
=== v8 신규 ===
[버그] 텔레그램 분할 전송 시 항목 중복 발송 버그 수정
[가독성] 3단 그룹(🚨긴급패치 / ⚠️위협동향 / 📰일반) + 상단 KEV 요약 + 목차
[정확도 D] NVD에서 CWE 자동 주입 (CWE-306 Missing Authentication 등)
[정확도 C] LLM 요약의 큰 수치(만/million 등)가 원문에 없으면 ⚠️ 미검증 표시
[안정성] NVD 파일 캐시(24h) → rate limit/속도 개선
[안정성] Gemini JSON 깨지면 1회 재요청 후 폴백
=== 유지 ===
[B] NVD CVSS·심각도 직접 주입 / [EPSS] FIRST / [KEV] CISA 대조
[A] 더미 IoC 필터 / 공식소스 / 503 재시도+모델폴백 / html.escape
=== 정확도 원칙 ===
숫자·등급(CVSS·CWE·EPSS·KEV)은 공식 API가 주입(신뢰). 서술은 AI 요약(참고용).
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

# ── 설정 ──────────────────────────────────────────────
FEEDS = {
    "The Hacker News":   ("https://feeds.feedburner.com/TheHackersNews", True),
    "BleepingComputer":  ("https://www.bleepingcomputer.com/feed/", True),
    "Krebs on Security": ("https://krebsonsecurity.com/feed/", True),
    "The Record":        ("https://therecord.media/feed/", True),
    "보안뉴스":          ("https://www.boannews.com/media/news_rss.xml", True),
    "CISA Advisories":   ("https://www.cisa.gov/cybersecurity-advisories/all.xml", True),
    # 미검증 → 실패해도 조용히 스킵
    "KISA 보안공지":     ("https://www.boho.or.kr/kr/rss.do?bbsId=B0000133", False),
}

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
NVD_CACHE_FILE = "nvd_cache.json"
NVD_CACHE_TTL = 24 * 3600   # 24시간

HOURS = 24
MAX_CANDIDATES_RSS = 14
ARTICLE_CHARS = 4000
MAX_ITEMS = 8
DEDUP_RATIO = 0.82          # 제목 유사도 이 이상이면 같은 사건으로 병합

GEMINI_MODELS = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-flash-latest"]
MAX_RETRIES = 4
RETRYABLE_STATUS = (429, 500, 502, 503, 504)

UA = {"User-Agent": "Mozilla/5.0 (compatible; secnews-digest/3.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
TG_LIMIT = 3500             # 텔레그램 4096자 한도 여유분


# ── 유틸 ──────────────────────────────────────────────
def _clean(s: str) -> str:
    return re.sub(r"<[^>]+>", "", html.unescape(s or "")).strip()


def _norm_title(t):
    """중복 비교용 제목 정규화(소문자, 기호 제거)."""
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
        print("RSS 수집 실패(검증된 소스):", " | ".join(fail))
    if skip:
        print("RSS 스킵(미검증 소스):", " | ".join(skip))
    cands.sort(key=lambda x: x["dt"], reverse=True)
    return dedup_candidates(cands[:MAX_CANDIDATES_RSS])


def dedup_candidates(cands):
    """제목 유사도로 같은 사건 병합(difflib, 가벼움)."""
    kept = []
    for c in cands:
        nt = _norm_title(c["title"])
        dup = False
        for k in kept:
            if difflib.SequenceMatcher(None, nt, _norm_title(k["title"])).ratio() >= DEDUP_RATIO:
                k.setdefault("also", []).append(c["source"])   # 병합된 출처 기록
                dup = True
                break
        if not dup:
            kept.append(c)
    if len(kept) != len(cands):
        print(f"기사 중복 병합: {len(cands)}건 → {len(kept)}건")
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
    print(f"본문 추출: 성공 {full}건 / snippet 폴백 {snip}건")
    return cands


def fetch_kev():
    try:
        data = requests.get(KEV_URL, timeout=30, headers=UA).json()
    except Exception as ex:
        print("KEV 수집 실패:", ex)
        return [], set()
    all_cves = {v.get("cveID", "").upper() for v in data.get("vulnerabilities", [])}
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
    print(f"KEV 신규 항목: {len(out)}건 / KEV 전체 CVE: {len(all_cves)}개")
    return out, all_cves


# ── NVD 파일 캐시 ─────────────────────────────────────
def _load_cache():
    try:
        with open(NVD_CACHE_FILE, encoding="utf-8") as f:
            c = json.load(f)
        if time.time() - c.get("_ts", 0) < NVD_CACHE_TTL:
            return c.get("data", {})
    except Exception:
        pass
    return {}


def _save_cache(data):
    try:
        with open(NVD_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"_ts": time.time(), "data": data}, f)
    except Exception:
        pass


# ── [B][D] NVD: CVSS·심각도·CWE 공식 조회 ─────────────
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
                cve_obj = vulns[0]["cve"]
                metrics = cve_obj.get("metrics", {})
                score, sev = None, ""
                for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(mk):
                        cvss = metrics[mk][0]["cvssData"]
                        score = cvss.get("baseScore")
                        sev = (cvss.get("baseSeverity")
                               or metrics[mk][0].get("baseSeverity") or "").title()
                        break
                # CWE 추출
                cwe = ""
                for w in cve_obj.get("weaknesses", []):
                    for d in w.get("description", []):
                        v = d.get("value", "")
                        if v.startswith("CWE-"):
                            cwe = v
                            break
                    if cwe:
                        break
                result = {"score": score, "severity": sev, "cwe": cwe}
    except Exception:
        pass
    cache[cve] = result
    return result


def epss_lookup_bulk(cves):
    if not cves:
        return {}
    try:
        r = requests.get(EPSS_API, params={"cve": ",".join(sorted(cves))}, headers=UA, timeout=30)
        if r.status_code != 200:
            return {}
        out = {}
        for d in r.json().get("data", []):
            try:
                out[d.get("cve", "").upper()] = f"{float(d.get('epss', 0)) * 100:.1f}%"
            except Exception:
                pass
        return out
    except Exception:
        return {}


# 흔한 CWE 한글 라벨(있으면 병기, 없으면 코드만)
CWE_LABEL = {
    "CWE-306": "Missing Authentication", "CWE-287": "Improper Authentication",
    "CWE-89": "SQL Injection", "CWE-79": "XSS", "CWE-78": "OS Command Injection",
    "CWE-22": "Path Traversal", "CWE-352": "CSRF", "CWE-918": "SSRF",
    "CWE-502": "Insecure Deserialization", "CWE-434": "Unrestricted File Upload",
    "CWE-862": "Missing Authorization", "CWE-863": "Incorrect Authorization",
    "CWE-269": "Improper Privilege Mgmt", "CWE-416": "Use After Free",
    "CWE-787": "Out-of-bounds Write", "CWE-94": "Code Injection",
    "CWE-77": "Command Injection", "CWE-20": "Improper Input Validation",
    "CWE-200": "Information Exposure", "CWE-798": "Hard-coded Credentials",
}


def enrich_cve_facts(items, kev_cves):
    per_item, all_cves = [], set()
    for it in items:
        found = sorted({m.upper() for m in CVE_RE.findall(f"{it.get('title','')} {it.get('content','')}")})
        per_item.append(found)
        all_cves.update(found)
    if not all_cves:
        print("본문 내 CVE: 0개 (NVD/EPSS 조회 생략)")
        return

    epss = epss_lookup_bulk(all_cves)
    cache = _load_cache()
    miss = [c for c in sorted(all_cves) if c not in cache]
    for i, cve in enumerate(miss):
        nvd_lookup(cve, cache)
        if i < len(miss) - 1:
            time.sleep(0.8)
    _save_cache(cache)

    enriched = 0
    for it, cves in zip(items, per_item):
        facts, cwes = [], []
        for cve in cves:
            parts = [cve]
            nv = cache.get(cve)
            if nv:
                if nv.get("score") is not None:
                    parts.append(f"CVSS {nv['score']} ({nv.get('severity','')})".strip())
                if nv.get("cwe"):
                    lab = CWE_LABEL.get(nv["cwe"], "")
                    cwes.append(f"{nv['cwe']}" + (f" {lab}" if lab else ""))
            if cve in epss:
                parts.append(f"EPSS {epss[cve]}")
            if cve in kev_cves:
                parts.append("CISA KEV 등재(실제 악용중)")
            facts.append(" · ".join(parts))
        if facts:
            it["facts"] = facts
        if cwes:
            it["cwes"] = sorted(set(cwes))
        if facts or cwes:
            enriched += 1
    print(f"CVE 사실 주입: {enriched}개 항목 / 대상 CVE {len(all_cves)}개 (NVD 신규조회 {len(miss)})")


# ── [A] 더미/예시 IoC 필터 ────────────────────────────
DUMMY_PATTERNS = [
    re.compile(r"^(aa:bb:cc|00:11:22|11:22:33|de:ad:be|de:ad:co)", re.I),
    re.compile(r"example\.(com|org|net)", re.I),
    re.compile(r"(LAPTOP|DESKTOP|GP-CLIENT|WINDOWS-LAPTOP|HOSTNAME)-?\d*$", re.I),
    re.compile(r"^(1\.2\.3\.4|0\.0\.0\.0|127\.0\.0\.1|192\.168\.|10\.0\.0\.|x\.x\.x\.x)", re.I),
    re.compile(r"^(domain|hostname|ip[-_]?addr|user_info)", re.I),
]


def clean_iocs(ioc_str):
    if not ioc_str:
        return ""
    keep = []
    for tok in re.split(r"[,\n]", ioc_str):
        t = tok.strip()
        if not t or t in ("원문 확인", "없음", "N/A", "-"):
            continue
        cmp = t.replace("[.]", ".").replace("[:]", ":")
        if any(p.search(cmp) for p in DUMMY_PATTERNS):
            continue
        keep.append(t)
    return ", ".join(keep)


# ── [C] LLM 수치 환각 검증 ────────────────────────────
NUM_TOKEN = re.compile(r"(\d[\d,]*\s*(?:만|억|million|billion|천)?)")


def verify_numbers(text, source_text):
    """요약 속 큰 수치가 원문에 근거 있는지 약식 검증 → 미검증이면 True 반환."""
    if not text or not source_text:
        return False
    src = source_text.lower().replace(",", "")
    for m in re.findall(r"(\d[\d,]{2,})\s*(만|억|million|billion)?", text):
        num = m[0].replace(",", "")
        if len(num) < 3:
            continue
        # 원문에 같은 숫자(또는 콤마 제거형)가 있으면 OK
        if num in src:
            continue
        # 만/억/million 단위 환산도 한 번 확인(예: 120만 ↔ 1200000 / 1.2 million)
        return True   # 근거 못 찾음 → 미검증 의심
    return False


# ── 요약 프롬프트 ─────────────────────────────────────
PROMPT = """아래는 지난 24시간 국내외 보안 소스에서 수집한 원자료(JSON)다.
content는 기사 본문(fulltext)/짧은 요약(snippet)/CISA 권고(kev) 중 하나다.
published는 원문 게시일이며 이미 주어졌다.
너는 모의해킹·정보보안 실무자를 위한 한국어 아침 브리핑 편집자다.

[정확성 규칙 — 가장 중요]
- 오직 제공된 content 안에 있는 사실만 사용한다. 없으면 그 필드에 "원문 확인".
- CVSS·심각도·CWE·EPSS·KEV는 절대 적지 마라(시스템이 공식 API로 채운다).
  severity 필드는 항상 빈 문자열("").
- 숫자(피해 규모/설치 수/계정 수 등)는 content에 적힌 그대로만 쓰고, 단위를 바꾸지 마라
  (예: '설치 수'를 '사이트 수'로 바꾸지 말 것). 불확실하면 표현을 생략한다.
- IoC는 content에 실제 존재하는 값만. 예시·더미(aa:bb.., example.com, LAPTOP-001,
  사설IP 등)는 적지 마라. 없으면 "".
- 추측·과장 금지.

[선별 규칙]
- 같은 사건은 하나로 병합, 중요도 순 최대 8개. content_type=kev 최우선.

[출력 형식]
- 아래 JSON만 출력(코드펜스/설명 금지). 한국어(기술용어 영문 병기 가능).
- summary, principle은 각각 1~2문장. 마크다운 기호(*, **, #, _) 금지.

{
  "tldr": "오늘 가장 중요한 위협/이슈 2~3문장",
  "items": [
    {
      "title": "제목 또는 CVE 번호",
      "severity": "",
      "category": "공격 유형(RCE/인증우회/권한상승/공급망/피싱/랜섬웨어/정보유출 등)",
      "summary": "무슨 일인지 1~2문장(재작성, 원문 복붙 금지)",
      "impact": "영향받는 제품/버전/대상(없으면 원문 확인)",
      "mitigation": "패치 버전·완화책·탐지 포인트(없으면 원문 확인)",
      "principle": "왜 통하는지 1~2문장(근거 없으면 원문 확인)",
      "ioc": "content에 실제 존재하는 IoC만 쉼표로(없으면 빈 문자열)",
      "attack": "근거 있으면 ATT&CK ID(예: T1566), 쉼표 구분, 없으면 빈 문자열",
      "published": "해당 항목 published 값 그대로",
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
    if r.status_code in RETRYABLE_STATUS:
        raise requests.exceptions.HTTPError(f"{r.status_code} 일시 오류 (재시도 대상)")
    if r.status_code == 400 and use_json_mime:
        raise ValueError("400-json-mime")
    r.raise_for_status()
    return r.json()["candidates"][0]["content"]["parts"][0]["text"]


def summarize(items):
    slim = [{k: it[k] for k in ("source", "title", "content", "content_type", "published", "link") if k in it}
            for it in items]
    payload = json.dumps(slim, ensure_ascii=False, indent=2)
    for model in GEMINI_MODELS:
        use_json = True
        for attempt in range(MAX_RETRIES):
            try:
                raw = _call_gemini(model, payload, use_json_mime=use_json)
                if parse_digest(raw):       # JSON 깨짐 즉시 감지
                    return raw
                # 깨졌으면 1회 재요청(같은 모델, 다음 attempt)
                print(f"[{model}] JSON 파싱 실패 → 재요청 [{attempt+1}/{MAX_RETRIES}]")
                continue
            except ValueError:
                print(f"[{model}] JSON 강제 옵션 미지원 → 옵션 제거 후 재시도")
                use_json = False
                continue
            except requests.exceptions.RequestException as e:
                wait = (2 ** attempt) * 5
                print(f"[{model}] 호출 실패({e}) → {wait}s 후 재시도 [{attempt+1}/{MAX_RETRIES}]")
                time.sleep(wait)
        print(f"[{model}] 재시도 모두 실패 → 다음 모델로 폴백")
    print("모든 모델/재시도 실패 → 요약 생략")
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


def merge_facts(data, src_items):
    facts_by_cve, cwes_by_cve, body_by_cve = {}, {}, {}
    for it in src_items:
        for f in it.get("facts", []):
            facts_by_cve.setdefault(f.split(" ")[0].upper(), f)
        for c in it.get("cwes", []):
            pass
        # CVE→CWE, CVE→본문 매핑
        for cve in {m.upper() for m in CVE_RE.findall(f"{it.get('title','')} {it.get('content','')}")}:
            if it.get("cwes"):
                cwes_by_cve.setdefault(cve, it["cwes"])
            body_by_cve.setdefault(cve, it.get("content", ""))

    for it in data.get("items", []):
        text = f"{it.get('title','')} {it.get('summary','')} {it.get('impact','')}"
        cves = sorted({m.upper() for m in CVE_RE.findall(text)})
        merged = [facts_by_cve[c] for c in cves if c in facts_by_cve]
        if merged:
            it["_facts"] = merged
        cwes = []
        for c in cves:
            cwes += cwes_by_cve.get(c, [])
        if cwes:
            it["_cwes"] = sorted(set(cwes))
        # 수치 검증용 원문 연결
        body = " ".join(body_by_cve.get(c, "") for c in cves)
        it["_unverified_num"] = verify_numbers(it.get("impact", ""), body) if body else False
    return data


def _esc(s):
    return html.escape(str(s or "").strip(), quote=False)


_BLANK = ("", "원문 확인", "없음", "N/A", "-", "확인 필요")


def _sev_icon(sev):
    s = (sev or "").lower()
    if "crit" in s:
        return "\U0001f534"
    if "high" in s:
        return "\U0001f7e0"
    if "med" in s or "mod" in s:
        return "\U0001f7e1"
    if "low" in s:
        return "\U0001f7e2"
    return "\u26aa"


def _sev_from_facts(facts):
    for f in facts:
        m = re.search(r"CVSS\s+([\d.]+)\s*\(([^)]+)\)", f)
        if m:
            return f"{m.group(2).title()} (CVSS {m.group(1)})", m.group(2), float(m.group(1))
    return "", "", -1.0


NUM = ["1\ufe0f\u20e3", "2\ufe0f\u20e3", "3\ufe0f\u20e3", "4\ufe0f\u20e3", "5\ufe0f\u20e3",
       "6\ufe0f\u20e3", "7\ufe0f\u20e3", "8\ufe0f\u20e3", "9\ufe0f\u20e3", "\U0001f51f"]


def _group_of(it):
    """3단 분류: urgent(KEV or CVSS>=9) / trend(피싱·캠페인·유출 등) / normal."""
    facts = it.get("_facts", [])
    is_kev = any("KEV" in f for f in facts)
    _, _, score = _sev_from_facts(facts)
    if is_kev or score >= 9.0:
        return "urgent"
    cat = (it.get("category", "") + it.get("title", "")).lower()
    if any(w in cat for w in ("피싱", "phishing", "캠페인", "campaign", "유출", "breach",
                              "랜섬", "ransom", "apt", "그룹", "actor", "해커", "스미싱")):
        return "trend"
    return "normal"


def _item_block(idx, it):
    n = NUM[idx] if idx < len(NUM) else f"{idx + 1}."
    facts = it.get("_facts", [])
    is_kev = any("KEV" in f for f in facts)

    title_line = f"{n} <b>{_esc(it.get('title'))}</b>"
    if is_kev:
        title_line += "  \U0001f6a8<b>실제 악용중</b>"
    lines = [title_line]

    sev_text, sev_raw, _ = _sev_from_facts(facts)
    if sev_text:
        lines.append(f"{_sev_icon(sev_raw)} <b>심각도</b>: {_esc(sev_text)} <i>(NVD)</i>")
    if it.get("_cwes"):
        lines.append(f"\U0001f9ea <b>CWE</b>: {_esc(', '.join(it['_cwes']))}")
    if it.get("category"):
        lines.append(f"\U0001f3f7 <b>분류</b>: {_esc(it['category'])}")

    epss_vals = []
    for f in facts:
        m = re.search(r"EPSS\s+([\d.]+%)", f)
        if m:
            epss_vals.append(f"{f.split(' ')[0]} {m.group(1)}")
    if epss_vals:
        lines.append(f"\U0001f4c8 <b>악용확률(EPSS)</b>: {_esc(', '.join(epss_vals))}")

    pub = _esc(it.get("published"))
    if pub and pub not in _BLANK:
        lines.append(f"\U0001f5d3 <b>게시일</b>: {pub}")
    if it.get("summary"):
        lines.append(f"\U0001f4cc <b>핵심</b>: {_esc(it['summary'])}")
    if it.get("impact"):
        warn = "  \u26a0\ufe0f<i>수치 미검증</i>" if it.get("_unverified_num") else ""
        lines.append(f"\U0001f4a5 <b>영향</b>: {_esc(it['impact'])}{warn}")
    if it.get("mitigation"):
        lines.append(f"\U0001f6e1 <b>대응</b>: {_esc(it['mitigation'])}")
    if it.get("principle"):
        lines.append(f"\U0001f50d <b>원리</b>: {_esc(it['principle'])}")
    ioc = clean_iocs(it.get("ioc", ""))
    if ioc:
        lines.append(f"\U0001f9e9 <b>IoC</b>: <code>{_esc(ioc)}</code>")
    atk = _esc(it.get("attack"))
    if atk and atk not in _BLANK:
        lines.append(f"\U0001f3af <b>ATT&amp;CK</b>: {atk} <i>(참고)</i>")
    if it.get("source"):
        lines.append(f"\U0001f517 {_esc(it['source'])}")
    return "\n".join(lines)


def format_blocks(data, today):
    items = data.get("items", [])[:MAX_ITEMS]

    # 그룹 분류 + 그룹 내 CVSS/KEV 우선 정렬
    groups = {"urgent": [], "trend": [], "normal": []}
    for it in items:
        groups[_group_of(it)].append(it)

    def sk(it):
        facts = it.get("_facts", [])
        _, _, score = _sev_from_facts(facts)
        return (0 if any("KEV" in f for f in facts) else 1, -score)
    for g in groups:
        groups[g].sort(key=sk)

    ordered = groups["urgent"] + groups["trend"] + groups["normal"]

    blocks = []
    # ── 헤더 + TL;DR ──
    head = f"\U0001f6e1\ufe0f <b>보안 아침 브리핑</b> \u2014 {today}"
    head += f"\n\U0001f4ca 오늘 총 <b>{len(ordered)}</b>건"
    tldr = _esc(data.get("tldr"))
    if tldr:
        head += f"\n\n\U0001f4f0 <b>TL;DR</b>\n{tldr}"

    # ── 상단 KEV 요약(가장 먼저 봐야 할 것) ──
    kev_cves = []
    for it in ordered:
        for f in it.get("_facts", []):
            if "KEV" in f:
                kev_cves.append(f.split(" ")[0])
    if kev_cves:
        head += ("\n\n\U0001f6a8 <b>실제 악용중(KEV) — 즉시 점검</b>\n"
                 + ", ".join(f"<code>{_esc(c)}</code>" for c in sorted(set(kev_cves))))

    # ── 그룹별 목차 ──
    labels = [("urgent", "\U0001f6a8 긴급 패치 필요"),
              ("trend", "\u26a0\ufe0f 위협 동향"),
              ("normal", "\U0001f4f0 일반 뉴스")]
    toc = ["\U0001f4d1 <b>오늘의 항목</b>"]
    pos = 0
    order_index = {}
    for key, lab in labels:
        if not groups[key]:
            continue
        toc.append(f"\n<b>{lab}</b> ({len(groups[key])}건)")
        for it in groups[key]:
            order_index[id(it)] = pos
            facts = it.get("_facts", [])
            _, sev_raw, _ = _sev_from_facts(facts)
            dot = _sev_icon(sev_raw) if sev_raw else "\u2796"
            kev = " \U0001f6a8" if any("KEV" in f for f in facts) else ""
            t = _esc(it.get("title"))   # 전체 제목 표시(자르지 않음)
            num = NUM[pos] if pos < len(NUM) else f"{pos+1}."
            toc.append(f"{num} {dot} {t}{kev}")
            pos += 1
    head += "\n\n" + "\n".join(toc)
    blocks.append(head)

    # ── 그룹별 상세 ──
    pos = 0
    for key, lab in labels:
        if not groups[key]:
            continue
        blocks.append(f"<b>{lab}</b>")   # 청크 구분선과 겹치지 않게 라벨만
        for it in groups[key]:
            blocks.append(_item_block(pos, it))
            pos += 1

    blocks.append(
        "\u2139\ufe0f <i>심각도\u00b7CWE\u00b7EPSS\u00b7KEV는 NVD/FIRST/CISA 공식 데이터. "
        "핵심\u00b7원리\u00b7대응 및 ATT&amp;CK는 AI 요약/추정이므로 대응 전 출처 원문 확인 권장.</i>"
    )
    return blocks


# ── 발송: 중복 없는 청크 분할(버그 수정본) ────────────
def _chunk(blocks):
    """블록들을 TG_LIMIT 이하 청크로 묶음. 각 블록은 정확히 한 청크에만 들어감."""
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


def send_telegram_plain(text):
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id = os.environ["TELEGRAM_CHAT_ID"]
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    for i in range(0, len(text), 3900):
        requests.post(url, data={"chat_id": chat_id, "text": text[i:i + 3900],
                                 "disable_web_page_preview": "true"}, timeout=30).raise_for_status()


def main():
    # 표시 날짜는 한국시간(KST=UTC+9) 기준. GitHub Actions는 UTC라 그냥 today()면 하루 밀림.
    KST = datetime.timezone(datetime.timedelta(hours=9))
    today = datetime.datetime.now(KST).strftime("%Y-%m-%d")
    kev_items, kev_cves = fetch_kev()
    rss = enrich_with_body(collect_rss_candidates())
    items = kev_items + rss
    print(f"총 후보: {len(items)}건 (KEV {len(kev_items)} + RSS {len(rss)})")

    if not items:
        send_telegram_plain(f"\U0001f6e1\ufe0f 보안 아침 브리핑 \u2014 {today}\n\n지난 24시간 내 신규 보안 항목이 없습니다.")
        return

    enrich_cve_facts(items, kev_cves)
    raw = summarize(items)
    data = parse_digest(raw)

    if not data or "items" not in data:
        print("요약 실패 → 안내 메시지만 발송하고 정상 종료")
        send_telegram_plain(
            f"\U0001f6e1\ufe0f 보안 아침 브리핑 \u2014 {today}\n\n"
            f"\u26a0\ufe0f 요약 서비스(Gemini) 일시 오류로 오늘 브리핑 생성에 실패했습니다.\n"
            f"잠시 후 자동 재시도되거나, 내일 정상 발송됩니다."
        )
        return

    data = merge_facts(data, items)
    blocks = format_blocks(data, today)
    send_telegram_blocks(blocks)
    print("발송 완료")


if __name__ == "__main__":
    main()
