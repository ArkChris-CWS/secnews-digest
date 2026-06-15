#!/usr/bin/env python3
"""
보안 아침 브리핑 봇 (정확도 풀버전 v6)
=== 이번 버전 핵심 ===
[B] NVD API로 CVE의 CVSS·심각도·CWE를 코드가 직접 조회 → AI 추측 제거(환각 0)
[EPSS] FIRST EPSS API로 '실제 악용 확률(%)' 직접 조회
[KEV] CISA KEV 등재 여부를 코드가 직접 판정 → "🚨 실제 악용중" 강조
[A] 더미/예시 IoC(aa:bb.., 00:11.., example, LAPTOP-001 등) 필터링
[C] 공식 소스 추가(CISA Advisories). 검증 안 된 소스(KISA 등)는 실패 시 자동 스킵
[안정성] Gemini 503/429 backoff 재시도 + 모델 폴백 + 최후 안전 폴백
[핵심] AT&T의 &, 버전 < 등 특수문자 html.escape 처리

=== 정확도 원칙 ===
- 숫자/등급(CVSS·심각도·EPSS·KEV)은 LLM이 아니라 '공식 API'가 주입 → 신뢰 가능
- 나머지 서술(핵심·원리·대응)은 LLM 요약이므로 참고용(원문 확인 전제)
"""
import os
import re
import html
import json
import time
import datetime

import feedparser
import requests
import trafilatura

# ── 설정 ──────────────────────────────────────────────
# value=True 이면 '검증된 소스'(실패 시 경고), False 이면 '미검증'(실패해도 조용히 스킵)
FEEDS = {
    "The Hacker News":   ("https://feeds.feedburner.com/TheHackersNews", True),
    "BleepingComputer":  ("https://www.bleepingcomputer.com/feed/", True),
    "Krebs on Security": ("https://krebsonsecurity.com/feed/", True),
    "The Record":        ("https://therecord.media/feed/", True),
    "보안뉴스":          ("https://www.boannews.com/media/news_rss.xml", True),
    # 공식 1차 소스 ──
    "CISA Advisories":   ("https://www.cisa.gov/cybersecurity-advisories/all.xml", True),
    # 미검증(URL 동적/차단 가능) → 실패해도 스킵. 동작 확인되면 True 로 승격
    "KISA 보안공지":     ("https://knvd.krcert.or.kr/rss/securityNotice.do", False),
    "KISA 보안권고":     ("https://www.boho.or.kr/rss/securityNotice.do", False),
}

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"

HOURS = 24
MAX_CANDIDATES_RSS = 12
ARTICLE_CHARS = 4000
MAX_ITEMS = 8

GEMINI_MODELS = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-flash-latest"]
MAX_RETRIES = 4
RETRYABLE_STATUS = (429, 500, 502, 503, 504)

UA = {"User-Agent": "Mozilla/5.0 (compatible; secnews-digest/2.0)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


# ── 유틸 ──────────────────────────────────────────────
def _clean(s: str) -> str:
    return re.sub(r"<[^>]+>", "", html.unescape(s or "")).strip()


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
    return cands[:MAX_CANDIDATES_RSS]


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
        it.pop("summary", None)
        it.pop("dt", None)
    print(f"본문 추출: 성공 {full}건 / snippet 폴백 {snip}건")
    return cands


def fetch_kev():
    """CISA KEV 전체 로드 → (신규 항목 리스트, 전체 CVE 집합) 반환."""
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


# ── [B] NVD: CVE별 CVSS·심각도·CWE 공식 조회 ───────────
def nvd_lookup(cve):
    """NVD 공식 API에서 CVSS/심각도/CWE 조회. 실패 시 None."""
    try:
        headers = dict(UA)
        key = os.environ.get("NVD_API_KEY")   # 있으면 사용(없어도 동작)
        if key:
            headers["apiKey"] = key
        r = requests.get(NVD_API, params={"cveId": cve}, headers=headers, timeout=30)
        if r.status_code != 200:
            return None
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return None
        metrics = vulns[0]["cve"].get("metrics", {})
        for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if mk in metrics and metrics[mk]:
                cvss = metrics[mk][0]["cvssData"]
                score = cvss.get("baseScore")
                sev = (cvss.get("baseSeverity")
                       or metrics[mk][0].get("baseSeverity") or "").title()
                return {"score": score, "severity": sev}
    except Exception:
        pass
    return None


# ── [EPSS] FIRST: 악용 확률 조회 ──────────────────────
def epss_lookup_bulk(cves):
    """여러 CVE의 EPSS(악용확률)를 한 번에 조회. {CVE: 'NN.N%'}."""
    if not cves:
        return {}
    try:
        r = requests.get(EPSS_API, params={"cve": ",".join(sorted(cves))},
                         headers=UA, timeout=30)
        if r.status_code != 200:
            return {}
        out = {}
        for d in r.json().get("data", []):
            cve = d.get("cve", "").upper()
            try:
                out[cve] = f"{float(d.get('epss', 0)) * 100:.1f}%"
            except Exception:
                pass
        return out
    except Exception:
        return {}


def enrich_cve_facts(items, kev_cves):
    """
    각 항목 본문/제목에서 CVE를 뽑아 NVD/EPSS/KEV 사실을 코드가 직접 주입.
    -> 결과는 item['facts'] 에 저장(LLM이 건드리지 않음).
    """
    # 1) 전체 CVE 수집
    per_item = []
    all_cves = set()
    for it in items:
        text = f"{it.get('title','')} {it.get('content','')}"
        found = sorted({m.upper() for m in CVE_RE.findall(text)})
        per_item.append(found)
        all_cves.update(found)

    if not all_cves:
        print("본문 내 CVE: 0개 (NVD/EPSS 조회 생략)")
        return

    # 2) EPSS 일괄 조회
    epss = epss_lookup_bulk(all_cves)

    # 3) NVD 개별 조회(레이트리밋 고려해 약간의 간격)
    nvd_cache = {}
    for i, cve in enumerate(sorted(all_cves)):
        nvd_cache[cve] = nvd_lookup(cve)
        if i < len(all_cves) - 1:
            time.sleep(0.8)   # NVD 무키 제한 완화(30s/5req)

    # 4) 항목별 facts 구성
    enriched = 0
    for it, cves in zip(items, per_item):
        facts = []
        for cve in cves:
            parts = [cve]
            nv = nvd_cache.get(cve)
            if nv and nv.get("score") is not None:
                parts.append(f"CVSS {nv['score']} ({nv.get('severity','')})".strip())
            if cve in epss:
                parts.append(f"EPSS {epss[cve]}")
            if cve in kev_cves:
                parts.append("CISA KEV 등재(실제 악용중)")
            facts.append(" · ".join(parts))
        if facts:
            it["facts"] = facts
            enriched += 1
    print(f"CVE 사실 주입: {enriched}개 항목 / 대상 CVE {len(all_cves)}개")


# ── [A] 더미/예시 IoC 필터 ────────────────────────────
DUMMY_PATTERNS = [
    re.compile(r"^(aa:bb:cc|00:11:22|11:22:33|de:ad:be|de:ad:co)", re.I),
    re.compile(r"example\.(com|org|net)", re.I),
    re.compile(r"(LAPTOP|DESKTOP|GP-CLIENT|WINDOWS-LAPTOP|HOSTNAME)-?\d*$", re.I),
    re.compile(r"^(1\.2\.3\.4|0\.0\.0\.0|127\.0\.0\.1|192\.168\.|10\.0\.0\.|x\.x\.x\.x)", re.I),
    re.compile(r"^(domain|hostname|ip[-_]?addr|user_info)", re.I),
]


def clean_iocs(ioc_str):
    """쉼표구분 IoC 문자열에서 더미/예시/사설 값 제거."""
    if not ioc_str:
        return ""
    keep = []
    for tok in re.split(r"[,\n]", ioc_str):
        t = tok.strip()
        if not t or t in ("원문 확인", "없음", "N/A", "-"):
            continue
        if any(p.search(t) for p in DUMMY_PATTERNS):
            continue
        keep.append(t)
    return ", ".join(keep)


# ── 요약 프롬프트 ─────────────────────────────────────
PROMPT = """아래는 지난 24시간 국내외 보안 소스에서 수집한 원자료(JSON)다.
content는 기사 본문(fulltext)/짧은 요약(snippet)/CISA 권고(kev) 중 하나다.
published는 원문 게시일이며 이미 주어졌다.
너는 모의해킹·정보보안 실무자를 위한 한국어 아침 브리핑 편집자다.

[정확성 규칙 — 가장 중요]
- 오직 제공된 content 안에 있는 사실만 사용한다. 없으면 그 필드에 "원문 확인".
- CVSS 점수·심각도·EPSS·KEV 여부는 절대 적지 마라(시스템이 공식 API로 따로 채운다).
  너는 severity 필드를 항상 빈 문자열("")로 둔다.
- IoC는 content에 '실제로' 존재하는 값만 적는다. 예시·더미(aa:bb.., example.com,
  LAPTOP-001, 1.2.3.4, 사설 IP, 'hostname' 같은 설명용)는 절대 적지 마라. 없으면 "".
- 추측·과장 금지.

[선별 규칙]
- 같은 사건을 여러 매체가 다루면 하나로 병합하고, 중요도 순으로 최대 8개만 고른다.
- content_type=kev 항목을 최우선으로 둔다.

[출력 형식]
- 아래 구조의 JSON만 출력(코드펜스/설명 금지). 모든 값 한국어(기술용어 영문 병기 가능).
- summary, principle은 각각 1~2문장. 마크다운 기호(*, **, #, _) 금지.

{
  "tldr": "오늘 가장 중요한 위협/이슈 2~3문장 요약",
  "items": [
    {
      "title": "제목 또는 CVE 번호",
      "severity": "",
      "category": "공격 유형(RCE/인증우회/권한상승/공급망/피싱/랜섬웨어/정보유출 등)",
      "summary": "무슨 일인지 1~2문장(재작성, 원문 복붙 금지)",
      "impact": "영향받는 제품/버전/대상(없으면 원문 확인)",
      "mitigation": "패치 버전·완화책·탐지 포인트(없으면 원문 확인)",
      "principle": "이 공격/취약점이 왜 통하는지 1~2문장(근거 없으면 원문 확인)",
      "ioc": "content에 실제 존재하는 IoC만 쉼표로(없으면 빈 문자열)",
      "attack": "근거 있으면 ATT&CK ID(예: T1566), 여러 개면 쉼표, 없으면 빈 문자열",
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
    # facts/published 등 코드 주입 필드는 LLM 입력에서 빼서 토큰 절약 + 오염 방지
    slim = []
    for it in items:
        slim.append({k: it[k] for k in
                     ("source", "title", "content", "content_type", "published", "link")
                     if k in it})
    payload = json.dumps(slim, ensure_ascii=False, indent=2)

    for model in GEMINI_MODELS:
        use_json = True
        for attempt in range(MAX_RETRIES):
            try:
                return _call_gemini(model, payload, use_json_mime=use_json)
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


# ── 코드 주입 사실을 LLM 결과에 병합 ──────────────────
def merge_facts(data, src_items):
    """
    LLM 결과 items에, 코드가 만든 facts(CVSS/EPSS/KEV)를 CVE 매칭으로 붙인다.
    매칭 키: 항목 텍스트에 등장하는 CVE.
    """
    # 원자료 항목별 facts 인덱스(첫 CVE 기준)
    facts_by_cve = {}
    for it in src_items:
        for f in it.get("facts", []):
            cve = f.split(" ")[0].upper()
            facts_by_cve.setdefault(cve, f)

    for it in data.get("items", []):
        text = f"{it.get('title','')} {it.get('summary','')} {it.get('impact','')}"
        cves = sorted({m.upper() for m in CVE_RE.findall(text)})
        merged = [facts_by_cve[c] for c in cves if c in facts_by_cve]
        if merged:
            it["_facts"] = merged   # 표시는 format 단계에서
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
    """facts 문자열들에서 CVSS 등급 추출(표시용)."""
    for f in facts:
        m = re.search(r"CVSS\s+([\d.]+)\s*\(([^)]+)\)", f)
        if m:
            return f"{m.group(2).title()} (CVSS {m.group(1)})", m.group(2)
    return "", ""


NUM = ["1\ufe0f\u20e3", "2\ufe0f\u20e3", "3\ufe0f\u20e3", "4\ufe0f\u20e3", "5\ufe0f\u20e3",
       "6\ufe0f\u20e3", "7\ufe0f\u20e3", "8\ufe0f\u20e3", "9\ufe0f\u20e3", "\U0001f51f"]


def format_blocks(data, today):
    blocks = []
    items = data.get("items", [])[:MAX_ITEMS]

    head = f"\U0001f6e1\ufe0f <b>보안 아침 브리핑</b> \u2014 {today}"
    head += f"\n\U0001f4ca 오늘 총 <b>{len(items)}</b>건"
    tldr = _esc(data.get("tldr"))
    if tldr:
        head += f"\n\n\U0001f4f0 <b>TL;DR</b>\n{tldr}"
    blocks.append(head)

    for i, it in enumerate(items):
        n = NUM[i] if i < len(NUM) else f"{i + 1}."
        facts = it.get("_facts", [])
        is_kev = any("KEV" in f for f in facts)

        title_line = f"{n} <b>{_esc(it.get('title'))}</b>"
        if is_kev:
            title_line += "  \U0001f6a8<b>실제 악용중</b>"
        lines = [title_line]

        # 심각도: 공식(NVD) 우선, 없으면 표시 안 함(LLM은 빈값 강제)
        sev_text, sev_raw = _sev_from_facts(facts)
        if sev_text:
            lines.append(f"{_sev_icon(sev_raw)} <b>심각도</b>: {_esc(sev_text)} <i>(NVD)</i>")

        if it.get("category"):
            lines.append(f"\U0001f3f7 <b>분류</b>: {_esc(it['category'])}")

        # EPSS(악용확률)
        epss_vals = []
        for f in facts:
            m = re.search(r"EPSS\s+([\d.]+%)", f)
            if m:
                cve = f.split(" ")[0]
                epss_vals.append(f"{cve} {m.group(1)}")
        if epss_vals:
            lines.append(f"\U0001f4c8 <b>악용확률(EPSS)</b>: {_esc(', '.join(epss_vals))}")

        pub = _esc(it.get("published"))
        if pub and pub not in _BLANK:
            lines.append(f"\U0001f5d3 <b>게시일</b>: {pub}")
        if it.get("summary"):
            lines.append(f"\U0001f4cc <b>핵심</b>: {_esc(it['summary'])}")
        if it.get("impact"):
            lines.append(f"\U0001f4a5 <b>영향</b>: {_esc(it['impact'])}")
        if it.get("mitigation"):
            lines.append(f"\U0001f6e1 <b>대응</b>: {_esc(it['mitigation'])}")
        if it.get("principle"):
            lines.append(f"\U0001f50d <b>원리</b>: {_esc(it['principle'])}")

        ioc = clean_iocs(it.get("ioc", ""))   # 더미 필터 적용
        if ioc:
            lines.append(f"\U0001f9e9 <b>IoC</b>: <code>{_esc(ioc)}</code>")
        atk = _esc(it.get("attack"))
        if atk and atk not in _BLANK:
            lines.append(f"\U0001f3af <b>ATT&amp;CK</b>: {atk}")
        if it.get("source"):
            lines.append(f"\U0001f517 {_esc(it['source'])}")
        blocks.append("\n".join(lines))

    blocks.append(
        "\u2139\ufe0f <i>심각도·EPSS·KEV는 NVD/FIRST/CISA 공식 데이터. "
        "핵심·원리·대응은 AI 요약이므로 대응 전 출처 원문 확인 권장.</i>"
    )
    return blocks


def send_telegram_blocks(blocks):
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id = os.environ["TELEGRAM_CHAT_ID"]
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    sep = "\n\n\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n\n"
    chunks, cur = [], ""
    for b in blocks:
        addition = (sep + b) if cur else b
        if cur and len(cur) + len(addition) > 3500:
            chunks.append(cur)
            cur = b
        else:
            cur += addition
    if cur:
        chunks.append(cur)
    for c in chunks:
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
    today = datetime.date.today().isoformat()

    kev_items, kev_cves = fetch_kev()
    rss = enrich_with_body(collect_rss_candidates())
    items = kev_items + rss
    print(f"총 후보: {len(items)}건 (KEV {len(kev_items)} + RSS {len(rss)})")

    if not items:
        send_telegram_plain(
            f"\U0001f6e1\ufe0f 보안 아침 브리핑 \u2014 {today}\n\n지난 24시간 내 신규 보안 항목이 없습니다."
        )
        return

    # [B][EPSS][KEV] 공식 데이터 주입(코드가 직접)
    enrich_cve_facts(items, kev_cves)

    # [LLM] 서술 요약
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

    data = merge_facts(data, items)        # 공식 사실 병합
    blocks = format_blocks(data, today)
    send_telegram_blocks(blocks)
    print("발송 완료")


if __name__ == "__main__":
    main()
