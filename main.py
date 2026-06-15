#!/usr/bin/env python3
"""
보안 아침 브리핑 봇 (실무 강화본 v5)
변경 요약:
- [품질] 헤더에 '오늘 총 N건' 카운트
- [품질] 항목별 심각도(🔴 Critical/CVSS) — 근거 있을 때만, 없으면 '원문 확인'
- [품질] 항목별 게시일(🗓) — RSS pubDate를 코드가 직접 주입(LLM 환각 방지)
- [품질] IoC 섹션(🧩) — 본문에 IP/해시/도메인/CVE가 있을 때만
- [안정성] 503/500/429/타임아웃 backoff 재시도(최대 4회) + 모델 폴백
- [안정성] response_mime_type 거부 모델이면 옵션 빼고 재시도
- [안정성] 끝까지 실패 시 '일시 오류' 알림만 보내고 워크플로 성공 종료
- [핵심] AT&T의 &, 버전 < 등 특수문자 html.escape로 안전 처리
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
FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "The Record": "https://therecord.media/feed/",
    "보안뉴스": "https://www.boannews.com/media/news_rss.xml",
    # "PortSwigger Research": "https://portswigger.net/research/rss",
    # "Exploit-DB": "https://www.exploit-db.com/rss.xml",
}

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

HOURS = 24
MAX_CANDIDATES_RSS = 10
ARTICLE_CHARS = 4000
MAX_ITEMS = 8

GEMINI_MODELS = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-flash-latest"]
MAX_RETRIES = 4
RETRYABLE_STATUS = (429, 500, 502, 503, 504)


# ── 유틸 ──────────────────────────────────────────────
def _clean(s: str) -> str:
    return re.sub(r"<[^>]+>", "", html.unescape(s or "")).strip()


def fetch_article_text(url: str):
    if not url:
        return None
    try:
        resp = requests.get(
            url, timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (compatible; secnews-digest/1.0)"},
        )
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
    cands, ok, fail = [], [], []
    for src, url in FEEDS.items():
        try:
            feed = feedparser.parse(url)
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
                        "published": dt.strftime("%Y-%m-%d"),   # 게시일(코드가 주입)
                        "dt": dt,
                    })
                    n += 1
            ok.append(f"{src}({n})")
        except Exception as ex:
            fail.append(f"{src}: {ex}")
    print("RSS 수집 성공:", ", ".join(ok) or "없음")
    if fail:
        print("RSS 수집 실패:", " | ".join(fail))
    cands.sort(key=lambda x: x["dt"], reverse=True)
    return cands[:MAX_CANDIDATES_RSS]


def enrich_with_body(cands):
    full, snip = 0, 0
    for it in cands:
        body = fetch_article_text(it["link"])
        if body:
            it["content"] = body
            it["content_type"] = "fulltext"
            full += 1
        else:
            it["content"] = it.get("summary", "")
            it["content_type"] = "snippet"
            snip += 1
        it.pop("summary", None)
        it.pop("dt", None)
    print(f"본문 추출: 성공 {full}건 / snippet 폴백 {snip}건")
    return cands


def fetch_kev():
    try:
        data = requests.get(KEV_URL, timeout=30, headers={"User-Agent": "secnews-digest"}).json()
    except Exception as ex:
        print("KEV 수집 실패:", ex)
        return []
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
    print(f"KEV 신규 항목: {len(out)}건")
    return out


# ── 요약 프롬프트(구조화 JSON + 환각 억제 + 신규 필드) ──
PROMPT = """아래는 지난 24시간 국내외 보안 소스에서 수집한 원자료(JSON)다.
각 항목의 content는 기사 본문(content_type=fulltext), 짧은 요약(snippet),
또는 CISA 권고(kev) 중 하나다. published 필드는 원문 게시일이며 이미 주어졌다.
너는 모의해킹·정보보안 실무자를 위한 한국어 아침 브리핑 편집자다.

[정확성 규칙 — 가장 중요]
- 오직 제공된 content 안에 있는 사실만 사용한다.
- content에 없는 CVE 번호·CVSS 점수·심각도·영향 버전·패치 버전·ATT&CK ID·IoC는
  절대 지어내지 않는다. 없으면 그 필드 값에 "원문 확인"이라고만 쓴다(severity는 ""로).
- 추측·과장 금지. 불확실하면 "확인 필요"로 표시한다.

[선별 규칙]
- 같은 사건을 여러 매체가 다루면 하나로 병합하고, 중요도 순으로 최대 8개만 고른다.
- content_type=kev(실제 악용중) 항목을 최우선으로 둔다.

[출력 형식 — 매우 중요]
- 반드시 아래 구조의 JSON만 출력한다. 코드펜스나 설명 문장을 붙이지 마라.
- 모든 값은 한국어로 작성한다(기술 용어는 영문 병기 가능).
- summary, principle은 각각 1~2문장으로 간결하게. 마크다운 기호(*, **, #, _)를 쓰지 마라.

{
  "tldr": "오늘 가장 중요한 위협/이슈를 2~3문장으로 요약",
  "items": [
    {
      "title": "제목 또는 CVE 번호",
      "severity": "content에 CVSS/심각도 근거가 있을 때만: Critical|High|Medium|Low (+가능하면 'CVSS 9.8' 병기). 근거 없으면 빈 문자열",
      "category": "공격 유형 (RCE/인증우회/권한상승/공급망/피싱/랜섬웨어/정보유출 등)",
      "summary": "무슨 일인지 1~2문장 (재작성, 원문 복붙 금지)",
      "impact": "영향받는 제품/버전/대상 (없으면 원문 확인)",
      "mitigation": "패치 버전·완화책·탐지 포인트 (없으면 원문 확인)",
      "principle": "이 공격/취약점이 왜 통하는지 1~2문장 (근거 없으면 원문 확인)",
      "ioc": "content에 실제로 있는 IoC만 (IP/도메인/해시/CVE 등) 쉼표로. 없으면 빈 문자열",
      "attack": "근거 있으면 ATT&CK 기법 ID(예: T1566). 여러 개면 쉼표. 없으면 빈 문자열",
      "published": "해당 항목의 원문 published 값을 그대로 복사",
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
    payload = json.dumps(items, ensure_ascii=False, indent=2)
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
                print(f"[{model}] 호출 실패({e}) → {wait}s 후 재시도 [{attempt + 1}/{MAX_RETRIES}]")
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


def _esc(s):
    return html.escape(str(s or "").strip(), quote=False)


_BLANK = ("", "원문 확인", "없음", "N/A", "-", "확인 필요")


def _sev_icon(sev):
    s = sev.lower()
    if "crit" in s:
        return "\U0001f534"   # 🔴
    if "high" in s:
        return "\U0001f7e0"   # 🟠
    if "medium" in s or "mod" in s:
        return "\U0001f7e1"   # 🟡
    if "low" in s:
        return "\U0001f7e2"   # 🟢
    return "\u26aa"           # ⚪


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
        lines = [f"{n} <b>{_esc(it.get('title'))}</b>"]

        sev = _esc(it.get("severity"))
        if sev and sev not in _BLANK:
            lines.append(f"{_sev_icon(sev)} <b>심각도</b>: {sev}")
        if it.get("category"):
            lines.append(f"\U0001f3f7 <b>분류</b>: {_esc(it['category'])}")
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
        ioc = _esc(it.get("ioc"))
        if ioc and ioc not in _BLANK:
            lines.append(f"\U0001f9e9 <b>IoC</b>: <code>{ioc}</code>")
        atk = _esc(it.get("attack"))
        if atk and atk not in _BLANK:
            lines.append(f"\U0001f3af <b>ATT&amp;CK</b>: {atk}")
        if it.get("source"):
            lines.append(f"\U0001f517 {_esc(it['source'])}")
        blocks.append("\n".join(lines))
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
        resp = requests.post(
            url,
            data={"chat_id": chat_id, "text": c, "parse_mode": "HTML",
                  "disable_web_page_preview": "true"},
            timeout=30,
        )
        resp.raise_for_status()


def send_telegram_plain(text):
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id = os.environ["TELEGRAM_CHAT_ID"]
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    for i in range(0, len(text), 3900):
        requests.post(
            url,
            data={"chat_id": chat_id, "text": text[i:i + 3900],
                  "disable_web_page_preview": "true"},
            timeout=30,
        ).raise_for_status()


def main():
    today = datetime.date.today().isoformat()

    kev = fetch_kev()
    rss = enrich_with_body(collect_rss_candidates())
    items = kev + rss
    print(f"총 후보: {len(items)}건 (KEV {len(kev)} + RSS {len(rss)})")

    if not items:
        send_telegram_plain(
            f"\U0001f6e1\ufe0f 보안 아침 브리핑 \u2014 {today}\n\n지난 24시간 내 신규 보안 항목이 없습니다."
        )
        return

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

    blocks = format_blocks(data, today)
    send_telegram_blocks(blocks)
    print("발송 완료")


if __name__ == "__main__":
    main()
