#!/usr/bin/env python3
"""
보안 아침 브리핑 봇 (정확도 개선본)
- 국내외 보안 RSS + CISA KEV 수집
- [개선1] 기사 '본문'을 직접 가져와(fetch) 모델에 제공 → 추측 대신 실제 근거로 요약
- [개선2] 엄격 프롬프트: 본문에 없는 CVE/CVSS/버전/ATT&CK는 만들지 않음
- [개선3] 텔레그램에 별표(**) 등 마크다운 기호가 노출되지 않도록 일반 텍스트로 정리
- Gemini(무료 티어)로 한국어 요약 → 텔레그램 발송
GitHub Actions cron으로 실행되므로 내 PC를 켜둘 필요가 없다.
"""
import os
import re
import html
import json
import datetime

import feedparser
import requests
import trafilatura

# ── 설정 ─────────────────────────────────────────────────────
FEEDS = {
    # 해외 뉴스
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "The Record": "https://therecord.media/feed/",
    # 국내 뉴스 (정확한 피드 URL은 https://www.boannews.com/custom/news_rss.asp 에서 확인)
    "보안뉴스": "https://www.boannews.com/media/news_rss.xml",
    # ── 선택: 모의해킹용 보강 소스. 켜려면 주석 해제 + URL 검증 ──
    # "PortSwigger Research": "https://portswigger.net/research/rss",
    # "Exploit-DB": "https://www.exploit-db.com/rss.xml",
}

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

HOURS = 24                 # 최근 몇 시간 내 글만
MAX_CANDIDATES_RSS = 10    # 본문 fetch 비용을 제한하기 위한 RSS 후보 상한(최신순)
ARTICLE_CHARS = 4000       # 기사 본문 추출 상한(토큰 절약)
MAX_ITEMS = 8              # 최종 브리핑 항목 수(모델이 선별)
GEMINI_MODEL = "gemini-2.5-flash"   # 무료 티어. 모델명은 Google AI Studio에서 확인 필요


# ── 유틸 ─────────────────────────────────────────────────────
def _clean(s: str) -> str:
    return re.sub(r"<[^>]+>", "", html.unescape(s or "")).strip()


# ── [개선1] 기사 본문 추출 ───────────────────────────────────
def fetch_article_text(url: str):
    """기사 URL에서 본문을 추출. 실패하면 None을 반환(→ snippet 폴백)."""
    if not url:
        return None
    try:
        resp = requests.get(
            url,
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (compatible; secnews-digest/1.0)"},
        )
        if resp.status_code != 200:
            return None
        text = trafilatura.extract(
            resp.text, include_comments=False, include_tables=False
        )
        if text and len(text.strip()) >= 200:
            return text.strip()[:ARTICLE_CHARS]
    except Exception:
        pass
    return None


# ── 수집: RSS 후보(본문 fetch 전) ────────────────────────────
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
                        "dt": dt,
                    })
                    n += 1
            ok.append(f"{src}({n})")
        except Exception as ex:
            fail.append(f"{src}: {ex}")
    print("RSS 수집 성공:", ", ".join(ok) or "없음")
    if fail:
        print("RSS 수집 실패:", " | ".join(fail))
    cands.sort(key=lambda x: x["dt"], reverse=True)   # 최신순
    return cands[:MAX_CANDIDATES_RSS]


# ── 본문 채우기(없으면 snippet 폴백) ─────────────────────────
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


# ── 수집: CISA KEV(실제 악용중, 신뢰 가능한 1차 정보) ────────
def fetch_kev():
    try:
        data = requests.get(
            KEV_URL, timeout=30, headers={"User-Agent": "secnews-digest"}
        ).json()
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
                "link": f'https://nvd.nist.gov/vuln/detail/{v.get("cveID", "")}',
            })
    print(f"KEV 신규 항목: {len(out)}건")
    return out


# ── [개선2] 엄격 프롬프트 + [개선3] 마크다운 기호 금지 ───────
PROMPT = """아래는 지난 24시간 동안 국내외 보안 소스에서 수집한 원자료(JSON)다.
각 항목의 content는 기사 본문(content_type=fulltext), 짧은 요약(snippet),
또는 CISA 권고(kev) 중 하나다.
너는 모의해킹·정보보안 실무자를 위한 한국어 아침 브리핑 편집자다.

[정확성 규칙 — 가장 중요]
- 오직 제공된 content 안에 있는 사실만 사용한다.
- content에 없는 CVE 번호·CVSS 점수·영향 버전·패치 버전·ATT&CK 기법 ID는
  절대 지어내지 않는다. 해당 정보가 없으면 그 필드에 "원문 확인"이라고만 쓴다.
- 추측·과장 금지. 불확실하면 "확인 필요"로 표시한다.

[형식 규칙]
- 마크다운 기호(*, **, #, _, `, >)를 절대 쓰지 마라. 텔레그램 일반 텍스트로
  보이므로 별표 등 기호가 그대로 노출된다. 강조가 필요하면 그냥 평문으로 쓴다.
- 맨 위에 [TL;DR] 2~3줄: 오늘 가장 중요한 위협/이슈 요약.
- 같은 사건을 여러 매체가 다루면 하나로 병합하고, 중요도 순으로 최대 8개만 선별한다.
  content_type=kev(실제 악용중) 항목을 최우선으로 둔다.
- 각 항목은 아래 형식을 지킨다(기호 없이):
  ▪ 제목 또는 CVE
   · 분류: 공격 유형(RCE/인증우회/권한상승/공급망/랜섬웨어 등)
   · 핵심: 무슨 일인지 1~2문장. 네 표현으로 재작성(원문 복붙 금지).
   · 영향: 영향받는 제품/버전/대상 (content에 없으면 "원문 확인").
   · 대응: 패치 버전·완화책·탐지 포인트 (content에 없으면 "원문 확인").
   · 원리: 이 공격/취약점이 왜 통하는지 핵심 메커니즘 1~2문장
           (content에 근거가 있을 때만; 없으면 "원문 확인").
   · ATT&CK: content에 근거가 있을 때만 기법 ID 표기(예: T1190). 아니면 생략.
   · 출처: link
- 한국어로만 작성(기술 용어는 영문 병기 가능). 텔레그램에서 읽기 좋은 분량으로.

원자료:
"""


def summarize(items):
    api_key = os.environ["GEMINI_API_KEY"]
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/"
        f"models/{GEMINI_MODEL}:generateContent?key={api_key}"
    )
    payload = json.dumps(items, ensure_ascii=False, indent=2)
    body = {"contents": [{"parts": [{"text": PROMPT + payload}]}]}
    r = requests.post(url, json=body, timeout=180)
    r.raise_for_status()
    data = r.json()
    return data["candidates"][0]["content"]["parts"][0]["text"]


# ── 발송: 텔레그램(일반 텍스트, 4096자 분할) ─────────────────
def send_telegram(text):
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id = os.environ["TELEGRAM_CHAT_ID"]
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    today = datetime.date.today().isoformat()
    text = f"🛡️ 보안 아침 브리핑 — {today}\n\n{text}"
    for i in range(0, len(text), 3900):
        chunk = text[i:i + 3900]
        resp = requests.post(
            url,
            data={
                "chat_id": chat_id,
                "text": chunk,
                "disable_web_page_preview": "true",
            },
            timeout=30,
        )
        resp.raise_for_status()


# ── 메인 ─────────────────────────────────────────────────────
def main():
    kev = fetch_kev()                                  # 1차 정보(추측 불필요)
    rss = enrich_with_body(collect_rss_candidates())   # 본문 fetch
    items = kev + rss                                  # KEV 우선
    print(f"총 후보: {len(items)}건 (KEV {len(kev)} + RSS {len(rss)})")
    if not items:
        send_telegram("지난 24시간 내 신규 보안 항목이 없습니다.")
        return
    digest = summarize(items)
    send_telegram(digest)
    print("발송 완료")


if __name__ == "__main__":
    main()
