#!/usr/bin/env python3
"""
보안 아침 브리핑 봇
- 국내외 보안 RSS + CISA KEV(실제 악용 취약점) 수집
- Gemini(무료 티어)로 모의해킹 실무용 한국어 요약
- 텔레그램으로 매일 아침 발송
GitHub Actions cron으로 실행되므로 내 PC를 켜둘 필요가 없다.
"""
import os
import re
import html
import json
import datetime

import feedparser
import requests

# ── 설정 ─────────────────────────────────────────────────────
# 소스를 켜고 끄려면 줄을 주석(#) 처리/해제. URL이 막히면 자동으로 건너뜀.
FEEDS = {
    # 해외 뉴스
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "The Record": "https://therecord.media/feed/",

    # 국내 뉴스 (정확한 피드 URL은 https://www.boannews.com/custom/news_rss.asp 에서 확인)
    "보안뉴스": "https://www.boannews.com/media/news_rss.xml",

    # ── 선택: 모의해킹용 보강 소스 (원리·PoC). 켜려면 주석 해제 + URL 검증 ──
    # "PortSwigger Research": "https://portswigger.net/research/rss",  # 웹 취약점 원리(추천)
    # "Exploit-DB": "https://www.exploit-db.com/rss.xml",              # PoC/익스플로잇 출현

    # 국내 공식(KISA 보호나라/KrCERT, KNVD)도 RSS를 제공한다. 정확한 피드 URL은
    #   https://knvd.krcert.or.kr/rssList.do
    #   https://krcert.or.kr/kr/subPage.do?menuNo=205121
    # 에서 확인해 위 형식대로 추가하면 된다.
}

# CISA KEV(Known Exploited Vulnerabilities, 실제 악용중 취약점) — 가장 중요한 소스
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

HOURS = 24            # 최근 몇 시간 내 글만 수집
MAX_ITEMS = 8         # 브리핑 최대 항목 수(요약 프롬프트에도 반영)
GEMINI_MODEL = "gemini-2.5-flash"   # 무료 티어. 모델명은 Google AI Studio에서 최신값 확인 필요


# ── 유틸 ─────────────────────────────────────────────────────
def _clean(s: str) -> str:
    """HTML 태그/엔티티 제거."""
    return re.sub(r"<[^>]+>", "", html.unescape(s or "")).strip()


# ── 수집: RSS ────────────────────────────────────────────────
def fetch_rss():
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=HOURS)
    items, ok, fail = [], [], []
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
                    items.append({
                        "source": src,
                        "title": _clean(e.get("title", "")),
                        "summary": _clean(e.get("summary", ""))[:600],
                        "link": e.get("link", ""),
                    })
                    n += 1
            ok.append(f"{src}({n})")
        except Exception as ex:  # 한 소스가 죽어도 전체는 계속
            fail.append(f"{src}: {ex}")
    print("RSS 수집 성공:", ", ".join(ok) or "없음")
    if fail:
        print("RSS 수집 실패:", " | ".join(fail))
    return items


# ── 수집: CISA KEV ───────────────────────────────────────────
def fetch_kev():
    try:
        data = requests.get(
            KEV_URL, timeout=30, headers={"User-Agent": "secnews-digest"}
        ).json()
    except Exception as ex:  # 차단 시 github.com/cisagov/kev-data 미러로 교체 가능
        print("KEV 수집 실패:", ex)
        return []
    cutoff = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
    out = []
    for v in data.get("vulnerabilities", []):
        if v.get("dateAdded", "") >= cutoff:
            out.append({
                "source": "CISA KEV (실제 악용중)",
                "title": f'{v.get("cveID", "")} - {v.get("vulnerabilityName", "")}',
                "summary": v.get("shortDescription", ""),
                "link": f'https://nvd.nist.gov/vuln/detail/{v.get("cveID", "")}',
            })
    print(f"KEV 신규 항목: {len(out)}건")
    return out


# ── 요약: Gemini(무료 티어) ──────────────────────────────────
PROMPT = """아래는 지난 24시간 동안 국내외 보안 소스에서 수집한 원자료(JSON)다.
너는 모의해킹·정보보안 실무자를 위한 한국어 아침 브리핑 편집자다.

작성 규칙:
1. 맨 위에 [TL;DR] 2~3줄: 오늘 가장 중요한 위협/이슈를 요약.
2. 같은 사건을 여러 매체가 다루면 하나로 병합하고, 중요도 순으로 최대 8개만 선별한다.
   CISA KEV(실제 악용중) 항목을 최우선으로 둔다.
3. 각 항목은 아래 형식을 지킨다:
   ▪ <제목 또는 CVE>
    · 분류: 공격 유형 (RCE/인증우회/권한상승/공급망/랜섬웨어 등)
    · 핵심: 무슨 일인지 1~2문장. 반드시 네 표현으로 재작성(원문 복붙 금지).
    · 영향: 영향받는 제품/버전/대상.
    · 대응: 구체적 조치 — 패치 버전, 완화책, 탐지 포인트.
    · 원리: 이 공격/취약점이 왜 통하는지 핵심 메커니즘 1~2문장.
            정보가 부족하면 '원문 참고 필요'라고만 쓴다(추측 금지).
    · ATT&CK: 관련 기법 ID가 명확하면 표기(예: T1190). 불명확하면 생략.
    · 출처: <link>
4. 과장/추측 금지. 불확실하면 '확인 필요'로 표시.
5. 한국어로만 작성(기술 용어는 영문 병기 가능). 텔레그램에서 읽기 좋은 분량으로.

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
    r = requests.post(url, json=body, timeout=120)
    r.raise_for_status()
    data = r.json()
    return data["candidates"][0]["content"]["parts"][0]["text"]


# ── 발송: 텔레그램 ───────────────────────────────────────────
def send_telegram(text):
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id = os.environ["TELEGRAM_CHAT_ID"]
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    today = datetime.date.today().isoformat()
    text = f"🛡️ 보안 아침 브리핑 — {today}\n\n{text}"
    for i in range(0, len(text), 3900):   # 텔레그램 메시지 4096자 제한 → 분할
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
    items = fetch_kev() + fetch_rss()      # KEV를 앞에 두어 우선순위 반영
    print(f"총 수집: {len(items)}건")
    if not items:
        send_telegram("지난 24시간 내 신규 보안 항목이 없습니다.")
        return
    digest = summarize(items)
    send_telegram(digest)
    print("발송 완료")


if __name__ == "__main__":
    main()
