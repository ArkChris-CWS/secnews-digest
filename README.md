# 보안 아침 브리핑 봇 (Telegram)

매일 아침 08:00(KST) 국내외 보안 뉴스 + CISA KEV(실제 악용 취약점)를 수집·요약해
텔레그램으로 보내는 봇. **GitHub Actions가 클라우드에서 실행하므로 내 PC를 켜둘 필요가 없다.**

```
수집(RSS + CISA KEV) → 요약(Gemini 무료 티어) → 발송(Telegram)
        └ GitHub Actions cron(매일 08:00 KST)이 자동 실행
```

비용: **0원** (GitHub Actions 무료 + Gemini 무료 티어 + 텔레그램 무료)

---

## 디렉터리 구조

```
secnews-digest/
├── main.py
├── requirements.txt
├── README.md
└── .github/
    └── workflows/
        └── daily.yml
```

---

## 셋업 (한 번만, 약 10분)

### 1. 텔레그램 봇 토큰 + chat_id

1. 텔레그램에서 `@BotFather` 검색 → `/newbot` → 안내대로 진행 → **봇 토큰** 받기
2. 방금 만든 봇과 대화창을 열고 아무 메시지나 한 번 전송
3. 브라우저에서 아래 주소 열기 (`<토큰>`을 본인 토큰으로 교체):
   `https://api.telegram.org/bot<토큰>/getUpdates`
4. 응답 JSON에서 `"chat":{"id": ...}` 의 숫자 = **chat_id**

### 2. Gemini API 키 (무료)

1. Google AI Studio(aistudio.google.com)에서 **API 키 발급** (신용카드 불필요)
2. ⚠️ 무료로 쓰려면 해당 프로젝트에 **결제(billing)를 켜지 말 것** — 켜면 무료 티어가 사라진다.

### 3. GitHub 저장소 + Secrets

1. 새 저장소 생성 후 이 파일들을 그대로 올린다.
   - 무료로 쓰려면 **public 저장소**가 가장 간단(Actions 무제한 무료).
   - private도 월 2,000분 무료라 이 작업(월 ~30분)은 무료 범위.
2. 저장소 **Settings → Secrets and variables → Actions → New repository secret** 에서 3개 등록:
   - `TELEGRAM_BOT_TOKEN`
   - `TELEGRAM_CHAT_ID`
   - `GEMINI_API_KEY`

### 4. 테스트 → 자동화

1. 저장소 **Actions** 탭 → `security-morning-digest` → **Run workflow** (수동 실행)
2. 텔레그램으로 브리핑이 오면 성공. 이후 매일 08:00(KST) 자동 발송된다.

---

## 소스 추가 / 검증

- 소스는 `main.py`의 `FEEDS` 딕셔너리에서 줄을 추가/주석 처리해 켜고 끈다.
- URL이 막히면 그 소스만 자동으로 건너뛰고, Actions 로그에 `RSS 수집 실패`로 표시된다.
- 모의해킹용 보강 소스(주석으로 포함됨): **PortSwigger Research**(웹 취약점 원리), **Exploit-DB**(PoC 출현).
  켤 때는 주석을 풀고 최신 RSS URL이 맞는지 확인할 것.
- 국내 공식 소스(KISA 보호나라/KrCERT, KNVD)도 RSS를 제공한다:
  - https://knvd.krcert.or.kr/rssList.do
  - https://krcert.or.kr/kr/subPage.do?menuNo=205121

---

## 알아둘 점

- **GitHub Actions 스케줄은 저장소가 60일간 활동(커밋 등)이 없으면 자동 중지**된다.
  중지되면 "다시 켜라"는 메일이 오고, 버튼 한 번으로 재개된다.
- GitHub cron은 부하 시간대에 수 분~수십 분 지연될 수 있다(정시 보장 X). "8시쯤"엔 충분.
- `main.py`의 `GEMINI_MODEL` 값(모델명)은 시점에 따라 바뀔 수 있으니, 호출이 실패하면
  Google AI Studio에서 사용 가능한 모델명을 확인해 교체한다.
- 요약의 "원리" 항목은 RSS 요약 기반이라 깊이가 제한적이다. 깊은 분석은 각 항목의
  출처 링크(패치 diff·CVE·연구 블로그)를 직접 보는 것을 전제로 한다.
