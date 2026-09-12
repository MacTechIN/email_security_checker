# MailShield v2 기술 조사: 이상 탐지 시 관리자 승인 전 메일 접근 차단

> 조사일: 2026-09-12 · 조사자: 보안 엔지니어링 리서치
> 대상 기능(v2 요구): "이상 탐지 시 로컬 사용자에게만 알림하는 대신, 지정된 관리자에게 메일을 보내고, 관리자가 확인/승인할 때까지 사용자가 해당 메시지에 접근하지 못하도록 차단한다."

---

## 1. 요약과 결론(핵심 5줄)

1. **진짜 '차단(enforcement)'은 배달 전(pre-delivery)에서만 가능하다.** Microsoft 365 / Google Workspace / Proofpoint / Mimecast의 격리는 모두 메시지가 사용자 사서함(INBOX)에 도달하기 *전에* 배달 경로에서 우회(divert)시켜 격리 큐에 잡아두고, 관리자/사용자가 release해야 비로소 배달한다. "숨긴다"가 아니라 "아직 배달하지 않는다"가 핵심이다.
2. **MailShield 같은 클라이언트 IMAP 앱은 배달된 메시지를 사용자로부터 진짜로 차단할 수 없다.** IMAP `UID MOVE` / `+X-GM-LABELS` / Gmail API `users.messages.modify(removeLabelIds:["INBOX"])`로 INBOX에서 치울 수는 있으나, 이는 Gmail의 "보관(archive)"과 동일해서 메시지는 **All Mail에 그대로 남고 검색·다른 클라이언트·모바일에서 즉시 재발견**된다. 라벨을 숨기는 커스텀 폴더도 사용자가 소유자이므로 언제든 되돌릴 수 있다.
3. **근본 한계**: 사용자가 사서함과 자격증명(앱 비밀번호/OAuth 토큰)을 *소유*하므로, 클라이언트 측 보류는 **강제(enforcement)가 아니라 권고(advisory)**일 뿐이다. 게다가 IMAP IDLE로 앱이 반응하기 전에 사용자가 다른 기기에서 먼저 읽는 **레이스 컨디션**을 막을 수 없다.
4. **진짜 차단이 필요하면 서버/관리자 통제가 전제**다. 개인 Gmail로는 불가능하고, **조직 소유 Google Workspace**에서 (a) content compliance/objectionable content 규칙으로 배달 전 관리자 격리, 또는 (b) 서비스 계정 + 도메인 전체 위임(domain-wide delegation)으로 서버가 사서함을 대리 제어하는 구조여야 한다. 또는 배달 경로에 프록시 메일 게이트웨이를 두는 방식이다.
5. **승인 워크플로 자체는 오픈소스로 충분히 구현 가능**하다. 관리자 알림 메일 발송(smtplib / Gmail API `users.messages.send`), 서명·만료 토큰(`itsdangerous` `URLSafeTimedSerializer` 또는 `PyJWT`) 기반 매직링크, 또는 Telegram/Slack 승인 버튼(콜백) 패턴이 표준적이다. **다만 프라이버시 관점에서 개인 사서함 소유자를 감시·차단하는 posture는 조직 소유 사서함 맥락에서만 정당화**된다.

---

## 2. 격리·보류 후 해제 모델 (상용 시스템은 어떻게 하나)

핵심 공통점: **모두 배달 전에 메시지를 가로채(divert) 격리 큐에 보관**하고, 승인(release) 시 배달한다. "사서함에 이미 있는 것을 숨기는" 방식이 아니다.

### 2.1 Microsoft 365 / Defender for Office 365
- 격리는 "안전하지 않을 수 있는 메시지를 담는 보안 보관 영역"으로, **검토·해제 전까지 받은편지함으로 배달되지 않는다**.
- **Release = 재배달(re-delivery)**: 해제하면 메시지가 그때 사서함으로 배달되며, Outlook에는 **원래 수신 시각이 아니라 재배달 시각**이 표시된다. 즉 물리적으로 in-place 복원이 아니라 큐에서 꺼내 새로 배달하는 구조임이 문서로 확인된다.
- **권한 모델**: 정책에 따라 사용자에게 `PermissionToRelease`(직접 해제) 또는 `PermissionToRequestRelease`(해제 요청)를 부여. 후자면 사용자가 요청 → 상태가 "Release requested"로 바뀌고 **관리자가 승인/거부**한다. 이 요청 승인 흐름이 바로 v2가 원하는 "관리자 확인 전 보류" 모델의 상용 레퍼런스다.
- **알림(digest)**: quarantine notification으로 사용자에게 격리 사실과 액션 링크 제공. 해제 요청 알림을 받으려면 감사 로깅이 켜져 있어야 함(기본 on).
- **API 한계(미확인/부분확인)**: Microsoft Graph는 현재 Exchange 격리를 직접 관리하는 정식 엔드포인트가 없다는 Q&A가 있음. `security/threatSubmission`(beta)는 위협 제출용이며 격리 release 관리와는 다르다. `ThreatSubmission.ReadWrite`는 **관리자 동의(admin consent) 필수**. 격리 release는 실무상 Defender 포털/Exchange Online PowerShell(`Get/Release-QuarantineMessage`)로 수행 (PowerShell cmdlet은 (미확인) — 문서 직접 확인 안 함).
  - 출처: learn.microsoft.com quarantine-policies / quarantine-admin-manage-messages-files / quarantine-quarantine-notifications; MS Q&A "Clarification on APIs for Managing Quarantine Emails".

### 2.2 Google Workspace 관리자 격리 (Admin Quarantine)
- **배달 전 격리 확정**: "관리자는 수신·발신 메일을 **배달되기 전에** 격리로 보내는 설정을 만들 수 있다"고 공식 문서가 명시.
- **설정 절차(콘솔)**: ① Menu → Apps → Google Workspace → Gmail → **Manage quarantines**에서 격리함 생성 → ② content compliance / objectionable content 등 **규칙(설정)**에서 트리거 조건에 "격리" 액션 연결.
- **관리자 액션**: (a) **Release** → 원래 수신자에게 배달, (b) **Block/Reject** → 배달하지 않고 (옵션) 발신자에게 통지. 어떤 규칙이 트리거됐는지 식별 가능.
- **권한/에디션**: Super administrator 또는 "Access Admin Quarantine" Gmail 권한 보유 관리자. 특정 에디션 제약은 문서에 명시 없음(미확인, 다만 Business/Enterprise 급 기능).
- **만료**: 조치가 없으면 **30일 후 자동 삭제**(복구 불가).
- content compliance 규칙 위반 시 "관리자 검토·승인 후 배달", 거부 시 사용자에게 통지 가능 — v2 요구와 가장 근접한 상용 메커니즘.
  - 출처: knowledge.workspace.google.com/admin/gmail/advanced/set-up-email-quarantine, manage-quarantined-messages; support.google.com/a/answer/1346936 (Control message delivery based on message content); workspaceupdates 2015/2017/2018 공지.

### 2.3 Proofpoint / Mimecast (게이트웨이형)
- 둘 다 **배달 경로 상의 게이트웨이**에서 메시지를 **held queue(보류 큐)**에 잡아둔다.
- **Quarantine Digest**: 사용자에게 정기 요약 메일 발송(Mimecast 하루 3회, Proofpoint Essentials 하루 최대 2회 ~9시/~15시). 사용자는 digest에서 **Release / Block / Permit** 수행.
- **Release = 1회성 배달**. "Release and Allow Sender"는 배달 + 향후 허용 필터 생성.
- 보존기간: Proofpoint 기본 14~30일.
- 시사점: **게이트웨이가 배달 경로 안에 있어야** 진짜 hold가 가능하다는 점을 재확인.
  - 출처: TAMU Proofpoint FAQ, USC Proofpoint digest guide, help.proofpoint.com Configuring User Digest Settings, Mimecast support (Configuring Digest Set Emails), frameworkit.com Mimecast held messages.

### 2.4 세 방식의 공통 메커니즘 표

| 방식 | 가로채는 지점 | 보류 형태 | 해제 = | 강제성 |
|---|---|---|---|---|
| M365/Defender | 배달 파이프라인 | 격리 스토어(사서함 밖) | 재배달 | 강제(서버) |
| Google Workspace | 배달 전 라우팅 | 관리자 격리함(사서함 밖) | 재배달 | 강제(관리자) |
| Proofpoint/Mimecast | 인입 게이트웨이 | held queue(게이트웨이) | 1회 배달 | 강제(게이트웨이) |
| **MailShield(클라이언트 IMAP)** | **배달 후 사서함 내부** | **라벨 이동(사서함 안)** | **라벨 복원** | **권고(비강제)** |

→ 결정적 차이: 상용은 **사서함 밖(배달 전)**에서 잡고, MailShield는 **사서함 안(배달 후)**에서만 움직일 수 있다.

---

## 3. 클라이언트 IMAP 앱이 '접근 차단'을 할 수 있는가 (가능/불가능의 정확한 경계)

### 3.1 결론 먼저
**할 수 없다(진짜 차단은 불가).** 배달이 이미 끝난 메시지에 대해 클라이언트가 할 수 있는 것은 "눈에 덜 띄게 옮기는 것"뿐이며, 사서함 소유자는 이를 즉시·완전히 되돌리거나 우회할 수 있다.

### 3.2 IMAP으로 할 수 있는 조작과 그 한계

**(a) INBOX에서 치우기 = Gmail "보관(archive)"과 동일**
- Gmail IMAP에서 각 폴더는 실제 위치가 아니라 **라벨**이다. "INBOX에서 삭제"는 사실상 **INBOX 라벨 제거**일 뿐이다.
- 명령 예:
  - IMAPClient: `client.remove_gmail_labels(uid, ['\\Inbox'])` 또는 raw `UID STORE <uid> -X-GM-LABELS (\\Inbox)`
  - 커스텀 라벨 부여: `UID STORE <uid> +X-GM-LABELS (MailShield-Hold)` (IMAP STORE 구문: `STORE 1 +X-GM-LABELS (foo)` / 제거는 `-X-GM-LABELS`).
  - 폴더 이동(비-Gmail 서버): `UID MOVE <uid> "MailShield-Hold"` (RFC 6851 MOVE). MOVE 미지원 서버는 `UID COPY` → `UID STORE +FLAGS (\Deleted)` → `EXPUNGE`.
- **한계**: 보관해도 메시지는 **All Mail에 그대로**다. 사용자가 검색(제목/발신자/키워드), 다른 데스크톱/모바일 클라이언트, Gmail 웹 "전체보관함"에서 **즉시 재발견**한다. "설계상 정상 동작"이며 버그가 아니다. 즉 INBOX 라벨 제거는 **숨김이 아니라 정리** 수준.

**(b) [Gmail]/Spam·Trash로 이동**
- 스팸/휴지통으로 옮겨도 사용자에게 그 폴더는 그대로 보인다. 오히려 "스팸함 확인" 습관 때문에 은폐 효과가 더 낮을 수 있고, 30일 후 삭제되는 부작용도 있음.

**(c) 커스텀 "MailShield-Hold" 라벨/폴더 + INBOX 제거**
- 가장 그럴듯하지만 여전히 **사용자가 그 폴더를 열면 끝**. 라벨을 IMAP `subscribe`에서 빼도 웹 UI/검색에는 노출. 앱이 IMAP `SEARCH X-GM-RAW`로 재감시할 수는 있으나 은폐는 불완전.

### 3.3 Gmail API 대안 (`users.messages.modify`)
- 엔드포인트: `POST https://gmail.googleapis.com/gmail/v1/users/{userId}/messages/{id}/modify`
- 바디: `{"removeLabelIds": ["INBOX"], "addLabelIds": ["Label_xxx"]}` (한 번에 최대 100개 라벨).
- **필요 스코프**: `https://www.googleapis.com/auth/gmail.modify` (또는 `https://mail.google.com/`). 라벨 생성은 `users.labels.create`.
- 효과는 IMAP 라벨 제거와 **동일**하다: INBOX에서만 사라지고 All Mail·검색에는 남는다. 즉 API를 써도 "숨김"의 본질적 한계는 그대로. `gmail.modify`는 삭제 불가(영구 삭제는 별도)라 파괴적 조작은 아님(장점).

### 3.4 근본 한계 (명확히)
- **소유자 = 자격증명 보유자**: 사용자가 앱 비밀번호/OAuth refresh token을 갖고 있으므로, 앱이 무엇을 하든 사용자는 같은 계정으로 다른 클라이언트에서 로그인해 라벨을 되돌리고 메시지를 읽을 수 있다. 클라이언트 hold는 정의상 **강제가 아니라 권고**.
- **레이스 컨디션**: MailShield는 IMAP IDLE로 EXISTS를 받은 *후*에야 반응한다(게다가 이 PC에서는 EXISTS가 `idle_done()`에서만 도착한다는 알려진 quirk 있음 — 메모리 참고). 그 사이 모바일 푸시 알림을 받은 사용자가 먼저 열람하면 차단 실패.
- **로컬 앱 변조**: 트레이 앱/설정/로컬 저장 토큰을 사용자가 종료·삭제·수정 가능.
- 대조: **진짜 배달 전 격리**는 서버/관리자 통제(§2, §3.5)에서만 성립.

### 3.5 조직 소유 Google Workspace에서 '가능한 것'
관리자가 통제하는 도메인이라면 진짜 강제가 가능:
1. **Content compliance / objectionable content 규칙**으로 조건 매칭 시 **배달 전 관리자 격리**(§2.2). 이것이 v2를 진짜로 구현하는 정공법. MailShield는 탐지 엔진 역할만 하거나, 규칙 트리거/조건을 관리하는 도구로 재포지셔닝.
2. **서비스 계정 + 도메인 전체 위임(domain-wide delegation)**: GCP에서 서비스 계정 생성 → Admin console → Security → Access and data control → API controls → **Manage Domain-Wide Delegation**에 client ID와 스코프 등록 → 서버가 **사용자 동의 없이** 임직원 사서함을 impersonate. Admin SDK로 대상 사서함 열거. 서버(관리자 신뢰)가 사서함을 대리 제어하므로 클라이언트 한계를 넘어선다.
   - 단, 이 경우도 Gmail API 조작은 여전히 "배달 후 라벨 이동"이라 은폐 한계는 동일. 진짜 배달 전 차단은 §2.2 규칙이 답.
3. **프록시 메일 게이트웨이**를 MX 경로에 배치(Proofpoint/Mimecast형) → 완전한 배달 전 hold.
   - 출처: developers.google.com/workspace/cloud-search/docs/guides/delegation, support.google.com/a/answer/14437356 (DWD best practices), Unipile Gmail API service account guide.

---

## 4. 관리자 승인 워크플로 설계와 코드

### 4.1 관리자 알림 메일 발송
앱은 이미 사용자 앱 비밀번호/OAuth를 갖고 있어 **사용자로서 발송은 자명**. 다만 감사·신뢰상 **별도 서비스 계정/전용 SMTP로 발송이 더 깔끔**.

- **smtplib (Gmail SMTP)**: `smtp.gmail.com:587` STARTTLS + 앱 비밀번호. 표준적, 의존성 0.
- **Gmail API `users.messages.send`**: MIME 생성 → `base64.urlsafe_b64encode(mime.as_bytes()).decode()` → `service.users().messages().send(userId="me", body={"raw": raw}).execute()`. 스코프 `gmail.send`.
  - 흔한 함정: Python3에서 `as_string()` 쓰면 `TypeError: a bytes-like object is required` → 반드시 `as_bytes()`.
- **SendGrid / Amazon SES**: 조직 배포 시 전용 발신 도메인·평판 관리에 유리(대안, 미검증 세부).

### 4.2 관리자가 "확인"하는 방식

| 방식 | 구현 | 장점 | 단점 |
|---|---|---|---|
| (a) 매직 링크/토큰 URL | 서명·만료 토큰을 담은 링크 → 소형 웹 엔드포인트가 검증 후 release | UX 최고, 원클릭 | 웹 서버/엔드포인트 필요, 토큰 유출·프리페치 위험 |
| (b) 회신-승인(reply-to-approve) | 관리자가 "APPROVE" 회신 → 앱이 IMAP으로 파싱 | 서버 불필요 | 파싱 신뢰성·위조 위험, 지연 |
| (c) 코드 회신 | 관리자가 일회용 코드 입력/회신 | 간단 | UX 나쁨 |
| (d) 관리자 콘솔/봇 | Telegram/Slack 버튼 콜백 | 즉시성, 감사로그 | 봇 인프라 필요 |

### 4.3 보안 토큰 설계 (권장)
- **itsdangerous `URLSafeTimedSerializer`**: HMAC(SECRET_KEY)로 서명, `max_age`로 만료. 변조 시 서명 불일치, 위조 불가.
  ```python
  from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
  s = URLSafeTimedSerializer(SECRET_KEY, salt="mailshield-release")
  token = s.dumps({"msg_id": gm_msgid, "action": "release", "admin": admin_email})
  # 링크: https://host/release?t=<token>
  try:
      data = s.loads(token, max_age=86400)  # 24h
  except SignatureExpired: ...   # 만료
  except BadSignature: ...       # 변조/위조
  ```
- **PyJWT** 대안: `jwt.encode({"exp": datetime.utcnow()+timedelta(hours=24), "msg_id":..., "act":"release"}, SECRET, algorithm="HS256")`, 검증 시 `jwt.decode(..., algorithms=["HS256"])` → `ExpiredSignatureError` 처리. 만료는 UTC 기준.
- **토큰 하드닝 원칙(연구 종합)**: 충분히 길고 예측 불가, **동작·수신자에 바인딩(scoped)**, **짧은 만료**, **1회성(single-use, 서버에 사용 상태 저장)**, 실패 시 **rate-limit**, 유출 의심 시 즉시 revoke. 이메일 매직링크는 **메일 클라이언트/보안 스캐너의 URL 프리페치가 토큰을 소모**할 수 있으므로 GET 한 번으로 상태를 바꾸지 말고 **확인 페이지(POST) 2단계**를 두는 것이 안전.

### 4.4 회신-승인 파싱
- `email-reply-parser`(PyPI, RubyGems 원본 포팅)로 인용문 제거 후 최신 회신 본문만 추출 → 키워드(APPROVE/RELEASE/DENY) 매칭. GitHub 계열 manual-approval 액션의 승인 키워드 관례: approve/approved/lgtm/yes, 거부: deny/denied/no.
- **위험**: 발신 주소 위조(SPF/DKIM 미검증 시), 회신 본문 위·변조. 회신-승인은 반드시 **서명 토큰을 본문/헤더에 동봉**해 병행 검증할 것(회신만으로 신뢰 금지).

### 4.5 오픈소스 승인 워크플로 레퍼런스
- **trstringer/manual-approval**, **sede-open/manual-approval** (GitHub Actions): 이슈 생성 → 승인자 코멘트 키워드로 진행. "four-eyes/2인 승인" 패턴과 키워드 관례를 그대로 차용 가능.
- **Telegram(python-telegram-bot / aiogram) InlineKeyboard 콜백**: 관리자 채팅에 [승인][거부] 버튼 → `callback_data`(1~64 bytes)에 토큰/메시지ID 실어 처리. human-in-the-loop 승인의 대표 패턴.
- **Slack**: interactive message buttons + 서명 검증(Signing Secret)으로 동일 구성(미검증 세부).

---

## 5. 재사용 가능한 오픈소스 (표)

| 이름 | URL | 언어 | 라이선스 | 최근 활동 | 재사용 포인트 |
|---|---|---|---|---|---|
| imap_tools | https://github.com/ikvk/imap_tools | Python (3.8+) | Apache-2.0 | v1.15.0 (2026-08-06) 활발 | 고수준 MailBox: `move/copy/flag/append`, IDLE start/poll/stop/wait, query builder. INBOX 라벨 이동·보류 폴더 처리에 최적. 외부 의존성 0 |
| IMAPClient | https://github.com/mjs/imapclient | Python (3.8–3.14) | New BSD | v3.0.1, 유지보수됨 | `move/copy/expunge`, `add_gmail_labels/remove_gmail_labels`, `idle`, UID 투명 처리. Gmail 라벨 조작 API가 깔끔 |
| google-api-python-client | https://github.com/googleapis/google-api-python-client | Python | Apache-2.0 | 활발(구글 공식) | Gmail API `users.messages.modify`(INBOX 제거/커스텀 라벨), `users.messages.send`, `users.labels.*`. 서비스 계정+DWD 조직 시나리오 |
| itsdangerous | https://github.com/pallets/itsdangerous | Python | BSD-3-Clause | Pallets 유지(활발) | `URLSafeTimedSerializer` 서명·만료 승인 토큰/매직링크 |
| PyJWT | https://github.com/jpadilla/pyjwt | Python | MIT | 활발 (2.x) | JWT 승인 토큰(exp/HS256), `ExpiredSignatureError` 처리 |
| SpamScope/mail-parser | https://github.com/SpamScope/mail-parser | Python (3) | Apache-2.0 | 유지보수됨(.msg 지원 등) | 격리 대상 메일 본문/헤더/첨부/발신IP 파싱→관리자 알림 요약 생성 |
| email-reply-parser | https://github.com/zapier/email-reply-parser (PyPI: email-reply-parser) | Python | MIT (미확인 정확 라이선스) | 사용 다수 | reply-to-approve 시 최신 회신 본문 추출 |
| python-telegram-bot | https://github.com/python-telegram-bot/python-telegram-bot | Python | LGPL-3.0 | v22.x 활발 | InlineKeyboard 승인/거부 버튼 콜백(관리자 승인 봇) |
| trstringer/manual-approval | https://github.com/trstringer/manual-approval | Go | MIT | 유지보수됨 | 승인/거부 키워드 관례·2인 승인 로직 참고 |

> "개인용 격리(personal quarantine)" 성격의 완성형 OSS는 조사 범위에서 **발견되지 않음(미확인)**. 격리는 대부분 게이트웨이/서버 제품 영역이라 개인 IMAP 클라이언트용 기성 프로젝트는 사실상 없음.

---

## 6. 보안·무결성·프라이버시 한계

### 6.1 무결성(왜 강제가 안 되는가)
- **자격증명 소유권**: 사용자가 계정 소유자 → 앱의 라벨/폴더 조작을 다른 클라이언트로 즉시 되돌리고 읽을 수 있음. 클라이언트 hold는 **비강제(advisory)**.
- **레이스**: IMAP IDLE 반응 지연(+ 본 PC의 EXISTS/idle_done quirk) 동안 모바일 푸시로 먼저 열람 가능 → **탐지-차단 사이 창(window)** 존재.
- **로컬 변조**: 트레이 앱 종료/삭제/설정 변경, 로컬 저장 토큰 추출 가능.
- **은폐 불가**: INBOX 라벨 제거/보관은 All Mail·검색·타 클라이언트에 그대로 노출(§3.2). "안 보이게"가 성립하지 않음.
- **토큰/링크 위험**: 매직링크 프리페치 소모, 회신-승인 위조 → §4.3 하드닝 필수.

### 6.2 프라이버시·동의(중요)
- **개인 Gmail**에서 소유자 본인의 사적 메일 메타데이터를 **제3자 "관리자"에게 전송**하고, 소유자가 자기 메일에 접근하는 것을 **차단**하려는 것은 본질적으로 **감시/DLP posture**다. 이는 **조직이 소유·관리하는 사서함**에서만 정당화되며, 개인 계정에 적용하면 (a) 소유자 스스로를 차단하는 모순, (b) 제3자에게 사적 통신을 유출하는 프라이버시 침해가 된다.
- 따라서 v2 차단 기능은 **개인 Gmail 대상 기본 비활성**이 옳고, **조직 관리형 배포에서 관리자·사용자 사전 고지·동의 하에서만** 켜야 한다. 로그/알림에 담기는 메일 내용은 최소화(제목·발신자·탐지사유 정도)하고 본문 원문 전송은 지양.

### 6.3 진짜 강제 가능한 조직 아키텍처
1. **Google Workspace content compliance 규칙 → 배달 전 관리자 격리 → release/reject** (정공법, §2.2).
2. **서비스 계정 + 도메인 전체 위임**으로 서버가 사서함 대리 제어(관리자 신뢰 기반, §3.5).
3. **MX 경로 프록시 게이트웨이**(Proofpoint/Mimecast형 held queue, §2.3).
- 세 경우 모두 **사서함이 조직 소유**이고, 통제 지점이 **배달 경로/서버**에 있어야 강제가 성립.

---

## 7. MailShield 적용안 (개인 Gmail vs 조직 Workspace 두 갈래, 단계별)

### 갈래 A — 개인 Gmail (현재 MailShield 구조)
차단은 **강제 불가**이므로 "차단"이 아니라 **"보류형 넛지(advisory hold)"**로 정직하게 포지셔닝.

- **Step A1 — 탐지 후 즉시 보류 이동**: `imap_tools`/IMAPClient로 INBOX 라벨 제거 + `MailShield-Hold` 라벨 부여(Gmail API `modify`로도 동일). 사용자에게 "관리자 승인 대기 중" 로컬 알림.
- **Step A2 — 관리자 알림**: smtplib 또는 Gmail API `send`로 관리자에게 요약(제목/발신자/탐지사유 + 서명 토큰 매직링크). mail-parser로 요약 생성.
- **Step A3 — 승인 처리**: itsdangerous/PyJWT 토큰 검증(만료·1회성). 승인 시 `+X-GM-LABELS (\\Inbox)`로 복원, 거부 시 라벨 유지 또는 Trash.
- **Step A4 — 한계 고지(필수)**: UI/문서에 "사용자가 검색·타 클라이언트로 접근 가능, 강제 차단 아님"을 명시. 개인 계정에서 관리자 전송은 기본 off + 명시적 동의.
- **레이스 완화(부분)**: IDLE 반응 최적화(본 PC quirk 대응: `idle_done()` 기반), 그래도 완전 차단 불가임을 인정.

### 갈래 B — 조직 Google Workspace (진짜 강제 목표)
- **Step B1 — 배달 전 격리로 이전**: MailShield의 탐지 로직을 유지하되 차단은 **Google Workspace content compliance / objectionable content 규칙 + 관리자 격리**로 수행(배달 전 hold, release/reject). MailShield는 탐지 신호 제공/규칙 관리 도구로 진화.
- **Step B2 — 서버 대리 제어(선택)**: 서비스 계정 + 도메인 전체 위임 등록(Admin console → API controls → Manage DWD, 스코프 `gmail.modify` 등) → 서버가 사서함 대리 조작·승인.
- **Step B3 — 승인 워크플로**: §4 그대로(매직링크/Telegram·Slack 버튼), 감사 로그 필수.
- **Step B4 — 거버넌스**: 관리자 권한 최소화(Access Admin Quarantine 권한), 30일 만료 정책 인지, 사용자 사전 고지.

### 우선순위 권고
- **단기**: 갈래 A의 "advisory hold + 관리자 알림 + 서명 토큰 승인"을 정직한 한계 고지와 함께 구현(개인 Gmail에서 실현 가능한 최대치).
- **중장기**: 조직 시장을 노린다면 갈래 B(Workspace 배달 전 격리 연동)로 재설계해야 "진짜 차단"이 성립.

---

## 8. 출처 URL 목록

- Microsoft 365 격리 정책: https://learn.microsoft.com/en-us/defender-office-365/quarantine-policies
- 관리자 격리 메시지 관리(release=재배달): https://learn.microsoft.com/en-us/defender-office-365/quarantine-admin-manage-messages-files
- 격리 알림/해제 요청: https://learn.microsoft.com/en-us/defender-office-365/quarantine-quarantine-notifications
- 격리 FAQ: https://learn.microsoft.com/en-us/defender-office-365/quarantine-faq
- MS Graph 격리 API 한계(Q&A): https://learn.microsoft.com/en-us/answers/questions/2140099/clarification-on-apis-for-managing-quarantine-emai
- MS Graph threatSubmission(admin consent): https://learn.microsoft.com/en-us/graph/api/resources/security-threatsubmission
- Google Workspace 격리 설정: https://knowledge.workspace.google.com/admin/gmail/advanced/set-up-email-quarantine
- Google Workspace 격리 메시지 관리: https://knowledge.workspace.google.com/admin/gmail/advanced/manage-quarantined-messages
- 콘텐츠 기반 배달 제어(content compliance): https://support.google.com/a/answer/1346936?hl=en
- 관리자 격리 공지: https://workspaceupdates.googleblog.com/2015/02/admin-quarantine-for-inbound-and.html
- Gmail IMAP 확장(X-GM-LABELS/RAW/MSGID, STORE 구문): https://developers.google.com/workspace/gmail/imap/imap-extensions
- Gmail API users.messages.modify(스코프/라벨): https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/modify
- Gmail 보관=INBOX 라벨 제거, All Mail 잔존: https://support.google.com/mail/answer/6576
- 도메인 전체 위임 가이드: https://developers.google.com/workspace/cloud-search/docs/guides/delegation
- DWD 베스트프랙티스: https://support.google.com/a/answer/14437356?hl=en
- Gmail API 서비스계정/DWD(2026 가이드): https://www.unipile.com/gmail-api-service-account-domain-wide-delegation/
- Proofpoint 격리 FAQ: https://service.tamu.edu/TDClient/36/Portal/KB/Article/491/Proofpoint-Email-Quarantine-FAQ
- Proofpoint digest 설정: https://help.proofpoint.com/Proofpoint_Essentials/Email_Security/User_Topics/040_spamsettings/Configuring_User_Digest_Settings
- Mimecast digest 설정: https://mimecastsupport.zendesk.com/hc/en-us/articles/34000742702739
- Mimecast held messages: https://www.frameworkit.com/knowledge-base/how-to-use-mimecast-for-held-messages
- imap_tools: https://github.com/ikvk/imap_tools · PyPI: https://pypi.org/project/imap-tools/
- IMAPClient: https://github.com/mjs/imapclient · docs: https://imapclient.readthedocs.io/
- google-api-python-client(send 예제 이슈): https://github.com/googleapis/google-api-python-client/issues/93
- SpamScope/mail-parser: https://github.com/SpamScope/mail-parser
- itsdangerous URLSafeTimedSerializer 사용: https://pyjwt.readthedocs.io/ (PyJWT) / https://itsdangerous.palletsprojects.com/
- PyJWT 사용예: https://pyjwt.readthedocs.io/en/latest/usage.html
- 승인 워크플로(GitHub Actions): https://github.com/trstringer/manual-approval , https://github.com/sede-open/manual-approval
- Telegram InlineKeyboardButton(콜백): https://docs.python-telegram-bot.org/en/stable/telegram.inlinekeyboardbutton.html
- URL에 이메일/토큰 노출 위험: https://www.suped.com/learn/email-deliverability/what-are-the-risks-of-including-email-addresses-as-url-parameters
