# BYTE BACK 방어전 자료실 — 12단계 저장점

이 저장소는 BYTE BACK 방어전 시작 틀 R5에서 출발한 학생 자료실입니다. 메모는 모두 실습용 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

- 배포 주소: https://choi-bujang-secret-vault-opal.vercel.app
- 현재 단계: 12단계(탈환 작전실을 완성합니다) 저장점 · 검사한 실행 코드 커밋 `2e902cd`

## 지금 작동하는 기능

1. 화면(`/`)에서 이메일·비밀번호로 로그인·로그아웃합니다. 로그인·토큰 갱신·로그아웃은 서버 함수 `/api/session`이 공식 Supabase SDK로 처리하고, 로그인 실패 이유를 화면에 보여 줍니다. 화면 코드에는 Supabase 주소나 키(공개 키 포함)가 없습니다.
2. 자료 API `/api/notes`는 요청의 로그인 토큰을 시작 틀의 `src/verify-login.mjs`로 검사합니다. 토큰이 없거나 검사에 실패하면 자료 없이 401로 거부합니다. 브라우저가 보낸 userId·role·owner_id는 믿지 않습니다.
3. 로그인한 사용자는 **자기** 가상 메모만 목록으로 보고, 읽기·추가·수정·삭제할 수 있습니다. 서버는 검증된 사용자 ID와 DB의 `owner_id`를 비교합니다. 남의 메모는 ID를 알아도 404로 거부하고, 수정으로 주인을 바꾸려 하면 403으로 거부합니다. 추가할 때는 본문의 `owner_id`를 무시하고 검증된 ID로 저장합니다.
4. 메모 자료 요청은 서버 함수 `/api/notes` 한곳으로만 갑니다. 브라우저는 Supabase에 직접 요청하지 않습니다. DB의 `vault_notes`는 `PUBLIC`·`anon`·`authenticated` 직접 권한이 모두 회수되어, 공개 키나 로그인 토큰으로 원본 자료 API(`originalApiUrl`)를 직접 불러도 거부됩니다. 서버 함수만 서버 전용 키(service_role)로 접근합니다. RLS와 4단계 정책 4개(`auth.uid() = owner_id`)는 예비 방어로 남겨 둡니다.
5. 정적 `/data.json`은 만들지 않습니다(404). 빌드는 `public/aleph.json`에 배포 저장소·커밋·주소·단계·`originalApiUrl`·`allowedRoutes`를 기록합니다. 모든 응답에 보안 헤더(`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`)가 붙습니다.
6. 판정기 `src/decider.mjs`는 운영 엔진이 확인한 요청에서 `deviceRegistered`가 `true`일 때만 내 자료실 읽기(`GET notes`)를 허용합니다(`device_registered`). 미등록이거나 값이 없으면 `deny`·`device_not_registered`입니다. 그 밖의 요청은 시작 틀 기본 거부(`starter.deny`)입니다.
7. 판정기는 엔진이 넘긴 접속 정보의 출처를 구분합니다(`readAccessContext`). 심판 가상 사건(`judge_fixture`)만 읽고, 실제 경로(`none`)나 그 밖의 출처(클라이언트 헤더 등)는 값을 모름(null)으로 둡니다. 빠진 값을 정상값으로 채우지 않습니다.
8. 판정기 `step_up_required`: 가상 사건에서 평소와 다른 시각(7~22시 밖)·처음 보는 네트워크·갑작스러운 대량 요청(10분 안 10건 이상)·평소와 다른 지역 중 2개 이상이 겹치면 `step_up`으로 추가 확인을 요구하고 자료를 주지 않습니다. 신호 하나로는 막지 않고 영구 차단하지 않습니다. 300초 안에 추가 확인을 마친 요청은 다시 판정해 허용합니다. 겹친 사유는 `stepUpReasons()`로 확인합니다.
9. 자원 ID로 구역을 나눕니다(`src/resources.mjs`). 메모는 `notes`·`note:<id>`(구역 `own_notes`), 강사 공지는 `notices`·`notice:<id>`(구역 `instructor_notices`)이며, 응답 머리 `X-Resource-Id`에 표시합니다.
10. 판정기 구역 규칙: 정확한 route·method·path 표로 메모 한 건 읽기·수정(`GET`·`PUT /notes/:id`)만 `zone_own_notes`로 허용합니다. 메모 전체 목록(`GET /notes`)은 여러 사람의 자료를 한꺼번에 여는 경로라 거부하고, 학생의 공지 수정은 `instructor_only`(`zone_instructor_notices`), 공지 목록·읽기와 그 밖의 경로·메서드·쿼리가 붙은 요청·`:id` 자리의 기능 이름(export 등)은 `route_allowlist`로 거부합니다. 메모 한 건의 주인 비교는 판정기가 추측하지 않고 자료 API가 합니다.
11. 자료 API는 검증된 사용자와 저장된 값을 다시 대조합니다. 남의 메모는 404(서버 기록 사유 `not_owner_or_missing`), 강사 공지는 읽기·수정 모두 DB 강사 명단 `vault_instructors`에 있을 때만 허용하고 아니면 403 `INSTRUCTOR_ONLY`입니다. 화면 메뉴나 요청 본문의 `role`은 믿지 않습니다.
12. 탐지기 `src/detect.mjs`(9단계): 가상 사건에서 가명 사용자·기기·요청 종류·판정·시각·네트워크만 읽습니다(메모 내용·토큰·실명은 읽지 않음). 규칙 `doppelganger_burst`는 같은 사용자의 GET이 어느 10분 구간에서 120건을 넘고 그 구간에 평소와 다른 네트워크 조회가 함께 있을 때만 의심으로 표시합니다(지역은 쓰지 않음, 네트워크 정보가 없는 연습 사건은 `docs/DETECT_EVENTS.md` 계약대로 다량 조회만 봄). 의심이면 `detect()`가 `{action:'propose_revocation', reasonCode:'burst_read', subject}`를, 별도 결과 `revocationProposal()`이 대상 가상 기기 한 개와 이유를 냅니다. 정상은 `observe`입니다. 회수를 직접 집행하지 않으며, 운영 반 엔진의 사건 전달·실제 회수는 연결·시험하지 않았습니다.
13. 복구(10단계): `backup/policy/`의 침해 전 정책 사본을 다시 읽어 SHA-256 지문, 사본 폴더 밖의 고정 기준(`src/policy-diff.mjs`의 `VERIFIED_POLICY_BACKUP`), Git 검증 커밋의 사본, 판정기 대조로 검증하고(사본과 지문을 함께 바꿔도 멈춤), `npm run backup:verify`로 시험 복원까지 해서 결과를 `backup/policy/verify-log.jsonl`에 남기며, 시험 정책 `policy/test-policy.json`과의 차이만 보여 준 뒤 확인을 받아 서비스 한 개만 되돌립니다(운영 판정기는 바꾸지 않음). 메모는 Supabase 비공개 사본 `vault_notes_backup`에서 내 메모 한 건만 `POST /api/notes/:id/restore`로 복원하고 감사 기록 `vault_restore_audit`에 한 줄 남깁니다.
14. 접속 앱(11단계): 설치형 웹앱 설정(`public/manifest.webmanifest`, 앱 이름 "BYTE BACK 내 자료실", 아이콘)과 화면 안 오프라인 안내 띠를 붙였습니다. 서비스 워커는 쓰지 않아 자료를 기기에 저장하지 않습니다. 앱 설치 여부는 기기 승인과 무관하다고 화면에 표시합니다.
15. 기기 승인(11단계): 로그인 뒤 "이 기기 승인 요청"을 누르면 패스키(ES256)를 만들고 **공개키만** 서버 기기 명단 `vault_devices`에 `pending`으로 저장합니다(버튼만으로는 권한이 생기지 않음). "승인 확인하고 자료실 열기"에서 서버(`api/device.js`)가 패스키 서명을 확인하고 명단에서 등록(`approved`) 여부를 찾은 뒤, **판정기 `decide()`에 `deviceRegistered`를 넣어** `allow`일 때만 기기 세션(30분, 화면 메모리에만)을 줍니다. 메모·공지·복원 API는 이 세션이 없거나 그 사이 승인이 취소되면 403으로 거부하고(`src/device-guard.mjs`), 화면도 승인 전에는 보호 자료를 요청·표시하지 않습니다. 기기 개인키는 기기(운영체제)에만 있고 브라우저 저장소에 넣지 않습니다.
16. 탈환 작전실(12단계): 로그인·승인 기기에서만 열리는 `GET /api/operations`가 판정기 규칙(배포 코드의 `RULE_IDS`)·탐지 사건(운영 엔진 미연결이라 미실행)·회수 상태(기기 명단)·복구 버전(정책 사본·정책 감사·내 메모 복원 감사)을 이번 요청에서 실제로 읽은 기록만으로 요약합니다. 구역마다 「실제 응답 확인 / 미실행 / 읽기 실패」를 구분하고, 메모 본문·제목·사용자 ID는 보여 주지 않으며 기기·메모 ID는 앞 4자리만 보입니다. 같은 요청 ID·시각·수치를 서버 로그 `operations: summary`에 남깁니다.
17. 실측 표(12단계): 작전실의 「1~11단계 실측 표 만들기」가 정상·금지 읽기 요청 14건을 실제 배포에 보내 단계·구분·요청·기대·실제 HTTP 결과·요청 ID·확인 시각을 한 표로 보여 줍니다. 서버 함수는 같은 요청 ID로 `trace: <함수> id=… status=…` 한 줄을 남깁니다(`src/request-trace.mjs`, 관측만). 쓰기·다른 계정·운영 엔진 요청과 41종 총공세는 미실행으로 남깁니다. 제출 묶음(`npm run bundle`)의 12단계 점검은 공개 GET만 보내고(`alephEvidence`로 점검 ID 연결) 나머지는 `not_run`입니다.

| 경로 | 동작 |
|---|---|
| `GET /api/notes` | 로그인 사용자의 메모 배열 `[{id,title,body}]` |
| `POST /api/notes` | `{id?,title,body}` → 201 `{id}` (id가 없으면 서버가 UUID 생성) |
| `GET /api/notes/:id` | 본인 메모면 `{id,title,body}`, 없거나 남의 것이면 404 |
| `PUT /api/notes/:id` | `{title,body}` → `{id,title,body}`, 없거나 남의 것이면 404, 주인 변경 시도는 403 |
| `DELETE /api/notes/:id` | 204, 없거나 남의 것이면 404 |
| `POST /api/session` | `{action}`(login·refresh·logout) 로그인 세션 처리 |
| `GET /api/notices` | 강사 공지 목록 `[{id,title,body}]`, 강사 명단에 없으면 403 (allowedRoutes에는 넣지 않음) |
| `GET /api/notices/:id` | 공지 한 건 `{id,title,body}`, 강사 명단에 없으면 403 (allowedRoutes에는 넣지 않음) |
| `PUT /api/notices/:id` | `{title,body}` → `{id,title,body}`, 강사 명단에 없으면 403 |
| `GET /api/operations` | (12단계) 로그인 필요, 학생은 승인 기기 세션 필요. 탈환 작전실 요약(가린 기록·수치) |
| `POST /api/device` | (11단계) 로그인 필요. `challenge`·`register`(공개키를 명단에 pending 으로)·`unlock`(패스키 확인 → 명단 → 판정기 allow 일 때만 기기 세션) |
| `POST /api/notes/:id/restore` | (10단계) 비공개 사본에서 내 메모 한 건만 복원. 본문 `{"preview":true}`면 검증 결과·사본 버전·바뀔 항목만 보여 주고 쓰지 않음, `{"expectBackupSha256":…}`면 미리 본 사본과 같을 때만 실행 → 200 `{id,title,body,restored:{…}}`. 사본 없음·남의 메모 404, 사본 검증 실패 409, 실행 뒤 대조 실패는 되돌리고 502 |

## 10단계: 안전 정책(RLS) 사본 검증·차이 보기·되돌리기 (Supabase SQL)

3차 침공은 가상 메모와 함께 DB의 안전 정책(`public.vault_notes`의 RLS와 4단계 정책 4개 `auth.uid() = owner_id`)을 바꿉니다. 정책 복원은 DB 안에서 합니다(`supabase/step10_policy_backup.sql`).

| 함수 | 하는 일 |
|---|---|
| `vault_policy_capture('s4-rls-v1')` | 지금 정책이 4단계 안전 기준(RLS 켜짐, 정책 4개, 모두 `auth.uid()`·`owner_id` 비교, authenticated 전용)과 같을 때만 침해 전 사본을 `vault_policy_backup`에 남김(SHA-256 함께). 기준과 다르면 사본을 만들지 않음 |
| `vault_policy_backup_verify(버전)` | 사본을 다시 읽어 SHA-256을 다시 계산·대조. 사본이 없거나 다르면 예외로 멈춤 |
| `vault_policy_diff(버전)` | 검증된 사본과 지금 정책의 **차이만** 보여 줌(읽기 전용, 아무것도 바꾸지 않음) |
| `vault_policy_restore(버전, false)` | 복원할 **버전과 바뀔 항목**만 보여 줌(미리 보기) |
| `vault_policy_restore(버전, true)` | 사본을 다시 읽어 검증 → `vault_notes` 정책만 사본대로 되돌림 → 다시 읽어 사본과 대조, 다르면 예외로 전체 취소. 사본 없음·검증 실패면 아무것도 바꾸지 않고 멈춤(감사 기록만) |

- 다른 표의 정책, 사본, 감사 기록(`vault_policy_audit`, 추가만 가능)은 건드리지 않습니다. 함수는 서버 전용 역할만 실행할 수 있습니다.
- 복원 시험: `supabase/step10_policy_restore_test.sql`이 정책을 침공처럼 바꾼 뒤(모두 읽기 정책 추가·본인 수정 정책 삭제) 미리 보기 → 복원 → **B 로그인으로 A 메모 0건(거부), A 로그인으로 자기 메모 보임(정상 유지)**을 확인하고 결과를 `vault_policy_audit`에 `policy_restore_test / pass`로 남깁니다. 실패하면 전부 취소됩니다.
- `policy/`·`backup/policy/`의 JSON 정책 사본과 `npm run policy:diff`·`policy:restore`·`backup:verify`는 판정기 경로 규칙의 로컬 연습용입니다.

## 10단계: 메모 한 건 복원 (서비스·경로)

- 서비스: 자료 API 서비스 `notes`의 복원 함수 `api/restore.js` (Vercel 서버 함수)
- 경로: `POST /api/notes/:id/restore` (`aleph.config.json`의 `restoreRoute`와 `allowedRoutes`에 기록, `vercel.json`이 `/api/restore?id=:id`로 연결)
- 사본: Supabase 비공개 표 `vault_notes_backup`(ID·소유자·제목·내용·내용 해시). `supabase/step10_note_backup.sql`이 그때 있던 메모를 사본으로 뜨고, 그 뒤 새로 만든 메모는 `POST /api/notes`가 만든 순간의 내용을 사본에 남깁니다. 사본은 DB 안에만 있고 Git·제출 묶음에 넣지 않습니다.
- 내용 해시: SHA-256(제목 + 코드 31 구분 문자 + 내용), `src/note-hash.mjs`와 SQL이 같은 방식입니다.
- 절차: 로그인 확인 → 내 사본(ID·소유자 일치) 찾기 → 사본 해시 검증 → 사본을 다시 읽어 봉인 대조(없거나 다르면 멈춤) → **미리 보기**(사본 버전·바뀔 항목, 쓰지 않음) → 확인 값이 미리 본 사본과 같을 때만 실행 → 지금 메모가 변조됐으면 고치고, 지워졌으면 다시 넣음(다른 메모는 건드리지 않음) → 다시 읽어 ID·소유자·내용 해시 대조(틀리면 복원 전 상태로 되돌리고 502) → 감사 기록 `vault_restore_audit`에 한 줄 추가(본문 없이 해시만, 미리 보기·중단·되돌림도 기록).
- 사본과 감사 기록은 DB 트리거로 수정·삭제가 막혀 있습니다(추가만 가능).
- DB 복원 함수(10단계 보강): `supabase/step10_restore_function.sql`의 `public.vault_restore_note`가 DB 안에서 사본을 다시 읽어 해시를 다시 계산·대조하고, 봉인 기록을 확인하며, 사본이 없거나 검증이 실패하면 멈춥니다(감사 기록에 stopped_… 기록). 미리 보기면 사본 버전·바뀔 항목만 돌려주고, 실행하면 한 건만 복원한 뒤 다시 읽어 대조해 다르면 예외로 변경 전체를 취소합니다. 서버 전용 역할만 실행할 수 있습니다(anon·authenticated 실행 불가). 서버 함수 `api/restore.js`는 봉인 값(HMAC)을 확인한 뒤 이 함수만 호출합니다.
- 봉인(10단계 보강): 새 메모의 사본을 남길 때 서버 전용 키에서 만든 키로 봉인(HMAC-SHA256: 메모 ID·소유자·내용 해시)을 `vault_notes_backup_seal`에 따로 남깁니다(`src/backup-seal.mjs`). 복원할 때 사본을 다시 읽어 봉인을 다시 계산해 비교하고, 봉인이 없거나 맞지 않으면 409 `BACKUP_UNVERIFIED`로 멈추며 아무것도 쓰지 않습니다. 응답에는 사본 버전(사본을 뜬 시각)·바뀐 항목·검증 결과를 함께 보여 줍니다. 봉인 표 이전에 SQL로 뜬 사본은 봉인이 없어 복원하지 않습니다. 서버 전용 키를 바꾸면 이전 봉인은 맞지 않게 됩니다.
- 확인은 시험 계정 B의 메모로만 합니다. 화면에서 B로 로그인 → 메모 카드의 **사본으로 복원**(확인 창에 사본 버전·바뀔 항목이 먼저 나오고 **확인**을 눌러야 실행), 지운 메모는 카드 아래 회색 ID를 적어 두었다가 **ID로 복원**.

## 10단계: 복구 뒤 1~9단계 재시험 순서

복구(정책 → 자료 순서)를 마친 뒤 아래 순서대로 다시 확인합니다. 결과 칸에는 **실제로 실행한 것만** 적고, 실행하지 않은 시험은 `미실행`으로 둡니다. 로컬 명령은 가상 요청·가상 사건 연습이며 심판 판정이 아닙니다. 마지막 기록: 2026-10-13.

### 0. 복구 자체 확인

| 순서 | 무엇을 | 어떻게 | 기대 | 결과 |
|---|---|---|---|---|
| 0-0 | **백업 검증(시험 복원 포함)** | `npm run backup:verify` | 사본 다시 읽기 → SHA-256·사본 폴더 밖 고정 기준·Git 검증 커밋(`c7bec6d`)·판정기 대조 일치 → 침공 연습 정책에 시험 복원 → 기대와 다른 요청 0개 → `backup/policy/verify-log.jsonl`에 pass 기록. 하나라도 틀리면 fail 기록 후 멈춤 | 로컬 실행: pass(기대와 다른 요청 4개 → 0개), 기록 남김 |
| 0-1 | 정책 사본 다시 읽기·검증 | `npm run policy:diff` | 사본 SHA-256·고정 기준·Git 이력·판정기 대조 일치, 시험 정책과 차이 표시(없으면 "차이 없음") | 로컬 실행: 검증 일치, 차이 없음 |
| 0-2 | 시험 정책 되돌리기 | `npm run policy:restore -- --service notes` 로 바뀔 항목 확인 → 맞으면 끝에 `--yes`(쓰기 직전에 사본을 다시 읽어 재검증, 미리 본 내용과 다르면 멈춤) | 바뀔 항목 표시 후 복원, 감사 이력 보존+1줄 | 로컬 실행: 침공 연습 사본으로 복원 확인(8개 항목), 실제 시험 정책은 바뀔 항목 없음 |
| 0-3 | B 메모 변조 → 한 건 복원 | B 로그인 → 카드 **수정** 후 **사본으로 복원** | `변조됨 → 복원 · ID·소유자·내용 해시 일치` | 학생이 배포 화면에서 실행: 일치 |
| 0-4 | B 메모 삭제 → 한 건 복원 | B 로그인 → 카드 ID 적기 → **삭제** → **ID로 복원** | `삭제됨 → 복원 · ID·소유자·내용 해시 일치` | 학생이 배포 화면에서 실행: 일치 |
| 0-5 | 다른 메모·감사 기록 보존 | B 목록의 다른 카드, Supabase `vault_restore_audit` | 다른 카드 그대로, 감사 기록 줄이 늘기만 함 | 다른 카드 그대로(학생 확인), 감사 기록 표 직접 조회는 미실행 |

### 1~9단계 정상·금지 요청 (이전에 막던 요청이 다시 거부되는지)

| 순서 | 단계 | 요청 | 기대 | 어떻게 | 결과 |
|---|---|---|---|---|---|
| 1 | 1 | 비로그인 `GET /data.json` | 404(가상 메모 노출 없음) | 시크릿 창에서 주소 열기 | 학생이 배포 화면에서 실행: 404 |
| 2 | 2·5 | 공개 키로 원본 자료 API(`originalApiUrl`) 직접 조회 | 401 또는 403 | `npm run bundle` 자기 점검(`anon_key_original_api_read`) | 미실행 |
| 3 | 3 | 로그인 없이 `GET /api/notes` | 401 | 시크릿 창에서 `/api/notes` 열기 | 학생이 배포 화면에서 실행: `LOGIN_REQUIRED`(401) |
| 4 | 3·4 | A 정상: 로그인 후 목록·추가·수정·삭제 | 모두 성공 | A 로그인 화면에서 카드 추가·수정·삭제 | 학생이 배포 화면에서 실행: 추가·수정·삭제 성공 |
| 5 | 4 | B가 A 메모 ID로 읽기·수정·삭제, 주인 변경 | 404, 주인 변경 403 | B 로그인, A 메모 ID로 요청 | 미실행 |
| 6 | 6 | 미등록 기기 요청 | `deny · device_not_registered` | `npm run decider:test` | 로컬 실행: 통과 |
| 7 | 7 | 복합 이상 접속 / 추가 확인 뒤 | `step_up` / `allow` | `npm run decider:test`, `npm run fixture:7` | 로컬 실행: 통과(step_up → allow) |
| 8 | 8 | 학생의 공지 읽기·수정 | 403 `INSTRUCTOR_ONLY` | B 로그인 후 `/api/notices` | 미실행 |
| 9 | 8 | 판정기: 메모 전체 목록, 공지 수정, 기능 경로 | 모두 deny, 메모 한 건 읽기·수정 allow | `npm run policy:restore -- --service notes`(가상 요청 확인), `npm run bundle` 로컬 판정기 점검 | 로컬 실행: 통과 |
| 10 | 9 | 탐지: 정상 사건 / 새 네트워크+다량 조회 | `observe` / `propose_revocation · burst_read` | `npm run detect:test` | 로컬 실행: 6개 통과 |
| 11 | 1~9 | 심판의 대표 공격 재전송 | 모두 거부, 정상 유지 | 10단계 제출 후 심판이 실행 | 미실행(심판 몫) |

## 다시 실행하는 방법

1. 학습용 Supabase SQL Editor에서 2단계 이전 SQL과 4단계 B 시험 메모 SQL(둘 다 메모 문장이 있어 저장소 밖 보관), `supabase/step3_notes_crud.sql`, `supabase/step4_rls_policies.sql`, `supabase/step5_revoke_direct_access.sql`, `supabase/step8_notices.sql`, `supabase/step8_instructors.sql`, `supabase/step10_note_backup.sql`, `supabase/step10_backup_seal.sql`, `supabase/step10_restore_function.sql`, `supabase/step10_policy_backup.sql`, `supabase/step10_policy_restore_test.sql`, `supabase/step11_devices.sql`을 차례로 실행합니다. 11단계부터 자료실은 화면에서 "이 기기 승인 요청" → 서버 쪽 명단(`vault_devices.status`)을 `approved`로 변경 → "승인 확인하고 자료실 열기" 순서로 엽니다. 이메일 자리는 실행할 때만 바꾸고 파일에는 저장하지 않습니다. A·B 시험 계정은 Authentication → Users에서 만듭니다.
2. Vercel 프로젝트 **Settings → Environment Variables**(Production)에 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`를 학생이 직접 넣습니다. 키 값은 코드·Git·채팅에 적지 않습니다.
3. main에 푸시하거나 Deployments에서 Redeploy 합니다.
4. 로컬 확인: `npm run build -- --local`, `npm run test:r5`, `npm run decider:test`, `npm run detect:test`(가상 사건 연습이며 심판 판정이 아님). 제출 묶음: `bundle-notes.json`을 만든 뒤 `npm run bundle`(결과 `artifacts/submission.json`, 둘 다 커밋하지 않음).

## 12단계: 출처와 설치·실행·중지·복구 안내

**검사한 커밋: `2e902cd`** (실행 코드 기준). 이 안내를 적은 README 커밋과 저장점 커밋은 문서·설정만 바꾸며, 실행 코드(`api/`·`src/`·`public/`·`scripts/`)가 `2e902cd`와 같은지는 `git diff --stat 2e902cd HEAD -- api src public scripts`로 확인합니다(출력이 없어야 같음).

### 출처: 학생 몫과 제공 엔진

| 출처 | 들어 있는 것 |
|---|---|
| **제공 엔진: ALEPH SDP 엔진** (운영 측 제공, 이 저장소에 코드 없음) | 운영 경로에서 신원·기기·경로를 먼저 확인하고, 계약(`docs/DECIDER_REQUEST.md`)의 요청으로 학생 판정기 `decide()`를 불러 결과를 집행합니다. 미등록 기기는 판정기보다 먼저 막고, 탐지 사건 전달·접속 회수·감사 보관도 엔진 몫입니다. 학생 코드가 `allow`를 내도 엔진의 앞선 검사를 되돌릴 수 없습니다. |
| **제공 시작 틀** (`ChoiTimo/aleph-defense-starter`, 고치지 않은 파일) | `src/verify-login.mjs`(로그인 토큰 검사), `scripts/bundle.mjs`(제출 묶음), `scripts/decider-test.mjs`·`scripts/detect-test.mjs`·`scripts/fixture-7.mjs`·`scripts/xdr-run.mjs`(가상 연습), `docs/DECIDER_REQUEST.md`·`docs/DETECT_EVENTS.md`(계약 문서), `test/*.test.mjs`, `api/ai.js`·`api/threat-intel.js`(미구현 뼈대) |
| **학생 몫 — 판정기** | `src/decider.mjs` (시작 틀 파일을 고침: `RULE_IDS` 7개 규칙) |
| **학생 몫 — 탐지 규칙** | `src/detect.mjs` (시작 틀 파일을 고침: `doppelganger_burst`, 회수 제안 `burst_read`) |
| **학생 몫 — 접속 앱** | `public/index.html`(화면·기기 승인·작전실·실측 표), `public/manifest.webmanifest`, `public/icon-*.png`, `api/device.js`, `api/session.js`, `src/device-auth.mjs`, `src/device-guard.mjs`, `supabase/step11_devices.sql` |
| **학생 몫 — 자료실** | `api/notes.js`·`api/notices.js`·`api/restore.js`·`api/operations.js`, `src/owner-key.mjs`·`src/resources.mjs`·`src/note-hash.mjs`·`src/backup-seal.mjs`·`src/auth-log.mjs`·`src/request-trace.mjs`·`src/policy-*.mjs`, `scripts/policy-*.mjs`·`scripts/backup-verify.mjs`, `supabase/step3~step10*.sql`, 시작 틀에서 고친 `src/attack-check.mjs`·`scripts/build-public.mjs`·`scripts/deployment-identity.mjs`·`vercel.json`·`package.json` |
| 외부 서비스(학생 계정) | Supabase(로그인·DB), Vercel(배포·서버 함수 실행). 키·비밀번호는 각 서비스의 설정 화면에만 있습니다. |

### 포장하지 않는 것(비밀값·개인 자료)

- `SUPABASE_SECRET_KEY`·계정 비밀번호·로그인 토큰·패스키 개인키는 저장소·로그·제출 묶음에 없습니다. 서버 키는 Vercel **Settings → Environment Variables**에만, 패스키 개인키는 기기(운영체제)에만 있습니다.
- 메모 문장이 든 SQL은 올리지 않습니다: 2단계 이전 SQL(`supabase/step2_vault_notes.sql`)은 `.gitignore`로 제외하고, 4단계 B 시험 메모 SQL은 저장소 폴더 밖에만 둡니다.
- `bundle-notes.json`·`artifacts/submission.json`·`.env*`·`node_modules/`는 커밋하지 않습니다.

### 재현 순서(처음부터)

1. **받기·설치**: `git clone https://github.com/jeonjieun03/choi-bujang-secret-vault && cd choi-bujang-secret-vault && git checkout 2e902cd && npm install` (Node.js 22 이상, 의존 패키지 `@supabase/supabase-js`·`jose` 두 개).
2. **로컬 확인**(배포·심판 판정이 아님): `npm run build -- --local`, `npm run test:r5`, `npm run decider:test`, `npm run detect:test`.
3. **DB 준비**: 학습용 Supabase SQL Editor에서 「다시 실행하는 방법」 1번의 SQL을 적힌 순서대로 실행합니다(마지막이 `supabase/step11_devices.sql`).
4. **서버 키 넣기**: Vercel Settings → Environment Variables(Production)에 `SUPABASE_URL`·`SUPABASE_SECRET_KEY`를 학생이 직접 넣습니다.
5. **배포**: main에 푸시하면 Vercel이 새로 받아 `npm install`·`npm run build`를 실행하고 `/aleph.json`에 커밋·단계·허용 경로를 적습니다. `/aleph.json`의 `commit`이 검사한 커밋인지 확인합니다.
6. **접속 앱 실행**: 배포 주소 → 로그인 → 「이 기기 승인 요청」(서버 명단에 `pending`) → Supabase에서 그 기기 줄의 `status`를 `approved`로 변경 → 「승인 확인하고 자료실 열기」(서버가 패스키·명단을 확인하고 판정기 `decide()`가 `allow`일 때만 기기 세션). 앱 설치 여부는 승인과 무관합니다.
7. **작전실 확인**: 자료실 아래 「탈환 작전실」에서 판정기 규칙·탐지 사건(운영 엔진 미연결이라 미실행)·회수 상태·복구 버전을 봅니다. Vercel Logs의 `operations: summary` 줄(같은 요청 ID)과 수치를 대조합니다.
8. **실측 표**: 「1~11단계 실측 표 만들기」로 정상·금지 요청을 실제 배포에 보내고, 표의 요청 ID를 Vercel Logs에서 검색해 `trace: … status=` 줄이 표와 같은지 봅니다. 쓰기·다른 계정·운영 엔진 요청과 41종 총공세는 미실행으로 남습니다.
9. **제출 묶음**: `bundle-notes.json`을 만든 뒤 `npm run bundle`. 12단계 점검은 공개 GET만 실제로 보내고 나머지는 `not_run`으로 적습니다.

### 구성 요소별 설치·실행·중지·복구

| 구성 요소 | 설치 | 실행 | 중지 | 복구 |
|---|---|---|---|---|
| 학생 판정기 `src/decider.mjs` | 재현 1번(외부 모듈 없음) | 운영: ALEPH SDP 엔진이 `decide(request)` 호출. 이 앱: `api/device.js`가 기기 승인 때 호출. 연습: `npm run decider:test`, `npm run fixture:7` | 엔진 쪽 경로 허용 끄기는 운영 측 권한입니다. 학생 쪽에서는 기기를 `revoked`로 바꾸면 새 기기 세션이 나가지 않습니다 | `git checkout 2e902cd -- src/decider.mjs` → 커밋·푸시(재배포) → `npm run decider:test` |
| 탐지 규칙 `src/detect.mjs` | 재현 1번 | 운영: 엔진이 사건을 전달하면 `detect(events)` 호출(현재 운영 사건 전달 미연결, 작전실에 미실행 표시). 연습: `npm run detect:test` | 운영 측 권한(사건 전달 끄기) | `git checkout 2e902cd -- src/detect.mjs` → 커밋·푸시 → `npm run detect:test` |
| 접속 앱 `public/`·`api/device.js`·`api/session.js` | 재현 3번의 `step11_devices.sql`, 재현 5번 배포. 브라우저 「앱 설치」는 선택(승인 아님) | 재현 6번. 로그인·기기 세션은 화면 메모리에만 있어 새로고침하면 다시 로그인 | 로그아웃. 기기 회수: Supabase에서 `update public.vault_devices set status = 'revoked' where device_id = '<기기 16자리>';` → 그 기기의 다음 보호 요청부터 403 | 회수한 기기를 다시 `approved`로 바꾸거나 새로 승인 요청. 코드는 `git checkout 2e902cd -- public api/device.js api/session.js` → 커밋·푸시 |
| 자료실 `api/notes·notices·restore·operations`, Supabase 표 | 재현 3~5번 | 재현 5~8번 | 전체 중지: Vercel에서 `SUPABASE_SECRET_KEY`를 지우고 Redeploy하면 로그인·자료 API(`session`·`notes`·`notices`·`restore`·`operations`·`device`)가 자료 없이 500(`SERVER_NOT_CONFIGURED`)으로 멈춤. 배포 되돌리기: Vercel Instant Rollback(이후 새 배포는 자동 연결되지 않으니 복구 때 Promote) | 코드: 검사한 커밋의 배포를 Deployments에서 **Promote** 하거나 `git checkout 2e902cd`로 되돌려 푸시. 메모 한 건: 화면 「ID로 복원」(`POST /api/notes/:id/restore`, 봉인 검증). 정책: SQL Editor에서 `select public.vault_policy_restore('s4-rls-v1', false);`로 미리 본 뒤 `true`로 실행. 복구 뒤 재시험: 재현 7~9번 |

로컬에서 Vercel 개발 서버(`vercel dev`)로 API를 띄우는 방법은 확인하지 않았습니다(미실행). 실제 API 확인은 Vercel 배포에서 했습니다.

## 남아 있는 약점

- 11단계 패스키를 Google 비밀번호 관리자 같은 동기화 저장소에 만들면 같은 계정의 다른 기기에서도 쓰일 수 있습니다. 서버 명단의 승인·`revoked`로 관리합니다.
- 로그인 세션(토큰)과 기기 세션은 화면 메모리에만 있습니다(11단계 `31366c2`부터 브라우저 저장소 미사용). 새로고침하거나 창을 닫으면 다시 로그인하고 기기 승인 확인을 다시 합니다.

- 1단계 커밋(`cf6ab50`)과 그 배포 기록에는 가상 메모가 남아 있습니다. 최신 파일에서 지워도 Git 이력과 이전 배포는 지워지지 않습니다.
- 자기 점검(`npm run bundle`)은 로그인 없는 요청만 자동으로 보냅니다. A·B 로그인이 필요한 점검은 미실행으로 기록하며, 화면에서 학생이 직접 확인했습니다.

## 단계 기록

- 1단계: 시작 틀 배포, 공개 `/data.json`으로 가상 메모 노출 확인(`cf6ab50`).
- 2단계: 메모를 Supabase `vault_notes`(RLS 켬, anon·authenticated 권한 회수)로 옮기고 서버 함수로 읽음. 정적 `/data.json` 제거.
- 3단계: Supabase Auth 로그인·로그아웃, `verify-login.mjs` 토큰 검사, 로그인 사용자 메모 CRUD, `identityProvider`·`allowedRoutes` 기록.
- 4단계: 메모 API가 검증된 사용자 ID와 `owner_id`를 비교(남의 메모 404, 주인 변경 403), A 기존 메모·B 시험 메모 소유자 지정, DB RLS 정책 4개와 최소 권한(anon 없음, authenticated는 SELECT·INSERT·UPDATE·DELETE).
- 5단계: 브라우저의 메모 자료 요청이 모두 서버 함수 경유임을 확인(직접 호출 없음), `vault_notes`의 PUBLIC·anon·authenticated 직접 권한 회수, `originalApiUrl` 기록.
  - 5단계 가점: 배포 정보 `/aleph.json`에 `originalApiUrl`·`allowedRoutes` 기록, 보안 헤더 추가, 로그인을 `/api/session`으로 옮겨 화면에서 Supabase 공개 키 제거.
- 6단계: 판정기에 `device_registered` 규칙 추가(등록 기기의 자료실 읽기만 허용, 미등록·값 없음은 `device_not_registered` 거부), `npm run decider:test` 확인 순서 기록.
- 7단계: 접속 정보 출처 구분 입력 검사, `step_up_required` 규칙 추가(복합 이상 `step_up`, 추가 확인 뒤 `allow`), 재로그인 검증 계약 상태 기록(실제 자료 차단은 미실행).
- 8단계: 메모·강사 공지 자원 ID 분리와 공지 API(`/api/notices`), 판정기 구역 규칙(`zone_own_notes`·`zone_instructor_notices`·`route_allowlist`), 자료 API의 소유자·강사 명단 재대조. 저장점 뒤 보강: 판정기에서 메모 전체 목록 거부·주인 추측 규칙 제거, 공지 읽기도 강사만(`cb0c918`에서 심판 통과).
- 9단계: 탐지기 입력 정리, `doppelganger_burst` 규칙(새 네트워크+10분 안 120건 초과), 별도 결과의 `propose_revocation` 제안(대상 가상 기기 한 개·`burst_read`). (`34468ec`에서 심판 통과)
- 10단계: 침해 전 정책 사본 검증·차이 보기(`npm run policy:diff`), 시험 정책 서비스 한 개 되돌리기(`npm run policy:restore`, 미리 보기 후 `--yes`, 감사 이력 보존), 비공개 메모 사본에서 한 건 복원(`POST /api/notes/:id/restore`, ID·소유자·내용 해시 대조, 감사 기록 추가만), 복구 뒤 재시험 순서. 저장점 뒤 보강: 메모 사본 봉인·DB 복원 함수, **DB 안전 정책(RLS) 사본을 SQL로 남기고 다시 읽어 검증·차이 보기·되돌리기와 복원 시험 기록**(`step10_policy_backup.sql`·`step10_policy_restore_test.sql`, `a7a7775`에서 심판 통과).
- 11단계: 설치형 웹앱 설정(manifest·아이콘·앱 이름)·오프라인 안내·기기 승인 상태 표시, 패스키 기기 승인 요청(서버 명단 pending), 서버 명단 확인 뒤 판정기 `decide()`가 allow일 때만 기기 세션 발급, 세션 없는 보호 요청 거부·미표시. 첫 시도(`stage11-try1` 브랜치)는 심판 격리 실행 오류가 이어져 되돌린 뒤 프롬프트 범위로 다시 만들었습니다. 저장점 뒤 보강: 심판 토큰은 브라우저 기기 세션 검사 예외(`8e1211a`), `allowedRoutes`를 판정기가 허용하는 3개 경로로 축소(`f8e5225`), 로그인 세션을 브라우저 저장소 대신 메모리에만 보관(`31366c2`, S11_KEY_EXPOSED 해결). (`31366c2`에서 심판 통과)
- 12단계: 탈환 작전실(`GET /api/operations`, 판정기 규칙·탐지 사건·회수 상태·복구 버전, 실제 응답/미실행 구분), 1~11단계 정상·금지 요청 실측 표와 서버 `trace` 기록, 12단계 묶음 점검(공개 GET만·`not_run` 구분), README 출처 구분과 설치·실행·중지·복구 안내(검사한 커밋 `2e902cd`).

## 6단계: 등록 기기 판정기 확인 순서

이 단계는 따로 설치할 접속 프로그램이 없습니다. 저장소 루트에서 아래 순서로 확인합니다.

1. `src/decider.mjs`의 `RULE_IDS`에 `device_registered`가 있는지 봅니다.
2. `npm run decider:test`를 실행합니다.
3. 출력에서 두 줄을 확인합니다.
   - `통과 · 등록 기기의 정상 요청` → 등록 기기(`deviceRegistered: true`)의 내 자료실 읽기는 `allow`
   - `통과 · 미등록 기기의 가상 요청` → 미등록 기기(`deviceRegistered: false`)는 `deny`·`device_not_registered`
4. 둘 중 하나라도 `확인 필요`가 나오면 `src/decider.mjs`의 `device_registered` 규칙을 다시 봅니다.

`npm run decider:test`는 가상 요청으로 하는 로컬 연습이며 심판 통과 증거가 아닙니다. 실제 미등록 기기 공격은 심판이 따로 보냅니다.

## 7단계: 다시 로그인 확인 계약과 시험 상태

- 계약 확인: 판정 요청에는 엔진이 넣어 주는 `stepUp: {verified, authAgeSeconds}` 칸이 있습니다(`docs/DECIDER_REQUEST.md`). 하지만 같은 로그인으로 다시 로그인한 시각을 실제로 검증하는 제공 엔진(`student-kit/sdp-core`)과 운영 통로는 이 저장소에 없습니다.
- 그래서 이번에는 **가상 사건 규칙만 시험**합니다. `npm run decider:test`에서 복합 이상 접속은 `step_up`(자료 없음), 60초 전 다시 확인한 같은 접속은 `allow`로 나옵니다.
- **실제 자료 차단(다시 로그인 전 차단 → 새 로그인 뒤 허용)은 미실행**입니다. 계약이 준비된 환경에서 엔진·심판이 실측합니다.
- 판정기와 시험 출력에는 토큰 원문을 기록하지 않습니다.

## 보너스 xdr-01: 무차별 로그인 공격 탐지 (`xdr/brute-force/`)

- `read-alerts.mjs`: 확인용. `xdr/fixtures/brute-force.json` 경보에서 시각·출발 주소·계정·규칙 수준·설명만 뽑고 비밀값처럼 보이는 값은 가립니다.
- `patterns.json`: MITRE ATT&CK T1110.001(같은 주소의 짧은 시간 로그인 실패 연속), T1110.003(여러 계정에 같은 비밀번호) 두 패턴과 근거.
- `decide.mjs`: 패턴을 상수로 담고 `decide(alert)`가 확신도 0.85 이상 `block`, 0.5 이상 `alert`, 그 아래 `record`를 돌려줍니다. import·파일·네트워크를 쓰지 않습니다.
- `respond.mjs`: `block`만 출발 주소 거부 규칙(만료 60분, 근거 경보 번호)으로 `deny-rules.json`에 만들고, `alert`·`block`은 `xdr/alerts.log`에 한 줄씩 쌓습니다. 계정은 막지 않고, 정상 이벤트가 있는 주소는 규칙에서 뺍니다. 판정기 앞 확인 단계 `checkDeny()`를 제공하며 `src/decider.mjs` 기존 규칙은 바꾸지 않습니다(현재 판정기 계약에는 출발 주소 항목이 없음).
- 다시 실행: `npm run xdr:run -- brute-force`(결과 `result.json`), `node xdr/brute-force/respond.mjs`(규칙·알림 갱신과 재생 확인).
- 시험 경보 결과: block 10 · alert 9 · record 9, 정상 이벤트 block 없음.

## 보너스 xdr-02: 웹 주입 공격 탐지 (`xdr/web-injection/`)

- `read-alerts.mjs`: 확인용. `xdr/fixtures/web-injection.json` 경보에서 시각·출발 주소·계정·규칙 수준·설명만 뽑고 비밀값처럼 보이는 값은 가립니다.
- `patterns.json`: MITRE ATT&CK T1190 근거의 네 패턴. SQL 구문(CWE-89), 스크립트 태그(CWE-79), 경로 이탈 `../` 반복(CWE-22), 명령 구분자(CWE-78)입니다.
- `decide.mjs`: 패턴을 상수로 담고 `decide(alert)`가 같은 주소에서 5번 이상 반복된 주입 표식은 `block`, 한 번뿐인 의심 표기나 수업명 같은 평범한 단어는 `alert`, 주입 신호가 없으면 `record`를 돌려줍니다. import·파일·네트워크를 쓰지 않습니다.
- `respond.mjs`: `block`만 출발 주소 거부 규칙(만료 60분, 근거 경보 번호)으로 `deny-rules.json`에 만들고, `alert`·`block`은 `xdr/alerts.log`에 한 줄씩 쌓습니다. 계정은 막지 않고, 정상 이벤트가 있는 주소는 규칙에서 뺍니다. 판정기 앞 확인 단계 `checkDeny()`를 제공하며 `src/decider.mjs` 기존 규칙은 바꾸지 않습니다.
- 다시 실행: `npm run xdr:run -- web-injection`(결과 `result.json`), `node xdr/web-injection/respond.mjs`(규칙·알림 갱신과 재생 확인).
- 시험 경보 결과: block 8 · alert 9 · record 9, 정상 이벤트 block 없음.

## 보너스 xdr-03: 알려진 취약점 악용 탐지 (`xdr/known-cve/`)

- `read-alerts.mjs`: 확인용. `xdr/fixtures/known-cve.json` 경보에서 경보 번호·시각·출발 주소·계정·규칙 수준·설명만 뽑고, 비밀값처럼 보이는 값과 원격 조회 구문(`${…}`, 겹친 구문 포함)은 가립니다. `decide.mjs`는 이 파일을 불러오지 않습니다.
- `patterns.json`: CVE-2021-44228·MITRE ATT&CK T1190 근거의 세 패턴. 머리글 안의 원격 조회 구문(`jndi-lookup-header`), 주소 인자 안의 원격 조회 구문(`jndi-lookup-param`), 알려진 취약점 점검 도구 흔적(`cve-scanner-trace`). 패턴마다 찾는 조건과 근거 한 줄이 있고, 완성된 공격 문자열은 적지 않았습니다.
- `decide.mjs`: 패턴을 상수로 담고 `decide(alert)`가 머리글·주소 인자의 완전한 원격 조회 구문(숨긴 표기·주소 인코딩을 풀어 봄)은 확신도 0.85 이상 `block`, CVE 이름·`jndi` 단어·잘린 조각·비슷한 도구 이름만 있으면 0.5 이상 `alert`, 그 밖은 `record`로 돌려줍니다. import·파일 읽기·쓰기·네트워크가 없습니다.
- `respond.mjs`: `block`만 출발 주소 거부 규칙(만료 60분, 근거 경보 번호)으로 `deny-rules.json`에 만들고, `alert`·`block`은 `xdr/alerts.log`에 한 줄씩 쌓습니다(중복 없음, 조회 구문 원문 없음). 계정은 막지 않고 정상 이벤트가 있던 주소는 규칙에서 뺍니다. 판정기의 기존 규칙은 고치지 않습니다.
- 다시 실행: `npm run xdr:run -- known-cve`(결과 `result.json`), `node xdr/known-cve/respond.mjs`(규칙·알림 갱신과 재생 확인).
- 시험 경보 결과: block 8 · alert 8 · record 8, 정상 이벤트 block 없음.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
