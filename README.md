# BYTE BACK 방어전 자료실 — 9단계 저장점

이 저장소는 BYTE BACK 방어전 시작 틀 R5에서 출발한 학생 자료실입니다. 메모는 모두 실습용 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

- 배포 주소: https://choi-bujang-secret-vault-opal.vercel.app
- 현재 단계: 9단계(도플갱어를 찾고 권한을 거둡니다) 저장점

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

## 다시 실행하는 방법

1. 학습용 Supabase SQL Editor에서 2단계 이전 SQL과 4단계 B 시험 메모 SQL(둘 다 메모 문장이 있어 저장소 밖 보관), `supabase/step3_notes_crud.sql`, `supabase/step4_rls_policies.sql`, `supabase/step5_revoke_direct_access.sql`, `supabase/step8_notices.sql`, `supabase/step8_instructors.sql`을 차례로 실행합니다. 이메일 자리는 실행할 때만 바꾸고 파일에는 저장하지 않습니다. A·B 시험 계정은 Authentication → Users에서 만듭니다.
2. Vercel 프로젝트 **Settings → Environment Variables**(Production)에 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`를 학생이 직접 넣습니다. 키 값은 코드·Git·채팅에 적지 않습니다.
3. main에 푸시하거나 Deployments에서 Redeploy 합니다.
4. 로컬 확인: `npm run build -- --local`, `npm run test:r5`, `npm run decider:test`, `npm run detect:test`(가상 사건 연습이며 심판 판정이 아님). 제출 묶음: `bundle-notes.json`을 만든 뒤 `npm run bundle`(결과 `artifacts/submission.json`, 둘 다 커밋하지 않음).

## 남아 있는 약점

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
- 9단계: 탐지기 입력 정리, `doppelganger_burst` 규칙(새 네트워크+10분 안 120건 초과), 별도 결과의 `propose_revocation` 제안(대상 가상 기기 한 개·`burst_read`).

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

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
