# BYTE BACK 방어전 자료실 — 3단계 저장점

이 저장소는 BYTE BACK 방어전 시작 틀 R5에서 출발한 학생 자료실입니다. 메모는 모두 실습용 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

- 배포 주소: https://choi-bujang-secret-vault-opal.vercel.app
- 현재 단계: 3단계(진짜 로그인) 저장점

## 지금 작동하는 기능

1. 화면(`/`)에서 Supabase Auth 이메일·비밀번호로 로그인·로그아웃합니다. 로그인 실패 이유를 화면에 보여 줍니다. 공개용 Project URL과 publishable key만 화면 코드에 있습니다.
2. 자료 API `/api/notes`는 요청의 로그인 토큰을 시작 틀의 `src/verify-login.mjs`로 검사합니다. 토큰이 없거나 검사에 실패하면 자료 없이 401로 거부합니다. 브라우저가 보낸 userId·role·owner_id는 믿지 않습니다.
3. 로그인한 사용자는 자기 가상 메모를 목록으로 보고, 추가·수정·삭제할 수 있습니다. 추가할 때 서버가 검증한 사용자 ID를 `owner_id`로 저장합니다.
4. 정적 `/data.json`은 만들지 않습니다(404). 빌드는 `public/aleph.json`에 배포 저장소·커밋·주소·단계를 기록합니다.

| 경로 | 동작 |
|---|---|
| `GET /api/notes` | 로그인 사용자의 메모 배열 `[{id,title,body}]` |
| `POST /api/notes` | `{id?,title,body}` → 201 `{id}` (id가 없으면 서버가 UUID 생성) |
| `GET /api/notes/:id` | `{id,title,body}`, 없으면 404 |
| `PUT /api/notes/:id` | `{title,body}` → `{id,title,body}`, 없으면 404 |
| `DELETE /api/notes/:id` | 204, 없으면 404 |

## 다시 실행하는 방법

1. 학습용 Supabase SQL Editor에서 2단계 이전 SQL(저장소 밖 보관)과 `supabase/step3_notes_crud.sql`을 차례로 실행합니다. 3단계 SQL의 `'A계정이메일'`은 실행할 때만 바꾸고 파일에는 저장하지 않습니다.
2. Vercel 프로젝트 **Settings → Environment Variables**(Production)에 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`를 학생이 직접 넣습니다. 키 값은 코드·Git·채팅에 적지 않습니다.
3. main에 푸시하거나 Deployments에서 Redeploy 합니다.
4. 로컬 확인: `npm run build -- --local`, `npm run test:r5`. 제출 묶음: `bundle-notes.json`을 만든 뒤 `npm run bundle`(결과 `artifacts/submission.json`, 둘 다 커밋하지 않음).

## 남아 있는 약점 (4단계에서 막을 것)

- 한 건 조회·수정·삭제(`/api/notes/:id`)는 아직 **소유자를 검사하지 않습니다.** B 계정이 A 메모의 ID를 알면 읽고 고치고 지울 수 있습니다.
- 1단계 커밋(`cf6ab50`)과 그 배포 기록에는 가상 메모가 남아 있습니다. 최신 파일에서 지워도 Git 이력과 이전 배포는 지워지지 않습니다.

## 단계 기록

- 1단계: 시작 틀 배포, 공개 `/data.json`으로 가상 메모 노출 확인(`cf6ab50`).
- 2단계: 메모를 Supabase `vault_notes`(RLS 켬, anon·authenticated 권한 회수)로 옮기고 서버 함수로 읽음. 정적 `/data.json` 제거.
- 3단계: Supabase Auth 로그인·로그아웃, `verify-login.mjs` 토큰 검사, 로그인 사용자 메모 CRUD, `identityProvider`·`allowedRoutes` 기록.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
