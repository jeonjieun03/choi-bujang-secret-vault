const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u;
const REPO = /^[A-Za-z0-9._-]{1,100}$/u;
const SHA = /^[a-f0-9]{40}$/iu;
const HOST = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/iu;

export function deploymentIdentity(env, config) {
  const owner = env.VERCEL_GIT_REPO_OWNER;
  const repo = env.VERCEL_GIT_REPO_SLUG;
  const commit = env.VERCEL_GIT_COMMIT_SHA;
  const host = env.VERCEL_URL;
  if (env.VERCEL_GIT_PROVIDER !== 'github' || !OWNER.test(owner || '')
      || !REPO.test(repo || '') || repo === '.' || repo === '..'
      || repo.toLowerCase().endsWith('.git') || !SHA.test(commit || '')
      || !HOST.test(host || '') || !Number.isInteger(config?.step)
      || config.step < 1 || config.step > 12
      || typeof config.judgeIssuer !== 'string'
      || !/^https:\/\/[a-z0-9-]+\.up\.railway\.app\/defense\/judge$/iu.test(config.judgeIssuer)
      || typeof config.sampleMarker !== 'string'
      || !/^[A-Z0-9_]{1,80}$/u.test(config.sampleMarker)) {
    throw new Error('배포 식별 정보를 확인할 수 없습니다. Vercel 시스템 환경변수와 aleph.config.json의 단계를 확인하세요.');
  }
  // 5단계부터: 원본 자료 API 주소(쿼리 없는 HTTPS)를 배포 정보에도 기록합니다. 비밀값은 넣지 않습니다.
  let originalApiUrl;
  if (config.originalApiUrl != null) {
    let url;
    try { url = new URL(config.originalApiUrl); } catch { url = null; }
    if (!url || url.protocol !== 'https:' || url.username || url.password
        || url.search || url.hash || config.originalApiUrl.includes('?')) {
      throw new Error('aleph.config.json의 originalApiUrl은 쿼리 없는 HTTPS 주소여야 합니다.');
    }
    originalApiUrl = url.href;
  }
  // 허용 경로(예: "GET /api/notes/:id")도 배포 정보에 기록합니다.
  const allowedRoutes = Array.isArray(config.allowedRoutes) ? config.allowedRoutes : [];
  if (allowedRoutes.length > 40 || allowedRoutes.some(route => typeof route !== 'string'
      || !/^(GET|POST|PUT|PATCH|DELETE) \/[A-Za-z0-9/:._-]{0,200}$/u.test(route))) {
    throw new Error('aleph.config.json의 allowedRoutes 형식을 확인하세요("메서드 /경로").');
  }
  return {
    schema: 'aleph.defense.deployment.v1',
    step: config.step,
    repoUrl: `https://github.com/${owner.toLowerCase()}/${repo.toLowerCase()}`,
    commit: commit.toLowerCase(),
    publicAppUrl: `https://${host.toLowerCase()}`,
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
    ...(originalApiUrl ? { originalApiUrl } : {}),
    ...(allowedRoutes.length ? { allowedRoutes } : {}),
  };
}
