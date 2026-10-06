import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const staleOutput = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
// 2단계: 메모는 서버 함수 /api/notes가 학습용 DB에서 읽습니다.
// 정적 /data.json은 더 이상 만들지 않고, 남아 있던 파일도 지웁니다.
await mkdir(resolve(root, 'public'), { recursive: true });
await rm(staleOutput, { force: true });
console.log('정적 public/data.json을 만들지 않습니다(자료는 /api/notes).');
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
