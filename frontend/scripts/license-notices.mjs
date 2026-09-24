import { readFile, readdir, writeFile } from 'node:fs/promises';
const lock = JSON.parse(await readFile('package-lock.json', 'utf8'));
const blocks = ['Third party notices for EVIDENCE\nGenerated from installed production dependencies. These licenses do not assign a license to the project owner’s code.'];
for (const [path, info] of Object.entries(lock.packages)) {
  if (!path || info.dev || !path.startsWith('node_modules/')) continue;
  const pkg = JSON.parse(await readFile(path + '/package.json', 'utf8'));
  const files = (await readdir(path)).filter(name => /^(licen[sc]e|copying|notice)(\.|$)/i.test(name));
  let text = pkg.name + ' ' + pkg.version + '\nLicense: ' + (typeof pkg.license === 'string' ? pkg.license : 'See package license');
  for (const file of files) text += '\n\n' + await readFile(path + '/' + file, 'utf8');
  blocks.push(text);
}
await writeFile('public/third-party-notices.txt', blocks.join('\n\n' + '='.repeat(72) + '\n\n') + '\n');
console.log('Production dependency notices prepared.');
