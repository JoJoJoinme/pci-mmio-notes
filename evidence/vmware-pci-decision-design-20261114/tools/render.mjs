// Re-render the authored Mermaid diagrams; no VMware binaries or services used.
// node tools/render.mjs --mermaid /path/mermaid-10.9.3.min.js
//   --modules /path/node_modules --browser /path/chrome.exe
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const flags = Object.fromEntries(Array.from({ length: (process.argv.length - 2) / 2 },
  (_, i) => [process.argv[2 + i * 2], process.argv[3 + i * 2]]));
for (const key of ['--mermaid', '--modules', '--browser']) {
  if (!flags[key]) throw new Error(`Missing ${key}`);
}
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const { chromium } = require(path.join(flags['--modules'], 'playwright'));
const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');
const browser = await chromium.launch({ executablePath: flags['--browser'], headless: true });
const receipt = {
  schemaVersion: 1,
  scope: 'Document rendering only; no new VMware runtime test',
  mermaidVersion: '10.9.3',
  mermaidSha256: sha256(await fs.readFile(flags['--mermaid'])),
  browserVersion: browser.version(),
  fontFamily: 'Microsoft YaHei, Noto Sans CJK SC, Arial, sans-serif',
  diagrams: [],
};
try {
  const page = await browser.newPage({ viewport: { width: 1900, height: 1400 }, deviceScaleFactor: 1.5 });
  // Diagrams contain only local text; no remote subresources are allowed.
  await page.route(/^https?:/, route => route.abort());
  const errors = [];
  page.on('pageerror', err => errors.push(String(err)));
  for (const [i, stem] of ['01-capable', '02-power-on', '03-dependency', '04-host-api-enable', '05-groups-vs-dependencies', '06-linux-group-main', '07-linux-alias-and-upstream', '08-linux-peer-recursion'].entries()) {
    const source = await fs.readFile(path.join(root, 'diagrams', `${stem}.mmd`), 'utf8');
    await page.setContent('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><style>body{margin:0;background:white;font-family:"Microsoft YaHei",sans-serif}</style><body></body></html>');
    await page.addScriptTag({ path: flags['--mermaid'] });
    const rendered = await page.evaluate(async ({ source, i }) => {
      mermaid.initialize({
        startOnLoad: false, securityLevel: 'strict', theme: 'base',
        fontFamily: 'Microsoft YaHei, Noto Sans CJK SC, Arial, sans-serif',
        themeVariables: {
          fontSize: '18px', primaryColor: '#f4f7fb', primaryTextColor: '#1f2937',
          primaryBorderColor: '#6c8299', lineColor: '#64748b',
          secondaryColor: '#eef5fc', tertiaryColor: '#ffffff',
          clusterBkg: '#fafbfd', clusterBorder: '#c8d2df', edgeLabelBackground: '#ffffff',
        },
        flowchart: { htmlLabels: false, useMaxWidth: false, nodeSpacing: 34, rankSpacing: 32, padding: 16, curve: 'linear' },
      });
      const { svg } = await mermaid.render(`design_graph_${i}`, source);
      document.body.innerHTML = svg;
      const element = document.querySelector('svg');
      const box = element.viewBox.baseVal;
      element.setAttribute('width', String(Math.ceil(box.width)));
      element.setAttribute('height', String(Math.ceil(box.height)));
      element.setAttribute('role', 'img');
      element.setAttribute('style', 'background:#fff');
      const w = Math.ceil(box.width), h = Math.ceil(box.height);
      const labels = [...element.querySelectorAll('text')].map(t => t.textContent);
      return { svg: element.outerHTML + '\n', width: w, height: h, labels };
    }, { source, i });
    if (rendered.svg.includes('foreignObject')) throw new Error(`${stem}: expected SVG text labels`);
    await fs.writeFile(path.join(root, 'diagrams', `${stem}.svg`), rendered.svg, 'utf8');
    await page.setViewportSize({ width: rendered.width + 2, height: rendered.height + 2 });
    await page.locator('svg').screenshot({ path: path.join(root, 'diagrams', `${stem}.png`) });
    receipt.diagrams.push({ stem, width: rendered.width, height: rendered.height,
      sourceSha256: sha256(source), svgSha256: sha256(rendered.svg),
      pngSha256: sha256(await fs.readFile(path.join(root, 'diagrams', `${stem}.png`))),
      labels: rendered.labels });
  }
  if (errors.length) throw new Error(errors.join('\n'));
  receipt.pageErrors = errors;
  await fs.writeFile(path.join(root, 'render-receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
  console.log(JSON.stringify({ diagrams: receipt.diagrams.map(({ stem, width, height }) => ({ stem, width, height })), pageErrors: errors }));
} finally {
  await browser.close();
}
