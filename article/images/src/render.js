// Renders each SVG diagram in this folder to a PNG in ../
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const jobs = [
  ['cover.svg', 'cover.png', 1200, 630],
  ['architecture.svg', 'architecture.png', 1600, 900],
  ['decision-flow.svg', 'decision-flow.png', 1200, 1000],
];

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ deviceScaleFactor: 2 });
  for (const [src, out, w, h] of jobs) {
    const svg = fs.readFileSync(path.join(__dirname, src), 'utf8');
    await page.setViewportSize({ width: w, height: h });
    await page.setContent(`<html><body style="margin:0">${svg}</body></html>`);
    await page.screenshot({ path: path.join(__dirname, '..', out), clip: { x: 0, y: 0, width: w, height: h } });
    console.log('wrote', out);
  }
  await browser.close();
})();
