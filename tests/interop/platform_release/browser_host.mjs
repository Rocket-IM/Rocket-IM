// 只负责启动真实Chrome；密码调用在安装了实际npm包的浏览器页面内执行。
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.ROCKETS_PLAYWRIGHT_MODULE);
const browser = await chromium.launch({
  executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  headless: true,
});
process.stdout.write(JSON.stringify({ browser_version: browser.version() }) + '\n');
const page = await browser.newPage();
page.on('pageerror', () => process.stderr.write('browser_page_error\n'));
page.on('console', message => {
  if (message.type() === 'error') process.stderr.write('browser_console_error\n');
});
let closing = false;
async function shutdown() {
  if (closing) return;
  closing = true;
  await browser.close();
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
await page.goto(process.argv[2], { waitUntil: 'domcontentloaded', timeout: 30000 });
process.stdout.write('browser_page_loaded\n');
await new Promise(resolve => browser.on('disconnected', resolve));
