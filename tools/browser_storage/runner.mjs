// 专用 profile 与稳定 origin：实际关闭整个 Chrome 后继续打开同一 OPFS 数据。
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";
import { runCases } from "./cases.mjs";
import { runCryptoCases } from "./crypto_cases.mjs";
import { runAnchorCases } from "./anchor_cases.mjs";
import { runAnchorFaultCases } from "./anchor_fault_cases.mjs";
import { runAnchorRaceCases } from "./anchor_race_cases.mjs";
import { runAnchorResponseLossCases } from "./anchor_response_loss_cases.mjs";
import { AnchorFixture } from "./anchor_fixture.mjs";
import { ProfileFixture } from "./profile_fixture.mjs";
import { RebuildFixture } from "./rebuild_fixture.mjs";
import { runRebuildCases } from "./rebuild_cases.mjs";
import { runRebuildFaultCases } from "./rebuild_fault_cases.mjs";

const [consumer, output, playwrightPath, executablePath] = process.argv.slice(2);
const { chromium } = createRequire(import.meta.url)(playwrightPath);
const report = { status: "RUNNING", cases: [], evidence: "real Chrome; dedicated persistent profile; ordinary records and real MLS with synthetic identities" };
const mime = { ".html": "text/html", ".js": "text/javascript", ".wasm": "application/wasm", ".json": "application/json" };
const server = http.createServer(async (req, res) => {
  try {
    const route = new URL(req.url, "http://localhost").pathname;
    const file = path.resolve(consumer, "." + decodeURIComponent(route === "/" ? "/index.html" : route));
    if (!file.startsWith(path.resolve(consumer) + path.sep)) throw new Error("invalid path");
    res.setHeader("Content-Type", mime[path.extname(file)] ?? "application/octet-stream");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Cache-Control", "no-store");
    res.end(await fs.readFile(file));
  } catch { res.writeHead(404); res.end("Not found"); }
});
let context;
let anchor;
let profiles;
let rebuild;
async function save() { await fs.writeFile(path.join(output, "browser.json"), JSON.stringify(report, null, 2) + "\n"); }
try {
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  report.origin = origin;
  anchor = await AnchorFixture.start(output, origin);
  rebuild = await RebuildFixture.attach(anchor);
  profiles = new ProfileFixture(output);
  const launch = async () => {
    context = await chromium.launchPersistentContext(path.join(output, "profile"), {
      executablePath, headless: true, viewport: { width: 1000, height: 700 },
      args: ["--no-first-run", "--no-default-browser-check"],
    });
    context.setDefaultTimeout(15000);
    return context;
  };
  await launch();
  report.browser = await (await context.newCDPSession(context.pages()[0])).send("Browser.getVersion");
  const kit = {
    origin,
    anchor,
    rebuild,
    context: () => context,
    async restart() { await context.close(); await launch(); },
    async backupProfile(name) {
      await context.close();
      try { return await profiles.backup(name); } finally { await launch(); }
    },
    async restoreProfile(name) {
      await context.close();
      try { return await profiles.restore(name); } finally { await launch(); }
    },
    async cloneProfile(name, cloneName) {
      const copy = await profiles.clone(name, cloneName);
      const clone = await chromium.launchPersistentContext(copy.path, {
        executablePath, headless: true, viewport: { width: 1000, height: 700 },
        args: ["--no-first-run", "--no-default-browser-check"],
      });
      clone.setDefaultTimeout(15000);
      return clone;
    },
    async page(owner = context) {
      const page = await owner.newPage();
      await page.goto(origin + "/index.html");
      await kit.attach(page);
      return page;
    },
    async attach(page) {
      await page.evaluate(async () => {
        window.probe = (await import("/dist/main.js")).probe;
        window.clients = {}; window.events = []; window.phases = [];
      });
    },
    async check(name, fn) {
      const started = Date.now();
      try { report.cases.push({ name, status: "PASS", details: await fn(), duration_ms: Date.now() - started }); }
      catch (error) { report.cases.push({ name, status: "FAIL", error: String(error.stack ?? error), duration_ms: Date.now() - started }); }
      await save();
      console.log(name + ": " + report.cases.at(-1).status);
    },
  };
  await runCases(kit);
  await runCryptoCases(kit);
  await runAnchorCases(kit);
  await runAnchorResponseLossCases(kit);
  await runAnchorFaultCases(kit);
  await runAnchorRaceCases(kit);
  await runRebuildCases(kit);
  await runRebuildFaultCases(kit);
  report.status = report.cases.every(c => c.status === "PASS") ? "PASS" : "FAIL";
} catch (error) { report.status = "FAIL"; report.error = String(error.stack ?? error); }
finally {
  if (context) await context.close().catch(() => {});
  if (anchor) {
    report.anchor = anchor.evidence;
    await anchor.stop().catch(() => {});
    report.anchor_files = await anchor.fileHashes().catch(() => null);
  }
  if (profiles) report.profile_copies = profiles.evidence;
  if (rebuild) {
    report.rebuild = rebuild.evidence;
    report.rebuild_trust_files = await rebuild.fileHashes();
  }
  server.close();
  await save();
}
process.exitCode = report.status === "PASS" ? 0 : 1;
