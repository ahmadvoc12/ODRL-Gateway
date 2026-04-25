import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const REPLACEMENTS = ["templates", "odrl", "gateway.mjs"];

const projectRoot = process.cwd();
const packageRoot = __dirname;

function log(msg) {
  console.log(`[ODRL-Gateway] ${msg}`);
}

function copy(src, dest) {
  const stat = fs.statSync(src);

  if (stat.isDirectory()) {
    fs.cpSync(src, dest, { recursive: true });
  } else {
    fs.copyFileSync(src, dest);
  }
}

function run() {
  log("POSTINSTALL TRIGGERED");
  log(`projectRoot: ${projectRoot}`);
  log(`packageRoot: ${packageRoot}`);

  REPLACEMENTS.forEach((item) => {
    const src = path.join(packageRoot, item);
    const dest = path.join(projectRoot, item);

    if (!fs.existsSync(src)) {
      log(`⚠️ Skip (not found): ${item}`);
      return;
    }

    try {
      if (fs.existsSync(dest)) {
        const backupPath = dest + ".backup";
        fs.rmSync(backupPath, { recursive: true, force: true });
        fs.cpSync(dest, backupPath, { recursive: true });
        log(`💾 Backup created: ${item}.backup`);

        fs.rmSync(dest, { recursive: true, force: true });
      }

      copy(src, dest);
      log(`✅ Injected: ${item}`);
    } catch (err) {
      log(`❌ Failed on ${item}: ${err.message}`);
    }
  });

  log("✅ DONE");
}

run();