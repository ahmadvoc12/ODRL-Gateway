import fs from "fs";
import path from "path";

const PACKAGE_NAME = "odrl-gateway";

const REPLACEMENTS = [
  "templates",
  "odrl",
  "gateway.mjs"
];

const projectRoot = process.cwd();

const packageRoot = path.join(
  projectRoot,
  "node_modules",
  PACKAGE_NAME
);

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
  log("Injecting ODRL-Gateway into current project...");

  if (!fs.existsSync(packageRoot)) {
    log("❌ Package not found in node_modules");
    return;
  }

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

  log("✅ ODRL-Gateway successfully installed into project");
}

run();