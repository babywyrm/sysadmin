#!/usr/bin/env node
"use strict";

// --- self-bootstrap ---
(function bootstrap() {
  try {
    require.resolve("mineflayer");
  } catch {
    const { execSync } = require("child_process");
    execSync("npm install mineflayer --save", {
      stdio: "inherit",
      cwd: __dirname,
    });
  }
})();

const mineflayer = require("mineflayer");
const fs = require("fs");
const path = require("path");
const readline = require("readline");

function usage() {
  console.log("Usage:");
  console.log(
    '  node client.js --host <host> --port <port> --user <name> --msg "text"'
  );
  console.log("");
  console.log("Options:");
  console.log("  --host        Target host");
  console.log("  --port        Target port");
  console.log("  --user        Username");
  console.log("  --msg         Message to send");
  console.log("  --ver         Protocol version (e.g. 1.21.1)");
  console.log("  --stay        Stay connected and print chat");
  console.log("  --config      Path to JSON config file");
  console.log("  --stdin       Read message from stdin (pipe support)");
  console.log("");
  console.log("Env vars:");
  console.log("  MC_HOST, MC_PORT, MC_USER, MC_MSG, MC_VER");
  console.log("");
  console.log("Config file (~/.mc-client.json or --config <path>):");
  console.log('  { "host": "...", "port": 25565, "user": "...", "ver": "..." }');
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    if (!key.startsWith("--")) continue;
    const value = argv[i + 1];
    if (value && !value.startsWith("--")) {
      args[key.slice(2)] = value;
      i += 1;
    } else {
      args[key.slice(2)] = true;
    }
  }
  return args;
}

function loadConfig(configPath) {
  const candidates = [
    configPath,
    path.join(process.env.HOME || "~", ".mc-client.json"),
    path.join(__dirname, ".mc-client.json"),
  ].filter(Boolean);

  for (const p of candidates) {
    try {
      return JSON.parse(fs.readFileSync(p, "utf8"));
    } catch {
      // not found or invalid, try next
    }
  }
  return {};
}

function randomName(len = 8) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  return Array.from(
    { length: len },
    () => chars[Math.floor(Math.random() * chars.length)]
  ).join("");
}

async function readStdin() {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin });
    const lines = [];
    rl.on("line", (line) => lines.push(line));
    rl.on("close", () => resolve(lines.join(" ").trim()));
  });
}

async function main() {
  const cliArgs = parseArgs(process.argv.slice(2));

  if (cliArgs.help) {
    usage();
    process.exit(0);
  }

  const config = loadConfig(cliArgs.config);

  // priority: CLI > env > config file
  const host =
    cliArgs.host || process.env.MC_HOST || config.host;
  const port = Number(
    cliArgs.port || process.env.MC_PORT || config.port
  );
  const username =
    cliArgs.user ||
    process.env.MC_USER ||
    config.user ||
    randomName();
  const ver =
    cliArgs.ver || process.env.MC_VER || config.ver;
  const stay = Boolean(cliArgs.stay);

  // message: CLI > env > stdin
  let msg = cliArgs.msg || process.env.MC_MSG;
  if (!msg && cliArgs.stdin) {
    msg = await readStdin();
  }

  if (!host || !port || !msg) {
    usage();
    process.exit(1);
  }

  const options = { host, port, username };
  if (ver) options.version = ver;

  const bot = mineflayer.createBot(options);
  let sent = false;

  bot.once("spawn", () => {
    bot.chat(msg);
    sent = true;

    if (!stay) {
      setTimeout(() => {
        bot.quit();
        process.exit(0);
      }, 1500);
    }
  });

  bot.on("messagestr", (message) => {
    if (stay) console.log(message);
  });

  bot.on("kicked", () => process.exit(2));
  bot.on("error", () => process.exit(3));

  setTimeout(() => {
    if (!sent) process.exit(4);
  }, 15000);
}

main();
