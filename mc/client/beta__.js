#!/usr/bin/env node
"use strict";

const mineflayer = require("mineflayer");

function usage() {
  console.log("Usage:");
  console.log(
    '  node client.js --host <host> --port <port> --user <name> --msg "text"'
  );
  console.log("");
  console.log("Options:");
  console.log("  --host     Target host");
  console.log("  --port     Target port");
  console.log("  --user     Username");
  console.log("  --msg      Message to send (required)");
  console.log("  --ver      Protocol version (e.g. 1.21.1)");
  console.log("  --stay     Stay connected and print chat");
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

function randomName(len = 8) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  return Array.from(
    { length: len },
    () => chars[Math.floor(Math.random() * chars.length)]
  ).join("");
}

const args = parseArgs(process.argv.slice(2));

if (!args.msg || !args.host || !args.port) {
  usage();
  process.exit(1);
}

const username = args.user || randomName();
const host = args.host;
const port = Number(args.port);
const stay = Boolean(args.stay);

const options = { host, port, username };
if (args.ver) options.version = args.ver;

const bot = mineflayer.createBot(options);

let sent = false;

bot.once("spawn", () => {
  bot.chat(args.msg);
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

bot.on("kicked", () => {
  process.exit(2);
});

bot.on("error", () => {
  process.exit(3);
});

setTimeout(() => {
  if (!sent) process.exit(4);
}, 15000);
