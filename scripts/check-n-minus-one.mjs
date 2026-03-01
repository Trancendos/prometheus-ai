#!/usr/bin/env node

import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const DEP_GROUPS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
];
const UNSUPPORTED_PREFIXES = [
  "workspace:",
  "file:",
  "link:",
  "git+",
  "github:",
  "http://",
  "https://",
];

function extractMajor(versionSpec) {
  const match = versionSpec.match(/(\d+)(?:\.\d+)?(?:\.\d+)?/);
  if (!match) {
    return null;
  }

  return Number(match[1]);
}

function usesUnsupportedVersionScheme(versionSpec) {
  return UNSUPPORTED_PREFIXES.some((prefix) => versionSpec.startsWith(prefix));
}

async function npmLatestVersion(packageName) {
  const { stdout } = await execFileAsync("npm", [
    "view",
    packageName,
    "version",
    "--json",
  ]);
  const parsed = JSON.parse(stdout.trim());
  if (typeof parsed !== "string") {
    throw new Error(`Unexpected npm metadata for ${packageName}`);
  }
  return parsed;
}

function formatRow(columns, widths) {
  return columns
    .map((column, index) => String(column).padEnd(widths[index], " "))
    .join("  ");
}

async function main() {
  const packageJson = JSON.parse(await readFile("package.json", "utf8"));
  const checks = [];

  for (const group of DEP_GROUPS) {
    const dependencies = packageJson[group] ?? {};
    for (const [name, versionSpec] of Object.entries(dependencies)) {
      checks.push({ group, name, versionSpec });
    }
  }

  if (checks.length === 0) {
    console.log("No dependencies declared; N/N-1 check skipped.");
    return;
  }

  const results = [];
  for (const check of checks) {
    const currentMajor = extractMajor(check.versionSpec);

    if (usesUnsupportedVersionScheme(check.versionSpec)) {
      results.push({
        ...check,
        latestVersion: "n/a",
        latestMajor: "n/a",
        currentMajor: currentMajor ?? "n/a",
        delta: "n/a",
        status: "FAIL",
        reason: "Unsupported version scheme",
      });
      continue;
    }

    if (currentMajor === null) {
      results.push({
        ...check,
        latestVersion: "n/a",
        latestMajor: "n/a",
        currentMajor: "n/a",
        delta: "n/a",
        status: "FAIL",
        reason: "Could not parse current major version",
      });
      continue;
    }

    try {
      const latestVersion = await npmLatestVersion(check.name);
      const latestMajor = extractMajor(latestVersion);
      if (latestMajor === null) {
        results.push({
          ...check,
          latestVersion,
          latestMajor: "n/a",
          currentMajor,
          delta: "n/a",
          status: "FAIL",
          reason: "Could not parse latest major version",
        });
        continue;
      }

      const delta = latestMajor - currentMajor;
      const status = delta <= 1 ? "PASS" : "FAIL";
      const reason =
        status === "PASS"
          ? "N or N-1 compliant"
          : `Major version lag is ${delta} (>1)`;

      results.push({
        ...check,
        latestVersion,
        latestMajor,
        currentMajor,
        delta,
        status,
        reason,
      });
    } catch (error) {
      results.push({
        ...check,
        latestVersion: "n/a",
        latestMajor: "n/a",
        currentMajor,
        delta: "n/a",
        status: "FAIL",
        reason: `npm lookup failed: ${error.message}`,
      });
    }
  }

  const headers = [
    "group",
    "package",
    "spec",
    "current_major",
    "latest",
    "latest_major",
    "delta",
    "status",
  ];
  const rows = results.map((result) => [
    result.group,
    result.name,
    result.versionSpec,
    result.currentMajor,
    result.latestVersion,
    result.latestMajor,
    result.delta,
    result.status,
  ]);

  const widths = headers.map((header, index) => {
    const rowMax = Math.max(...rows.map((row) => String(row[index]).length), 0);
    return Math.max(header.length, rowMax);
  });

  console.log(formatRow(headers, widths));
  console.log(widths.map((width) => "-".repeat(width)).join("  "));
  for (const row of rows) {
    console.log(formatRow(row, widths));
  }

  const failures = results.filter((result) => result.status === "FAIL");
  if (failures.length > 0) {
    console.error("\nN/N-1 compliance check failed:");
    for (const failure of failures) {
      console.error(`- ${failure.name}: ${failure.reason}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log("\nN/N-1 compliance check passed for all direct dependencies.");
}

await main();
