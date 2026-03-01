#!/usr/bin/env node

import { execFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const DEFAULT_OWNER = "Trancendos";
const DEFAULT_LIMIT = 200;
const DEFAULT_MARKDOWN_OUTPUT = "reports/org-security-audit.md";
const DEFAULT_JSON_OUTPUT = "reports/org-security-audit.json";

const args = process.argv.slice(2);
const owner = args[0] || DEFAULT_OWNER;
const limit = Number(args[1] || DEFAULT_LIMIT);

if (Number.isNaN(limit) || limit <= 0) {
  console.error("Limit must be a positive number.");
  process.exit(1);
}

async function ghJson(commandArgs, { allowFailure = false } = {}) {
  try {
    const { stdout } = await execFileAsync("gh", commandArgs, {
      maxBuffer: 1024 * 1024 * 20,
    });
    return JSON.parse(stdout);
  } catch (error) {
    if (allowFailure) {
      return null;
    }
    const stderr = error.stderr ? String(error.stderr).trim() : "";
    throw new Error(
      `gh ${commandArgs.join(" ")} failed${stderr ? `: ${stderr}` : ""}`,
    );
  }
}

function toNameSet(contents) {
  if (!Array.isArray(contents)) {
    return new Set();
  }
  return new Set(contents.map((entry) => entry.name));
}

function detectStack(rootNames) {
  const stacks = [];
  if (rootNames.has("package.json")) {
    stacks.push("node");
  }
  if (
    rootNames.has("pyproject.toml") ||
    rootNames.has("requirements.txt") ||
    rootNames.has("Pipfile")
  ) {
    stacks.push("python");
  }
  if (rootNames.has("go.mod")) {
    stacks.push("go");
  }
  if (rootNames.has("Cargo.toml")) {
    stacks.push("rust");
  }
  if (
    rootNames.has("pom.xml") ||
    rootNames.has("build.gradle") ||
    rootNames.has("build.gradle.kts")
  ) {
    stacks.push("java");
  }
  if (rootNames.has("Gemfile")) {
    stacks.push("ruby");
  }
  if (rootNames.has("composer.json")) {
    stacks.push("php");
  }
  if (rootNames.has("Dockerfile")) {
    stacks.push("container");
  }
  if (stacks.length === 0) {
    return "unknown";
  }
  return stacks.join("+");
}

function hasArchitectureArtifacts(rootNames) {
  for (const name of rootNames) {
    const lower = name.toLowerCase();
    if (
      lower === "architecture.md" ||
      lower === "adr.md" ||
      lower.startsWith("architecture-")
    ) {
      return true;
    }
  }
  return rootNames.has("docs");
}

function workflowMatches(workflowNames, regex) {
  return workflowNames.some((name) => regex.test(name));
}

function calculatePriority(gaps) {
  const criticalGaps = [
    "No Dependabot updates",
    "No CVE/security workflow",
    "No dependency workflow",
  ];
  const criticalCount = gaps.filter((gap) => criticalGaps.includes(gap)).length;

  if (criticalCount >= 2) {
    return "P0";
  }
  if (criticalCount === 1) {
    return "P1";
  }
  if (gaps.length > 0) {
    return "P2";
  }
  return "P3";
}

function gapString(gaps) {
  if (gaps.length === 0) {
    return "none";
  }
  return gaps.join("; ");
}

function statusMark(value) {
  return value ? "yes" : "no";
}

function markdownEscape(value) {
  return String(value).replaceAll("|", "\\|");
}

async function fetchRepoBaseline(repo) {
  const branch = repo.defaultBranchRef?.name || "main";
  const encodedRef = encodeURIComponent(branch);
  const rootContents = await ghJson(
    ["api", `repos/${repo.nameWithOwner}/contents?ref=${encodedRef}`],
    { allowFailure: true },
  );
  const rootNames = toNameSet(rootContents);

  let githubNames = new Set();
  let workflowNames = [];

  if (rootNames.has(".github")) {
    const githubContents = await ghJson(
      ["api", `repos/${repo.nameWithOwner}/contents/.github?ref=${encodedRef}`],
      { allowFailure: true },
    );
    githubNames = toNameSet(githubContents);

    if (githubNames.has("workflows")) {
      const workflows = await ghJson(
        [
          "api",
          `repos/${repo.nameWithOwner}/contents/.github/workflows?ref=${encodedRef}`,
        ],
        { allowFailure: true },
      );
      if (Array.isArray(workflows)) {
        workflowNames = workflows.map((entry) => entry.name);
      }
    }
  }

  const hasDependabot =
    githubNames.has("dependabot.yml") || githubNames.has("dependabot.yaml");
  const hasSecurityPolicy =
    rootNames.has("SECURITY.md") || githubNames.has("SECURITY.md");
  const hasCodeowners =
    rootNames.has("CODEOWNERS") ||
    githubNames.has("CODEOWNERS") ||
    githubNames.has("codeowners");
  const hasCveWorkflow = workflowMatches(
    workflowNames,
    /(security|codeql|osv|trivy|audit|cve|sast|vuln|scan)/i,
  );
  const hasDependencyWorkflow = workflowMatches(
    workflowNames,
    /(depend|dependency|deps|review|outdated|sbom|bom)/i,
  );
  const hasArchitectureDoc = hasArchitectureArtifacts(rootNames);
  const stack = detectStack(rootNames);

  const gaps = [];
  if (!hasDependabot) {
    gaps.push("No Dependabot updates");
  }
  if (!hasCveWorkflow) {
    gaps.push("No CVE/security workflow");
  }
  if (!hasDependencyWorkflow) {
    gaps.push("No dependency workflow");
  }
  if (!hasSecurityPolicy) {
    gaps.push("No SECURITY.md policy");
  }
  if (!hasCodeowners) {
    gaps.push("No CODEOWNERS");
  }
  if (!hasArchitectureDoc) {
    gaps.push("No architecture docs");
  }

  return {
    repo: repo.nameWithOwner,
    url: repo.url,
    updatedAt: repo.updatedAt,
    stack,
    hasDependabot,
    hasSecurityPolicy,
    hasCodeowners,
    hasCveWorkflow,
    hasDependencyWorkflow,
    hasArchitectureDoc,
    workflowCount: workflowNames.length,
    priority: calculatePriority(gaps),
    gaps,
  };
}

function sortByPriorityAndName(results) {
  const score = { P0: 0, P1: 1, P2: 2, P3: 3 };
  return [...results].sort((a, b) => {
    const priorityDiff = score[a.priority] - score[b.priority];
    if (priorityDiff !== 0) {
      return priorityDiff;
    }
    return a.repo.localeCompare(b.repo);
  });
}

function buildMarkdown(ownerName, results) {
  const generatedAt = new Date().toISOString();
  const counts = {
    total: results.length,
    p0: results.filter((result) => result.priority === "P0").length,
    p1: results.filter((result) => result.priority === "P1").length,
    p2: results.filter((result) => result.priority === "P2").length,
    p3: results.filter((result) => result.priority === "P3").length,
    missingDependabot: results.filter((result) => !result.hasDependabot).length,
    missingCveWorkflow: results.filter((result) => !result.hasCveWorkflow).length,
    missingDependencyWorkflow: results.filter(
      (result) => !result.hasDependencyWorkflow,
    ).length,
  };

  const lines = [];
  lines.push(`# Org Security Baseline Audit - ${ownerName}`);
  lines.push("");
  lines.push(`Generated: ${generatedAt}`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`- Total repositories audited: ${counts.total}`);
  lines.push(`- Priority P0: ${counts.p0}`);
  lines.push(`- Priority P1: ${counts.p1}`);
  lines.push(`- Priority P2: ${counts.p2}`);
  lines.push(`- Priority P3: ${counts.p3}`);
  lines.push(`- Missing Dependabot: ${counts.missingDependabot}`);
  lines.push(`- Missing CVE workflow: ${counts.missingCveWorkflow}`);
  lines.push(`- Missing dependency workflow: ${counts.missingDependencyWorkflow}`);
  lines.push("");
  lines.push("## Repository Baseline Matrix");
  lines.push("");
  lines.push(
    "| Repository | Stack | Dependabot | CVE Workflow | Dependency Workflow | SECURITY.md | CODEOWNERS | Architecture Doc | Priority | Gaps |",
  );
  lines.push(
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
  );

  for (const result of sortByPriorityAndName(results)) {
    lines.push(
      `| ${markdownEscape(result.repo)} | ${result.stack} | ${statusMark(result.hasDependabot)} | ${statusMark(result.hasCveWorkflow)} | ${statusMark(result.hasDependencyWorkflow)} | ${statusMark(result.hasSecurityPolicy)} | ${statusMark(result.hasCodeowners)} | ${statusMark(result.hasArchitectureDoc)} | ${result.priority} | ${markdownEscape(gapString(result.gaps))} |`,
    );
  }

  lines.push("");
  lines.push("## Notes");
  lines.push("");
  lines.push(
    "- This audit is file-presence based and intended as a fast baseline signal.",
  );
  lines.push(
    "- Repositories with Priority P0 should receive security baseline rollout first.",
  );
  lines.push(
    "- Re-run this audit after each baseline rollout wave to track closure.",
  );
  lines.push("");

  return lines.join("\n");
}

async function main() {
  console.log(`Fetching repositories for owner '${owner}' (limit ${limit})...`);
  const repos = await ghJson([
    "repo",
    "list",
    owner,
    "--limit",
    String(limit),
    "--json",
    "nameWithOwner,url,updatedAt,defaultBranchRef",
  ]);

  const results = [];
  for (const repo of repos) {
    console.log(`Auditing ${repo.nameWithOwner}...`);
    try {
      const baseline = await fetchRepoBaseline(repo);
      results.push(baseline);
    } catch (error) {
      results.push({
        repo: repo.nameWithOwner,
        url: repo.url,
        updatedAt: repo.updatedAt,
        stack: "unknown",
        hasDependabot: false,
        hasSecurityPolicy: false,
        hasCodeowners: false,
        hasCveWorkflow: false,
        hasDependencyWorkflow: false,
        hasArchitectureDoc: false,
        workflowCount: 0,
        priority: "P0",
        gaps: [`Audit error: ${error.message}`],
      });
    }
  }

  const markdown = buildMarkdown(owner, results);

  await mkdir(path.dirname(DEFAULT_MARKDOWN_OUTPUT), { recursive: true });
  await writeFile(DEFAULT_MARKDOWN_OUTPUT, markdown, "utf8");
  await writeFile(
    DEFAULT_JSON_OUTPUT,
    JSON.stringify(
      {
        owner,
        generatedAt: new Date().toISOString(),
        results: sortByPriorityAndName(results),
      },
      null,
      2,
    ),
    "utf8",
  );

  const p0Repos = results.filter((result) => result.priority === "P0").length;
  console.log(
    `Audit complete. Wrote ${DEFAULT_MARKDOWN_OUTPUT} and ${DEFAULT_JSON_OUTPUT}.`,
  );
  console.log(`P0 repositories identified: ${p0Repos}/${results.length}`);
}

await main();
