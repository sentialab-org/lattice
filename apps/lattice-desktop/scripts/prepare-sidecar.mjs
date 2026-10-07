import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const appDir = resolve(scriptDir, "..");
const repoDir = resolve(appDir, "../..");
const release = process.argv.includes("--release");
const triple = execFileSync("rustc", ["--print", "host-tuple"], { encoding: "utf8" }).trim();
const extension = triple.includes("windows") ? ".exe" : "";
const profile = release ? "release" : "debug";
const packages = ["lattice-node", "lattice-update-helper", "lattice-worker"];

for (const packageName of packages) {
  const cargoArgs = ["build", "--manifest-path", resolve(repoDir, "Cargo.toml"), "-p", packageName];

  if (release) {
    cargoArgs.push("--release");
  }

  execFileSync("cargo", cargoArgs, { stdio: "inherit" });

  const source = resolve(repoDir, "target", profile, packageName + extension);
  const destination = resolve(
    appDir,
    "src-tauri",
    "binaries",
    packageName + "-" + triple + extension
  );

  mkdirSync(dirname(destination), { recursive: true });
  copyFileSync(source, destination);
  console.log("Prepared " + destination);
}
