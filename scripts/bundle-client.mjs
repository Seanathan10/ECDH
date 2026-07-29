import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceDir = "ecdh-demo";
const outDir = resolve(root, "public/download");

const FILES = [ "ecdh.c", "Makefile" ];

rmSync( outDir, { recursive: true, force: true } );
mkdirSync( outDir, { recursive: true } );

for (const file of FILES) {
	cpSync(resolve(root, sourceDir, file), resolve(outDir, file));
}

execFileSync("tar", ["-czf", resolve(outDir, "ecdh-demo.tar.gz"), "--exclude", "ecdh", sourceDir], {
	cwd: root,
	stdio: "inherit",
});

console.log("bundled " + sourceDir + "/ -> public/download/ (" + FILES.join(", ") + " + tarball)");
