const [major, minor, patch] = process.versions.node.split(".").map(Number);
const floor = { 22: [23, 4], 24: [22, 1], 26: [12, 1] }[major];
if (!floor || minor < floor[0] || (minor === floor[0] && patch < floor[1])) {
  console.error(`Node ${process.version} is below the supported floor`);
  process.exit(1);
}
