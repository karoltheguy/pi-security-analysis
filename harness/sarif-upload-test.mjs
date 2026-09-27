// harness/sarif-upload-test.mjs — pure unit test for shouldUploadSarif (plain node, no framework)
// No session boot, no fixture repo. Imports shouldUploadSarif from ./print.mjs.
import { shouldUploadSarif } from "./print.mjs";

function report(label, ok) {
  console.log(`${ok ? "OK  " : "FAIL"} ${label}`);
  return ok;
}

let failed = false;

failed =
  !report(
    "shouldUploadSarif: exitCode 0 + sarif hook → true",
    shouldUploadSarif({ exitCode: 0, hook: "curl -T %s x" }) === true,
  ) || failed;

failed =
  !report(
    "shouldUploadSarif: exitCode 1 + hook → false",
    shouldUploadSarif({ exitCode: 1, hook: "cmd" }) === false,
  ) || failed;

failed =
  !report(
    "shouldUploadSarif: exitCode 3 + hook → false",
    shouldUploadSarif({ exitCode: 3, hook: "cmd" }) === false,
  ) || failed;

failed =
  !report(
    "shouldUploadSarif: exitCode 0 + empty hook → false",
    shouldUploadSarif({ exitCode: 0, hook: "" }) === false,
  ) || failed;

failed =
  !report(
    "shouldUploadSarif: exitCode 0 + undefined hook → false",
    shouldUploadSarif({ exitCode: 0 }) === false,
  ) || failed;

process.exitCode = failed ? 1 : 0;
