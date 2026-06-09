# Research

Vulnerability research conducted using vulnscope.

## Findings

| Package | Type | Severity | Advisory | Status |
|---------|------|----------|----------|--------|
| marsdb | Arbitrary Code Execution via `$where` | Critical | [GHSA-5mrr-rgp6-x4gr](https://github.com/advisories/GHSA-5mrr-rgp6-x4gr) | [PR submitted](https://github.com/github/advisory-database/pull/7914) |

## marsdb — ACE/RCE via unsanitized `$where` selector

**File:** `marsdb-poc.js`

The `$where` query selector passes user-supplied strings directly to the
`Function()` constructor without any sanitization:

```js
// DocumentMatcher.js:419
selectorValue = Function('obj', 'return ' + selectorValue);
```

**Impact:**
- Node.js <= 18: Full RCE via `require('child_process')`
- Node.js >= 20: ACE confirmed — arbitrary JS execution, authentication bypass

**Discovery:** Identified via vulnscope's Claude-powered deep analysis on the
`GHSA-5mrr-rgp6-x4gr` advisory, which lacked a PoC and technical details.
