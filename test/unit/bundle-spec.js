const fs = require('fs');
const path = require('path');
const src = require('../../src/marked.js');
// The UMD bundle package.json#browser points at. It is generated from src/ by
// rollup, but the release packs it as committed instead of re-running rollup
// (that would rewrite the license banner with the current year), so a fix
// landed in src/ does NOT reach it on its own -- CVE-2022-21680 and
// CVE-2022-21681 were fixed in src/rules.js while this bundle still shipped
// the vulnerable block.def / inline.reflink / inline.nolink regexes.
// Re-parsing the ReDoS corpus through the bundle fails the moment it drifts
// from src/ again: a vulnerable copy backtracks until jasmine times the spec
// out. lib/marked.esm.js is not covered here because Node 8 cannot import it;
// marked.min.js is deliberately not covered either, since it is regenerated
// from lib/marked.js by `npm run minify` during packaging.
const bundle = require('../../lib/marked.js');

const cubicDef = require('../specs/redos/cubic_def.js');
const reflinkRedos = fs.readFileSync(
  path.resolve(__dirname, '../specs/redos/reflink_redos.md'),
  'utf8'
);

describe('lib/marked.js bundle ReDoS parity with src/', () => {
  beforeEach(() => {
    bundle.setOptions(bundle.getDefaults());
  });

  it('resolves the block.def ReDoS input without backtracking', () => {
    const start = Date.now();
    const actual = bundle(cubicDef.markdown);

    expect(Date.now() - start).toBeLessThan(2000);
    expect(actual).toBe(src(cubicDef.markdown));
  });

  it('resolves the reflink/nolink ReDoS input without backtracking', () => {
    const start = Date.now();
    const actual = bundle(reflinkRedos);

    expect(Date.now() - start).toBeLessThan(2000);
    expect(actual).toBe(src(reflinkRedos));
  });

  it('exposes the hardened link-reference rules', () => {
    const rules = bundle.Lexer.rules;

    expect(rules.block.normal._label.source).toBe(src.Lexer.rules.block.normal._label.source);
    expect(rules.inline.normal.reflink.source).toBe(src.Lexer.rules.inline.normal.reflink.source);
    expect(rules.inline.normal.nolink.source).toBe(src.Lexer.rules.inline.normal.nolink.source);
    expect(rules.block.normal.def.source).toBe(src.Lexer.rules.block.normal.def.source);
  });
});
