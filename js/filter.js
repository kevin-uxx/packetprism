/* PacketPrism — display filter engine.
 * Grammar:  expr  := or
 *           or    := and (('||' | 'or') and)*
 *           and   := not (('&&' | 'and') not)*
 *           not   := ('!' | 'not') not | primary
 *           primary := '(' expr ')' | field [op value]
 *  ops: == != > < >= <= contains matches(~)   (eq ne gt lt ge le also accepted)
 */
(function (global) {
  'use strict';
  const WORD_OPS = { and: '&&', or: '||', not: '!', eq: '==', ne: '!=', gt: '>', lt: '<', ge: '>=', le: '<=', contains: 'contains', matches: '~' };
  const CMP = new Set(['==', '!=', '>', '<', '>=', '<=', 'contains', '~']);

  function tokenize(s) {
    const toks = [];
    const re = /\s*(?:(\(|\))|(&&|\|\||!=|==|>=|<=|>|<|!|~|=)|("(?:[^"\\]|\\.)*"|'[^']*')|([A-Za-z0-9_.:\-\/*]+))/y;
    let i = 0;
    while (i < s.length) {
      if (/^\s*$/.test(s.slice(i))) break;
      re.lastIndex = i;
      const m = re.exec(s);
      if (!m) throw new Error(`Unexpected character "${s.slice(i).trim()[0]}"`);
      i = re.lastIndex;
      if (m[1]) toks.push({ t: 'paren', v: m[1] });
      else if (m[2]) toks.push({ t: 'op', v: m[2] === '=' ? '==' : m[2] });
      else if (m[3]) toks.push({ t: 'str', v: m[3][0] === '"' ? JSON.parse(m[3]) : m[3].slice(1, -1) });
      else {
        const lw = m[4].toLowerCase();
        if (WORD_OPS[lw]) toks.push({ t: 'op', v: WORD_OPS[lw] });
        else toks.push({ t: 'word', v: m[4] });
      }
    }
    return toks;
  }

  function parseNum(raw) {
    const s = String(raw);
    if (/^0x[0-9a-f]+$/i.test(s)) return parseInt(s, 16);
    if (/^-?\d+(\.\d+)?$/.test(s)) return Number(s);
    return null;
  }

  function makeCmp(field, op, raw) {
    const num = parseNum(raw);
    const rs = String(raw).toLowerCase();
    let rx = null;
    if (op === '~') { try { rx = new RegExp(raw, 'i'); } catch (e) { throw new Error(`Invalid regex: ${e.message}`); } }
    const test = v => {
      if (v === undefined || v === null) return false;
      if (op === 'contains') return String(v).toLowerCase().includes(rs);
      if (op === '~') return rx.test(String(v));
      if (typeof v === 'number' && num !== null) {
        switch (op) { case '==': return v === num; case '!=': return v !== num; case '>': return v > num; case '<': return v < num; case '>=': return v >= num; case '<=': return v <= num; }
      }
      const sv = String(v).toLowerCase();
      switch (op) { case '==': return sv === rs; case '!=': return sv !== rs; case '>': return sv > rs; case '<': return sv < rs; case '>=': return sv >= rs; case '<=': return sv <= rs; }
      return false;
    };
    return f => {
      const v = f[field];
      if (Array.isArray(v)) return op === '!=' ? v.every(test) : v.some(test);
      return test(v);
    };
  }

  function compile(src, known) {
    const toks = tokenize(src);
    if (!toks.length) return null;
    let p = 0;
    const peek = () => toks[p];
    const isOp = v => peek() && peek().t === 'op' && peek().v === v;
    function parseOr() { let l = parseAnd(); while (isOp('||')) { p++; const r = parseAnd(), a = l; l = f => a(f) || r(f); } return l; }
    function parseAnd() { let l = parseNot(); while (isOp('&&')) { p++; const r = parseNot(), a = l; l = f => a(f) && r(f); } return l; }
    function parseNot() { if (isOp('!')) { p++; const e = parseNot(); return f => !e(f); } return parsePrimary(); }
    function parsePrimary() {
      const t = toks[p++];
      if (!t) throw new Error('Unexpected end of filter');
      if (t.t === 'paren' && t.v === '(') {
        const e = parseOr();
        const c = toks[p++];
        if (!c || c.v !== ')') throw new Error('Missing closing parenthesis');
        return e;
      }
      if (t.t !== 'word') throw new Error(`Unexpected "${t.v}"`);
      const field = t.v.toLowerCase();
      if (known && !known(field)) throw new Error(`"${t.v}" is neither a field nor a protocol`);
      const o = peek();
      if (o && o.t === 'op' && CMP.has(o.v)) {
        p++;
        const vt = toks[p++];
        if (!vt || (vt.t !== 'word' && vt.t !== 'str')) throw new Error(`Expected a value after "${o.v}"`);
        return makeCmp(field, o.v, vt.v);
      }
      return f => { const v = f[field]; return v !== undefined && v !== 0 && v !== '' && v !== false; };
    }
    const fn = parseOr();
    if (p < toks.length) throw new Error(`Unexpected "${toks[p].v}"`);
    return fn;
  }

  global.DisplayFilter = { compile, tokenize };
})(window);
