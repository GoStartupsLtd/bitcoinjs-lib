import * as bscript from '../script';
import * as scriptNumber from '../script_number';
import { Payment, PaymentOpts, Stack } from './index';
import * as lazy from './lazy';
import { p2ms } from './p2ms';
const OPS = bscript.OPS;
const typef = require('typeforce');

const OP_INT_BASE = OPS.OP_RESERVED; // OP_1 - 1
function decodeNumber(op: number | Buffer): number {
  if (typeof op === 'number') {
    if (op === OPS.OP_0) {
      return 0;
    } else if (OPS.OP_1 <= op && op <= OPS.OP_16) {
      return op - OP_INT_BASE;
    } else {
      throw new TypeError(`Invalid opcode. Expect a number op but got ${op}`);
    }
  } else {
    return scriptNumber.decode(op);
  }
}

// input: OP_0 [signatures ...]
// output: locktime OP_CHECKLOCKTIMEVERIFY OP_DROP m [pubKeys ...] n OP_CHECKMULTISIG
export function p2cltvms(a: Payment, opts?: PaymentOpts): Payment {
  const innerPayment = Object.assign({}, a) as Payment;
  let fallbackLocktime = a.locktime || 0;
  if (a.output) {
    const chunks = bscript.decompile(a.output) as Stack;
    if (chunks[1] !== OPS.OP_CHECKLOCKTIMEVERIFY || chunks[2] !== OPS.OP_DROP) {
      throw new TypeError('Output is not p2cltvms' + `(${chunks})`);
    }
    if (!typef.Buffer(chunks[0]) && !typef.Number(chunks[0])) {
      throw new TypeError(
        `Invalid CLTV parameter. Should be "Buffer | number" but got "${typeof chunks[0]}"`,
      );
    }
    fallbackLocktime = decodeNumber(chunks[0]);
    const p2msOutput = chunks.slice(3);
    innerPayment.output = bscript.compile(p2msOutput);
  }

  const o = p2ms(innerPayment, opts);
  o.m, o.n, o.pubkey; // force lazy decoding

  o.locktime = a.locktime || fallbackLocktime;
  if (o.output) {
    const chunks = bscript.decompile(o.output) as Stack;
    chunks.splice(
      0,
      0,
      scriptNumber.encode(o.locktime),
      OPS.OP_CHECKLOCKTIMEVERIFY,
      OPS.OP_DROP,
    );
    o.output = bscript.compile(chunks);
  }

  lazy.prop(o, 'name', () => {
    if (!o.m || !o.n) return;
    return `p2cltvms(${o.m} of ${o.n})`;
  });
  return Object.assign({}, o, a);
}
