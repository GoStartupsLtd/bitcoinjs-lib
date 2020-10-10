import * as assert from 'assert';
import { describe, it } from 'mocha';

import {
  ECPair,
  networks as NETWORKS,
  Psbt,
  Transaction,
  TransactionBuilder,
} from '..';
import * as bcrypto from '../src/crypto';
import * as bscript from '../src/script';

const OPS = bscript.OPS;
const network = NETWORKS.bitcoingold;

describe('TransactionBuilder', () => {
  it('goldtestcase', () => {
    const value = 50 * 1e8;
    const txid =
      '40c8a218923f23df3692530fa8e475251c50c7d630dccbdfbd92ba8092f4aa13';
    const vout = 0;

    const wif = 'L54PmHcjKXi8H6v9cLAJ7DgGJFDpaFpR2YsV2WARieb82dz3QAfr';
    const keyPair = ECPair.fromWIF(wif, network);

    const pkh = bcrypto.hash160(keyPair.publicKey);
    const spk = bscript.compile([
      OPS.OP_DUP,
      OPS.OP_HASH160,
      pkh,
      OPS.OP_EQUALVERIFY,
      OPS.OP_CHECKSIG,
    ]);

    const txb = new TransactionBuilder(network);
    txb.addInput(txid, vout, Transaction.DEFAULT_SEQUENCE, spk);
    txb.addOutput('GfEHv6hKvAX8HYfFzabMY2eiYDtC9eViqe', value);
    txb.enableBitcoinGold(true);
    txb.setVersion(2);

    const hashType = Transaction.SIGHASH_ALL | Transaction.SIGHASH_FORKID;

    txb.sign(0, keyPair, undefined, hashType, value);

    const tx = txb.build();
    const hex = tx.toHex();
    assert.strictEqual(
      '020000000113aaf49280ba92bddfcbdc30d6c7501c2575e4a80f539236df233f9218a2c840000000006b483045022100c594c8e0750b1b6ec4e267b6d6c7098840f86fa9467f8aa452f439c3a72e0cd9022019759d800fffd7fcb78d16468f5693ea07a13da33607e0e8fbb4cdb5967075b441210201ad6a9a15457b162a71f1d5db8fe27ff001abc4ae3a888214f9407cb0da863cffffffff0100f2052a010000001976a914ea95bd5087d3b5f2df279304a46ad827225c4e8688ac00000000',
      hex,
    );
  });

  it('goldtestcase_multisig_1', () => {
    const value = 50 * 1e8;

    const txHex =
      '020000000113aaf49280ba92bddfcbdc30d6c7501c2575e4a80f539236df233f9218a2c840000000009200483045022100b3b4211b8e8babc667dcca0b6f1c1284f191170a38a59bc3b9d7541d68c3c7a002200196267b87a7b80f3f556b3372e5ee6ed19b4b9e802c34916f45bc2b11d2de1a414752210201ad6a9a15457b162a71f1d5db8fe27ff001abc4ae3a888214f9407cb0da863c2103e6533849994cf76a9009447f2ad6dbf84c78e6f5f48fe77cf83cd9a3fe2e30ec52aeffffffff0100f2052a010000001976a914ea95bd5087d3b5f2df279304a46ad827225c4e8688ac00000000';
    const tx = Transaction.fromHex(txHex);

    const txb = TransactionBuilder.fromTransaction(
      tx,
      network,
      Transaction.FORKID_BTG,
      [value],
    );

    assert.strictEqual(undefined, (txb as any).__INPUTS[0].signatures[0]);
    assert.strictEqual(
      (txb as any).__INPUTS[0].signatures[1].toString('hex'),
      '3045022100b3b4211b8e8babc667dcca0b6f1c1284f191170a38a59bc3b9d7541d68c3c7a002200196267b87a7b80f3f556b3372e5ee6ed19b4b9e802c34916f45bc2b11d2de1a41',
    );

    const hex = txb.build().toHex();
    assert.strictEqual(txHex, hex);
  });

  it('goldtestcase_multisig_0', () => {
    const value = 50 * 1e8;

    const txHex =
      '020000000113aaf49280ba92bddfcbdc30d6c7501c2575e4a80f539236df233f9218a2c840000000009100473044022025cb6ee7a63c7403645be2ed4ffcf9cd41d773ee3ba57a05dc335c4427f647660220323a038daac698efdc700ffa8d90e6641ed9eb4ab82808df0506a9da08863d29414752210201ad6a9a15457b162a71f1d5db8fe27ff001abc4ae3a888214f9407cb0da863c2103e6533849994cf76a9009447f2ad6dbf84c78e6f5f48fe77cf83cd9a3fe2e30ec52aeffffffff0100f2052a010000001976a914ea95bd5087d3b5f2df279304a46ad827225c4e8688ac00000000';
    const tx = Transaction.fromHex(txHex);
    // tx.ins[0].value = value

    const txb = TransactionBuilder.fromTransaction(
      tx,
      network,
      Transaction.FORKID_BTG,
      [value],
    );

    assert.strictEqual(
      (txb as any).__INPUTS[0].signatures[0].toString('hex'),
      '3044022025cb6ee7a63c7403645be2ed4ffcf9cd41d773ee3ba57a05dc335c4427f647660220323a038daac698efdc700ffa8d90e6641ed9eb4ab82808df0506a9da08863d2941',
    );
    assert.strictEqual((txb as any).__INPUTS[0].signatures[1], undefined);

    const hex = txb.build().toHex();
    assert.strictEqual(txHex, hex);
  });
});

describe('PsbtBitcoinGold', () => {
  it('can sign p2pkh', () => {
    const txHex =
      '02000000019a6f4afcc1adcb2c363ae9e70a3233081cc6e53535b1218ca98bfdc10d2c0d6d00000000484730440220688494e278cfd7d9a69ed16315a6acadee3843153d3e503028002f17c270bfc5022004cfa9289239527b4277f9908f1b9d09713963f14300020c980d883ca19e011f41fdffffff0239300000000000001976a914a6f10b0d663f9714cca7ff555f6badd153df6f4088ac626112000000000017a9144d93014ad2f317fbd77dc4c18e81e731e48bf62487d2070000';
    const txid =
      '1363a4e5c806350bc80205c8d692e8c9df3820570ea94a1bceb0cada6730ea4a';
    const vout = 0;

    const wif = 'cRQcrfrCVadS3zGA2SF5DzDKhPD9YccP2upsY46VNxfUTeeua3iQ';
    const keyPair = ECPair.fromWIF(wif, NETWORKS.bitcoingoldregtest);

    const psbt = new Psbt({ network: NETWORKS.bitcoingoldregtest });
    psbt.addInput({
      hash: txid,
      index: vout,
      nonWitnessUtxo: Buffer.from(txHex, 'hex'),
      sighashType: Transaction.SIGHASH_ALL | Transaction.SIGHASH_FORKID,
    });
    psbt.addOutput({
      address: 'msUVLJqc6r3rgCgpZnhia1wdKwrmWiXw66',
      value: 10000,
    });
    psbt.signInput(0, keyPair, [
      Transaction.SIGHASH_ALL | Transaction.SIGHASH_FORKID,
    ]);
    const ok = psbt.validateSignaturesOfAllInputs();
    assert.ok(ok, 'Must be valid');
    psbt.finalizeAllInputs();
    const finalizedTx = psbt.extractTransaction().toHex();

    assert.strictEqual(
      finalizedTx,
      '02000000014aea3067dacab0ce1b4aa90e572038dfc9e892d6c80502c80b3506c8e5a46313000000006a4730440220442bd6638017730120390d15ceb12b0baaea38e3a168c707591ac4f2a44bbaf3022058fbe379aaaf18d3ded08e5aa9c363e044c86281fa67685318eaf89047ffd8b9412103eca050ae8c28884be591c20d7370dfcf846f0f56ce40dfe463204df35bbac15effffffff0110270000000000001976a914832a2be4f27f39c4b04cde1511f2791f6f0534a088ac00000000',
    );
  });

  it('can sign cltv-multisig', () => {
    const net = NETWORKS.bitcoingoldregtest;
    const wifs = [
      'cNbbtkrw8pG1kRxdAfDNL2Y712kAbsGQzhcPvic5YCg2PT4Xq8wJ',
      'cRQcrfrCVadS3zGA2SF5DzDKhPD9YccP2upsY46VNxfUTeeua3iQ',
    ];
    const keys = wifs.map(wif => ECPair.fromWIF(wif, net));

    const chunks = [
      bscript.number.encode(100),
      OPS.OP_CHECKLOCKTIMEVERIFY,
      OPS.OP_DROP,
      OPS.OP_2,
      keys[0].publicKey,
      keys[1].publicKey,
      OPS.OP_2,
      OPS.OP_CHECKMULTISIG,
    ];
    const script = bscript.compile(chunks);
    assert.strictEqual(
      script.toString('hex'),
      '0164b175522102f524dd1f51e21260af8b8506b30f2c977b29183f29d952c551f2dc502334a13b2103eca050ae8c28884be591c20d7370dfcf846f0f56ce40dfe463204df35bbac15e52ae',
    );

    // p2sh: 2MxScb213puH4yrEqxcT4MRjPTHeEqud5U1
    // fund tx id: 49c1cf131e384094dfb254175ed4aa076ac6cd02e5bfc4e3a27c5bd6dce1044e
    const rawTx =
      '0200000004d66c101305bd5f2a2f3c5286db71df98e61a7d1fcf3464defb2d1cd83c2692970000000048473044022021a447b7a2f80001f3ffc7c874e7a3b2a0ba78110f1c32f4ff364f66a20559eb02204a8ab5699688b8d47184696ec28e461f64091333fe8cd125139b7661ec06b6c741feffffff0396b0f7a8f0b3680a62807119ac403f063d559815eadeabd2f8828d503700c40000000048473044022014ea109796e1a75e755688df982a7ca2e66fcf9540f38c9cdc76c8d536ce638f02203199c554131bdb2ed8df606593ec6c527539368670f5439de00c34fefc9309a841feffffff62e294bf6d17e8f75458002145023c9abb35156cb7eb9c25493817de0ba1ffbd0000000048473044022025cc01c17922a95f0ecc8cb959e9f180060464d310092b60680dc2515ec97360022029e5cfdce02e027c51816742128b1c8748a90f89046e8550222f31e7101be60a41fefffffff943edaa5f5f93de036f499776dca9d6dfe0eab0df4c1e3880f1550055a87f61000000004847304402203d46855fd96fe45caa121254fdf3b1088931c472747ca1bf0f39fa55ff2e04c3022066d7887197c300031d07036533cb8dbab0bb80e522be940a158d15b2c878ed7b41feffffff0200e1f5050000000017a914390011af3fd148ff9ebd26eeb216a16e8b068e7587bff413000000000017a914b81fd6decc8c6f3f41d07e8a322acce98dc3a4cf87d4070000';

    const psbt = new Psbt({ network: net });
    psbt.setLocktime(200);
    psbt.addInput({
      hash: '49c1cf131e384094dfb254175ed4aa076ac6cd02e5bfc4e3a27c5bd6dce1044e',
      index: 0,
      nonWitnessUtxo: Buffer.from(rawTx, 'hex'),
      redeemScript: script,
      sighashType: Transaction.SIGHASH_ALL | Transaction.SIGHASH_FORKID,
      sequence: 1,
    });
    psbt.addOutput({
      address: 'msUVLJqc6r3rgCgpZnhia1wdKwrmWiXw66',
      value: 99999000,
    });
    assert.strictEqual(psbt.getInputType(0), 'p2sh-cltvmultisig');

    psbt.signInput(0, keys[0], [
      Transaction.SIGHASH_ALL | Transaction.SIGHASH_FORKID,
    ]);
    psbt.signInput(0, keys[1], [
      Transaction.SIGHASH_ALL | Transaction.SIGHASH_FORKID,
    ]);
    const ok = psbt.validateSignaturesOfAllInputs();
    assert.ok(ok, 'Must be valid');

    psbt.finalizeAllInputs();
    const finalizedTx = psbt.extractTransaction().toHex();
    assert.strictEqual(
      finalizedTx,
      '02000000014e04e1dcd65b7ca2e3c4bfe502cdc66a07aad45e1754b2df9440381e13cfc14900000000de00473044022016b33af7266647059a99507d8a2502a505e450f9d0f64db149938c099147ce3b022022e7c01000d51463e2fb8dba444463e4c32c32cab16c3a92070e26664c1dbcd241483045022100cc450b6aa79dc64dcd8fdba8d37608d993431e59d2f53cbc3fd7e2cfc33773ba022068ee7a742cca93ea8b0a9cf7d1f63c7ae21f3eab79e415035ddb9b34ee89e36b414b0164b175522102f524dd1f51e21260af8b8506b30f2c977b29183f29d952c551f2dc502334a13b2103eca050ae8c28884be591c20d7370dfcf846f0f56ce40dfe463204df35bbac15e52ae010000000118ddf505000000001976a914832a2be4f27f39c4b04cde1511f2791f6f0534a088acc8000000',
    );
  });
});
