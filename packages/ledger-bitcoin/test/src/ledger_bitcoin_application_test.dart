import 'dart:typed_data';

import 'package:ledger_bitcoin/ledger_bitcoin.dart';
import 'package:ledger_bitcoin/src/ledger_bitcoin_application.dart'
    show applyWalletPolicySignature;
import 'package:ledger_bitcoin/src/utils/buffer_writer.dart';
import 'package:ledger_bitcoin/src/utils/utils.dart';
import 'package:test/test.dart';

void main() {
  test('rejects a legacy policy in registered wallet APIs', () async {
    final app = BitcoinLedgerApp.nativeSegwit(_UnusedLedgerConnection());

    await expectLater(
      app.registerWallet(walletPolicy: app.walletPolicy),
      throwsArgumentError,
    );
  });

  test('rejects an empty registered wallet name', () async {
    final app = BitcoinLedgerApp.nativeSegwit(_UnusedLedgerConnection());
    final policy = WalletPolicy('', 'wpkh(@0/**)', const []);

    await expectLater(
      app.registerWallet(walletPolicy: policy),
      throwsArgumentError,
    );
  });

  test('rejects hardened registered wallet address indexes', () async {
    final app = BitcoinLedgerApp.nativeSegwit(_UnusedLedgerConnection());
    final policy = WalletPolicy('test', 'wpkh(@0/**)', const []);

    await expectLater(
      app.getWalletAddressWithPolicy(
        walletPolicy: policy,
        walletHMAC: Uint8List(32),
        change: 0,
        addressIndex: 1 << 31,
      ),
      throwsArgumentError,
    );
  });

  test('accepts a Taproot key-path signature for the tweaked output key', () {
    final outputKey = Uint8List.fromList(List.filled(32, 0x11));
    final signature = Uint8List.fromList(List.filled(64, 0x22));
    final psbt = PsbtV2()
      ..setGlobalInputCount(1)
      ..setInputWitnessUtxo(
        0,
        Uint8List(8),
        Uint8List.fromList([0x51, 0x20, ...outputKey]),
      );

    applyWalletPolicySignature(
      psbt: psbt,
      inputIndex: 0,
      keyAugment: outputKey,
      signature: signature,
    );

    expect(psbt.getInputTapKeySig(0), signature);
  });

  test('normalizes a Taproot non-witness UTXO before applying a signature', () {
    final outputKey = Uint8List.fromList(List.filled(32, 0x11));
    final signature = Uint8List.fromList(List.filled(64, 0x22));
    final previousTransaction = _previousTransaction(
      Uint8List.fromList([0x51, 0x20, ...outputKey]),
    );
    final txid = sha256Hasher(sha256Hasher(previousTransaction));
    final psbt = PsbtV2()
      ..setGlobalInputCount(1)
      ..setInputPreviousTxId(0, txid)
      ..setInputOutputIndex(0, 0)
      ..setInputNonWitnessUtxo(0, previousTransaction);

    psbt.normalizeInputUtxosForSigning();
    applyWalletPolicySignature(
      psbt: psbt,
      inputIndex: 0,
      keyAugment: outputKey,
      signature: signature,
    );

    expect(psbt.getInputTapKeySig(0), signature);
    expect(psbt.getInputWitnessUtxo(0)?.$2, [0x51, 0x20, ...outputKey]);
  });

  test('removes a witness UTXO from a legacy input', () {
    final outputScript = Uint8List.fromList([
      0x76,
      0xa9,
      0x14,
      ...List.filled(20, 0x11),
      0x88,
      0xac,
    ]);
    final previousTransaction = _previousTransaction(outputScript);
    final psbt = PsbtV2()
      ..setGlobalInputCount(1)
      ..setInputPreviousTxId(
        0,
        sha256Hasher(sha256Hasher(previousTransaction)),
      )
      ..setInputOutputIndex(0, 0)
      ..setInputNonWitnessUtxo(0, previousTransaction)
      ..setInputWitnessUtxo(0, Uint8List(8), outputScript);

    psbt.normalizeInputUtxosForSigning();

    expect(psbt.getInputWitnessUtxo(0), isNull);
    expect(psbt.getInputNonWitnessUtxo(0), previousTransaction);
  });

  test('rejects malformed previous transactions', () {
    final outputKey = Uint8List.fromList(List.filled(32, 0x11));
    final outputScript = Uint8List.fromList([0x51, 0x20, ...outputKey]);
    final previousTransaction = _previousTransaction(
      outputScript,
    );
    final nonCanonicalTransaction = Uint8List.fromList([
      ...previousTransaction.sublist(0, 4),
      0xfd,
      0x01,
      0x00,
      ...previousTransaction.sublist(5),
    ]);
    final superfluousWitness = _witnessPreviousTransaction(
      previousTransaction,
      Uint8List.fromList([0]),
    );
    final excessiveWitnessCount = _witnessPreviousTransaction(
      previousTransaction,
      Uint8List.fromList([0xfe, 0x00, 0xca, 0x9a, 0x3b]),
    );

    for (final transaction in [
      nonCanonicalTransaction,
      superfluousWitness,
      excessiveWitnessCount,
    ]) {
      final psbt = PsbtV2()
        ..setGlobalInputCount(1)
        ..setInputPreviousTxId(
          0,
          sha256Hasher(sha256Hasher(previousTransaction)),
        )
        ..setInputOutputIndex(0, 0)
        ..setInputNonWitnessUtxo(0, transaction);

      expect(psbt.normalizeInputUtxosForSigning, throwsFormatException);
    }
  });
}

Uint8List _previousTransaction(Uint8List outputScript) {
  final transaction = BufferWriter()
    ..writeUInt32(2)
    ..writeVarInt(1)
    ..writeSlice(Uint8List(32))
    ..writeUInt32(0xffffffff)
    ..writeVarSlice(Uint8List(0))
    ..writeUInt32(0xffffffff)
    ..writeVarInt(1)
    ..writeUInt64(1000)
    ..writeVarSlice(outputScript)
    ..writeUInt32(0);
  return transaction.buffer();
}

Uint8List _witnessPreviousTransaction(
  Uint8List transaction,
  Uint8List witness,
) =>
    Uint8List.fromList([
      ...transaction.sublist(0, 4),
      0,
      1,
      ...transaction.sublist(4, transaction.length - 4),
      ...witness,
      ...transaction.sublist(transaction.length - 4),
    ]);

class _UnusedLedgerConnection implements LedgerConnection {
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('The legacy policy must fail before device access');
}
