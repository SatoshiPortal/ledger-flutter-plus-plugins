import 'dart:typed_data';

import 'package:ledger_bitcoin/src/operations/bitcoin_sign_psbt_operation.dart';
import 'package:ledger_bitcoin/src/utils/int_extension.dart';
import 'package:test/test.dart';

void main() {
  test('parses a SegWit partial signature response', () {
    final pubkey = Uint8List.fromList([0x02, ...List.filled(32, 0x11)]);
    final signature = Uint8List.fromList([
      0x30,
      0x06,
      0x02,
      0x01,
      0x01,
      0x02,
      0x01,
      0x01,
      0x01,
    ]);
    final payload = Uint8List.fromList([
      ...300.toVarint(),
      pubkey.length,
      ...pubkey,
      ...signature,
    ]);

    final result = parseSignPsbtPartialSignature(payload);

    expect(result.$1, 300);
    expect(result.$2, pubkey);
    expect(result.$3, signature);
  });

  test('parses a Taproot key-path signature response', () {
    final pubkey = Uint8List.fromList(List.filled(32, 0x11));
    final signature = Uint8List.fromList(List.filled(64, 0x22));
    final payload = Uint8List.fromList([
      ...1.toVarint(),
      pubkey.length,
      ...pubkey,
      ...signature,
    ]);

    final result = parseSignPsbtPartialSignature(payload);

    expect(result.$1, 1);
    expect(result.$2, pubkey);
    expect(result.$3, signature);
  });

  test('parses a Taproot script-path signature response', () {
    final keyAugment = Uint8List.fromList([
      ...List.filled(32, 0x11),
      ...List.filled(32, 0x22),
    ]);
    final signature = Uint8List.fromList([
      ...List.filled(64, 0x33),
      0x01,
    ]);
    final payload = Uint8List.fromList([
      ...2.toVarint(),
      keyAugment.length,
      ...keyAugment,
      ...signature,
    ]);

    final result = parseSignPsbtPartialSignature(payload);

    expect(result.$1, 2);
    expect(result.$2, keyAugment);
    expect(result.$3, signature);
  });

  test('rejects unsupported signing responses', () {
    final taggedPayload = Uint8List.fromList([
      ...0x10000.toVarint(),
      33,
      ...List.filled(34, 0x01),
    ]);

    expect(
      () => parseSignPsbtPartialSignature(taggedPayload),
      throwsFormatException,
    );

    final invalidTaprootSignature = Uint8List.fromList([
      ...0.toVarint(),
      32,
      ...List.filled(32, 0x11),
      ...List.filled(63, 0x22),
    ]);
    expect(
      () => parseSignPsbtPartialSignature(invalidTaprootSignature),
      throwsFormatException,
    );

    final invalidEcdsaSignature = Uint8List.fromList([
      ...0.toVarint(),
      33,
      ...List.filled(33, 0x11),
      0x30,
      0x01,
      0x01,
    ]);
    expect(
      () => parseSignPsbtPartialSignature(invalidEcdsaSignature),
      throwsFormatException,
    );
  });

  test('rejects invalid Taproot sighash encodings', () {
    for (final sighash in [0x00, 0xff]) {
      final payload = Uint8List.fromList([
        ...0.toVarint(),
        32,
        ...List.filled(32, 0x11),
        ...List.filled(64, 0x22),
        sighash,
      ]);

      expect(
        () => parseSignPsbtPartialSignature(payload),
        throwsFormatException,
      );
    }
  });

  test('requires a returned signature to use the requested sighash', () {
    final defaultSignature = Uint8List.fromList(List.filled(64, 0x22));
    final allSignature = Uint8List.fromList([
      ...List.filled(64, 0x22),
      0x01,
    ]);

    expect(
      () => validateSignPsbtSignatureSighash(
        signature: defaultSignature,
        requestedSighash: 0x01,
        isTaproot: true,
      ),
      throwsFormatException,
    );
    expect(
      () => validateSignPsbtSignatureSighash(
        signature: allSignature,
        requestedSighash: 0x00,
        isTaproot: true,
      ),
      throwsFormatException,
    );
  });
}
