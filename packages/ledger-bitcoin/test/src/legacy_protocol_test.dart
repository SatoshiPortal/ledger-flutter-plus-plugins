import 'dart:convert';
import 'dart:typed_data';

import 'package:ledger_bitcoin/ledger_bitcoin.dart';
import 'package:ledger_bitcoin/src/ledger/ledger_input_operation.dart';
import 'package:ledger_bitcoin/src/operations/bitcoin_extended_public_key_operation.dart';
import 'package:ledger_bitcoin/src/operations/bitcoin_master_fingerprint_operation.dart';
import 'package:ledger_bitcoin/src/operations/bitcoin_sign_psbt_operation.dart';
import 'package:test/test.dart';

void main() {
  final factories = <String, BitcoinLedgerApp Function(LedgerConnection)>{
    'native segwit': BitcoinLedgerApp.nativeSegwit,
    'nested segwit': BitcoinLedgerApp.nestedSegwit,
    'legacy': BitcoinLedgerApp.legacy,
  };
  for (final entry in factories.entries) {
    test('${entry.key} address requests retain protocol 0 and no HMAC',
        () async {
      final connection = _ScriptedConnection([
        ...ascii.encode('device-address'),
        0x90,
        0x00,
      ]);
      final app = entry.value(connection);

      expect(await app.getAccounts(display: true), ['device-address']);
      final command = connection.commands.single;
      expect(command.sublist(0, 4), [0xe1, 0x03, 0x00, 0x00]);
      expect(command[5], 1, reason: 'the device must display the address');
      expect(command.sublist(38, 70), List.filled(32, 0));
      expect(command.sublist(70), [0, 0, 0, 0, 0]);
    });
  }

  test('address flow rejects user refusal and truncated status words',
      () async {
    for (final response in <List<int>>[
      [0x69, 0x85],
      [0x90]
    ]) {
      final app = BitcoinLedgerApp.nativeSegwit(_ScriptedConnection(response));
      await expectLater(
        app.getAccounts(),
        response.length == 1
            ? throwsFormatException
            : throwsA(predicate(
                (Object e) => e.toString().contains('SW_DENIED_BY_USER'))),
      );
    }
  });

  test('default PSBT signing command retains protocol 0 and no HMAC', () async {
    final command = BitcoinSignPsbtOperation(
      walletPolicy: WalletPolicy('', 'wpkh(@0/**)', ['test-key']),
      globalKeysValuesRoot: Uint8List(33),
      inputCount: 1,
      outputCount: 1,
      inputsMapsRoot: Uint8List(32),
      outputsMapsRoot: Uint8List(32),
    );
    final frames = await command.write(ByteDataWriter());
    expect(frames.single.sublist(0, 4), [0xe1, 0x04, 0x00, 0x00]);
    expect(
        frames.single.sublist(frames.single.length - 32), List.filled(32, 0));
  });
}

class _ScriptedConnection implements LedgerConnection {
  final List<int> response;
  final commands = <Uint8List>[];

  _ScriptedConnection(this.response);

  @override
  Future<T> sendOperation<T>(
    Object operation, {
    LedgerTransformer? transformer,
  }) async {
    if (operation is BitcoinMasterFingerprintOperation) {
      return Uint8List.fromList([1, 2, 3, 4]) as T;
    }
    if (operation is BitcoinExtendedPublicKeyOperation) return 'test-xpub' as T;
    if (operation is! LedgerInputOperation<Uint8List>) {
      throw StateError('Unexpected operation');
    }
    commands.addAll(await operation.write(ByteDataWriter()));
    return Uint8List.fromList(response) as T;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('Unexpected connection access');
}
