import 'dart:typed_data';

import 'package:ledger_bitcoin/ledger_bitcoin.dart';
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
}

class _UnusedLedgerConnection implements LedgerConnection {
  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw StateError('The legacy policy must fail before device access');
}
