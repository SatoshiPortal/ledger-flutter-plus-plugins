import 'package:convert/convert.dart';
import 'package:ledger_bitcoin/ledger_bitcoin.dart';
import 'package:test/test.dart';

void main() {
  test('serializes a protocol v1 wallet policy', () {
    final policy = WalletPolicy(
      'Cold storage',
      'wsh(sortedmulti(2,@0/**,@1/**))',
      [
        "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
        "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
      ],
    );

    expect(
      hex.encode(policy.id),
      'cd9474ae9e74403128477789789db43a215e996af80d60120f0d844f8404ac64',
    );
  });

  test('rejects invalid wallet names', () {
    final policy = WalletPolicy(
      ' Cold storage',
      'wsh(sortedmulti(2,@0/**,@1/**))',
      const [],
    );

    expect(policy.serialize, throwsArgumentError);
  });
}
