import 'dart:convert';
import 'dart:typed_data';

import 'package:ledger_bitcoin/psbt.dart';
import 'package:ledger_bitcoin/src/psbt/constants.dart';
import 'package:ledger_bitcoin/src/psbt/keypair.dart';
import 'package:test/test.dart';

void main() {
  group('PsbtV2', () {
    test("deserialize a psbt", () {
      final psbtBuf = base64.decode(
        "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
      );

      final psbt = PsbtV2();
      psbt.deserialize(psbtBuf);

      expect(psbt.getGlobalInputCount(), 1);
      expect(psbt.getGlobalOutputCount(), 2);
    });

    test('round trips a version 0 psbt', () {
      final psbtV0 = base64.decode(
        'cHNidP8BAFICAAAAAR/BzFdxy4OGDMVtlLz+2ThgjBf2NmJDW0HpxE/8/TFCAQAAAAD9////ATkFAAAAAAAAFgAUqo7zdMr638p2kC3bXPYcYLv9nYUAAAAAAAEBK0wGAAAAAAAAIlEg/AoQ0wjH5BtLvDZC+P2KwomFOxznVaDG0NSV8D2fLaQBAwQBAAAAIhXBUBcQi+zqje3FMAuyI4azqzA2esJi+c5eWDJuuD46IvUjIGsW6MH5efpMwPBbajAK//+UFFm28g3nfeVbAWDvjkysrMAhFlAXEIvs6o3txTALsiOGs6swNnrCYvnOXlgybrg+OiL1HQB2IjpuMAAAgAEAAIAAAACAAgAAgAAAAAAAAAAAIRZrFujB+Xn6TMDwW2owCv//lBRZtvIN533lWwFg745MrD0BCS7aAzYX4hDuf30ON4pASuocSLVqoQMCK+z3dG5HAKT1rML9MAAAgAEAAIAAAACAAgAAgAAAAAAAAAAAARcgUBcQi+zqje3FMAuyI4azqzA2esJi+c5eWDJuuD46IvUBGCAJLtoDNhfiEO5/fQ43ikBK6hxItWqhAwIr7Pd0bkcApAAA',
      );
      final psbt = PsbtV2()..deserialize(psbtV0);

      expect(psbt.getGlobalInputCount(), 1);
      expect(psbt.getGlobalOutputCount(), 1);
      expect(psbt.asPsbtV0(), psbtV0);
    });

    test('rejects a version 0 psbt without an unsigned transaction', () {
      final psbtV0 = base64.decode('cHNidP8A');

      expect(
        () => PsbtV2()..deserialize(psbtV0),
        throwsA(
          isA<FormatException>().having(
            (error) => error.message,
            'message',
            'PSBT v0 is missing its unsigned transaction',
          ),
        ),
      );
    });

    test('rejects PSBT fields that are incompatible with its version', () {
      final versionTwoWithUnsignedTransaction = base64.decode(
        'cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAH7BAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==',
      );
      final versionZeroWithRequiredLocktime = base64.decode(
        'cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonAREEjI3EYgAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==',
      );

      expect(
        () => PsbtV2()..deserialize(versionTwoWithUnsignedTransaction),
        throwsFormatException,
      );
      expect(
        () => PsbtV2()..deserialize(versionZeroWithRequiredLocktime),
        throwsFormatException,
      );
    });

    test('rejects malformed version 2 transaction fields', () {
      final missingGlobal = testPsbtV2()
        ..globalMap.remove(_emptyKey(PSBTGlobal.txVersion.value));
      final missingInput = testPsbtV2()
        ..inputMaps[0].remove(_emptyKey(PSBTIn.previousTXID.value));
      final missingOutput = testPsbtV2()
        ..outputMaps[0].remove(_emptyKey(PSBTOut.amount.value));
      final keyDataGlobal = testPsbtV2()
        ..globalMap[Key(
          PSBTGlobal.txVersion.value,
          Uint8List.fromList([0x99]),
        ).toString()] = Uint8List.fromList([2, 0, 0, 0]);

      for (final psbt in [
        missingGlobal,
        missingInput,
        missingOutput,
        keyDataGlobal,
      ]) {
        expect(
          () => PsbtV2()..deserialize(psbt.serialize()),
          throwsFormatException,
        );
      }
    });

    test('uses the required height locktime when converting to version 0', () {
      final psbt = testPsbtV2()
        ..setGlobalFallbackLocktime(0)
        ..setInputRequiredHeightLocktime(0, 900000);

      psbt.setEffectiveLocktimeAsFallback();

      final decoded = PsbtV2()..deserialize(psbt.asPsbtV0());

      expect(decoded.getGlobalFallbackLocktime(), 900000);
      expect(decoded.getInputRequiredHeightLocktime(0), isNull);
    });

    test('uses the required time locktime when converting to version 0', () {
      final psbt = testPsbtV2()
        ..setGlobalFallbackLocktime(0)
        ..setInputRequiredTimeLocktime(0, 500000000);

      final decoded = PsbtV2()..deserialize(psbt.asPsbtV0());

      expect(decoded.getGlobalFallbackLocktime(), 500000000);
      expect(decoded.getInputRequiredTimeLocktime(0), isNull);
    });
  });
}

PsbtV2 testPsbtV2() => PsbtV2()
  ..setGlobalPsbtVersion(2)
  ..setGlobalTxVersion(2)
  ..setGlobalInputCount(1)
  ..setGlobalOutputCount(1)
  ..setInputPreviousTxId(0, Uint8List(32))
  ..setInputOutputIndex(0, 0)
  ..setInputSequence(0, 0xfffffffe)
  ..setOutputAmount(0, 1000)
  ..setOutputScript(0, Uint8List(0));

String _emptyKey(int keyType) => Key(keyType, Uint8List(0)).toString();
