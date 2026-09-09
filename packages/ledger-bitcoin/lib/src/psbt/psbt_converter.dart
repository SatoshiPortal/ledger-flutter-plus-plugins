import "dart:typed_data";

import "package:ledger_bitcoin/src/psbt/constants.dart";
import "package:ledger_bitcoin/src/psbt/keypair.dart";
import "package:ledger_bitcoin/src/psbt/map_extension.dart";
import "package:ledger_bitcoin/src/psbt/psbtv2.dart";
import "package:ledger_bitcoin/src/utils/buffer_writer.dart";

extension V0Serializer on PsbtV2 {
  void setEffectiveLocktimeAsFallback() =>
      setGlobalFallbackLocktime(_transactionLocktime());

  Uint8List asPsbtV0() {
    final excludedGlobalKeyTypes = [
      PSBTGlobal.unsignedTX,
      PSBTGlobal.txVersion,
      PSBTGlobal.fallbackLocktime,
      PSBTGlobal.inputCount,
      PSBTGlobal.outputCount,
      PSBTGlobal.txModifiable,
      PSBTGlobal.version,
    ].map((e) => Key(e.value, Uint8List(0)).toString());

    final excludedInputKeyTypes = [
      PSBTIn.previousTXID,
      PSBTIn.outputIndex,
      PSBTIn.sequence,
      PSBTIn.requiredTimeLocktime,
      PSBTIn.requiredHeightLocktime,
    ].map((e) => Key(e.value, Uint8List(0)).toString());

    final excludedOutputKeyTypes = [
      PSBTOut.amount,
      PSBTOut.script,
    ].map((e) => Key(e.value, Uint8List(0)).toString());

    final buf = BufferWriter()..writeSlice(psbtMagicBytes);

    final sGlobalMap = <String, Uint8List>{"00": extractUnsignedTX(false)};

    for (final key in globalMap.keys) {
      if (!excludedGlobalKeyTypes.contains(key)) {
        sGlobalMap[key] = globalMap[key]!;
      }
    }

    sGlobalMap.serializeMap(buf);
    for (final map in inputMaps) {
      final sMap = Map.from(map)
        ..removeWhere((k, v) => excludedInputKeyTypes.contains(k));
      sMap.serializeMap(buf);
    }
    for (final map in outputMaps) {
      final sMap = Map.from(map)
        ..removeWhere((k, v) => excludedOutputKeyTypes.contains(k));
      sMap.serializeMap(buf);
    }
    return buf.buffer();
  }

  Uint8List extractUnsignedTX([bool withSegwit = true]) {
    final tx = BufferWriter()..writeUInt32(getGlobalTxVersion());

    final isSegwit = getInputWitnessUtxo(0) != null && withSegwit;
    if (isSegwit) {
      tx.writeSlice(Uint8List.fromList([0, 1]));
    }

    final inputCount = getGlobalInputCount();
    tx.writeVarInt(inputCount);

    for (var i = 0; i < inputCount; i++) {
      tx
        ..writeSlice(getInputPreviousTxid(i))
        ..writeUInt32(getInputOutputIndex(i))
        ..writeVarSlice(Uint8List(0))
        ..writeUInt32(getInputSequence(i));
    }

    final outputCount = getGlobalOutputCount();
    tx.writeVarInt(outputCount);
    for (var i = 0; i < outputCount; i++) {
      tx.writeUInt64(getOutputAmount(i));
      tx.writeVarSlice(getOutputScript(i));
    }
    tx.writeUInt32(_transactionLocktime());
    return tx.buffer();
  }

  int _transactionLocktime() {
    final requiredTimes = <int>[];
    final requiredHeights = <int>[];
    var timeAllowed = true;
    var heightAllowed = true;

    for (var index = 0; index < getGlobalInputCount(); index++) {
      final time = getInputRequiredTimeLocktime(index);
      final height = getInputRequiredHeightLocktime(index);
      if (time == null && height == null) continue;
      if (time == null) {
        timeAllowed = false;
      } else if (time < 500000000) {
        throw const FormatException('Invalid required time locktime');
      } else {
        requiredTimes.add(time);
      }
      if (height == null) {
        heightAllowed = false;
      } else if (height == 0 || height >= 500000000) {
        throw const FormatException('Invalid required height locktime');
      } else {
        requiredHeights.add(height);
      }
    }

    if (heightAllowed && requiredHeights.isNotEmpty) {
      return requiredHeights.reduce(
        (maximum, value) => value > maximum ? value : maximum,
      );
    }
    if (timeAllowed && requiredTimes.isNotEmpty) {
      return requiredTimes.reduce(
        (maximum, value) => value > maximum ? value : maximum,
      );
    }
    if (requiredTimes.isNotEmpty || requiredHeights.isNotEmpty) {
      throw const FormatException('PSBT inputs require incompatible locktimes');
    }
    return getGlobalFallbackLocktime() ?? 0;
  }
}
