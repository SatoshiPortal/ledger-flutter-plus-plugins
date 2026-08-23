import 'dart:core';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:ledger_bitcoin/src/psbt/constants.dart';
import 'package:ledger_bitcoin/src/psbt/keypair.dart';
import 'package:ledger_bitcoin/src/psbt/map_extension.dart';
import 'package:ledger_bitcoin/src/utils/buffer_reader.dart';
import 'package:ledger_bitcoin/src/utils/buffer_writer.dart';
import 'package:ledger_bitcoin/src/utils/int_extension.dart';
import 'package:ledger_bitcoin/src/utils/uint8list_extension.dart';
import 'package:ledger_bitcoin/src/utils/utils.dart';

/// Implements Partially Signed Bitcoin Transaction version 2, BIP370, as
/// documented at https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki
/// and https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
///
/// A psbt is a data structure that can carry all relevant information about a
/// transaction through all stages of the signing process. From constructing an
/// unsigned transaction to extracting the final serialized transaction ready for
/// broadcast.
///
/// This implementation is limited to what's needed in ledger_bitcoin to carry
/// out its duties. It stores the Taproot fields required for registered wallet
/// policy signing, but its transaction finalizer only supports key-path spends.
///
/// This class is made purposefully dumb, so it's easy to add support for
/// complementary fields as needed in the future.
class PsbtV2 {
  final globalMap = <String, Uint8List>{};
  final inputMaps = <Map<String, Uint8List>>[];
  final outputMaps = <Map<String, Uint8List>>[];

  void setGlobalTxVersion(int version) =>
      _setGlobal(PSBTGlobal.txVersion, version.toUint32LE());

  int getGlobalTxVersion() => _getGlobal(PSBTGlobal.txVersion).readUint32LE(0);

  void setGlobalFallbackLocktime(int locktime) =>
      _setGlobal(PSBTGlobal.fallbackLocktime, locktime.toUint32LE());

  int? getGlobalFallbackLocktime() =>
      _getGlobalOptional(PSBTGlobal.fallbackLocktime)?.readUint32LE(0);

  void setGlobalInputCount(int inputCount) =>
      _setGlobal(PSBTGlobal.inputCount, inputCount.toVarint());

  int getGlobalInputCount() => intFromVarint(_getGlobal(PSBTGlobal.inputCount));

  void setGlobalOutputCount(int outputCount) =>
      _setGlobal(PSBTGlobal.outputCount, outputCount.toVarint());

  int getGlobalOutputCount() =>
      intFromVarint(_getGlobal(PSBTGlobal.outputCount));

  void setGlobalTxModifiable(Uint8List byte) =>
      _setGlobal(PSBTGlobal.txModifiable, byte);

  Uint8List? getGlobalTxModifiable() =>
      _getGlobalOptional(PSBTGlobal.txModifiable);

  void setGlobalPsbtVersion(int psbtVersion) =>
      _setGlobal(PSBTGlobal.version, psbtVersion.toUint32LE());

  int getGlobalPsbtVersion() => _getGlobal(PSBTGlobal.version).readUint32LE(0);

  void setInputNonWitnessUtxo(int inputIndex, Uint8List transaction) =>
      _setInput(inputIndex, PSBTIn.nonWitnessUTXO, _b(), transaction);

  Uint8List? getInputNonWitnessUtxo(int inputIndex) =>
      _getInputOptional(inputIndex, PSBTIn.nonWitnessUTXO, _b());

  void setInputWitnessUtxo(int inputIndex, Uint8List amount, Uint8List scriptPubKey) {
    final buf = BufferWriter()
      ..writeSlice(amount)
      ..writeVarSlice(scriptPubKey);
    _setInput(inputIndex, PSBTIn.witnessUTXO, _b(), buf.buffer());
  }

  (Uint8List, Uint8List)? getInputWitnessUtxo(int inputIndex) {
    final utxo = _getInputOptional(inputIndex, PSBTIn.witnessUTXO, _b());
    if (utxo == null) return null;
    final buf = BufferReader(utxo);
    return (buf.readSlice(8), buf.readVarSlice());
  }

  Uint8List? getInputUtxoScript(int inputIndex) {
    final witnessUtxo = getInputWitnessUtxo(inputIndex);
    if (witnessUtxo != null) return witnessUtxo.$2;

    return _getInputNonWitnessOutput(inputIndex)?.script;
  }

  void normalizeInputUtxosForSigning() {
    for (var inputIndex = 0; inputIndex < inputMaps.length; inputIndex++) {
      final output = _getInputNonWitnessOutput(inputIndex);
      if (output == null) continue;
      final redeemScript = getInputRedeemScript(inputIndex);
      final isWitnessInput = _isWitnessProgram(output.script) ||
          (redeemScript != null && _isWitnessProgram(redeemScript));
      if (!isWitnessInput) {
        deleteInputEntries(inputIndex, [PSBTIn.witnessUTXO]);
        continue;
      }
      if (getInputWitnessUtxo(inputIndex) != null) continue;
      setInputWitnessUtxo(
        inputIndex,
        output.amount.toUint64LE(),
        output.script,
      );
    }
  }

  _UnsignedTransactionOutput? _getInputNonWitnessOutput(int inputIndex) {
    final transaction = getInputNonWitnessUtxo(inputIndex);
    if (transaction == null) return null;
    final previousTransaction = _parsePreviousTransaction(transaction);
    if (!listEquals(
      previousTransaction.txid,
      getInputPreviousTxid(inputIndex),
    )) {
      throw const FormatException(
        'PSBT non-witness UTXO does not match the previous transaction ID',
      );
    }
    final outputIndex = getInputOutputIndex(inputIndex);
    if (outputIndex >= previousTransaction.outputs.length) {
      throw const FormatException(
        'PSBT non-witness UTXO does not contain the referenced output',
      );
    }
    return previousTransaction.outputs[outputIndex];
  }

  void setInputPartialSig(
          int inputIndex, Uint8List pubkey, Uint8List signature) =>
      _setInput(inputIndex, PSBTIn.partialSig, pubkey, signature);

  Uint8List? getInputPartialSig(int inputIndex, Uint8List pubkey) =>
      _getInputOptional(inputIndex, PSBTIn.partialSig, pubkey);

  void setInputSighashType(int inputIndex, int sigHashtype) =>
      _setInput(inputIndex, PSBTIn.sighashType, _b(), sigHashtype.toUint32LE());

  int? getInputSighashType(int inputIndex) =>
      _getInputOptional(inputIndex, PSBTIn.sighashType, _b())?.readUint32LE(0);

  void setInputRedeemScript(int inputIndex, Uint8List redeemScript) =>
      _setInput(inputIndex, PSBTIn.redeemScript, _b(), redeemScript);

  Uint8List? getInputRedeemScript(int inputIndex) =>
      _getInputOptional(inputIndex, PSBTIn.redeemScript, _b());

  void setInputBip32Derivation(int inputIndex, Uint8List pubkey,
      Uint8List masterFingerprint, List<int> path) {
    if (pubkey.length != 33) {
      throw Exception("Invalid pubkey length: ${pubkey.length}");
    }
    _setInput(
      inputIndex,
      PSBTIn.bip32Derivation,
      pubkey,
      _encodeBip32Derivation(masterFingerprint, path),
    );
  }

  (Uint8List, List<int>)? getInputBip32Derivation(
      int inputIndex, Uint8List pubkey) {
    final buf = _getInputOptional(inputIndex, PSBTIn.bip32Derivation, pubkey);
    if (buf == null) return null;
    return _decodeBip32Derivation(buf);
  }

  void setInputFinalScriptsig(int inputIndex, Uint8List scriptSig) =>
      _setInput(inputIndex, PSBTIn.finalScriptsig, _b(), scriptSig);

  Uint8List? getInputFinalScriptsig(int inputIndex) =>
      _getInputOptional(inputIndex, PSBTIn.finalScriptsig, _b());

  void setInputFinalScriptwitness(int inputIndex, Uint8List scriptWitness) =>
      _setInput(inputIndex, PSBTIn.finalScriptwitness, _b(), scriptWitness);

  Uint8List getInputFinalScriptwitness(int inputIndex) =>
      _getInput(inputIndex, PSBTIn.finalScriptwitness, _b());

  void setInputPreviousTxId(int inputIndex, Uint8List txid) =>
      _setInput(inputIndex, PSBTIn.previousTXID, _b(), txid);

  Uint8List getInputPreviousTxid(int inputIndex) =>
      _getInput(inputIndex, PSBTIn.previousTXID, _b());

  void setInputOutputIndex(int inputIndex, int outputIndex) =>
      _setInput(inputIndex, PSBTIn.outputIndex, _b(), outputIndex.toUint32LE());

  int getInputOutputIndex(int inputIndex) =>
      _getInput(inputIndex, PSBTIn.outputIndex, _b()).readUint32LE(0);

  void setInputSequence(int inputIndex, int sequence) =>
      _setInput(inputIndex, PSBTIn.sequence, _b(), sequence.toUint32LE());

  int getInputSequence(int inputIndex) =>
      _getInputOptional(inputIndex, PSBTIn.sequence, _b())?.readUint32LE(0) ??
      0xffffffff;

  void setInputRequiredTimeLocktime(int inputIndex, int locktime) =>
      _setInput(
        inputIndex,
        PSBTIn.requiredTimeLocktime,
        _b(),
        locktime.toUint32LE(),
      );

  int? getInputRequiredTimeLocktime(int inputIndex) => _getInputOptional(
        inputIndex,
        PSBTIn.requiredTimeLocktime,
        _b(),
      )?.readUint32LE(0);

  void setInputRequiredHeightLocktime(int inputIndex, int locktime) =>
      _setInput(
        inputIndex,
        PSBTIn.requiredHeightLocktime,
        _b(),
        locktime.toUint32LE(),
      );

  int? getInputRequiredHeightLocktime(int inputIndex) => _getInputOptional(
        inputIndex,
        PSBTIn.requiredHeightLocktime,
        _b(),
      )?.readUint32LE(0);

  void setInputTapKeySig(int inputIndex, Uint8List sig) =>
      _setInput(inputIndex, PSBTIn.tapKeySig, _b(), sig);

  Uint8List? getInputTapKeySig(int inputIndex) =>
      _getInputOptional(inputIndex, PSBTIn.tapKeySig, _b());

  void setInputTapScriptSig(int inputIndex, Uint8List pubkey,
      Uint8List leafHash, Uint8List signature) {
    if (pubkey.length != 32 || leafHash.length != 32) {
      throw ArgumentError('Taproot script signature key must be 64 bytes');
    }
    _setInput(
      inputIndex,
      PSBTIn.tapScriptSig,
      joinUint8Lists([pubkey, leafHash]),
      signature,
    );
  }

  Uint8List? getInputTapScriptSig(
          int inputIndex, Uint8List pubkey, Uint8List leafHash) =>
      _getInputOptional(
        inputIndex,
        PSBTIn.tapScriptSig,
        joinUint8Lists([pubkey, leafHash]),
      );

  void setInputTapBip32Derivation(int inputIndex, Uint8List pubkey,
      List<Uint8List> hashes, Uint8List masterFingerprint, List<int> path) {
    if (pubkey.length != 32) {
      throw Exception("Invalid pubkey length: ${pubkey.length}");
    }
    final buf = _encodeTapBip32Derivation(hashes, masterFingerprint, path);
    _setInput(inputIndex, PSBTIn.tapBip32Derivation, pubkey, buf);
  }

  (List<Uint8List>, Uint8List, List<int>) getInputTapBip32Derivation(
          int inputIndex, Uint8List pubkey) =>
      _decodeTapBip32Derivation(
          _getInput(inputIndex, PSBTIn.tapBip32Derivation, pubkey));

  Uint8List? getInputTapInternalKey(int inputIndex) =>
      _getInputOptional(inputIndex, PSBTIn.tapInternalKey, _b());

  List<Uint8List> getInputKeyDatas(int inputIndex, PSBTIn keyType) =>
      _getKeyDatas(inputMaps[inputIndex], keyType.value);

  void setOutputRedeemScript(int outputIndex, Uint8List redeemScript) =>
      _setOutput(outputIndex, PSBTOut.redeemScript, _b(), redeemScript);

  Uint8List getOutputRedeemScript(int outputIndex) =>
      _getOutput(outputIndex, PSBTOut.redeemScript, _b());

  void setOutputBip32Derivation(
          int outputIndex, Uint8List pubkey, Uint8List masterFingerprint, List<int> path) =>
      _setOutput(
        outputIndex,
        PSBTOut.bip32Derivation,
        pubkey,
        _encodeBip32Derivation(masterFingerprint, path),
      );

  (Uint8List, List<int>) getOutputBip32Derivation(
          int outputIndex, Uint8List pubkey) =>
      _decodeBip32Derivation(
          _getOutput(outputIndex, PSBTOut.bip32Derivation, pubkey));

  void setOutputAmount(int outputIndex, int amount) =>
      _setOutput(outputIndex, PSBTOut.amount, _b(), amount.toUint64LE());

  int getOutputAmount(int outputIndex) =>
      _getOutput(outputIndex, PSBTOut.amount, _b()).readUint64LE(0);

  void setOutputScript(int outputIndex, Uint8List scriptPubKey) =>
      _setOutput(outputIndex, PSBTOut.script, _b(), scriptPubKey);

  Uint8List getOutputScript(int outputIndex) =>
      _getOutput(outputIndex, PSBTOut.script, _b());

  void setOutputTapBip32Derivation(int outputIndex, Uint8List pubkey,
      List<Uint8List> hashes, Uint8List fingerprint, List<int> path) {
    final buf = _encodeTapBip32Derivation(hashes, fingerprint, path);
    _setOutput(outputIndex, PSBTOut.tapBip32Derivation, pubkey, buf);
  }

  (List<Uint8List>, Uint8List, List<int>) getOutputTapBip32Derivation(
          int outputIndex, Uint8List pubkey) =>
      _decodeTapBip32Derivation(
          _getOutput(outputIndex, PSBTOut.tapBip32Derivation, pubkey));

  void setOutputDNSSECProof(int outputIndex, Uint8List dnssecProof) =>
      _setOutput(outputIndex, PSBTOut.dnssecProof, _b(), dnssecProof);

  Uint8List getOutputDNSSECProof(int outputIndex) =>
      _getOutput(outputIndex, PSBTOut.dnssecProof, _b());

  void deleteInputEntries(int inputIndex, List<PSBTIn> keyTypes) {
    final map = inputMaps[inputIndex];
    final inKeyTypes = keyTypes.map((e) => e.value).toList();
    map.removeWhere((k, _) => _isKeyType(k, inKeyTypes));
  }

  void copy(PsbtV2 to) {
    copyMap(globalMap, to.globalMap);
    copyMaps(inputMaps, to.inputMaps);
    copyMaps(outputMaps, to.outputMaps);
  }

  void copyMaps(
      List<Map<String, Uint8List>> from, List<Map<String, Uint8List>> to) {
    from.asMap().forEach((index, m) {
      final toIndex = <String, Uint8List>{};
      copyMap(m, toIndex);
      to.insert(index, toIndex);
    });
  }

  void copyMap(Map<String, Uint8List> from, Map<String, Uint8List> to) =>
      from.forEach((k, v) => to[k] = v);

  Uint8List serialize() {
    final buf = BufferWriter()..writeSlice(psbtMagicBytes);
    globalMap.serializeMap(buf);
    for (final map in inputMaps) {
      map.serializeMap(buf);
    }
    for (final map in outputMaps) {
      map.serializeMap(buf);
    }
    return buf.buffer();
  }

  void deserialize(Uint8List psbt) {
    globalMap.clear();
    inputMaps.clear();
    outputMaps.clear();

    final bufferReader = BufferReader(psbt);
    if (!listEquals(bufferReader.readSlice(5), psbtMagicBytes)) {
      throw Exception("Invalid magic bytes");
    }
    while (_readKeyPair(globalMap, bufferReader)) {}

    if (_containsNonEmptyKeyData(globalMap, PSBTGlobal.unsignedTX.value) ||
        _containsNonEmptyKeyData(globalMap, PSBTGlobal.version.value)) {
      throw const FormatException('PSBT global singleton contains key data');
    }

    final versionBytes = _getGlobalOptional(PSBTGlobal.version);
    _validateValueLength(globalMap, PSBTGlobal.version.value, 4);
    final psbtVersion = versionBytes?.readUint32LE(0) ?? 0;
    if (psbtVersion != 0 && psbtVersion != 2) {
      throw Exception('Only PSBT versions 0 and 2 are supported');
    }
    _validateGlobalVersionFields(psbtVersion);

    final unsignedTransaction = psbtVersion == 0
        ? _parseUnsignedTransaction(
            _getGlobalOptional(PSBTGlobal.unsignedTX) ??
                (throw const FormatException(
                  'PSBT v0 is missing its unsigned transaction',
                )),
          )
        : null;
    final inputCount =
        unsignedTransaction?.inputs.length ?? getGlobalInputCount();
    final outputCount =
        unsignedTransaction?.outputs.length ?? getGlobalOutputCount();

    for (var i = 0; i < inputCount; i++) {
      inputMaps.insert(i, <String, Uint8List>{});
      while (_readKeyPair(inputMaps[i], bufferReader)) {}
    }
    for (var i = 0; i < outputCount; i++) {
      outputMaps.insert(i, <String, Uint8List>{});
      while (_readKeyPair(outputMaps[i], bufferReader)) {}
    }

    if (bufferReader.available() != 0) {
      throw Exception('Unexpected trailing PSBT data');
    }
    _validateMapVersionFields(psbtVersion);

    if (unsignedTransaction != null) {
      _normalizeToV2(unsignedTransaction);
    }
  }

  void _validateGlobalVersionFields(int psbtVersion) {
    if (psbtVersion == 2) {
      if (_containsKeyType(globalMap, PSBTGlobal.unsignedTX.value)) {
        throw const FormatException(
          'PSBT v2 cannot contain an unsigned transaction',
        );
      }
      final v2KeyTypes = [
        PSBTGlobal.txVersion.value,
        PSBTGlobal.fallbackLocktime.value,
        PSBTGlobal.inputCount.value,
        PSBTGlobal.outputCount.value,
        PSBTGlobal.txModifiable.value,
        PSBTGlobal.version.value,
      ];
      if (v2KeyTypes.any(
        (keyType) => _containsNonEmptyKeyData(globalMap, keyType),
      )) {
        throw const FormatException('PSBT v2 global field contains key data');
      }
      final requiredKeyTypes = [
        PSBTGlobal.txVersion.value,
        PSBTGlobal.inputCount.value,
        PSBTGlobal.outputCount.value,
      ];
      if (requiredKeyTypes.any(
        (keyType) => !_containsEmptyKeyData(globalMap, keyType),
      )) {
        throw const FormatException(
            'PSBT v2 is missing a required global field');
      }
      _validateValueLength(globalMap, PSBTGlobal.txVersion.value, 4);
      _validateValueLength(globalMap, PSBTGlobal.fallbackLocktime.value, 4);
      _validateCompactSize(globalMap, PSBTGlobal.inputCount.value);
      _validateCompactSize(globalMap, PSBTGlobal.outputCount.value);
      _validateValueLength(globalMap, PSBTGlobal.txModifiable.value, 1);
      return;
    }

    final v2KeyTypes = [
      PSBTGlobal.txVersion.value,
      PSBTGlobal.fallbackLocktime.value,
      PSBTGlobal.inputCount.value,
      PSBTGlobal.outputCount.value,
      PSBTGlobal.txModifiable.value,
    ];
    if (v2KeyTypes.any((keyType) => _containsKeyType(globalMap, keyType))) {
      throw const FormatException('PSBT v0 contains a PSBT v2 global field');
    }
  }

  void _validateMapVersionFields(int psbtVersion) {
    if (psbtVersion == 2) {
      final v2InputKeyTypes = [
        PSBTIn.previousTXID.value,
        PSBTIn.outputIndex.value,
        PSBTIn.sequence.value,
        PSBTIn.requiredTimeLocktime.value,
        PSBTIn.requiredHeightLocktime.value,
      ];
      if (inputMaps.any(
        (map) => v2InputKeyTypes.any(
          (keyType) => _containsNonEmptyKeyData(map, keyType),
        ),
      )) {
        throw const FormatException('PSBT v2 input field contains key data');
      }
      final requiredInputKeyTypes = [
        PSBTIn.previousTXID.value,
        PSBTIn.outputIndex.value,
      ];
      if (inputMaps.any(
        (map) => requiredInputKeyTypes.any(
          (keyType) => !_containsEmptyKeyData(map, keyType),
        ),
      )) {
        throw const FormatException(
            'PSBT v2 input is missing a required field');
      }
      for (final map in inputMaps) {
        _validateValueLength(map, PSBTIn.previousTXID.value, 32);
        _validateValueLength(map, PSBTIn.outputIndex.value, 4);
        _validateValueLength(map, PSBTIn.sequence.value, 4);
        _validateValueLength(map, PSBTIn.requiredTimeLocktime.value, 4);
        _validateValueLength(map, PSBTIn.requiredHeightLocktime.value, 4);
      }

      final v2OutputKeyTypes = [
        PSBTOut.amount.value,
        PSBTOut.script.value,
      ];
      if (outputMaps.any(
        (map) => v2OutputKeyTypes.any(
          (keyType) => _containsNonEmptyKeyData(map, keyType),
        ),
      )) {
        throw const FormatException('PSBT v2 output field contains key data');
      }
      final requiredOutputKeyTypes = [
        PSBTOut.amount.value,
        PSBTOut.script.value,
      ];
      if (outputMaps.any(
        (map) => requiredOutputKeyTypes.any(
          (keyType) => !_containsEmptyKeyData(map, keyType),
        ),
      )) {
        throw const FormatException(
            'PSBT v2 output is missing a required field');
      }
      for (final map in outputMaps) {
        _validateValueLength(map, PSBTOut.amount.value, 8);
      }
      return;
    }

    final v2InputKeyTypes = [
      PSBTIn.previousTXID.value,
      PSBTIn.outputIndex.value,
      PSBTIn.sequence.value,
      PSBTIn.requiredTimeLocktime.value,
      PSBTIn.requiredHeightLocktime.value,
    ];
    if (inputMaps.any(
      (map) => v2InputKeyTypes.any(
        (keyType) => _containsKeyType(map, keyType),
      ),
    )) {
      throw const FormatException('PSBT v0 contains a PSBT v2 input field');
    }

    final v2OutputKeyTypes = [PSBTOut.amount.value, PSBTOut.script.value];
    if (outputMaps.any(
      (map) => v2OutputKeyTypes.any(
        (keyType) => _containsKeyType(map, keyType),
      ),
    )) {
      throw const FormatException('PSBT v0 contains a PSBT v2 output field');
    }
  }

  bool _containsKeyType(Map<String, Uint8List> map, int keyType) =>
      map.keys.any((key) => _isKeyType(key, [keyType]));

  bool _containsEmptyKeyData(Map<String, Uint8List> map, int keyType) =>
      map.containsKey(Key(keyType, Uint8List(0)).toString());

  bool _containsNonEmptyKeyData(Map<String, Uint8List> map, int keyType) {
    final emptyKey = Key(keyType, Uint8List(0)).toString();
    return map.keys.any(
      (key) => key != emptyKey && _isKeyType(key, [keyType]),
    );
  }

  void _validateValueLength(
    Map<String, Uint8List> map,
    int keyType,
    int expectedLength,
  ) {
    final value = map[Key(keyType, Uint8List(0)).toString()];
    if (value != null && value.length != expectedLength) {
      throw const FormatException('PSBT field has an invalid value length');
    }
  }

  void _validateCompactSize(Map<String, Uint8List> map, int keyType) {
    final value = map[Key(keyType, Uint8List(0)).toString()];
    if (value == null) return;

    var valid = false;
    try {
      valid = listEquals(intFromVarint(value).toVarint(), value);
    } catch (_) {
      // Report malformed external data as a PSBT format failure.
    }
    if (!valid) {
      throw const FormatException(
          'PSBT field has an invalid CompactSize value');
    }
  }

  void _normalizeToV2(_UnsignedTransaction transaction) {
    setGlobalPsbtVersion(2);
    setGlobalTxVersion(transaction.version);
    setGlobalFallbackLocktime(transaction.locktime);
    setGlobalInputCount(transaction.inputs.length);
    setGlobalOutputCount(transaction.outputs.length);

    for (final (index, input) in transaction.inputs.indexed) {
      setInputPreviousTxId(index, input.txid);
      setInputOutputIndex(index, input.outputIndex);
      setInputSequence(index, input.sequence);
    }
    for (final (index, output) in transaction.outputs.indexed) {
      setOutputAmount(index, output.amount);
      setOutputScript(index, output.script);
    }

    globalMap.remove(Key(PSBTGlobal.unsignedTX.value, Uint8List(0)).toString());
  }

  bool _readKeyPair(Map<String, Uint8List> map, BufferReader bufferReader) {
    final keyLen = bufferReader.readVarInt();
    if (keyLen == 0) return false;

    final keyType = bufferReader.readUInt8();
    final keyData = bufferReader.readSlice(keyLen - 1);
    final value = bufferReader.readVarSlice();
    final key = Key(keyType, keyData).toString();
    if (map.containsKey(key)) {
      throw const FormatException('PSBT contains a duplicate key');
    }

    map[key] = value;
    return true;
  }

  List<Uint8List> _getKeyDatas(Map<String, Uint8List> map, int keyType) {
    final result = <Uint8List>[];
    map.forEach((k, v) {
      if (_isKeyType(k, [keyType])) {
        result.add(hex.decode(k.substring(2)) as Uint8List);
      }
    });
    return result;
  }

  bool _isKeyType(String hexKey, List<int> keyTypes) {
    final keyType = (hex.decode(hexKey.substring(0, 2)) as Uint8List).first;
    return keyTypes.any((k) => k == keyType);
  }

  void _setGlobal(PSBTGlobal keyType, Uint8List value) {
    final key = Key(keyType.value, Uint8List(0));
    globalMap[key.toString()] = value;
  }

  Uint8List _getGlobal(PSBTGlobal keyType) =>
      globalMap.get(keyType.value, _b(), false)!;

  Uint8List? _getGlobalOptional(PSBTGlobal keyType) =>
      globalMap.get(keyType.value, _b(), true);

  void _setInput(
          int index, PSBTIn keyType, Uint8List keyData, Uint8List value) =>
      _getMap(index, inputMaps).set(keyType.value, keyData, value);

  Uint8List _getInput(int index, PSBTIn keyType, Uint8List keyData) =>
      inputMaps[index].get(keyType.value, keyData, false)!;

  Uint8List? _getInputOptional(int index, PSBTIn keyType, Uint8List keyData) =>
      inputMaps[index].get(keyType.value, keyData, true);

  void _setOutput(
          int index, PSBTOut keyType, Uint8List keyData, Uint8List value) =>
      _getMap(index, outputMaps).set(keyType.value, keyData, value);

  Uint8List _getOutput(int index, PSBTOut keyType, Uint8List keyData) =>
      outputMaps[index].get(keyType.value, keyData, false)!;

  Map<String, Uint8List> _getMap(int index, List<Map<String, Uint8List>> maps) {
    if (maps.elementAtOrNull(index) == null) {
      maps.insert(index, {});
    }
    return maps[index];
  }

  Uint8List _encodeBip32Derivation(
      Uint8List masterFingerprint, List<int> path) {
    final buf = BufferWriter();
    _writeBip32Derivation(buf, masterFingerprint, path);
    return buf.buffer();
  }

  (Uint8List, List<int>) _decodeBip32Derivation(Uint8List buffer) =>
      _readBip32Derivation(BufferReader(buffer));

  void _writeBip32Derivation(
      BufferWriter buf, Uint8List masterFingerprint, List<int> path) {
    buf.writeSlice(masterFingerprint);
    for (final element in path) {
      buf.writeUInt32(element);
    }
  }

  (Uint8List, List<int>) _readBip32Derivation(BufferReader bufferReader) {
    final masterFingerprint = bufferReader.readSlice(4);
    final path = <int>[];

    while (bufferReader.available() > 0) {
      path.add(bufferReader.readUInt32());
    }
    return (masterFingerprint, path);
  }

  Uint8List _encodeTapBip32Derivation(
      List<Uint8List> hashes, Uint8List masterFingerprint, List<int> path) {
    final buf = BufferWriter()..writeVarInt(hashes.length);
    for (var h in hashes) {
      buf.writeSlice(h);
    }
    _writeBip32Derivation(buf, masterFingerprint, path);
    return buf.buffer();
  }

  (List<Uint8List>, Uint8List, List<int>) _decodeTapBip32Derivation(
      Uint8List buffer) {
    final buf = BufferReader(buffer);
    final hashCount = buf.readVarInt();
    final hashes = <Uint8List>[];
    for (var i = 0; i < hashCount; i++) {
      hashes.add(buf.readSlice(32));
    }
    final deriv = _readBip32Derivation(buf);
    return (hashes, deriv.$1, deriv.$2);
  }

  Uint8List _b() => Uint8List(0);
}

_UnsignedTransaction _parseUnsignedTransaction(Uint8List bytes) {
  final reader = BufferReader(bytes);
  final version = reader.readUInt32();
  final inputs = <_UnsignedTransactionInput>[];

  final inputCount = reader.readCanonicalVarInt();
  for (var i = 0; i < inputCount; i++) {
    final txid = reader.readSlice(32);
    final outputIndex = reader.readUInt32();
    if (reader.readCanonicalVarSlice().isNotEmpty) {
      throw Exception('PSBT unsigned transaction has a non-empty scriptSig');
    }
    inputs.add((
      txid: txid,
      outputIndex: outputIndex,
      sequence: reader.readUInt32(),
    ));
  }

  final outputs = <_UnsignedTransactionOutput>[];
  final outputCount = reader.readCanonicalVarInt();
  for (var i = 0; i < outputCount; i++) {
    outputs.add((
      amount: reader.readUInt64(),
      script: reader.readCanonicalVarSlice(),
    ));
  }

  final locktime = reader.readUInt32();
  if (reader.available() != 0) {
    throw Exception('Unexpected trailing transaction data');
  }
  return (
    version: version,
    inputs: inputs,
    outputs: outputs,
    locktime: locktime,
  );
}

_PreviousTransaction _parsePreviousTransaction(Uint8List bytes) {
  final reader = BufferReader(bytes);
  final stripped = BufferWriter();
  final version = reader.readUInt32();
  stripped.writeUInt32(version);

  var inputCount = reader.readCanonicalVarInt();
  var hasWitness = false;
  if (inputCount == 0) {
    if (reader.readUInt8() != 1) {
      throw const FormatException('Invalid witness transaction marker');
    }
    hasWitness = true;
    inputCount = reader.readCanonicalVarInt();
  }
  stripped.writeVarInt(inputCount);
  for (var i = 0; i < inputCount; i++) {
    stripped
      ..writeSlice(reader.readSlice(32))
      ..writeUInt32(reader.readUInt32())
      ..writeVarSlice(reader.readCanonicalVarSlice())
      ..writeUInt32(reader.readUInt32());
  }

  final outputCount = reader.readCanonicalVarInt();
  stripped.writeVarInt(outputCount);
  final outputs = <_UnsignedTransactionOutput>[];
  for (var i = 0; i < outputCount; i++) {
    final amount = reader.readUInt64();
    final script = reader.readCanonicalVarSlice();
    outputs.add((amount: amount, script: script));
    stripped
      ..writeUInt64(amount)
      ..writeVarSlice(script);
  }

  if (hasWitness) {
    var hasWitnessData = false;
    for (var i = 0; i < inputCount; i++) {
      if (reader.readCanonicalVector().isNotEmpty) {
        hasWitnessData = true;
      }
    }
    if (!hasWitnessData) {
      throw const FormatException('Superfluous witness serialization');
    }
  }
  stripped.writeUInt32(reader.readUInt32());
  if (reader.available() != 0) {
    throw const FormatException('Unexpected trailing transaction data');
  }

  final firstHash = sha256Hasher(stripped.buffer());
  return (txid: sha256Hasher(firstHash), outputs: outputs);
}

bool _isWitnessProgram(Uint8List script) {
  if (script.length < 4 || script.length > 42) return false;
  final version = script.first;
  final isWitnessVersion = version == 0 || (version >= 0x51 && version <= 0x60);
  final programLength = script[1];
  return isWitnessVersion &&
      programLength >= 2 &&
      programLength <= 40 &&
      script.length == programLength + 2;
}

typedef _UnsignedTransaction = ({
  int version,
  List<_UnsignedTransactionInput> inputs,
  List<_UnsignedTransactionOutput> outputs,
  int locktime,
});

typedef _UnsignedTransactionInput = ({
  Uint8List txid,
  int outputIndex,
  int sequence,
});

typedef _UnsignedTransactionOutput = ({int amount, Uint8List script});

typedef _PreviousTransaction = ({
  Uint8List txid,
  List<_UnsignedTransactionOutput> outputs,
});
