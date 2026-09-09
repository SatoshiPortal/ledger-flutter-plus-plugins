import 'dart:typed_data';

import 'package:dart_varuint_bitcoin/dart_varuint_bitcoin.dart' as varuint;

// A awesome BufferReader by Ledger
class BufferReader {
  final Uint8List buffer;
  final ByteData _byteData;
  int offset;

  BufferReader(this.buffer, {this.offset = 0})
      : _byteData = ByteData.view(buffer.buffer);

  int available() => buffer.length - offset;

  int readUInt8() {
    final result = _byteData.getUint8(offset);
    offset++;
    return result;
  }

  int readInt32() {
    final result = _byteData.getInt32(offset, Endian.little);
    offset += 4;
    return result;
  }

  int readUInt32() {
    final result = _byteData.getUint32(offset, Endian.little);
    offset += 4;
    return result;
  }

  int readUInt64() {
    final n = _byteData.getUint64(offset, Endian.little);
    offset += 8;
    return n;
  }

  int readVarInt() {
    final vi = varuint.decode(buffer, offset);
    offset += vi.bytes;
    return vi.output;
  }

  int readCanonicalVarInt() {
    final vi = varuint.decode(buffer, offset);
    if (vi.bytes != varuint.encodingLength(vi.output)) {
      throw const FormatException('Non-canonical CompactSize value');
    }
    offset += vi.bytes;
    return vi.output;
  }

  Uint8List readSlice(int n) {
    if (buffer.length < offset + n) {
      throw Exception("Cannot read slice out of bounds");
    }
    final result = buffer.sublist(offset, offset + n);
    offset += n;
    return result;
  }

  Uint8List readVarSlice() => readSlice(readVarInt());

  Uint8List readCanonicalVarSlice() => readSlice(readCanonicalVarInt());

  List<Uint8List> readVector() {
    final count = readVarInt();
    final vector = <Uint8List>[];
    for (var i = 0; i < count; i++) {
      vector.add(readVarSlice());
    }
    return vector;
  }

  List<Uint8List> readCanonicalVector() {
    final count = readCanonicalVarInt();
    if (count > available()) {
      throw const FormatException('Vector exceeds the remaining data');
    }
    final vector = <Uint8List>[];
    for (var i = 0; i < count; i++) {
      vector.add(readCanonicalVarSlice());
    }
    return vector;
  }
}
