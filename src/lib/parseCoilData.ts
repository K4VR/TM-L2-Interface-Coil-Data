export const MIN_COIL_PACKET_BYTES = 130;

export type CoilData = {
  msgNumber: number;
  wordLength: number;
  seqNumber: number;
  schedule: number;
  coilNumber: string;
  orderNumber: string;
  customer: string;
  grade: string;
  weight: number;
  entryWidth: number;
  entryLength: number;
  entryGauge: number;
  targetGauge: number;
  plusGaugeTol: number;
  minusGaugeTol: number;
  elongationTarget: number;
  speedTarget: number;
  rollingForce: number;
  entryTension: number;
  bendForceRef: number;
  bendTarget: number;
  gaugeControlMode: number;
};

export type CoilFieldKey = keyof CoilData;

export type CoilFieldDef = {
  key: CoilFieldKey;
  offset: number;
  name: string;
  csvName: string;
  typeLabel: string;
  format: 'int' | 'float3' | 'float6' | 'string';
};

/**
 * Little-endian L2 → PLC coil telegram layout.
 * Strings are ASCII, NUL-padded. Offset 74–75 is unused alignment padding.
 */
export const COIL_FIELDS: readonly CoilFieldDef[] = [
  { key: 'msgNumber', offset: 0, name: 'Msg Number', csvName: 'Msg Number', typeLabel: 'uint16', format: 'int' },
  { key: 'wordLength', offset: 2, name: 'Word Length', csvName: 'Word Length', typeLabel: 'uint16', format: 'int' },
  { key: 'seqNumber', offset: 4, name: 'Sequence Number', csvName: 'Word Sequence Number', typeLabel: 'uint16', format: 'int' },
  { key: 'schedule', offset: 6, name: 'Schedule', csvName: 'Long Schedule', typeLabel: 'uint32', format: 'int' },
  { key: 'coilNumber', offset: 10, name: 'Coil Number', csvName: 'Long Coil Number', typeLabel: 'char[16]', format: 'string' },
  { key: 'orderNumber', offset: 26, name: 'Order Number', csvName: 'Order number', typeLabel: 'char[16]', format: 'string' },
  { key: 'customer', offset: 42, name: 'Customer', csvName: 'Customer', typeLabel: 'char[26]', format: 'string' },
  { key: 'grade', offset: 68, name: 'Grade', csvName: 'Grade', typeLabel: 'char[6]', format: 'string' },
  { key: 'weight', offset: 76, name: 'Weight', csvName: 'Weight', typeLabel: 'int32', format: 'int' },
  { key: 'entryWidth', offset: 80, name: 'Entry Width', csvName: 'Entry Width Single', typeLabel: 'float32', format: 'float3' },
  { key: 'entryLength', offset: 84, name: 'Entry Length', csvName: 'Entry Length Single', typeLabel: 'float32', format: 'float3' },
  { key: 'entryGauge', offset: 88, name: 'Entry Gauge', csvName: 'Entry Gauge Single', typeLabel: 'float32', format: 'float6' },
  { key: 'targetGauge', offset: 92, name: 'Target Gauge', csvName: 'Target Gauge Single', typeLabel: 'float32', format: 'float6' },
  { key: 'plusGaugeTol', offset: 96, name: 'Plus Gauge Tolerance', csvName: 'Plus Gauge Tolerance Single', typeLabel: 'float32', format: 'float6' },
  { key: 'minusGaugeTol', offset: 100, name: 'Minus Gauge Tolerance', csvName: 'Minus Gauge Tolerance Single', typeLabel: 'float32', format: 'float6' },
  { key: 'elongationTarget', offset: 104, name: 'Elongation Target', csvName: 'Elongation target Single', typeLabel: 'float32', format: 'float3' },
  { key: 'speedTarget', offset: 108, name: 'Speed Target', csvName: 'Speed Target Single', typeLabel: 'float32', format: 'float3' },
  { key: 'rollingForce', offset: 112, name: 'Rolling Force', csvName: 'Rolling Force Single', typeLabel: 'float32', format: 'float3' },
  { key: 'entryTension', offset: 116, name: 'Entry Tension', csvName: 'Entry Tension Single', typeLabel: 'float32', format: 'float3' },
  { key: 'bendForceRef', offset: 120, name: 'Bend Force Reference', csvName: 'Bend Force Reference Single', typeLabel: 'float32', format: 'float3' },
  { key: 'bendTarget', offset: 124, name: 'Bend Target', csvName: 'Bend Target Single', typeLabel: 'float32', format: 'float3' },
  { key: 'gaugeControlMode', offset: 128, name: 'Gauge Control Mode', csvName: 'Gauge Control Mode Word', typeLabel: 'uint16', format: 'int' },
];

const DUMP_LINE =
  /^\s*(?:0x)?[0-9A-Fa-f]{3,8}:?(?:\s{1,4}|\t)(?:[0-9A-Fa-f]{2}\s+){2,}/;

function looksLikeHexDump(text: string): boolean {
  const lines = text.split(/\r?\n/).filter((line) => line.trim().length > 0);
  if (lines.length === 0) {
    return false;
  }
  const dumpLines = lines.filter((line) => DUMP_LINE.test(line));
  return dumpLines.length >= Math.max(1, Math.ceil(lines.length * 0.5));
}

function hexFromDump(text: string): string {
  const parts: string[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }
    const offsetMatch = line.match(/^(?:0x)?[0-9A-Fa-f]{3,8}:?[ \t]+(.*)$/);
    if (!offsetMatch) {
      continue;
    }

    const hexBytes: string[] = [];
    for (const token of offsetMatch[1].split(/[ \t]+/)) {
      if (!/^[0-9A-Fa-f]{2}$/.test(token)) {
        break;
      }
      hexBytes.push(token);
      if (hexBytes.length >= 16) {
        break;
      }
    }
    if (hexBytes.length > 0) {
      parts.push(hexBytes.join(''));
    }
  }
  if (parts.length === 0) {
    throw new Error('Could not find hex bytes in Wireshark dump.');
  }
  return parts.join('');
}

function hexFromStream(text: string): string {
  const withoutPrefixes = text.replace(/0x/gi, '');
  return withoutPrefixes.replace(/[\s,;:_-]/g, '');
}

/** Normalize Wireshark hex stream, spaced hex, or hex-dump panes into a compact hex string. */
export function extractHex(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error('Please enter hex data from Wireshark');
  }

  const compact = looksLikeHexDump(trimmed) ? hexFromDump(trimmed) : hexFromStream(trimmed);

  if (!/^[0-9A-Fa-f]*$/.test(compact)) {
    throw new Error('Invalid hex string. Only hexadecimal characters (0-9, A-F) are allowed.');
  }
  if (compact.length % 2 !== 0) {
    throw new Error('Hex string must have an even number of characters.');
  }
  if (compact.length === 0) {
    throw new Error('Please enter hex data from Wireshark');
  }

  return compact.toLowerCase();
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function readAscii(bytes: Uint8Array, start: number, end: number): string {
  return new TextDecoder('ascii').decode(bytes.subarray(start, end)).replace(/\0/g, '').trim();
}

export function parseCoilBytes(bytes: Uint8Array): CoilData {
  if (bytes.length < MIN_COIL_PACKET_BYTES) {
    throw new Error(
      `Packet is ${bytes.length} bytes; coil data requires at least ${MIN_COIL_PACKET_BYTES} bytes (offsets 0–129).`,
    );
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const le = true;

  return {
    msgNumber: view.getUint16(0, le),
    wordLength: view.getUint16(2, le),
    seqNumber: view.getUint16(4, le),
    schedule: view.getUint32(6, le),
    coilNumber: readAscii(bytes, 10, 26),
    orderNumber: readAscii(bytes, 26, 42),
    customer: readAscii(bytes, 42, 68),
    grade: readAscii(bytes, 68, 74),
    weight: view.getInt32(76, le),
    entryWidth: view.getFloat32(80, le),
    entryLength: view.getFloat32(84, le),
    entryGauge: view.getFloat32(88, le),
    targetGauge: view.getFloat32(92, le),
    plusGaugeTol: view.getFloat32(96, le),
    minusGaugeTol: view.getFloat32(100, le),
    elongationTarget: view.getFloat32(104, le),
    speedTarget: view.getFloat32(108, le),
    rollingForce: view.getFloat32(112, le),
    entryTension: view.getFloat32(116, le),
    bendForceRef: view.getFloat32(120, le),
    bendTarget: view.getFloat32(124, le),
    gaugeControlMode: view.getUint16(128, le),
  };
}

export function parseHexData(hexString: string): CoilData {
  try {
    const hex = extractHex(hexString);
    return parseCoilBytes(hexToBytes(hex));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.startsWith('Parse error:')) {
      throw err;
    }
    throw new Error(`Parse error: ${message}`);
  }
}

export function formatFieldValue(data: CoilData, field: CoilFieldDef): string {
  const value = data[field.key];
  if (field.format === 'string' || field.format === 'int') {
    return String(value);
  }
  const n = value as number;
  return field.format === 'float6' ? n.toFixed(6) : n.toFixed(3);
}

function csvEscape(value: string): string {
  if (/[",\n\r]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

export function toTabSeparated(data: CoilData): string {
  return COIL_FIELDS.map((field) => formatFieldValue(data, field)).join('\t');
}

export function toCsv(data: CoilData): string {
  const headers = COIL_FIELDS.map((field) => csvEscape(field.csvName)).join(',');
  const values = COIL_FIELDS.map((field) => csvEscape(formatFieldValue(data, field))).join(',');
  return `${headers}\n${values}\n`;
}

/** Sample L2 coil telegram used by the "Load sample" control. */
export const SAMPLE_HEX =
  '8e0001004e0039300000434f494c2d323032342d3030303031004f52442d39383736353433323100000041434d4520535445454c20434f525000000000000000000000004133360000000000a86100000000424200401c450000003efca9f13d6f12033b6f12033b00002040000048440080bb4400004841000000410000d0400100';

export const SAMPLE_WIRESHARK_DUMP = `0000  8e 00 01 00 4e 00 39 30 00 00 43 4f 49 4c 2d 32  ....N.90..COIL-2
0010  30 32 34 2d 30 30 30 30 31 00 4f 52 44 2d 39 38  024-00001.ORD-98
0020  37 36 35 34 33 32 31 00 00 00 41 43 4d 45 20 53  7654321...ACME S
0030  54 45 45 4c 20 43 4f 52 50 00 00 00 00 00 00 00  TEEL CORP.......
0040  00 00 00 00 41 33 36 00 00 00 00 00 a8 61 00 00  ....A36......a..
0050  00 00 42 42 00 40 1c 45 00 00 00 3e fc a9 f1 3d  ..BB.@.E...>...=
0060  6f 12 03 3b 6f 12 03 3b 00 00 20 40 00 00 48 44  o..;o..;.. @..HD
0070  00 80 bb 44 00 00 48 41 00 00 00 41 00 00 d0 40  ...D..HA...A...@
0080  01 00                                           ..`;
