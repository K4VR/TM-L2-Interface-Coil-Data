import { describe, expect, it } from 'vitest';
import {
  SAMPLE_HEX,
  SAMPLE_WIRESHARK_DUMP,
  extractHex,
  parseHexData,
  toCsv,
  toTabSeparated,
} from './parseCoilData';

describe('extractHex', () => {
  it('accepts a compact hex stream', () => {
    expect(extractHex('8e 00 01 00')).toBe('8e000100');
  });

  it('strips 0x prefixes, colons, and commas', () => {
    expect(extractHex('0x8e,00:01-00')).toBe('8e000100');
  });

  it('extracts bytes from a Wireshark hex dump and ignores ASCII', () => {
    expect(extractHex(SAMPLE_WIRESHARK_DUMP)).toBe(SAMPLE_HEX);
  });

  it('rejects non-hex characters in a stream', () => {
    expect(() => extractHex('8e00ZZ')).toThrow(/Invalid hex/);
  });

  it('rejects an odd number of hex digits', () => {
    expect(() => extractHex('8e0')).toThrow(/even number/);
  });
});

describe('parseHexData', () => {
  it('parses the sample L2 coil telegram', () => {
    const data = parseHexData(SAMPLE_HEX);
    expect(data.msgNumber).toBe(142);
    expect(data.wordLength).toBe(1);
    expect(data.seqNumber).toBe(78);
    expect(data.schedule).toBe(12345);
    expect(data.coilNumber).toBe('COIL-2024-00001');
    expect(data.orderNumber).toBe('ORD-987654321');
    expect(data.customer).toBe('ACME STEEL CORP');
    expect(data.grade).toBe('A36');
    expect(data.weight).toBe(25000);
    expect(data.entryWidth).toBeCloseTo(48.5, 5);
    expect(data.entryLength).toBeCloseTo(2500, 3);
    expect(data.entryGauge).toBeCloseTo(0.125, 6);
    expect(data.targetGauge).toBeCloseTo(0.118, 6);
    expect(data.plusGaugeTol).toBeCloseTo(0.002, 6);
    expect(data.minusGaugeTol).toBeCloseTo(0.002, 6);
    expect(data.elongationTarget).toBeCloseTo(2.5, 5);
    expect(data.speedTarget).toBeCloseTo(800, 3);
    expect(data.rollingForce).toBeCloseTo(1500, 3);
    expect(data.entryTension).toBeCloseTo(12.5, 5);
    expect(data.bendForceRef).toBeCloseTo(8, 5);
    expect(data.bendTarget).toBeCloseTo(6.5, 5);
    expect(data.gaugeControlMode).toBe(1);
  });

  it('parses the same packet from a Wireshark dump', () => {
    const data = parseHexData(SAMPLE_WIRESHARK_DUMP);
    expect(data.coilNumber).toBe('COIL-2024-00001');
    expect(data.gaugeControlMode).toBe(1);
  });

  it('rejects packets shorter than 130 bytes', () => {
    expect(() => parseHexData('8e0001004e00')).toThrow(/130 bytes/);
  });

  it('rejects empty input', () => {
    expect(() => parseHexData('   ')).toThrow(/Please enter hex data/);
  });
});

describe('export helpers', () => {
  it('builds tab-separated values in field order', () => {
    const tsv = toTabSeparated(parseHexData(SAMPLE_HEX));
    const cols = tsv.split('\t');
    expect(cols[0]).toBe('142');
    expect(cols[4]).toBe('COIL-2024-00001');
    expect(cols[8]).toBe('25000');
    expect(cols[9]).toBe('48.500');
    expect(cols[11]).toBe('0.125000');
    expect(cols[21]).toBe('1');
  });

  it('quotes CSV fields that contain commas', () => {
    const data = parseHexData(SAMPLE_HEX);
    data.customer = 'ACME STEEL, INC';
    const csv = toCsv(data);
    expect(csv).toContain('"ACME STEEL, INC"');
    expect(csv.split('\n')[0]).toContain('Long Coil Number');
  });
});
