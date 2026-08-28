import { useState, type KeyboardEvent } from 'react';
import { Upload, Copy, Download, Eraser, FlaskConical } from 'lucide-react';
import {
  COIL_FIELDS,
  SAMPLE_HEX,
  formatFieldValue,
  parseHexData,
  toCsv,
  toTabSeparated,
  type CoilData,
} from '../lib/parseCoilData';

export default function CoilDataParser() {
  const [hexInput, setHexInput] = useState('');
  const [parsedData, setParsedData] = useState<CoilData | null>(null);
  const [error, setError] = useState('');
  const [copyStatus, setCopyStatus] = useState('');

  const handleParse = () => {
    setError('');
    setParsedData(null);
    setCopyStatus('');

    if (!hexInput.trim()) {
      setError('Please enter hex data from Wireshark');
      return;
    }

    try {
      setParsedData(parseHexData(hexInput));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      handleParse();
    }
  };

  const copyToClipboard = async () => {
    if (!parsedData) {
      return;
    }

    const text = toTabSeparated(parsedData);
    try {
      await navigator.clipboard.writeText(text);
      setCopyStatus('Copied tab-separated values');
    } catch {
      window.prompt('Copy tab-separated values:', text);
      setCopyStatus('Select and copy the values');
    }
  };

  const downloadCSV = () => {
    if (!parsedData) {
      return;
    }

    const blob = new Blob([toCsv(parsedData)], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'coil_data.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 p-8">
      <div className="mx-auto max-w-6xl">
        <div className="rounded-lg bg-white p-8 shadow-2xl">
          <div className="mb-6 flex items-center gap-3">
            <Upload className="h-8 w-8 text-blue-600" />
            <h1 className="text-3xl font-bold text-gray-800">Coil Data Parser</h1>
          </div>

          <p className="mb-2 text-gray-600">
            Paste hex data from Wireshark to convert a Level 2 coil telegram into spreadsheet format.
          </p>
          <p className="mb-6 text-sm text-gray-500">
            Copy the TCP application payload (hex stream or hex dump). All multi-byte values are
            little-endian. Ctrl/Cmd+Enter parses.
          </p>

          <div className="mb-6">
            <label htmlFor="hex-input" className="mb-2 block text-sm font-medium text-gray-700">
              Hex Data from Wireshark
            </label>
            <textarea
              id="hex-input"
              value={hexInput}
              onChange={(event) => setHexInput(event.target.value)}
              onKeyDown={handleKeyDown}
              className="h-32 w-full rounded-lg border border-gray-300 p-3 font-mono text-sm focus:border-blue-500 focus:ring-2 focus:ring-blue-500"
              placeholder="Paste hex string here (e.g., 8e0001004e000000...)"
              spellCheck={false}
            />
          </div>

          <div className="mb-6 flex flex-wrap gap-3">
            <button
              type="button"
              onClick={handleParse}
              className="flex-1 rounded-lg bg-blue-600 px-6 py-3 font-semibold text-white transition-colors hover:bg-blue-700"
            >
              Parse Data
            </button>
            <button
              type="button"
              onClick={() => {
                setHexInput(SAMPLE_HEX);
                setError('');
                setParsedData(null);
                setCopyStatus('');
              }}
              className="inline-flex items-center gap-2 rounded-lg border border-gray-300 px-4 py-3 font-semibold text-gray-700 transition-colors hover:bg-gray-50"
            >
              <FlaskConical className="h-4 w-4" />
              Load sample
            </button>
            <button
              type="button"
              onClick={() => {
                setHexInput('');
                setError('');
                setParsedData(null);
                setCopyStatus('');
              }}
              className="inline-flex items-center gap-2 rounded-lg border border-gray-300 px-4 py-3 font-semibold text-gray-700 transition-colors hover:bg-gray-50"
            >
              <Eraser className="h-4 w-4" />
              Clear
            </button>
          </div>

          {error && (
            <div className="mb-6 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-red-700">
              {error}
            </div>
          )}

          {parsedData && (
            <div className="space-y-6">
              <div className="flex flex-wrap items-center gap-4">
                <button
                  type="button"
                  onClick={() => void copyToClipboard()}
                  className="inline-flex items-center gap-2 rounded-lg bg-green-600 px-4 py-2 font-semibold text-white transition-colors hover:bg-green-700"
                >
                  <Copy className="h-4 w-4" />
                  Copy as Tab-Separated
                </button>
                <button
                  type="button"
                  onClick={downloadCSV}
                  className="inline-flex items-center gap-2 rounded-lg bg-purple-600 px-4 py-2 font-semibold text-white transition-colors hover:bg-purple-700"
                >
                  <Download className="h-4 w-4" />
                  Download CSV
                </button>
                {copyStatus && <span className="text-sm text-green-700">{copyStatus}</span>}
              </div>

              <div className="overflow-x-auto rounded-lg bg-gray-50 p-6">
                <h2 className="mb-4 text-xl font-bold text-gray-800">Parsed Data</h2>
                <table className="w-full border-collapse bg-white shadow-sm">
                  <thead>
                    <tr className="bg-blue-600 text-white">
                      <th className="border border-gray-300 px-4 py-2 text-left font-semibold">
                        Byte Offset
                      </th>
                      <th className="border border-gray-300 px-4 py-2 text-left font-semibold">
                        Field
                      </th>
                      <th className="border border-gray-300 px-4 py-2 text-left font-semibold">
                        Type
                      </th>
                      <th className="border border-gray-300 px-4 py-2 text-left font-semibold">
                        Value
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {COIL_FIELDS.map((field) => (
                      <tr key={field.key} className="hover:bg-gray-50">
                        <td className="border border-gray-300 px-4 py-2 font-mono text-sm text-gray-600">
                          {field.offset}
                        </td>
                        <td className="border border-gray-300 px-4 py-2 font-medium">{field.name}</td>
                        <td className="border border-gray-300 px-4 py-2 font-mono text-sm text-gray-500">
                          {field.typeLabel}
                        </td>
                        <td className="border border-gray-300 px-4 py-2">
                          {formatFieldValue(parsedData, field)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
