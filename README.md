# Temper Mill L2 Coil Data Parser

Web tool for decoding Level 2 coil telegrams captured from a PLC control interface. Paste Wireshark hex (stream or dump) and export the decoded fields as tab-separated values or CSV.

## How to use

No install. Double-click `index.html` or open it from your browser:

**File → Open File → `index.html`**

Then paste the Wireshark hex stream or hex dump and click **Parse Data**. A 54-byte Ethernet/IP/TCP header at the start is skipped automatically, so you can paste the full frame. Use **Load sample** to try a built-in telegram that includes that header.

## Packet layout

Little-endian binary, 130 bytes minimum:

| Offset | Type | Field |
| --- | --- | --- |
| 0 | uint16 | Msg Number |
| 2 | uint16 | Word Length |
| 4 | uint16 | Sequence Number |
| 6 | uint32 | Schedule |
| 10 | char[16] | Coil Number |
| 26 | char[16] | Order Number |
| 42 | char[26] | Customer |
| 68 | char[6] | Grade |
| 74 | — | unused padding |
| 76 | int32 | Weight |
| 80 | float32 | Entry Width |
| 84 | float32 | Entry Length |
| 88 | float32 | Entry Gauge |
| 92 | float32 | Target Gauge |
| 96 | float32 | Plus Gauge Tolerance |
| 100 | float32 | Minus Gauge Tolerance |
| 104 | float32 | Elongation Target |
| 108 | float32 | Speed Target |
| 112 | float32 | Rolling Force |
| 116 | float32 | Entry Tension |
| 120 | float32 | Bend Force Reference |
| 124 | float32 | Bend Target |
| 128 | uint16 | Gauge Control Mode |
