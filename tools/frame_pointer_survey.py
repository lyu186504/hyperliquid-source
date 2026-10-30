#!/usr/bin/env python3
"""Census frame-pointer prologues over FDE-bounded functions in a captured target.

Answers one unresolved build-provenance field (RE-002, `frame_pointers`): a
prologue survey over FDE-bounded functions. The survey is a deterministic
offline byte-pattern census; it never executes or disassembles the target.
"""
import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path

from artifacts import ROOT, check
from elf_index import sections
from fde_extents import fde_extents

WINDOW = 16  # Prologue bytes inspected at each FDE-bounded function start.
ENDBR64 = b'\xf3\x0f\x1e\xfa'  # endbr64: CET/IBT landing pad, not a frame-pointer marker.
PUSH_RBP = b'\x55'  # push rbp as the first window instruction only; a bare 0x55 byte is not decoded evidence.
PAIR = PUSH_RBP + b'\x48\x89\xe5'  # push rbp; mov rbp,rsp
CLASSES = ('frame_pointer_immediate', 'frame_pointer_deferred', 'push_rbp_first',
           'no_frame_pointer_pattern', 'zero_length_extent')
LIMITATIONS = (
    'A byte-pattern census, not decoded instructions: the pair 55 48 89 e5 found after the '
    'window start can straddle an instruction boundary, so frame_pointer_deferred is a '
    'hypothesis checked against the window bytes recorded per row. push_rbp_first means '
    'push rbp is the first window instruction (after an optional endbr64) and mov rbp,rsp '
    'does not follow it in the window; rbp is then a saved general register, not an '
    'established frame pointer. Absence of the pattern does not prove a frameless '
    'function: a frame pointer can be established after the window, and code without '
    'unwind data has no FDE at all. An FDE extent is the unwind-described range, not a '
    'validated function boundary. This census resolves only the RE-002 frame_pointers '
    'field; it establishes no other build flag, no component ownership and no equivalence.'
)


def prologue_window(data, start, size):
    """Return (window_bytes, file_offset) for an FDE-bounded function start."""
    length = min(WINDOW, size)
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= start and start + length <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'Ambiguous file-backed window for extent start {start:#x}')
    section = matches[0]
    offset = section['offset'] + start - section['address']
    return data[offset:offset + length], offset


def classify(window):
    """Classify one prologue window; a leading endbr64 is stripped before matching."""
    endbr64 = window.startswith(ENDBR64)
    body = window[len(ENDBR64):] if endbr64 else window
    at = body.find(PAIR)
    if at == 0:
        kind = 'frame_pointer_immediate'
    elif at > 0:
        kind = 'frame_pointer_deferred'
    elif body[:1] == PUSH_RBP:
        kind = 'push_rbp_first'
    else:
        kind = 'no_frame_pointer_pattern'
    return kind, endbr64


def survey(data):
    """Return (summary, rows) over every FDE record in section order."""
    extents, ordered, _ = fde_extents(data)
    counts = collections.Counter()
    class_bytes = collections.Counter()
    endbr64 = collections.Counter()
    per_section = collections.defaultdict(collections.Counter)
    rows = []
    for fde in ordered:
        size = fde['end'] - fde['start']
        if size == 0:
            kind, pad = 'zero_length_extent', False
            window, offset = b'', ''
        else:
            window, offset = prologue_window(data, fde['start'], size)
            kind, pad = classify(window)
        counts[kind] += 1
        class_bytes[kind] += size
        endbr64['endbr64' if pad else 'no_endbr64'] += 1
        per_section[fde['section']][kind] += 1
        rows.append({'start_va': fde['start'], 'end_va': fde['end'], 'size': size,
                     'section': fde['section'], 'endbr64': pad, 'prologue_class': kind,
                     'window_bytes': len(window), 'file_offset': offset,
                     'prologue_hex': window.hex()})
    summary = {
        'binary_sha256': hashlib.sha256(data).hexdigest(),
        'window_bytes': WINDOW,
        'fde_records': extents['fde_records'],
        'unique_fde_starts': extents['unique_fde_starts'],
        'denominator_fde_records': extents['fde_records'],
        'class_counts': {kind: counts[kind] for kind in CLASSES},
        'class_extent_bytes': {kind: class_bytes[kind] for kind in CLASSES},
        'endbr64_counts': dict(sorted(endbr64.items())),
        'per_section': {name: dict(sorted(counter.items())) for name, counter in sorted(per_section.items())},
        'classified_rows': len(rows),
        'limitations': LIMITATIONS,
    }
    return summary, rows


def generate(binary, prefix):
    summary, rows = survey(binary.read_bytes())
    prefix.parent.mkdir(parents=True, exist_ok=True)
    with prefix.with_suffix('.tsv').open('w', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(['start_va', 'end_va', 'size', 'section', 'endbr64', 'prologue_class',
                         'window_bytes', 'file_offset', 'prologue_hex'])
        for row in rows:
            writer.writerow([hex(row['start_va']), hex(row['end_va']), row['size'], row['section'],
                             str(row['endbr64']).lower(), row['prologue_class'], row['window_bytes'],
                             row['file_offset'] if row['file_offset'] == '' else hex(row['file_offset']),
                             row['prologue_hex']])
    prefix.with_suffix('.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', choices=['94', '115', 'visor'], required=True)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'work/frame-pointer-survey')
    args = parser.parse_args()
    rel = {'94': 'artifacts/node/94/hl-node', '115': 'artifacts/node/115/hl-node',
           'visor': 'artifacts/visor/captured/hl-visor'}[args.release]
    inventory = 'hl-visor.inventory.json' if args.release == 'visor' else f'hl-node-{args.release}.inventory.json'
    item = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files'] if i['path'] == rel)
    check(ROOT / rel, item)
    summary, _ = generate(ROOT / rel, args.output_dir / f'{args.release}-frame-pointer')
    expected = json.loads((ROOT / f'research/imported/{inventory}').read_text())['fde_count_eh_frame_hdr']
    if summary['fde_records'] != expected:
        raise ValueError('Parsed unwind count differs from retained inventory')
    if sum(summary['class_counts'].values()) != summary['fde_records']:
        raise ValueError('Class counts do not cover the FDE denominator')
    print(json.dumps({k: v for k, v in summary.items() if k != 'limitations'}, indent=2))


if __name__ == '__main__':
    main()
