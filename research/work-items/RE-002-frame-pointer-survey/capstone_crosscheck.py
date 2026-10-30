#!/usr/bin/env python3
"""Packet-specific cross-check: decode sampled prologues with capstone.

Not part of the repository tooling: the repository tools are standard-library
only. This script needs `pip install capstone` and a materialized LFS target,
and is kept in the work-item directory like RE-001-fde-extents'
readelf_crosscheck.py. It independently re-derives each sampled
frame_pointer_survey class from decoded instructions and reports agreement
counts, which the packet records in validation-capstone.json.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import capstone  # noqa: E402 - third-party, packet-specific only
from frame_pointer_survey import survey  # noqa: E402

SAMPLE_PER_CLASS = 60
RELEASES = {
    '94': 'artifacts/node/94/hl-node',
    '115': 'artifacts/node/115/hl-node',
    'visor': 'artifacts/visor/captured/hl-visor',
}
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = False


def decoded(data, file_offset, count=6):
    window = data[file_offset:file_offset + 48]
    return [f'{i.mnemonic} {i.op_str}'.strip() for i in list(md.disasm(window, 0))[:count]]


def check_class(kind, insns):
    """Return True when the decoded stream supports the byte-pattern class."""
    body = [i for i in insns if i != 'endbr64']
    if kind == 'frame_pointer_immediate':
        return len(body) >= 2 and body[0] == 'push rbp' and body[1] == 'mov rbp, rsp'
    if kind == 'frame_pointer_deferred':
        pushes = [n for n, i in enumerate(body) if i == 'push rbp']
        return any(n + 1 < len(body) and body[n + 1] == 'mov rbp, rsp' for n in pushes)
    if kind == 'push_rbp_first':
        return body[:1] == ['push rbp'] and 'mov rbp, rsp' not in body
    if kind == 'no_frame_pointer_pattern':
        return 'push rbp' not in body
    return None  # zero_length_extent: nothing to decode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', choices=sorted(RELEASES), required=True)
    args = parser.parse_args()
    binary = ROOT / RELEASES[args.release]
    data = binary.read_bytes()
    summary, rows = survey(data)
    per_class = {}
    for kind in summary['class_counts']:
        members = [r for r in rows if r['prologue_class'] == kind]
        step = max(1, len(members) // SAMPLE_PER_CLASS)
        sample = members[::step][:SAMPLE_PER_CLASS]
        agree = mismatch = undecidable = 0
        details = []
        for row in sample:
            if kind == 'zero_length_extent' or row['window_bytes'] == 0:
                continue
            try:
                insns = decoded(data, row['file_offset'])
            except Exception as error:  # noqa: BLE001 - report, do not stop the run
                undecidable += 1
                details.append((hex(row['start_va']), f'decode error {error}'))
                continue
            verdict = check_class(kind, insns)
            if verdict is None:
                undecidable += 1
            elif verdict:
                agree += 1
            else:
                mismatch += 1
                details.append((hex(row['start_va']), ' '.join(insns[:4])))
        per_class[kind] = {'sampled': len(sample), 'agree': agree, 'mismatch': mismatch,
                           'undecidable': undecidable, 'mismatch_examples': details[:5]}
    print(json.dumps({'binary_sha256': summary['binary_sha256'],
                      'fde_records': summary['fde_records'],
                      'class_counts': summary['class_counts'],
                      'validation': per_class}, indent=2))


if __name__ == '__main__':
    main()
