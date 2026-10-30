import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from frame_pointer_survey import CLASSES, ENDBR64, PAIR, classify, survey

TEXT, HDR, FRAME, EXCEPT = 0x1000, 0x2000, 0x3000, 0x4000
OFFSET = {TEXT: 0x400, HDR: 0x600, FRAME: 0x800, EXCEPT: 0xa00}
SHOFF = 0xc00
# (start, size, augmentation): prologue bytes are placed in .text by build().
FUNCTIONS = [
    (0x1000, 0x20, 'zR'),  # endbr64; push rbp; mov rbp,rsp
    (0x1030, 0x20, 'zR'),  # push rbp; mov rbp,rsp
    (0x1060, 0x20, 'zR'),  # push r15; push rbp; mov rbp,rsp
    (0x1090, 0x20, 'zR'),  # push rbp; mov rax,rbx
    (0x10c0, 0x20, 'zR'),  # endbr64; sub rsp,0x28
    (0x10f0, 0x20, 'zR'),  # xor eax,eax; ret
    (0x1120, 0x00, 'zR'),  # zero-length extent
    (0x1130, 0x02, 'zR'),  # two-byte window: 55 48
]
EXPECTED = {
    0x1000: ('frame_pointer_immediate', True, 16),
    0x1030: ('frame_pointer_immediate', False, 16),
    0x1060: ('frame_pointer_deferred', False, 16),
    0x1090: ('push_rbp_first', False, 16),
    0x10c0: ('no_frame_pointer_pattern', True, 16),
    0x10f0: ('no_frame_pointer_pattern', False, 16),
    0x1120: ('zero_length_extent', False, 0),
    0x1130: ('push_rbp_first', False, 2),
}
PROLOGUES = {
    0x1000: ENDBR64 + PAIR,
    0x1030: PAIR,
    0x1060: b'\x41\x57' + PAIR,            # push r15
    0x1090: b'\x55\x48\x89\xd8',           # push rbp; mov rax,rbx
    0x10c0: ENDBR64 + b'\x48\x83\xec\x28',  # endbr64; sub rsp,0x28
    0x10f0: b'\x31\xc0\xc3',               # xor eax,eax; ret
    0x1130: b'\x55\x48',
}


def sdata4(value):
    return struct.pack('<i', value)


def build():
    """Build a minimal ELF64-LE image with the encodings observed in the captured nodes."""
    frame, layout = bytearray(), {'cie': {}, 'fde': []}

    def record(make_body):
        start = len(frame)
        body = make_body(FRAME + start + 4)
        body += b'\0' * (-len(body) % 4)  # DW_CFA_nop padding
        frame.extend(struct.pack('<I', len(body)) + body)
        return start

    def cie(augmentation):
        def body(va):
            head = struct.pack('<I', 0) + b'\1' + augmentation.encode() + b'\0' + bytes([1, 0x78, 16])
            if augmentation == 'zR':
                return head + b'\1\x1b'
            slot = va + len(head) + 2
            return head + b'\7\x9b' + sdata4(0x4008 - slot) + b'\x1b\x1b'
        return body

    for augmentation in ['zR', 'zPLR']:
        start = record(cie(augmentation))
        layout['cie'][augmentation] = start
    for start_va, size, augmentation in FUNCTIONS:
        cie_va = FRAME + layout['cie'][augmentation]

        def body(va, start_va=start_va, size=size, augmentation=augmentation, cie_va=cie_va):
            out = struct.pack('<I', va - cie_va) + sdata4(start_va - (va + 4)) + struct.pack('<I', size)
            if augmentation == 'zR':
                return out + b'\0'
            return out + b'\4' + sdata4(0)
        layout['fde'].append(record(body))
    frame.extend(b'\0' * 4)

    rows = sorted((f[0], FRAME + off) for f, off in zip(FUNCTIONS, layout['fde']))
    header = bytes([1, 0x1b, 3, 0x3b]) + sdata4(FRAME - (HDR + 4)) + struct.pack('<I', len(rows))
    for start_va, fde_va in rows:
        header += sdata4(start_va - HDR) + sdata4(fde_va - HDR)

    data = bytearray(SHOFF + 6 * 64)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, SHOFF)
    struct.pack_into('<HHH', data, 58, 64, 6, 1)
    names = b'\0.shstrtab\0.text\0.eh_frame_hdr\0.eh_frame\0.gcc_except_table\0'
    data[64:64 + len(names)] = names
    text = bytearray(b'\xcc' * 0x140)
    for start_va, prologue in PROLOGUES.items():
        text[start_va - TEXT:start_va - TEXT + len(prologue)] = prologue
    data[OFFSET[TEXT]:OFFSET[TEXT] + 0x140] = text
    data[OFFSET[HDR]:OFFSET[HDR] + len(header)] = header
    data[OFFSET[FRAME]:OFFSET[FRAME] + len(frame)] = frame
    table = [(0, 0, 0, 0, 0, 0), (names.index(b'.shstrtab'), 3, 0, 0, 64, len(names)),
             (names.index(b'.text'), 1, 6, TEXT, OFFSET[TEXT], 0x140),
             (names.index(b'.eh_frame_hdr'), 1, 2, HDR, OFFSET[HDR], len(header)),
             (names.index(b'.eh_frame\0'), 1, 2, FRAME, OFFSET[FRAME], len(frame)),
             (names.index(b'.gcc_except_table'), 1, 2, EXCEPT, OFFSET[EXCEPT], 0x10)]
    for index, row in enumerate(table):
        struct.pack_into('<IIQQQQIIQQ', data, SHOFF + index * 64, *row, 0, 0, 1, 0)
    return data


class ClassifyTests(unittest.TestCase):
    def test_window_classes(self):
        cases = [
            (PAIR, 'frame_pointer_immediate'),
            (ENDBR64 + PAIR, 'frame_pointer_immediate'),
            (b'\x41\x57' + PAIR, 'frame_pointer_deferred'),
            (b'\x55\x48\x89\xd8', 'push_rbp_first'),
            (b'\x31\xc0\xc3', 'no_frame_pointer_pattern'),
            (b'\x55', 'push_rbp_first'),
            (b'\x48', 'no_frame_pointer_pattern'),
            (b'\x41\x55\x48\x89\xd8', 'no_frame_pointer_pattern'),  # push r13; mov rax,rbx: 0x55 is not a prologue
        ]
        for window, expected in cases:
            with self.subTest(window=window):
                kind, _ = classify(window)
                self.assertEqual(kind, expected)

    def test_endbr64_flag_is_independent_of_class(self):
        self.assertTrue(classify(ENDBR64 + b'\x31\xc0')[1])
        self.assertFalse(classify(b'\x31\xc0')[1])


class SurveyTests(unittest.TestCase):
    def test_census_over_fde_denominator(self):
        summary, rows = survey(build())
        self.assertEqual(summary['fde_records'], len(FUNCTIONS))
        self.assertEqual(summary['denominator_fde_records'], summary['fde_records'])
        self.assertEqual(sum(summary['class_counts'].values()), summary['fde_records'])
        self.assertEqual(summary['classified_rows'], len(FUNCTIONS))
        self.assertEqual(set(summary['class_counts']), set(CLASSES))
        self.assertEqual(summary['unique_fde_starts'], len(FUNCTIONS))
        by_start = {r['start_va']: r for r in rows}
        for start_va, (kind, pad, window_bytes) in EXPECTED.items():
            row = by_start[start_va]
            self.assertEqual((row['prologue_class'], row['endbr64'], row['window_bytes']), (kind, pad, window_bytes))
        self.assertEqual(summary['class_counts'],
                         {'frame_pointer_immediate': 2, 'frame_pointer_deferred': 1,
                          'push_rbp_first': 2, 'no_frame_pointer_pattern': 2,
                          'zero_length_extent': 1})
        self.assertEqual(summary['endbr64_counts'], {'endbr64': 2, 'no_endbr64': 6})
        self.assertEqual(summary['class_extent_bytes']['zero_length_extent'], 0)
        self.assertEqual(summary['class_extent_bytes']['frame_pointer_immediate'], 0x40)
        self.assertEqual(summary['per_section'], {'.text': summary['class_counts']})

    def test_rows_record_window_bytes_for_review(self):
        _, rows = survey(build())
        by_start = {r['start_va']: r for r in rows}
        self.assertEqual(by_start[0x1000]['prologue_hex'], (ENDBR64 + PAIR + b'\xcc' * 8).hex())
        self.assertEqual(by_start[0x1130]['prologue_hex'], b'\x55\x48'.hex())
        self.assertEqual(by_start[0x1130]['window_bytes'], 2)
        self.assertEqual(by_start[0x1120]['prologue_hex'], '')
        self.assertEqual(by_start[0x1120]['file_offset'], '')
        self.assertEqual(by_start[0x1000]['file_offset'], 0x400)

    def test_corrupting_the_pair_moves_the_class(self):
        # Comparator corruption control: flipping the push rbp opcode must move the
        # row out of the frame-pointer classes instead of silently matching.
        data = build()
        start = 0x1030 - TEXT + OFFSET[TEXT]
        data[start] = 0x54  # push rsp, not push rbp
        summary, rows = survey(data)
        self.assertEqual(summary['class_counts']['frame_pointer_immediate'], 1)
        self.assertEqual(summary['class_counts']['no_frame_pointer_pattern'], 3)
        self.assertEqual(rows[1]['prologue_class'], 'no_frame_pointer_pattern')

    def test_corrupting_endbr64_prefix_keeps_the_frame_pointer_class(self):
        # Removing a leading endbr64 moves the pair off the window start, so the row
        # becomes deferred; it must not fall out of the frame-pointer classes.
        data = build()
        start = 0x1000 - TEXT + OFFSET[TEXT]
        data[start:start + 4] = b'\x90' * 4
        summary, rows = survey(data)
        self.assertEqual(rows[0]['prologue_class'], 'frame_pointer_deferred')
        self.assertEqual(rows[0]['endbr64'], False)
        self.assertEqual(summary['class_counts']['frame_pointer_immediate'], 1)
        self.assertEqual(summary['class_counts']['frame_pointer_deferred'], 2)
        self.assertEqual(summary['endbr64_counts']['endbr64'], 1)


class TargetTests(unittest.TestCase):
    """Structural checks against a captured target; skipped without LFS material."""

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.binary = root / 'artifacts/node/94/hl-node'
        cls.identity = next(i for i in json.loads(
            (root / 'provenance/artifacts.json').read_text())['files']
            if i['path'] == 'artifacts/node/94/hl-node')
        cls.inventory = json.loads((root / 'research/imported/hl-node-94.inventory.json').read_text())

    def setUp(self):
        if not self.binary.is_file():
            self.skipTest('captured node #94 is not materialized')
        from artifacts import check
        check(self.binary, self.identity)
        self.data = self.binary.read_bytes()

    def test_real_target_census_is_structural(self):
        summary, rows = survey(self.data)
        self.assertEqual(summary['binary_sha256'], self.identity['sha256'])
        self.assertEqual(sum(summary['class_counts'].values()), summary['fde_records'])
        self.assertEqual(summary['classified_rows'], summary['fde_records'])
        self.assertEqual(len(rows), summary['fde_records'])
        self.assertEqual(summary['fde_records'], self.inventory['fde_count_eh_frame_hdr'])
        self.assertTrue(set(summary['class_counts']) <= set(CLASSES))
        self.assertGreater(summary['unique_fde_starts'], 0)


if __name__ == '__main__':
    unittest.main()
