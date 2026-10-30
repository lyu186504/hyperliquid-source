# RE-002-frame-pointer-survey: Do FDE-bounded functions in the captured targets establish rbp frame pointers in their prologues?

- Component ID: build provenance (no catalogue component)
- Target releases and full SHA-256:
  - `artifacts/node/94/hl-node` `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91774280 bytes)
  - `artifacts/node/115/hl-node` `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105896032 bytes)
  - `artifacts/visor/captured/hl-visor` `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31` (8305392 bytes)
- Source commit: upstream `main` at `1f8c67c` (this packet's checkout). No reference source was used.
- Claim status: observation for the byte-pattern census, inference for the class labels.
- Scope included: the first 16 bytes at every FDE-bounded function start in the three
  targets, classified by byte pattern. Resolves the `frame_pointers` row of
  [`RE-002-build-provenance`](../RE-002-build-provenance/README.md).
- Scope excluded: decoded-instruction validation beyond the capstone cross-check sample,
  execution of any target, rebuilding, and every other RE-002 unresolved field
  (`opt_level`, `lto`, `codegen_units`, `overflow_checks`, `target_cpu_features`,
  `rustflags`, `cargo_lock`, `first_party_crate_versions`, `panic_strategy`).

## Reproduce

Run from the repository root after `make pull` (or an LFS fetch):

```sh
make frame-pointer-survey          # node #94, node #115 and the captured visor
python3 -m unittest tests.test_frame_pointer_survey -v
make doctor
```

The capstone cross-check recorded below is packet-specific (the repository tools are
standard-library only). To re-run it, `pip install capstone` and then:

```sh
python3 research/work-items/RE-002-frame-pointer-survey/capstone_crosscheck.py --release 94
```

`tools/frame_pointer_survey.py` refuses a target whose SHA-256 or size differs from
`provenance/artifacts.json`. It reads the files and never runs them. Each target takes
about 7 seconds (node #94), 8 seconds (node #115) and under 1 second (visor) on the
recorded platform; the per-target TSV and JSON are written under `work/`.

Recorded environment (this packet):

| Item | Value |
| --- | --- |
| Platform | macOS 14.8.7, darwin 23.6.0, x86_64 (Apple Intel) |
| Python | 3.13.12 |
| git / git-lfs | 2.39.2 (Apple Git-143) / 3.7.1 |
| Commands | as above, from the repository root |

Checks run and their exact outcomes:

| Check | Outcome |
| --- | --- |
| `python3 tools/frame_pointer_survey.py --release 94` | pass; 121,299 rows, count matches the retained inventory |
| `python3 tools/frame_pointer_survey.py --release 115` | pass; 135,313 rows, count matches the retained inventory |
| `python3 tools/frame_pointer_survey.py --release visor` | pass; 11,028 rows, count matches the retained inventory |
| `python3 -m unittest tests.test_frame_pointer_survey -v` | 7 tests, all pass (one needs materialized LFS input) |
| `make doctor` | runs; reports `gpg: available=false` on this host |
| `make test` (full suite) | 288 tests; the 33 errors are pre-existing on this host: they belong to tools that shell out to GNU `objdump`/`readelf` (`test_wei_buffered_cap`, `test_spot_wei_scale`, `test_evm_amount_scale`, `test_truncated_debug_static`, `test_state_roots`, `test_consensus_wire`, `test_info_request_path` and others). macOS ships LLVM `objdump`, which does not accept their GNU options. No new test fails because of this change. |
| `make verify` | **not completed on this host.** SHA-256 and size checks pass for every materialized artifact (verified directly against `provenance/artifacts.json`), but `tools/artifacts.py` requires the `gpg` CLI for detached-signature verification and `tools/verify_imports.py` requires the pinned submodules; neither `gpg` nor the submodules are available here. No signature or pin result is claimed. |
| `make catalogue-check` | **not completed on this host.** `tools/catalogue.py` derives reference-path counts from the uninitialized `references/can1357-hl` submodule; regenerating without it writes an empty catalogue, so the committed generated files were restored and left untouched. This change adds no component or progress record. |

## Evidence

### Census (observation; denominator = FDE records parsed from `.eh_frame_hdr`)

| Target | FDE records | `frame_pointer_immediate` | `frame_pointer_deferred` | `push_rbp_first` | `no_frame_pointer_pattern` | `endbr64` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| node #94 | 121,299 | 1,536 (1.27%) | 7 (0.006%) | 28,712 (23.67%) | 91,044 (75.06%) | 9,098 (7.50%) |
| node #115 | 135,313 | 1,142 (0.84%) | 7 (0.005%) | 37,633 (27.81%) | 96,531 (71.34%) | 9,094 (6.72%) |
| visor | 11,028 | 657 (5.96%) | 7 (0.06%) | 2,261 (20.50%) | 8,103 (73.48%) | 997 (9.04%) |

Zero-length extents: 0 in all three targets. Unique FDE starts equal FDE records in all
three targets, so no duplicate-start inflation affects the denominator.

Class definitions (byte patterns over the first 16 window bytes, after stripping one
leading `endbr64`):

| Class | Pattern |
| --- | --- |
| `frame_pointer_immediate` | window begins `55 48 89 e5` (`push rbp; mov rbp,rsp`) |
| `frame_pointer_deferred` | that pair appears later in the window |
| `push_rbp_first` | window begins `55` and the pair does not follow |
| `no_frame_pointer_pattern` | neither of the above |
| `zero_length_extent` | FDE range is empty |

### Instruction-level cross-check (independent validation; not part of the tool)

`validation-capstone.json` records a capstone 5.0.7 decode of an evenly spaced sample of
up to 60 function starts per class per target, compared with the byte-pattern class:

| Target | `frame_pointer_immediate` | `frame_pointer_deferred` | `push_rbp_first` | `no_frame_pointer_pattern` |
| --- | --- | --- | --- | --- |
| node #94 | 60/60 agree | 6/7 (one pair straddling an instruction boundary) | 60/60 | 58/60 |
| node #115 | 60/60 agree | 6/7 (one pair straddling an instruction boundary) | 60/60 | 57/60 |
| visor | 60/60 agree | 7/7 | 60/60 | 58/60 |

The `no_frame_pointer_pattern` disagreements decode as
`endbr64; push r15; push r14; push r13; push rbp; ...` or similar: `push rbp` appears
inside the window but not as the first instruction, which the class definition excludes by
construction. The one `frame_pointer_deferred` disagreement per node decodes as
`cmp rsi, 0xf; jbe ...; mov al, 1; mov cl, 1` at the sampled start: the pair bytes sit
inside other instructions, the documented straddling risk of byte-pattern matching. Both
classes keep their window bytes in every TSV row so a reviewer can re-check any row.

### Interpretation (inference)

- All three targets were built without forced frame pointers: 71.3–75.1% of FDE-bounded
  functions open with no `push rbp` at all, and only 0.84% (#115) to 5.96% (visor) open
  with `push rbp; mov rbp,rsp`.
- The `push_rbp_first` class (20.5–27.8%) is rbp used as a saved general register, not a
  frame pointer: `mov rbp,rsp` does not follow. This is consistent with the x86-64 System V
  ABI treating rbp as a callee-saved general register when the frame pointer is omitted.
- `endbr64` appears in 6.7–9.0% of functions, consistent with CET/IBT landing pads on
  indirectly-reachable code.
- The visor establishes frame pointers about 4.7× more often than node #94 and 7.1× more
  often than node #115 (5.96% vs 1.27% and 0.84%). All three remain minority prologues;
  no per-component attribution is made.

## Implementation and comparison

`tools/frame_pointer_survey.py` is a deterministic offline tool in the repository's
existing style: standard library only, digest-authenticated inputs via
`tools/artifacts.py`, FDE extents from `tools/fde_extents.py`, fail-closed VA mapping, and
TSV + JSON outputs. It adds no dependency and executes no target.

The classifier requires `push rbp` as the **first** window instruction (after one optional
`endbr64`); a bare `0x55` byte elsewhere in the window is not decoded evidence and is not
counted. That rule was added after the cross-check showed `push r13` (`41 55`) and similar
encodings inflating the earlier looser class.

Corruption controls in `tests/test_frame_pointer_survey.py`:

- flipping the `push rbp` opcode of a synthetic function moves the row from
  `frame_pointer_immediate` to `no_frame_pointer_pattern`;
- replacing a leading `endbr64` with NOPs moves the row to `frame_pointer_deferred`
  (the pair is no longer at the window start) without leaving the frame-pointer family;
- `41 55 48 89 d8` (`push r13; mov rax,rbx`) stays `no_frame_pointer_pattern`;
- a two-byte extent is reported with `window_bytes=2`, and zero-length extents get their
  own class instead of being silently dropped;
- class counts are asserted to sum to the FDE denominator, and per-section counts are
  asserted to match.

The synthetic ELF builder in the test file emits the same CIE/FDE encodings the captured
nodes use (`zR`, `pcrel|sdata4`), so the survey path is exercised without LFS data.

## Results and limitations

- Node #94: 121,299 FDE-bounded functions; 1,536 (1.27%) establish an rbp frame pointer in
  the prologue window, 28,712 (23.67%) open with `push rbp` as a general-register save, and
  91,044 (75.06%) open with neither. Node #115: 135,313 functions; 1,142 (0.84%), 37,633
  (27.81%) and 96,531 (71.34%). Visor: 11,028 functions; 657 (5.96%), 2,261 (20.50%) and
  8,103 (73.48%).
- Limitations: the census is a 16-byte byte-pattern window, not a disassembly; a frame
  pointer established after the window, and code without unwind data, are both outside the
  denominator. An FDE extent is an unwind range, not a validated function boundary. The
  census resolves the RE-002 `frame_pointers` field only; it establishes no other build
  flag, no component ownership, and no equivalence.
- No progress gate is requested.

Next question: do the 1,536 (#94) frame-pointer-establishing functions cluster in linked
C++ or jemalloc code, and does the same clustering hold for #115?
