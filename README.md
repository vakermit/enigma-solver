# Enigma Solver

Multi-approach Enigma machine solver: IoC brute force, GPU-accelerated Bombe-style crib dragging, and Z3 SAT/SMT constraint solving.

## Implementations

### Python (`python/`)

Reference IoC solver using [py-enigma](https://pypi.org/project/py-enigma/), plus a Z3 SMT crib solver.

```bash
cd python
./install.sh              # creates venv, installs py-enigma
source .venv/bin/activate
python esolve.py --help
python esolve.py "CIPHERTEXT" --lang english --beam 50
python esolve.py "CIPHERTEXT" --navy --lang german    # M3 Navy (rotors I-VIII)
python esolve.py "CIPHERTEXT" --m4 --lang german      # M4 four-rotor Navy
```

**Z3 SAT Solver** — constraint-based crib attack using Z3's SMT solver:
```bash
pip install z3-solver
python crib_sat.py -f unknown_message.txt -c ../cribs/german_naval.txt --m4
python crib_sat.py -f unknown_message.txt -w WETTER --navy    # single crib
```

For each rotor combination, encodes the Enigma as Z3 constraints with starting positions, ring settings, and plugboard as variables. Z3 uses constraint propagation — not brute force — making short messages an advantage (smaller formula).

Windows:
```powershell
cd python
.\install.ps1
.venv\Scripts\Activate.ps1
python esolve.py "CIPHERTEXT" --lang english --beam 50
```

### C++ (`cpp/`)

High-performance solvers with multi-threaded CPU and Metal GPU backends.

```bash
cd cpp
make                    # CPU IoC solver (multi-threaded)
make gpu                # Metal GPU IoC solver (macOS only)
make crib               # Metal GPU crib solver (macOS only)
```

**IoC Solver** — brute-force with beam search:
```bash
./solver --help
./solver -f ../python/unknown_message.txt -l german --navy --plugboard
./solver -f ../python/unknown_message.txt -l german --m4 --plugboard
```

**GPU IoC Solver** — same algorithm on Metal compute shaders:
```bash
./solver_gpu -f ../python/unknown_message.txt -l german --navy --m4 --plugboard
```

**GPU Crib Solver** — hybrid GPU IoC filter + CPU Bombe-style crib analysis:
```bash
./crib_solver -f ../python/unknown_message.txt -c ../cribs/german_naval.txt --m4
./crib_solver -f ../python/unknown_message.txt -c ../cribs/german_naval.txt --m4 -b 10000 --min-len 8
```

Phase 1 uses the GPU to compute IoC across all rotor/position configurations, keeping the top N (beam). Phase 2 runs a Bombe-style plugboard consistency check on CPU for each surviving config against every crib at every valid position. Results ranked by crib length + bigram score + IoC.

All C++ solvers support `--navy` (rotors I-VIII, 336 combos) and `--m4` (M4 four-rotor with Beta/Gamma + thin reflectors). The M4 GPU solver uses a composite reflector technique — folding the Greek rotor + thin reflector into an effective reflector — to reuse the 3-rotor GPU kernel for all 104 M4 variants.

### Rust (`rust/`)

Zero-dependency IoC solver using `std::thread` for parallelism.

```bash
cd rust
cargo build --release
./target/release/enigma-solver --help
./target/release/enigma-solver -l english "CIPHERTEXT"
```

### Go (`go/`)

Standard library only, goroutines for parallelism.

```bash
cd go
go build -o solver .
./solver -l english "CIPHERTEXT"
```

## Crib Dictionaries (`cribs/`)

Pre-built word lists for crib-dragging attacks, in Enigma-encoded format:

- `german_naval.txt` — Kriegsmarine: weather reports, position reports, U-boat terminology, numbers
- `german_army.txt` — Wehrmacht/Luftwaffe: military units, orders, Army encoding (Q=CH, FRAGE=?)
- `english.txt` — English-language messages (for testing)

Navy encoding: `X`=space/period, `Y`=comma, `UD`=?. Army encoding: `X`=period, `ZZ`=comma, `Q`=CH, `FRAGE`=?. Numbers always spelled out (EINS, ZWO, DREI...).

## How It Works

### IoC Brute Force (`esolve.py`, `solver`, `solver_gpu`)

1. **Brute force** all rotor permutations × start positions, scoring each decryption by Index of Coincidence
2. **Ring refinement** — top N candidates tested across 26 settings per ring position
3. **Plugboard hill climbing** (optional, `--plugboard`) — iteratively adds letter-pair swaps that improve bigram score
4. **Results ranked** by bigram frequency match against English or German

### Bombe Crib Solver (`crib_solver`)

1. **GPU Phase 1**: IoC filter — compute IoC for all configurations, keep top N (beam width)
2. **CPU Phase 2**: for each surviving config × each crib at each valid position:
   - Pre-filter by self-encryption (Enigma never encrypts a letter to itself)
   - Compute the full rotor permutation R_i at each crib step
   - Run Bombe-style check: try all 26 plugboard assumptions for the first crib letter, propagate through the crib, check for contradictions
   - If consistent: a Bombe "stop" — potential solution
3. **Ranking**: stops sorted by combined crib length + bigram score + raw IoC

### Z3 SAT Solver (`crib_sat.py`)

For each rotor combination, builds a Z3 formula encoding the full Enigma encryption path with starting positions, ring settings, and plugboard as variables. The crib provides equality constraints that Z3 resolves via SMT constraint propagation. Best suited for situations with known plaintext or partial key information.

### Fitness Metrics

- **Index of Coincidence (IoC)**: measures letter distribution deviation from random. English ~0.067, German ~0.076, random ~0.038. Plugboard-invariant — works without knowing the plugboard. Unreliable below ~100 characters.
- **Bigram frequency**: scores consecutive letter pairs against language tables. More discriminating than IoC for final ranking and plugboard recovery.

## Limitations

- Short messages (<100 chars) degrade IoC accuracy — the statistical signal is marginal and may not distinguish correct settings from noise
- Crib attacks require guessing the plaintext content; short cribs (<6 chars) produce excessive false positives
- The M4 four-rotor naval Enigma has a much larger key space (×26 for the Greek rotor position, ×2 for thin reflectors) — full M4 search is ~26× slower than 3-rotor
- Messages that were historically "never deciphered" typically had no available cribs and were too short for statistical attacks

## Performance

Tested on Apple M1 Max, 88-character ciphertext (Army, 60 combos):

| Implementation | Phase 1 Time | Speedup |
|----------------|-------------|---------|
| Python | 153 s | 1x |
| Go (goroutines) | 545 ms | 280x |
| Rust (std::thread) | 324 ms | 472x |
| C++ CPU (10 threads) | 218 ms | 700x |
| C++ Metal GPU (32 cores) | 87 ms | 1,760x |

M4 Navy (336 combos × 26 Greek positions × 2 thin reflectors = 104 passes):

| Solver | Time | Configurations |
|--------|------|----------------|
| C++ GPU IoC (`solver_gpu --m4`) | 20 s | 613M |
| C++ GPU Crib (`crib_solver --m4`) | 56 s | 613M IoC + 7.5M Bombe checks |
| Python IoC (`esolve.py --m4`) | ~65 min | 23.6M (4th rotor fixed at A) |

## Files

```
python/
  esolve.py          # IoC brute-force solver
  crib_sat.py        # Z3 SMT crib solver
  enigma_test.py     # encrypt/decrypt demo
  unknown_message.txt # unsolved WW2 naval Enigma message (72 chars)
  efind.py           # early experiment
  requirements.txt
  install.sh / install.ps1

cpp/
  enigma.h           # header-only Enigma (8 rotors, Greek, thin reflectors, double notch)
  solver.cpp         # multi-threaded CPU IoC solver
  metal_solver.mm    # Metal GPU IoC solver
  crib_solver.mm     # Metal GPU + CPU Bombe crib solver
  Makefile

cribs/
  german_naval.txt   # Kriegsmarine crib dictionary
  german_army.txt    # Wehrmacht / Luftwaffe crib dictionary
  english.txt        # English crib dictionary

rust/
  src/main.rs
  Cargo.toml

go/
  main.go
  go.mod

docs/
  enigma_history.md     # the machine
  cryptanalysis_math.md # IoC, bigrams, the Bombe, hill climbing, keyspace
  bletchley_park.md     # the place and its people
  german_procedures.md  # networks, key sheets, message formats
  message_formatting.md # 250-char limit, IoC thresholds, punctuation encoding
```

## Background Reading

- [The Enigma Machine](docs/enigma_history.md)
- [The Mathematics of Breaking Enigma](docs/cryptanalysis_math.md)
- [Bletchley Park: The Place and Its People](docs/bletchley_park.md)
- [German Enigma Procedures and Variations](docs/german_procedures.md)
- [Message Length and Formatting](docs/message_formatting.md)
