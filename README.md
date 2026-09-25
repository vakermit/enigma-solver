# Enigma Solver

Ciphertext-only Enigma machine solver using Index of Coincidence (IoC) scoring and bigram frequency analysis.

Given only ciphertext, recovers rotor selection, rotor positions, ring settings, and (optionally) plugboard pairings through brute-force search with beam pruning and hill climbing.

## Implementations

### Python (`python/`)

Reference implementation using [py-enigma](https://pypi.org/project/py-enigma/). Slower but easy to read and modify.

```bash
cd python
./install.sh              # creates venv, installs py-enigma
source .venv/bin/activate
python esolve.py --help
python esolve.py "CIPHERTEXT" --lang english --beam 50
python esolve.py "CIPHERTEXT" --navy --lang german    # M3 Navy (rotors I-VIII, 336 combos)
python esolve.py "CIPHERTEXT" --m4 --lang german      # M4 four-rotor Navy
```

Windows:
```powershell
cd python
.\install.ps1
.venv\Scripts\Activate.ps1
python esolve.py "CIPHERTEXT" --lang english --beam 50
```

### C++ (`cpp/`)

High-performance implementation with multi-threaded CPU and Metal GPU backends. ~700x faster than Python (CPU), ~1,760x faster (GPU).

```bash
cd cpp
make                    # CPU solver (multi-threaded)
make gpu                # Metal GPU solver (macOS only)
./solver --help
./solver "CIPHERTEXT" -l english -b 50
./solver_gpu "CIPHERTEXT" -l english -b 50
```

The GPU solver requires macOS with Metal support. It compiles the compute shader at runtime — no Xcode installation needed, just the Command Line Tools.

## How It Works

1. **Brute force** all 60 rotor permutations x 17,576 start positions (1,054,560 configurations), scoring each decryption by IoC
2. **Ring refinement** — top N candidates tested across 26 settings per ring position (left, middle, right)
3. **Plugboard hill climbing** (optional, `-p` flag) — iteratively adds letter-pair swaps that improve bigram score
4. **Results ranked** by bigram frequency match against English or German

### Fitness Metrics

- **Index of Coincidence (IoC)**: measures how far a text's letter distribution is from random. English ~0.067, German ~0.076, random ~0.038. Used for rotor/position search.
- **Bigram frequency**: scores consecutive letter pairs against language-specific frequency tables. More discriminating than IoC — used for final ranking and plugboard recovery.

## Limitations

- Short messages degrade IoC accuracy: <50 chars is unreliable, 50-100 marginal, 150+ reliable. Historical messages averaged 200-250 chars. The solver warns at each threshold. See [docs/message_formatting.md](docs/message_formatting.md) for the statistical derivation.
- Heavy plugboard usage (10 pairs) on short messages produces ambiguous results — historically, the Allies needed cribs (known plaintext) for these cases
- Python supports Army (I-V), Navy M3 (I-VIII), and M4 (Beta/Gamma + I-VIII + thin reflectors); C++ currently supports Army only

## Performance

Tested on Apple M1 Max, 88-character ciphertext:

| Implementation | Phase 1 Time | Speedup |
|----------------|-------------|---------|
| Python | 153 s | 1x |
| C++ CPU (10 threads) | 218 ms | 700x |
| C++ Metal GPU (32 cores) | 87 ms | 1,760x |

## Files

```
python/
  esolve.py          # main solver
  enigma_test.py     # encrypt/decrypt demo
  efind.py           # early experiment
  requirements.txt
  install.sh         # setup for macOS/Linux
  install.ps1        # setup for Windows

cpp/
  enigma.h           # header-only Enigma machine
  solver.cpp         # multi-threaded CPU solver
  metal_solver.mm    # Metal GPU solver (macOS)
  Makefile

docs/
  enigma_history.md     # the machine: origins, military adoption, mechanical evolution
  cryptanalysis_math.md # IoC, bigrams, Banburismus, the Bombe, hill climbing, keyspace
  bletchley_park.md     # the place, the Poles, Turing, Welchman, Knox, the women, Colossus
  german_procedures.md  # networks, key sheets, message formats, Navy Kenngruppen, variants
  message_formatting.md # 250-char limit, IoC vs length thresholds, punctuation/number encoding
```

## Background Reading

- [The Enigma Machine](docs/enigma_history.md) — Scherbius's 1918 patent through the M4 four-rotor variant. The mechanical evolution, the operational procedures that created vulnerabilities, and the key dates in cryptanalysis from Rejewski's 1932 breakthrough to the M4 blackout and recovery.
- [The Mathematics of Breaking Enigma](docs/cryptanalysis_math.md) — Friedman's Index of Coincidence, bigram frequency analysis, Turing's Banburismus and the Bombe, hill climbing for plugboard recovery, and the combinatorics of the 159-quintillion-configuration keyspace.
- [Bletchley Park: The Place and Its People](docs/bletchley_park.md) — Station X, the Polish mathematicians who broke Enigma five years before the British, Turing, Welchman, Knox, the 7,500 women who made up 75% of the workforce, Tommy Flowers and Colossus, and the three decades of silence that followed.
- [German Enigma Procedures and Variations](docs/german_procedures.md) — The named radio networks (Red, Dolphin, Shark), daily key sheets, Army vs. Navy indicator systems, the Kenngruppen system, Short Weather Cipher and Short Signal Book, machine variants from the Enigma I through the M4, and the procedural failures that gave the codebreakers their openings.
- [Message Length and Formatting](docs/message_formatting.md) — The 250-character limit and why it existed, the statistical thresholds where IoC becomes reliable (with the math), punctuation and number substitutions (FRAGE, ZWO, KLAM), and why the historical message length sits at the boundary where ciphertext-only attacks become effective.
