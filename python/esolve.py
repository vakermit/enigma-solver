#!/usr/bin/env python3
"""
esolve.py - Enigma ciphertext-only solver.

Beam search through rotor/position/ring combinations scored by IoC,
then optional plugboard hill climbing scored by bigram frequency.

Usage:
    uv run --with py-enigma esolve.py "CIPHERTEXT"
    uv run --with py-enigma esolve.py -f ciphertext.txt --lang english
    uv run --with py-enigma esolve.py "CIPHERTEXT" --plugboard -o settings.json
"""

import argparse
import itertools
import json
import sys
import time
from dataclasses import dataclass, asdict
from enigma.machine import EnigmaMachine

ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
ROTORS_ARMY = ['I', 'II', 'III', 'IV', 'V']
ROTORS_NAVY = ['I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII']
M4_FOURTH = ['Beta', 'Gamma']
THIN_REFLECTORS = ['B-Thin', 'C-Thin']

IOC_TARGET = {
    'english': 0.0667, 'german': 0.0762, 'spanish': 0.0766,
    'french': 0.0746, 'dutch': 0.0798, 'portuguese': 0.0745,
    'polish': 0.0651, 'russian': 0.0670, 'random': 0.0385,
}

ENGLISH_BIGRAMS = {
    'TH': 35.6, 'HE': 30.7, 'IN': 24.3, 'ER': 20.5, 'AN': 19.9,
    'RE': 18.5, 'ON': 17.6, 'AT': 14.9, 'EN': 14.5, 'ND': 13.5,
    'TI': 13.4, 'ES': 13.4, 'OR': 12.8, 'TE': 12.0, 'OF': 11.4,
    'ED': 11.2, 'IS': 11.1, 'IT': 11.0, 'AL': 10.9, 'AR': 10.7,
    'ST': 10.5, 'TO': 10.5, 'NT': 10.4, 'NG': 9.5, 'SE': 9.3,
    'HA': 9.3, 'AS': 8.7, 'OU': 8.7, 'IO': 8.3, 'LE': 8.3,
    'VE': 8.3, 'CO': 7.9, 'ME': 7.9, 'DE': 7.6, 'HI': 7.6,
    'RI': 7.3, 'RO': 7.3, 'IC': 7.0, 'NE': 6.9, 'EA': 6.9,
    'RA': 6.9, 'CE': 6.5, 'LI': 6.2, 'CH': 5.9, 'LL': 5.8,
    'BE': 5.8, 'MA': 5.7, 'SI': 5.5, 'OM': 5.5, 'UR': 5.4,
}

GERMAN_BIGRAMS = {
    'EN': 39.5, 'ER': 37.5, 'CH': 27.5, 'DE': 20.2, 'EI': 19.8,
    'ND': 18.5, 'TE': 17.6, 'IN': 17.5, 'IE': 16.5, 'GE': 15.5,
    'UN': 14.3, 'ST': 13.8, 'ES': 13.2, 'AN': 12.7, 'RE': 12.5,
    'HE': 12.0, 'BE': 11.5, 'AU': 10.8, 'NE': 10.5, 'SC': 10.2,
    'SE': 9.8, 'DI': 9.5, 'NG': 9.2, 'IC': 8.8, 'DA': 8.5,
    'EM': 8.2, 'EL': 8.0, 'VE': 7.8, 'HA': 7.5, 'AL': 7.2,
    'IT': 7.0, 'IS': 6.8, 'SI': 6.5, 'SO': 6.2, 'RA': 6.0,
    'SS': 5.8, 'AB': 5.5, 'RI': 5.3, 'FE': 5.0, 'MI': 4.8,
}

SPANISH_BIGRAMS = {
    'DE': 25.5, 'EN': 23.8, 'ES': 21.5, 'EL': 16.2, 'LA': 15.0,
    'OS': 14.5, 'AR': 14.0, 'ON': 13.5, 'ER': 13.0, 'AN': 12.8,
    'AS': 12.5, 'AL': 12.0, 'RE': 11.8, 'SE': 11.5, 'CI': 11.0,
    'RA': 10.8, 'CO': 10.5, 'TE': 10.2, 'ST': 9.8, 'OR': 9.5,
    'AD': 9.2, 'IO': 9.0, 'TA': 8.8, 'NE': 8.5, 'NT': 8.2,
    'IE': 8.0, 'DO': 7.8, 'UE': 7.5, 'NO': 7.2, 'AC': 7.0,
    'MA': 6.8, 'EC': 6.5, 'TO': 6.2, 'LE': 6.0, 'PA': 5.8,
    'IN': 5.5, 'LO': 5.2, 'PO': 5.0, 'DA': 4.8, 'ME': 4.5,
}

FRENCH_BIGRAMS = {
    'ES': 27.5, 'EN': 25.0, 'DE': 24.0, 'LE': 20.5, 'RE': 19.0,
    'NT': 17.5, 'ON': 16.8, 'ER': 16.0, 'AN': 15.5, 'TE': 15.0,
    'ET': 14.5, 'EL': 13.8, 'SE': 13.2, 'AI': 12.8, 'OU': 12.5,
    'LA': 12.0, 'IT': 11.5, 'NS': 11.0, 'ED': 10.8, 'NE': 10.5,
    'ME': 10.2, 'CE': 9.8, 'QU': 9.5, 'IO': 9.2, 'IE': 9.0,
    'AT': 8.8, 'EM': 8.5, 'CO': 8.2, 'OR': 8.0, 'IS': 7.8,
    'AR': 7.5, 'LI': 7.2, 'RI': 7.0, 'PA': 6.8, 'TI': 6.5,
    'UR': 6.2, 'AL': 6.0, 'IL': 5.8, 'UN': 5.5, 'ST': 5.2,
}

DUTCH_BIGRAMS = {
    'EN': 38.0, 'DE': 27.5, 'ER': 24.0, 'AN': 18.5, 'ET': 17.0,
    'IN': 16.5, 'HE': 16.0, 'TE': 15.5, 'EE': 14.5, 'GE': 14.0,
    'ND': 13.5, 'VE': 13.0, 'IJ': 12.5, 'AA': 12.0, 'ST': 11.5,
    'OO': 11.0, 'OR': 10.5, 'EL': 10.0, 'RE': 9.5, 'AR': 9.0,
    'IE': 8.5, 'AL': 8.0, 'DA': 7.8, 'ON': 7.5, 'NG': 7.2,
    'CH': 7.0, 'VA': 6.8, 'IS': 6.5, 'IT': 6.2, 'ES': 6.0,
    'BE': 5.8, 'ME': 5.5, 'DI': 5.2, 'SE': 5.0, 'AT': 4.8,
    'TO': 4.5, 'WA': 4.2, 'LE': 4.0, 'OE': 3.8, 'NI': 3.5,
}

PORTUGUESE_BIGRAMS = {
    'DE': 25.0, 'OS': 19.0, 'AS': 18.5, 'RA': 16.0, 'DO': 15.5,
    'ES': 15.0, 'AR': 14.5, 'EN': 14.0, 'DA': 13.5, 'ER': 13.0,
    'CO': 12.5, 'AD': 12.0, 'RE': 11.5, 'AN': 11.0, 'NT': 10.5,
    'EM': 10.0, 'OR': 9.5, 'TE': 9.0, 'AL': 8.5, 'SE': 8.2,
    'ON': 8.0, 'MA': 7.8, 'TO': 7.5, 'AC': 7.2, 'IO': 7.0,
    'TA': 6.8, 'NO': 6.5, 'ST': 6.2, 'EI': 6.0, 'ME': 5.8,
    'PA': 5.5, 'CA': 5.2, 'PO': 5.0, 'RI': 4.8, 'OU': 4.5,
    'IN': 4.2, 'EL': 4.0, 'IA': 3.8, 'IS': 3.5, 'SI': 3.2,
}

POLISH_BIGRAMS = {
    'IE': 25.0, 'NI': 20.5, 'CZ': 18.5, 'RZ': 17.0, 'PO': 16.5,
    'NA': 16.0, 'ST': 15.5, 'OW': 14.5, 'AN': 14.0, 'PR': 13.5,
    'ZE': 13.0, 'WI': 12.5, 'RA': 12.0, 'KO': 11.5, 'DO': 11.0,
    'MI': 10.5, 'SI': 10.0, 'NE': 9.5, 'GO': 9.0, 'OD': 8.5,
    'RO': 8.0, 'TO': 7.8, 'JE': 7.5, 'IA': 7.2, 'NO': 7.0,
    'WA': 6.8, 'SZ': 6.5, 'IC': 6.2, 'AL': 6.0, 'TA': 5.8,
    'EN': 5.5, 'OS': 5.2, 'KA': 5.0, 'IN': 4.8, 'EG': 4.5,
    'LI': 4.2, 'IS': 4.0, 'SK': 3.8, 'OR': 3.5, 'PI': 3.2,
}

RUSSIAN_BIGRAMS = {
    'ST': 25.0, 'NA': 22.5, 'EN': 20.0, 'NO': 18.5, 'TO': 17.5,
    'OV': 16.5, 'NI': 15.5, 'RA': 15.0, 'KO': 14.5, 'PO': 14.0,
    'OR': 13.5, 'GO': 13.0, 'OB': 12.5, 'ER': 12.0, 'NE': 11.5,
    'PR': 11.0, 'RE': 10.5, 'TA': 10.0, 'RO': 9.5, 'ET': 9.0,
    'AN': 8.5, 'LI': 8.0, 'OS': 7.5, 'OT': 7.0, 'LE': 6.8,
    'DA': 6.5, 'OL': 6.2, 'SK': 6.0, 'DE': 5.8, 'VE': 5.5,
    'MI': 5.2, 'TI': 5.0, 'SE': 4.8, 'IS': 4.5, 'AL': 4.2,
    'IN': 4.0, 'EL': 3.8, 'ON': 3.5, 'RI': 3.2, 'ES': 3.0,
}


FMT_ALIASES = {
    'army': 'army', 'luftwaffe': 'army', 'airforce': 'army',
    'navy': 'navy', 'kriegsmarine': 'navy',
    'raw': 'raw',
}

NUM_TO_WORD = {
    '0': 'NULL', '1': 'EINS', '2': 'ZWO', '3': 'DREI', '4': 'VIER',
    '5': 'FUENF', '6': 'SECHS', '7': 'SIEBEN', '8': 'ACHT', '9': 'NEUN',
}

WORD_TO_NUM = {v: k for k, v in NUM_TO_WORD.items()}


def encode_enigma(text, fmt='army'):
    """Convert human-readable text to Enigma-formatted uppercase alpha."""
    if fmt == 'raw':
        return ''.join(c for c in text.upper() if c.isalpha())
    text = text.upper()
    for digit, word in NUM_TO_WORD.items():
        text = text.replace(digit, word)
    if fmt == 'navy':
        text = text.replace('?', 'UD')
        text = text.replace(',', 'Y')
    else:
        text = text.replace('?', 'FRAGE')
        text = text.replace(',', 'ZZ')
        text = text.replace('CH', 'Q')
    text = text.replace(':', 'XX')
    text = text.replace('(', 'KLAM')
    text = text.replace(')', 'KLAM')
    text = text.replace('.', 'X')
    text = text.replace(' ', '')
    return ''.join(c for c in text if c.isalpha())


def decode_enigma(text, fmt='army'):
    """Reverse Enigma formatting to human-readable text.

    Only decodes unambiguous substitutions. Q→CH and Y→comma are NOT
    reversed because Q and Y are common letters and decoding them
    would corrupt legitimate uses.
    """
    if fmt == 'raw':
        return text
    # Multi-char substitutions first (longest match wins)
    for word, digit in sorted(WORD_TO_NUM.items(), key=lambda x: -len(x[0])):
        text = text.replace(word, digit)
    if fmt == 'navy':
        text = text.replace('UD', '?')
    else:
        text = text.replace('FRAGE', '?')
        text = text.replace('FRAQ', '?')
    text = text.replace('KLAM', '()')
    if fmt != 'navy':
        text = text.replace('ZZ', ', ')
    text = text.replace('XX', ': ')
    text = text.replace('X', ' ')
    return text


def group_text(text, size=5):
    """Format text into N-letter groups."""
    return ' '.join(text[i:i + size] for i in range(0, len(text), size))


@dataclass
class Candidate:
    rotors: str
    reflector: str
    rings: list
    start: str
    plugboard: str
    ioc: float
    bigram_score: float
    plaintext: str


def calc_ioc(text):
    n = len(text)
    if n <= 1:
        return 0.0
    freq = [0] * 26
    for c in text:
        if 'A' <= c <= 'Z':
            freq[ord(c) - 65] += 1
    total = sum(freq)
    if total <= 1:
        return 0.0
    return sum(f * (f - 1) for f in freq) / (total * (total - 1))


def calc_bigram_score(text, bigrams):
    if len(text) < 2:
        return 0.0
    score = sum(bigrams.get(text[i:i+2], 0.0) for i in range(len(text) - 1))
    return score / (len(text) - 1)


def decrypt(ct, rotors, reflector, rings, start, plugboard=''):
    machine = EnigmaMachine.from_key_sheet(
        rotors=rotors,
        reflector=reflector,
        ring_settings=rings,
        plugboard_settings=plugboard,
    )
    machine.set_display(start)
    return machine.process_text(ct)


def beam_phase(ct, candidates, position_idx, label, beam_width):
    """Expand one rotor position across the beam. Returns sorted top-N."""
    expanded = []
    seen = set()
    for (ioc, rs, start, rings) in candidates:
        for letter in ALPHABET:
            s = list(start)
            s[position_idx] = letter
            s = ''.join(s)
            key = (rs, s, tuple(rings))
            if key in seen:
                continue
            seen.add(key)
            pt = decrypt(ct, rs, 'B', rings, s)  # reflector passed separately
            expanded.append((calc_ioc(pt), rs, s, rings))

    expanded.sort(reverse=True)
    top = expanded[:beam_width]
    print(f'  {label}: best IoC {top[0][0]:.6f}  ({top[0][1]} @ {top[0][2]} rings={top[0][3]})')
    return top


def ring_phase(ct, candidates, ring_idx, label, beam_width, reflector):
    """Expand one ring setting across the beam."""
    expanded = []
    seen = set()
    for (ioc, rs, start, rings) in candidates:
        for r in range(0, 26):
            new_rings = list(rings)
            new_rings[ring_idx] = r
            key = (rs, start, tuple(new_rings))
            if key in seen:
                continue
            seen.add(key)
            pt = decrypt(ct, rs, reflector, new_rings, start)
            expanded.append((calc_ioc(pt), rs, start, new_rings))

    expanded.sort(reverse=True)
    top = expanded[:beam_width]
    print(f'  {label}: best IoC {top[0][0]:.6f}  (rings={top[0][3]})')
    return top


BIGRAM_TABLES = {
    'english': ENGLISH_BIGRAMS, 'german': GERMAN_BIGRAMS,
    'spanish': SPANISH_BIGRAMS, 'french': FRENCH_BIGRAMS,
    'dutch': DUTCH_BIGRAMS, 'portuguese': PORTUGUESE_BIGRAMS,
    'polish': POLISH_BIGRAMS, 'russian': RUSSIAN_BIGRAMS,
}


def solve(ct, beam_width, reflector, lang, rotors,
          quick_pass=False, quick_pass_pct=25, separate_rings=False):
    bigrams = BIGRAM_TABLES.get(lang, ENGLISH_BIGRAMS)
    rotor_combos = list(itertools.permutations(rotors, 3))
    total_trials = 0

    # Quick pass: full 26^3 per combo, but score by top-100 average IoC
    # to rank combos. Keep top N%, then only refine rings on those.
    # Runs the same brute force but collects per-combo stats for pruning.
    if quick_pass:
        keep_n = max(1, int(len(rotor_combos) * quick_pass_pct / 100))
        n_qp = len(rotor_combos) * 17576
        print(f'\n--- Quick pass + search: {len(rotor_combos)} combos × 17,576 = {n_qp:,} trials ---')
        print(f'  Will keep top {quick_pass_pct}% ({keep_n} combos) for ring refinement')
        combo_data = []
        for ci, combo in enumerate(rotor_combos):
            rs = ' '.join(combo)
            combo_results = []
            for l in ALPHABET:
                for m in ALPHABET:
                    for r in ALPHABET:
                        pt = decrypt(ct, rs, reflector, [0, 0, 0], l + m + r)
                        ioc = calc_ioc(pt)
                        combo_results.append((ioc, rs, l + m + r, [0, 0, 0]))
            combo_results.sort(reverse=True)
            peak_ioc = combo_results[0][0]
            combo_data.append((peak_ioc, combo_results))
            if (ci + 1) % 10 == 0:
                print(f'  ... {ci + 1}/{len(rotor_combos)} combos done')
        total_trials += n_qp

        combo_data.sort(reverse=True)
        surviving = combo_data[:keep_n]
        best_combo_rs = surviving[0][1][0][1]
        worst_kept_rs = surviving[-1][1][0][1]
        print(f'  Best combo: {best_combo_rs} (peak IoC: {combo_data[0][0]:.6f})')
        print(f'  Cutoff: {worst_kept_rs} (peak IoC: {surviving[-1][0]:.6f})')
        print(f'  Eliminated {len(rotor_combos) - keep_n} combos from ring refinement')

        # Merge top candidates from surviving combos
        all_cands = []
        for _, results in surviving:
            all_cands.extend(results[:beam_width])
        all_cands.sort(reverse=True)
        refined = all_cands[:beam_width]
        print(f'  Best IoC: {refined[0][0]:.6f}  ({refined[0][1]} @ {refined[0][2]})')

    elif separate_rings:
        # Two-phase beam search: left×mid first, then expand right
        intermediate_beam = beam_width * 5
        n_trials = len(rotor_combos) * 676
        print(f'\n--- Phase 1a: {len(rotor_combos)} combos × 676 left×mid = {n_trials:,} trials ---')
        print(f'  Intermediate beam: {intermediate_beam}')
        candidates = []
        for ci, combo in enumerate(rotor_combos):
            rs = ' '.join(combo)
            for left in ALPHABET:
                for mid in ALPHABET:
                    pt = decrypt(ct, rs, reflector, [0, 0, 0], left + mid + 'A')
                    ioc = calc_ioc(pt)
                    candidates.append((ioc, rs, left + mid + 'A', [0, 0, 0]))
            if (ci + 1) % 20 == 0:
                print(f'  ... {ci + 1}/{len(rotor_combos)} combos done')
        total_trials += len(candidates)
        candidates.sort(reverse=True)
        candidates = candidates[:intermediate_beam]
        print(f'  Best IoC: {candidates[0][0]:.6f}  ({candidates[0][1]} @ {candidates[0][2]})')

        print(f'\n--- Phase 1b: top {intermediate_beam} × 26 right positions ---')
        expanded = []
        seen = set()
        for (_, rs, start, rings) in candidates:
            for right in ALPHABET:
                s = start[0] + start[1] + right
                key = (rs, s, tuple(rings))
                if key in seen:
                    continue
                seen.add(key)
                pt = decrypt(ct, rs, reflector, rings, s)
                expanded.append((calc_ioc(pt), rs, s, rings))
        total_trials += len(expanded)
        expanded.sort(reverse=True)
        refined = expanded[:beam_width]
        print(f'  Best IoC: {refined[0][0]:.6f}  ({refined[0][1]} @ {refined[0][2]})')

    else:
        # Full brute force: all combos × all 26^3 positions
        n_trials = len(rotor_combos) * 17576
        print(f'\n--- Phase 1: {len(rotor_combos)} combos × 17,576 positions = {n_trials:,} trials ---')
        candidates = []
        for ci, combo in enumerate(rotor_combos):
            rs = ' '.join(combo)
            for l in ALPHABET:
                for m in ALPHABET:
                    for r in ALPHABET:
                        pt = decrypt(ct, rs, reflector, [0, 0, 0], l + m + r)
                        ioc = calc_ioc(pt)
                        candidates.append((ioc, rs, l + m + r, [0, 0, 0]))
            if (ci + 1) % 10 == 0:
                print(f'  ... {ci + 1}/{len(rotor_combos)} rotor combos done')
        total_trials += len(candidates)
        candidates.sort(reverse=True)
        refined = candidates[:beam_width]
        print(f'  Best IoC: {refined[0][0]:.6f}  ({refined[0][1]} @ {refined[0][2]})')

    # Ring setting refinement (left, middle, right)
    for idx, name in enumerate(['left', 'middle', 'right']):
        print(f'\n--- Ring refinement: top {beam_width} × 26 {name} ring settings ---')
        new_candidates = []
        seen = set()
        for (_, rs, start, rings) in refined:
            for r in range(0, 26):
                new_rings = list(rings)
                new_rings[idx] = r
                key = (rs, start, tuple(new_rings))
                if key in seen:
                    continue
                seen.add(key)
                pt = decrypt(ct, rs, reflector, new_rings, start)
                new_candidates.append((calc_ioc(pt), rs, start, new_rings))
        total_trials += len(new_candidates)
        new_candidates.sort(reverse=True)
        refined = new_candidates[:beam_width]
        print(f'  Best IoC: {refined[0][0]:.6f}  (rings={refined[0][3]})')

    # Score final candidates with bigrams for ranking
    results = []
    for (ioc, rs, start, rings) in refined:
        pt = decrypt(ct, rs, reflector, rings, start)
        bg = calc_bigram_score(pt, bigrams)
        results.append(Candidate(
            rotors=rs, reflector=reflector, rings=rings,
            start=start, plugboard='', ioc=ioc,
            bigram_score=bg, plaintext=pt,
        ))
    results.sort(key=lambda c: c.bigram_score, reverse=True)
    return results, total_trials


def solve_m4(ct, beam_width, lang, rotors):
    """M4 four-rotor solver. Tests Beta/Gamma × thin reflectors, then 3-rotor combos."""
    bigrams = BIGRAM_TABLES.get(lang, ENGLISH_BIGRAMS)
    rotor_combos = list(itertools.permutations(rotors, 3))
    total_trials = 0

    all_candidates = []
    for fourth in M4_FOURTH:
        for thin_ref in THIN_REFLECTORS:
            n_trials = len(rotor_combos) * 26 * 26 * 26
            print(f'\n--- M4: {fourth} + {thin_ref} — {len(rotor_combos)} combos × 17,576 positions = {n_trials:,} ---')
            candidates = []
            for ci, combo in enumerate(rotor_combos):
                rs = f'{fourth} {" ".join(combo)}'
                for l_pos in ALPHABET:
                    for m_pos in ALPHABET:
                        for r_pos in ALPHABET:
                            start = 'A' + l_pos + m_pos + r_pos
                            machine = EnigmaMachine.from_key_sheet(
                                rotors=rs,
                                reflector=thin_ref,
                                ring_settings=[0, 0, 0, 0],
                                plugboard_settings='',
                            )
                            machine.set_display(start)
                            pt = machine.process_text(ct)
                            ioc = calc_ioc(pt)
                            candidates.append((ioc, rs, start, [0, 0, 0, 0], thin_ref))
                if (ci + 1) % 20 == 0:
                    print(f'  ... {ci + 1}/{len(rotor_combos)} combos done')
            total_trials += len(candidates)
            candidates.sort(reverse=True)
            best = candidates[:beam_width]
            print(f'  Best IoC: {best[0][0]:.6f}  ({best[0][1]} @ {best[0][2]})')
            all_candidates.extend(best)

    # Also try all 26 positions for the 4th rotor on top candidates
    print(f'\n--- M4 Phase 2: top {beam_width} × 26 fourth-rotor positions ---')
    all_candidates.sort(reverse=True)
    top = all_candidates[:beam_width]
    expanded = []
    seen = set()
    for (_, rs, start, rings, ref) in top:
        for fourth_pos in ALPHABET:
            s = fourth_pos + start[1:]
            key = (rs, s, tuple(rings), ref)
            if key in seen:
                continue
            seen.add(key)
            machine = EnigmaMachine.from_key_sheet(
                rotors=rs, reflector=ref,
                ring_settings=rings, plugboard_settings='',
            )
            machine.set_display(s)
            pt = machine.process_text(ct)
            ioc = calc_ioc(pt)
            expanded.append((ioc, rs, s, rings, ref))
    total_trials += len(expanded)
    expanded.sort(reverse=True)
    refined = expanded[:beam_width]
    print(f'  Best IoC: {refined[0][0]:.6f}  ({refined[0][1]} @ {refined[0][2]})')

    # Ring refinement for positions 1-3 (skip 4th rotor ring, it doesn't step)
    for idx, name in enumerate(['left', 'middle', 'right']):
        ring_idx = idx + 1
        print(f'\n--- M4 Ring: top {beam_width} × 26 {name} ring settings ---')
        new_candidates = []
        seen = set()
        for (_, rs, start, rings, ref) in refined:
            for r in range(0, 26):
                new_rings = list(rings)
                new_rings[ring_idx] = r
                key = (rs, start, tuple(new_rings), ref)
                if key in seen:
                    continue
                seen.add(key)
                machine = EnigmaMachine.from_key_sheet(
                    rotors=rs, reflector=ref,
                    ring_settings=new_rings, plugboard_settings='',
                )
                machine.set_display(start)
                pt = machine.process_text(ct)
                ioc = calc_ioc(pt)
                new_candidates.append((ioc, rs, start, new_rings, ref))
        total_trials += len(new_candidates)
        new_candidates.sort(reverse=True)
        refined = new_candidates[:beam_width]
        print(f'  Best IoC: {refined[0][0]:.6f}  (rings={refined[0][3]})')

    results = []
    for (ioc, rs, start, rings, ref) in refined:
        machine = EnigmaMachine.from_key_sheet(
            rotors=rs, reflector=ref,
            ring_settings=rings, plugboard_settings='',
        )
        machine.set_display(start)
        pt = machine.process_text(ct)
        bg = calc_bigram_score(pt, bigrams)
        results.append(Candidate(
            rotors=rs, reflector=ref, rings=rings,
            start=start, plugboard='', ioc=ioc,
            bigram_score=bg, plaintext=pt,
        ))
    results.sort(key=lambda c: c.bigram_score, reverse=True)
    return results, total_trials


def hill_climb_plugboard(ct, candidate, bigrams, max_pairs=13):
    """Add plugboard pairs one at a time, keeping each that improves bigram score."""
    best = candidate
    pt = decrypt(ct, best.rotors, best.reflector, best.rings, best.start, best.plugboard)
    best_score = calc_bigram_score(pt, bigrams)
    used = set()
    pairs_found = 0

    while pairs_found < max_pairs:
        improved = False
        best_pair = None
        best_new_score = best_score

        available = [c for c in ALPHABET if c not in used]
        for i, a in enumerate(available):
            for b in available[i + 1:]:
                test_plug = (best.plugboard + ' ' + a + b).strip()
                pt = decrypt(ct, best.rotors, best.reflector, best.rings, best.start, test_plug)
                score = calc_bigram_score(pt, bigrams)
                if score > best_new_score:
                    best_new_score = score
                    best_pair = a + b
                    improved = True

        if not improved:
            break

        used.add(best_pair[0])
        used.add(best_pair[1])
        best.plugboard = (best.plugboard + ' ' + best_pair).strip()
        best_score = best_new_score
        pairs_found += 1
        print(f'  +{best_pair} (bigram: {best_score:.2f}, pairs: {pairs_found})')

    best.plaintext = decrypt(ct, best.rotors, best.reflector, best.rings, best.start, best.plugboard)
    best.bigram_score = best_score
    best.ioc = calc_ioc(best.plaintext)
    return best


def save_settings(candidate, filepath):
    settings = {
        'rotors': candidate.rotors,
        'reflector': candidate.reflector,
        'ring_settings': candidate.rings,
        'start_position': candidate.start,
        'plugboard': candidate.plugboard,
        'ioc': round(candidate.ioc, 6),
        'bigram_score': round(candidate.bigram_score, 4),
        'plaintext': candidate.plaintext,
    }
    with open(filepath, 'w') as f:
        json.dump(settings, f, indent=2)
    print(f'\nSettings saved to {filepath}')


def main():
    parser = argparse.ArgumentParser(
        description='Enigma ciphertext-only solver using beam search + IoC',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('ciphertext', nargs='?', help='Ciphertext to solve')
    parser.add_argument('-f', '--file', help='Read ciphertext from file')
    parser.add_argument('-l', '--lang', default='german',
                        choices=['english', 'german', 'spanish', 'french',
                                 'dutch', 'portuguese', 'polish', 'russian'],
                        help='Target language (default: german)')
    parser.add_argument('-b', '--beam', type=int, default=50,
                        help='Beam width / top-N kept per phase (default: 50)')
    parser.add_argument('-r', '--reflector', choices=['B', 'C', 'both'], default='B',
                        help='Reflector to try (default: B)')
    parser.add_argument('-p', '--plugboard', action='store_true',
                        help='Run plugboard hill climbing on best result')
    parser.add_argument('-o', '--output', metavar='FILE',
                        help='Save best settings to JSON file')
    parser.add_argument('-n', '--show', type=int, default=10,
                        help='Number of results to display (default: 10)')
    parser.add_argument('--navy', action='store_true',
                        help='Navy M3 mode: rotors I-VIII (336 combos instead of 60)')
    parser.add_argument('--m4', action='store_true',
                        help='Navy M4 mode: 4 rotors (Beta/Gamma + I-VIII + thin reflectors)')
    parser.add_argument('--quick-pass', action='store_true',
                        help='Quick pre-filter: eliminate low-scoring rotor combos before full search')
    parser.add_argument('--quick-pass-pct', type=int, default=25,
                        help='Percentage of rotor combos to keep in quick pass (default: 25)')
    parser.add_argument('--test-separate-rings', action='store_true',
                        help='Test rotor positions one at a time (left→mid→right beam search)')
    parser.add_argument('--fmt', choices=list(FMT_ALIASES.keys()), default=None,
                        help='Punctuation standard: army (default), luftwaffe, airforce, '
                             'navy, kriegsmarine, raw. --navy auto-selects navy.')
    parser.add_argument('--pretty-input', action=argparse.BooleanOptionalAction, default=True,
                        help='Display ciphertext in letter groups (default: on)')
    parser.add_argument('--pretty-output', action=argparse.BooleanOptionalAction, default=True,
                        help='Decode plaintext substitutions (FRAGE→?, X→space, etc.) (default: on)')
    parser.add_argument('--raw', action='store_true',
                        help='Shorthand for --fmt raw --no-pretty-input --no-pretty-output')
    args = parser.parse_args()

    # Resolve formatting standard
    if args.raw:
        punct_fmt = 'raw'
        args.pretty_input = False
        args.pretty_output = False
    elif args.fmt:
        punct_fmt = FMT_ALIASES[args.fmt]
    elif args.navy or args.m4:
        punct_fmt = 'navy'
    else:
        punct_fmt = 'army'

    group_size = 4 if punct_fmt == 'navy' else 5

    if args.file:
        with open(args.file) as f:
            ct_raw = f.read().strip()
    elif args.ciphertext:
        ct_raw = args.ciphertext
    else:
        parser.error('Provide ciphertext as argument or via -f/--file')

    has_nonalpha = any(not c.isalpha() and not c.isspace() for c in ct_raw)
    ct = encode_enigma(ct_raw, punct_fmt) if has_nonalpha else ''.join(
        c for c in ct_raw.upper() if c.isalpha()
    )
    if has_nonalpha and punct_fmt != 'raw':
        print(f'Input converted ({punct_fmt} standard): {ct[:60]}{"..." if len(ct) > 60 else ""}')

    if len(ct) < 50:
        print(f'WARNING: {len(ct)} chars is very short — IoC confidence intervals overlap '
              f'heavily with random. Results unreliable. Historical messages were 200-250 chars.',
              file=sys.stderr)
    elif len(ct) < 100:
        print(f'NOTE: {len(ct)} chars is short. IoC separation from random is marginal. '
              f'Results may miss correct settings.', file=sys.stderr)
    elif len(ct) < 150:
        print(f'NOTE: {len(ct)} chars — workable but below the 200-250 char historical norm.',
              file=sys.stderr)

    rotors = ROTORS_NAVY if (args.navy or args.m4) else ROTORS_ARMY
    mode = 'M4' if args.m4 else ('Navy M3' if args.navy else 'Army/Luftwaffe')

    ct_display = group_text(ct, group_size) if args.pretty_input else ct
    print(f'Ciphertext ({len(ct)} chars): {ct_display[:72]}{"..." if len(ct_display) > 72 else ""}')
    fmt_label = f'{punct_fmt}' + (' (pretty)' if args.pretty_output else '')
    print(f'Language: {args.lang} | Beam: {args.beam} | Reflector: {args.reflector} | Mode: {mode} | Fmt: {fmt_label}')
    print(f'Target IoC: {IOC_TARGET[args.lang]:.4f} (random: {IOC_TARGET["random"]:.4f})')
    n_combos = len(list(itertools.permutations(rotors, 3)))
    print(f'Rotors: {" ".join(rotors)} ({n_combos} permutations)')

    reflectors = ['B', 'C'] if args.reflector == 'both' else [args.reflector]
    bigrams = BIGRAM_TABLES.get(args.lang, ENGLISH_BIGRAMS)

    all_results = []
    total_trials = 0
    t0 = time.time()

    if args.m4:
        results, trials = solve_m4(ct, args.beam, args.lang, rotors)
        all_results.extend(results)
        total_trials += trials
    else:
        for ref in reflectors:
            if len(reflectors) > 1:
                print(f'\n{"=" * 50}\n  Reflector {ref}\n{"=" * 50}')
            results, trials = solve(ct, args.beam, ref, args.lang, rotors,
                                    quick_pass=args.quick_pass,
                                    quick_pass_pct=args.quick_pass_pct,
                                    separate_rings=args.test_separate_rings)
            all_results.extend(results)
            total_trials += trials

    all_results.sort(key=lambda c: c.bigram_score, reverse=True)
    elapsed = time.time() - t0

    if args.plugboard and all_results:
        print(f'\n--- Plugboard hill climbing ---')
        all_results[0] = hill_climb_plugboard(ct, all_results[0], bigrams)

    print(f'\n{"=" * 90}')
    print(f'Done: {total_trials:,} decryptions in {elapsed:.1f}s')
    print(f'{"=" * 90}')

    show_n = min(args.show, len(all_results))
    print(f'\nTop {show_n} results:')
    print(f'{"#":>3}  {"Rotors":<12} {"Ref":>3} {"Rings":<10} {"Start":<6} {"IoC":>7} {"Bigram":>7}  Plaintext')
    print('-' * 90)

    for i, c in enumerate(all_results[:show_n]):
        ring_str = f'{c.rings[0]:>2},{c.rings[1]:>2},{c.rings[2]:>2}'
        raw_preview = c.plaintext[:35]
        preview = decode_enigma(raw_preview, punct_fmt) if args.pretty_output else raw_preview
        plug = '*' if c.plugboard else ' '
        print(f'{i + 1:>3}{plug} {c.rotors:<12} {c.reflector:>3} {ring_str:<10} {c.start:<6} '
              f'{c.ioc:>7.5f} {c.bigram_score:>7.2f}  {preview}')

    if args.plugboard and all_results and all_results[0].plugboard:
        print(f'\nBest plugboard: {all_results[0].plugboard}')
        full_pt = all_results[0].plaintext
        if args.pretty_output:
            print(f'Full plaintext (raw):     {full_pt}')
            print(f'Full plaintext (decoded): {decode_enigma(full_pt, punct_fmt)}')
        else:
            print(f'Full plaintext: {full_pt}')
    elif all_results and args.pretty_output:
        full_pt = all_results[0].plaintext
        decoded = decode_enigma(full_pt, punct_fmt)
        if decoded != full_pt:
            print(f'\nBest plaintext (decoded): {decoded}')

    if args.output and all_results:
        save_settings(all_results[0], args.output)


if __name__ == '__main__':
    main()
