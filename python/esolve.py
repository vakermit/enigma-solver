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

IOC_TARGET = {'english': 0.0667, 'german': 0.0762, 'random': 0.0385}

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


def solve(ct, beam_width, reflector, lang, rotors):
    bigrams = GERMAN_BIGRAMS if lang == 'german' else ENGLISH_BIGRAMS
    rotor_combos = list(itertools.permutations(rotors, 3))
    total_trials = 0

    # Phase 1: brute-force all rotor combos × all 26³ start positions
    n_trials = len(rotor_combos) * 26 * 26 * 26
    print(f'\n--- Phase 1: {len(rotor_combos)} rotor combos × 17,576 positions = {n_trials:,} trials ---')
    candidates = []
    for ci, combo in enumerate(rotor_combos):
        rs = ' '.join(combo)
        for l in ALPHABET:
            for m in ALPHABET:
                for r in ALPHABET:
                    start = l + m + r
                    pt = decrypt(ct, rs, reflector, [0, 0, 0], start)
                    ioc = calc_ioc(pt)
                    candidates.append((ioc, rs, start, [0, 0, 0]))
        if (ci + 1) % 10 == 0:
            print(f'  ... {ci + 1}/{len(rotor_combos)} rotor combos done')
    total_trials += len(candidates)
    candidates.sort(reverse=True)
    refined = candidates[:beam_width]
    print(f'  Best IoC: {refined[0][0]:.6f}  ({refined[0][1]} @ {refined[0][2]})')

    # Phase 4-6: ring setting refinement (left, middle, right)
    for idx, name in enumerate(['left', 'middle', 'right']):
        print(f'\n--- Phase {idx + 4}: top {beam_width} × 26 {name} ring settings ---')
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
    bigrams = GERMAN_BIGRAMS if lang == 'german' else ENGLISH_BIGRAMS
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
    parser.add_argument('-l', '--lang', choices=['english', 'german'], default='german',
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
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            ct = f.read().strip()
    elif args.ciphertext:
        ct = args.ciphertext
    else:
        parser.error('Provide ciphertext as argument or via -f/--file')

    ct = ''.join(c for c in ct.upper() if c.isalpha())

    if len(ct) < 20:
        print(f'WARNING: ciphertext is only {len(ct)} chars — IoC will be unreliable', file=sys.stderr)

    rotors = ROTORS_NAVY if (args.navy or args.m4) else ROTORS_ARMY
    mode = 'M4' if args.m4 else ('Navy M3' if args.navy else 'Army/Luftwaffe')

    print(f'Ciphertext ({len(ct)} chars): {ct[:60]}{"..." if len(ct) > 60 else ""}')
    print(f'Language: {args.lang} | Beam: {args.beam} | Reflector: {args.reflector} | Mode: {mode}')
    print(f'Target IoC: {IOC_TARGET[args.lang]:.4f} (random: {IOC_TARGET["random"]:.4f})')
    n_combos = len(list(itertools.permutations(rotors, 3)))
    print(f'Rotors: {" ".join(rotors)} ({n_combos} permutations)')

    reflectors = ['B', 'C'] if args.reflector == 'both' else [args.reflector]
    bigrams = GERMAN_BIGRAMS if args.lang == 'german' else ENGLISH_BIGRAMS

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
            results, trials = solve(ct, args.beam, ref, args.lang, rotors)
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
        preview = c.plaintext[:35]
        plug = '*' if c.plugboard else ' '
        print(f'{i + 1:>3}{plug} {c.rotors:<12} {c.reflector:>3} {ring_str:<10} {c.start:<6} '
              f'{c.ioc:>7.5f} {c.bigram_score:>7.2f}  {preview}')

    if args.plugboard and all_results and all_results[0].plugboard:
        print(f'\nBest plugboard: {all_results[0].plugboard}')
        print(f'Full plaintext: {all_results[0].plaintext}')

    if args.output and all_results:
        save_settings(all_results[0], args.output)


if __name__ == '__main__':
    main()
