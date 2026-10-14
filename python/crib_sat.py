#!/usr/bin/env python3
"""
Z3 SMT Enigma crib solver.

For each rotor combination (1,344 for M4), encodes the Enigma machine as
Z3 constraints with starting positions, ring settings, and plugboard as
variables. Z3 searches the full key space via constraint propagation —
not brute force — which makes short messages an ADVANTAGE (smaller formula).

Usage:
    python3 crib_sat.py -f ../python/unknown_message.txt -c ../cribs/german_naval.txt --m4
    python3 crib_sat.py -f ../python/unknown_message.txt -w WETTER --m4
"""

import z3
import sys
import time
import argparse
import itertools

WIRING = [
    [4,10,12,5,11,6,3,16,21,25,13,19,14,22,24,7,23,20,18,15,0,8,1,17,2,9],
    [0,9,3,10,18,8,17,20,23,1,11,7,22,19,12,2,16,6,25,13,15,24,5,21,14,4],
    [1,3,5,7,9,11,2,15,17,19,23,21,25,13,24,4,8,22,6,0,10,12,20,18,16,14],
    [4,18,14,21,15,25,9,0,24,16,20,8,17,7,23,11,13,5,19,6,10,3,2,12,22,1],
    [21,25,1,17,6,8,19,24,20,15,18,3,13,7,11,23,0,22,12,9,16,14,5,4,2,10],
    [9,15,6,21,14,20,12,5,24,16,1,4,13,7,25,17,3,10,0,18,23,11,8,2,19,22],
    [13,25,9,7,6,17,2,23,12,24,18,22,1,14,20,5,0,8,21,11,15,4,10,16,3,19],
    [5,10,16,7,19,11,23,14,2,1,9,18,15,3,25,17,0,12,4,22,13,8,20,24,6,21],
]
INV_WIRING = [[0]*26 for _ in range(8)]
for r in range(8):
    for i in range(26):
        INV_WIRING[r][WIRING[r][i]] = i

GREEK_WIRING = [
    [11,4,24,9,21,2,13,8,23,22,15,1,16,12,3,17,19,0,10,25,6,5,20,7,14,18],
    [5,18,14,10,0,13,20,4,17,7,12,1,19,8,24,2,22,11,16,15,25,23,21,6,9,3],
]
INV_GREEK = [[0]*26 for _ in range(2)]
for r in range(2):
    for i in range(26):
        INV_GREEK[r][GREEK_WIRING[r][i]] = i

REFLECTOR_B_THIN = [4,13,10,16,0,20,24,22,9,8,2,14,15,1,11,12,3,23,25,21,5,19,7,17,6,18]
REFLECTOR_C_THIN = [17,3,14,1,9,13,19,10,21,4,7,12,11,5,2,22,25,0,23,6,24,8,15,18,20,16]

NOTCH_A = [16, 4, 21, 9, 25, 25, 25, 25]
NOTCH_B = [-1, -1, -1, -1, -1, 12, 12, 12]

ROTOR_NAMES = ['I','II','III','IV','V','VI','VII','VIII']
GREEK_NAMES = ['Beta', 'Gamma']
THIN_REF_NAMES = ['B-Thin', 'C-Thin']


def z3_table(table, idx):
    """Constant table lookup: table[idx] where idx is Z3 Int."""
    r = z3.IntVal(table[0])
    for k in range(1, 26):
        r = z3.If(idx == k, z3.IntVal(table[k]), r)
    return r


def z3_plug(pvars, idx):
    """Variable array lookup: pvars[idx] where pvars is list of Z3 Ints."""
    r = pvars[0]
    for k in range(1, 26):
        r = z3.If(idx == k, pvars[k], r)
    return r


def mod26(expr):
    return expr % 26


def rotor_fwd(table, sig, pos):
    return mod26(z3_table(table, mod26(sig + pos)) - pos + 26)


def rotor_rev(table, sig, pos):
    return mod26(z3_table(table, mod26(sig + pos)) - pos + 26)


def solve_combo(ct, crib, crib_pos, lr, mr, rr, reflector,
                greek_idx=-1, greek_ref=None, timeout_ms=10000):
    s = z3.Solver()
    s.set("timeout", timeout_ms)

    sl = z3.Int('sl')
    sm = z3.Int('sm')
    sr = z3.Int('sr')
    rl = z3.Int('rl')
    rm = z3.Int('rm')
    rr_v = z3.Int('rr_v')

    for v in [sl, sm, sr, rl, rm, rr_v]:
        s.add(v >= 0, v < 26)

    if greek_idx >= 0:
        sg = z3.Int('sg')
        s.add(sg >= 0, sg < 26)

    P = [z3.Int(f'P{i}') for i in range(26)]
    for i in range(26):
        s.add(P[i] >= 0, P[i] < 26)
        s.add(z3_plug(P, P[i]) == i)

    s.add(z3.Sum([z3.If(P[i] != i, 1, 0) for i in range(26)]) <= 20)

    # Notch positions
    nm_a = mod26(z3.IntVal(NOTCH_A[mr]) - rm + 26)
    nr_a = mod26(z3.IntVal(NOTCH_A[rr]) - rr_v + 26)
    nm_b = mod26(z3.IntVal(NOTCH_B[mr]) - rm + 26) if NOTCH_B[mr] >= 0 else None
    nr_b = mod26(z3.IntVal(NOTCH_B[rr]) - rr_v + 26) if NOTCH_B[rr] >= 0 else None

    # Unroll stepping
    n_steps = crib_pos + len(crib)
    pl = [None] * (n_steps + 1)
    pm = [None] * (n_steps + 1)
    pr = [None] * (n_steps + 1)

    pl[0] = mod26(sl - rl + 26)
    pm[0] = mod26(sm - rm + 26)
    pr[0] = mod26(sr - rr_v + 26)

    for i in range(n_steps):
        m_notch = pm[i] == nm_a
        if nm_b is not None:
            m_notch = z3.Or(m_notch, pm[i] == nm_b)

        r_notch = pr[i] == nr_a
        if nr_b is not None:
            r_notch = z3.Or(r_notch, pr[i] == nr_b)

        pr[i+1] = mod26(pr[i] + 1)
        pm[i+1] = z3.If(z3.Or(r_notch, m_notch), mod26(pm[i] + 1), pm[i])
        pl[i+1] = z3.If(m_notch, mod26(pl[i] + 1), pl[i])

    fwd_r_t = WIRING[rr]
    fwd_m_t = WIRING[mr]
    fwd_l_t = WIRING[lr]
    rev_r_t = INV_WIRING[rr]
    rev_m_t = INV_WIRING[mr]
    rev_l_t = INV_WIRING[lr]

    for j in range(len(crib)):
        step = crib_pos + j
        p_l = pl[step + 1]
        p_m = pm[step + 1]
        p_r = pr[step + 1]

        pt_ch = crib[j]
        ct_ch = ct[crib_pos + j]

        sig = P[pt_ch]
        sig = rotor_fwd(fwd_r_t, sig, p_r)
        sig = rotor_fwd(fwd_m_t, sig, p_m)
        sig = rotor_fwd(fwd_l_t, sig, p_l)

        if greek_idx >= 0:
            gp = mod26(sg + 26)
            sig = rotor_fwd(GREEK_WIRING[greek_idx], sig, gp)
            sig = z3_table(greek_ref, sig)
            sig = rotor_rev(INV_GREEK[greek_idx], sig, gp)
        else:
            sig = z3_table(reflector, sig)

        sig = rotor_rev(rev_l_t, sig, p_l)
        sig = rotor_rev(rev_m_t, sig, p_m)
        sig = rotor_rev(rev_r_t, sig, p_r)
        sig = z3_plug(P, sig)

        s.add(sig == ct_ch)

    result = s.check()
    if result == z3.sat:
        m = s.model()
        sol = {
            'start': [m[sl].as_long(), m[sm].as_long(), m[sr].as_long()],
            'rings': [m[rl].as_long(), m[rm].as_long(), m[rr_v].as_long()],
            'plug': [m[P[i]].as_long() for i in range(26)],
        }
        if greek_idx >= 0:
            sol['greek_pos'] = m[sg].as_long()
        return sol
    return None


def load_cribs(path, min_len=6):
    words = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line[0] == '#':
                continue
            nums = [ord(c) - 65 for c in line.upper() if 'A' <= c <= 'Z']
            if min_len <= len(nums) <= 16:
                words.append((line, nums))
    return words


def self_encrypt_filter(crib_nums, ct, ct_len):
    positions = []
    for p in range(ct_len - len(crib_nums) + 1):
        if not any(crib_nums[i] == ct[p + i] for i in range(len(crib_nums))):
            positions.append(p)
    return positions


def decrypt_with_settings(ct, lr, mr, rr, rings, start, plug, reflector,
                          greek_idx=-1, greek_pos=0, greek_ref_wiring=None):
    from enigma.machine import EnigmaMachine
    if greek_idx >= 0:
        rotors_str = f"{GREEK_NAMES[greek_idx]} {ROTOR_NAMES[lr]} {ROTOR_NAMES[mr]} {ROTOR_NAMES[rr]}"
        ref_name = 'B-Thin' if greek_ref_wiring is REFLECTOR_B_THIN else 'C-Thin'
        ring_list = [0, rings[0], rings[1], rings[2]]
        start_str = chr(65+greek_pos) + chr(65+start[0]) + chr(65+start[1]) + chr(65+start[2])
    else:
        rotors_str = f"{ROTOR_NAMES[lr]} {ROTOR_NAMES[mr]} {ROTOR_NAMES[rr]}"
        ref_name = 'B'
        ring_list = list(rings)
        start_str = chr(65+start[0]) + chr(65+start[1]) + chr(65+start[2])

    plug_pairs = []
    seen = set()
    for i in range(26):
        if plug[i] > i and i not in seen:
            plug_pairs.append(chr(65+i) + chr(65+plug[i]))
            seen.add(i)
            seen.add(plug[i])
    plug_str = ' '.join(plug_pairs)

    machine = EnigmaMachine.from_key_sheet(
        rotors=rotors_str, reflector=ref_name,
        ring_settings=ring_list, plugboard_settings=plug_str)
    machine.set_display(start_str)
    ct_str = ''.join(chr(65 + c) for c in ct)
    return machine.process_text(ct_str), plug_str, start_str


def main():
    parser = argparse.ArgumentParser(description='Z3 SMT Enigma crib solver')
    parser.add_argument('-f', '--file', required=True, help='Ciphertext file')
    parser.add_argument('-c', '--cribs', help='Crib dictionary file')
    parser.add_argument('-w', '--crib', help='Single crib word')
    parser.add_argument('--navy', action='store_true', help='Navy: rotors I-VIII')
    parser.add_argument('--m4', action='store_true', help='M4 mode')
    parser.add_argument('--min-len', type=int, default=6, help='Min crib length (default: 6)')
    parser.add_argument('--timeout', type=int, default=10000, help='Z3 timeout per solve (ms)')
    parser.add_argument('--max-results', type=int, default=10, help='Stop after N solutions')
    args = parser.parse_args()

    if args.m4:
        args.navy = True

    with open(args.file) as f:
        raw = f.read().strip()
    ct = [ord(c) - 65 for c in raw.upper() if 'A' <= c <= 'Z']
    ct_len = len(ct)
    ct_str = ''.join(chr(65+c) for c in ct)

    words = []
    if args.crib:
        nums = [ord(c) - 65 for c in args.crib.upper() if 'A' <= c <= 'Z']
        if len(nums) >= 3:
            words.append((args.crib.upper(), nums))
    if args.cribs:
        words.extend(load_cribs(args.cribs, args.min_len))

    if not words:
        print("Error: no cribs provided", file=sys.stderr)
        return 1

    entries = []
    for text, nums in words:
        positions = self_encrypt_filter(nums, ct, ct_len)
        for p in positions:
            entries.append((text, nums, p))

    num_rotors = 8 if args.navy else 5
    combos = list(itertools.permutations(range(num_rotors), 3))

    if args.m4:
        configs = [(g, tr) for g in range(2) for tr in range(2)]
    else:
        configs = [(-1, -1)]

    print(f'Ciphertext ({ct_len} chars): {ct_str[:60]}{"..." if ct_len > 60 else ""}')
    print(f'Mode: {"M4" if args.m4 else "Navy" if args.navy else "Army"} | '
          f'Rotors: {num_rotors} ({len(combos)} combos)')
    print(f'Cribs: {len(words)} words, {len(entries)} valid (word, position) entries')
    print(f'Configs: {len(configs)} × {len(combos)} = {len(configs) * len(combos)} rotor setups')
    print(f'Z3 timeout: {args.timeout}ms per solve')

    # Sort entries by crib length descending (longest cribs = strongest constraints)
    entries.sort(key=lambda e: -len(e[1]))

    t0 = time.time()
    total_solves = 0
    solutions = []
    solved_combos = set()

    for gi, (greek_idx, thin_ref_idx) in enumerate(configs):
        if greek_idx >= 0:
            thin_ref = REFLECTOR_B_THIN if thin_ref_idx == 0 else REFLECTOR_C_THIN
            config_name = f'{GREEK_NAMES[greek_idx]} + {THIN_REF_NAMES[thin_ref_idx]}'
        else:
            thin_ref = None
            config_name = 'Reflector B'

        print(f'\n--- {config_name}: {len(combos)} combos ---')

        for ci, (lr, mr, rr) in enumerate(combos):
            combo_key = (greek_idx, thin_ref_idx, lr, mr, rr)
            if combo_key in solved_combos:
                continue

            for text, crib_nums, pos in entries:
                total_solves += 1

                sol = solve_combo(
                    ct, crib_nums, pos, lr, mr, rr,
                    reflector=thin_ref if thin_ref else REFLECTOR_B_THIN,
                    greek_idx=greek_idx,
                    greek_ref=thin_ref,
                    timeout_ms=args.timeout,
                )

                if sol:
                    solved_combos.add(combo_key)
                    elapsed = time.time() - t0
                    rotor_str = ' '.join(ROTOR_NAMES[x] for x in [lr, mr, rr])
                    if greek_idx >= 0:
                        rotor_str = f'{GREEK_NAMES[greek_idx]} {rotor_str}'
                    start_str = ''.join(chr(65+x) for x in sol['start'])
                    if greek_idx >= 0:
                        start_str = chr(65 + sol['greek_pos']) + start_str
                    ring_str = ','.join(str(x) for x in sol['rings'])

                    plug_pairs = []
                    for a in range(26):
                        b = sol['plug'][a]
                        if b > a:
                            plug_pairs.append(chr(65+a) + chr(65+b))
                    plug_str = ' '.join(plug_pairs) or '(none)'

                    print(f'\n*** SAT! Crib "{text}" at pos {pos} ({elapsed:.1f}s, {total_solves} solves) ***')
                    print(f'  Rotors: {rotor_str}')
                    if greek_idx >= 0:
                        print(f'  Reflector: {THIN_REF_NAMES[thin_ref_idx]}')
                    print(f'  Start: {start_str} | Rings: {ring_str}')
                    print(f'  Plugboard: {plug_str}')

                    try:
                        pt, ps, ss = decrypt_with_settings(
                            ct, lr, mr, rr, sol['rings'], sol['start'], sol['plug'],
                            thin_ref, greek_idx, sol.get('greek_pos', 0), thin_ref)
                        print(f'  Plaintext: {pt}')
                    except Exception as e:
                        print(f'  (py-enigma decrypt failed: {e})')

                    solutions.append(sol)
                    if len(solutions) >= args.max_results:
                        print(f'\nReached {args.max_results} solutions, stopping.')
                        break

            if len(solutions) >= args.max_results:
                break

            if (ci + 1) % 50 == 0:
                elapsed = time.time() - t0
                rate = total_solves / elapsed if elapsed > 0 else 0
                print(f'  {ci+1}/{len(combos)} combos ({total_solves} solves, '
                      f'{rate:.0f}/s, {elapsed:.1f}s, {len(solutions)} found)')

        if len(solutions) >= args.max_results:
            break

    elapsed = time.time() - t0
    print(f'\n{"="*80}')
    print(f'Done: {total_solves} Z3 solves in {elapsed:.1f}s '
          f'({total_solves/elapsed:.0f}/s)')
    print(f'Solutions found: {len(solutions)}')
    print(f'{"="*80}')


if __name__ == '__main__':
    main()
