use std::env;
use std::fs;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

const WIRING: [[i32; 26]; 5] = [
    [4,10,12,5,11,6,3,16,21,25,13,19,14,22,24,7,23,20,18,15,0,8,1,17,2,9],
    [0,9,3,10,18,8,17,20,23,1,11,7,22,19,12,2,16,6,25,13,15,24,5,21,14,4],
    [1,3,5,7,9,11,2,15,17,19,23,21,25,13,24,4,8,22,6,0,10,12,20,18,16,14],
    [4,18,14,21,15,25,9,0,24,16,20,8,17,7,23,11,13,5,19,6,10,3,2,12,22,1],
    [21,25,1,17,6,8,19,24,20,15,18,3,13,7,11,23,0,22,12,9,16,14,5,4,2,10],
];
const NOTCH: [i32; 5] = [16, 4, 21, 9, 25];
const REFLECTOR_B: [i32; 26] = [24,17,20,7,16,18,11,3,15,23,13,6,14,10,12,8,4,1,5,25,2,22,21,9,0,19];
const ROTOR_NAMES: [&str; 5] = ["I", "II", "III", "IV", "V"];

static mut INV_WIRING: [[i32; 26]; 5] = [[0; 26]; 5];

#[derive(Copy, Clone)]
struct Combo { r: [usize; 3] }

static mut COMBOS: [Combo; 60] = {
    let mut arr = [Combo { r: [0; 3] }; 60];
    let mut i = 0;
    while i < 60 { arr[i] = Combo { r: [0, 0, 0] }; i += 1; }
    arr
};
static mut NUM_COMBOS: usize = 0;

fn init() {
    unsafe {
        for r in 0..5 {
            for i in 0..26 {
                INV_WIRING[r][WIRING[r][i] as usize] = i as i32;
            }
        }
        let mut n = 0;
        for a in 0..5 {
            for b in 0..5 {
                if b == a { continue; }
                for c in 0..5 {
                    if c == a || c == b { continue; }
                    COMBOS[n] = Combo { r: [a, b, c] };
                    n += 1;
                }
            }
        }
        NUM_COMBOS = n;
    }
}

fn m26(x: i32) -> i32 { ((x % 26) + 26) % 26 }

struct Machine {
    fwd: [[i32; 26]; 3],
    rev: [[i32; 26]; 3],
    reflector: [i32; 26],
    plugboard: [i32; 26],
    pos: [i32; 3],
    notch_pos: [i32; 3],
}

impl Machine {
    fn setup(lr: usize, mr: usize, rr: usize,
             l_ring: i32, m_ring: i32, r_ring: i32,
             l_start: i32, m_start: i32, r_start: i32,
             refl: &[i32; 26]) -> Self {
        let mut m = Machine {
            fwd: [WIRING[lr], WIRING[mr], WIRING[rr]],
            rev: unsafe { [INV_WIRING[lr], INV_WIRING[mr], INV_WIRING[rr]] },
            reflector: *refl,
            plugboard: [0; 26],
            pos: [m26(l_start - l_ring), m26(m_start - m_ring), m26(r_start - r_ring)],
            notch_pos: [m26(NOTCH[lr] - l_ring), m26(NOTCH[mr] - m_ring), m26(NOTCH[rr] - r_ring)],
        };
        for i in 0..26 { m.plugboard[i] = i as i32; }
        m
    }

    fn step(&mut self) {
        let mid_notch = self.pos[1] == self.notch_pos[1];
        let right_notch = self.pos[2] == self.notch_pos[2];
        self.pos[2] = (self.pos[2] + 1) % 26;
        if right_notch || mid_notch { self.pos[1] = (self.pos[1] + 1) % 26; }
        if mid_notch { self.pos[0] = (self.pos[0] + 1) % 26; }
    }

    fn encrypt_char(&mut self, c: i32) -> i32 {
        self.step();
        let mut sig = self.plugboard[c as usize];
        for r in (0..3).rev() {
            let pin = (sig + self.pos[r]) % 26;
            sig = m26(self.fwd[r][pin as usize] - self.pos[r]);
        }
        sig = self.reflector[sig as usize];
        for r in 0..3 {
            let contact = (sig + self.pos[r]) % 26;
            sig = m26(self.rev[r][contact as usize] - self.pos[r]);
        }
        self.plugboard[sig as usize]
    }

    fn process(&mut self, input: &[i32], output: &mut [i32]) {
        for i in 0..input.len() {
            output[i] = self.encrypt_char(input[i]);
        }
    }

    fn set_plugboard(&mut self, pairs: &str) {
        for i in 0..26 { self.plugboard[i] = i as i32; }
        let mut chars = pairs.chars().filter(|c| c.is_ascii_uppercase());
        while let (Some(a), Some(b)) = (chars.next(), chars.next()) {
            let ai = (a as i32) - 65;
            let bi = (b as i32) - 65;
            self.plugboard[ai as usize] = bi;
            self.plugboard[bi as usize] = ai;
            chars.next(); // skip space
        }
    }
}

fn calc_ioc(text: &[i32]) -> f64 {
    let n = text.len();
    if n <= 1 { return 0.0; }
    let mut freq = [0i32; 26];
    for &c in text { freq[c as usize] += 1; }
    let sum: i32 = freq.iter().map(|&f| f * (f - 1)).sum();
    sum as f64 / (n as f64 * (n as f64 - 1.0))
}

static EN_BG: [(usize, usize, f32); 50] = [
    (19,7,35.6),(7,4,30.7),(8,13,24.3),(4,17,20.5),(0,13,19.9),
    (17,4,18.5),(14,13,17.6),(0,19,14.9),(4,13,14.5),(13,3,13.5),
    (19,8,13.4),(4,18,13.4),(14,17,12.8),(19,4,12.0),(14,5,11.4),
    (4,3,11.2),(8,18,11.1),(8,19,11.0),(0,11,10.9),(0,17,10.7),
    (18,19,10.5),(19,14,10.5),(13,19,10.4),(13,6,9.5),(18,4,9.3),
    (7,0,9.3),(0,18,8.7),(14,20,8.7),(8,14,8.3),(11,4,8.3),
    (21,4,8.3),(2,14,7.9),(12,4,7.9),(3,4,7.6),(7,8,7.6),
    (17,8,7.3),(17,14,7.3),(8,2,7.0),(13,4,6.9),(4,0,6.9),
    (17,0,6.9),(2,4,6.5),(11,8,6.2),(2,7,5.9),(11,11,5.8),
    (1,4,5.8),(12,0,5.7),(18,8,5.5),(14,12,5.5),(20,17,5.4),
];

static DE_BG: [(usize, usize, f32); 40] = [
    (4,13,39.5),(4,17,37.5),(2,7,27.5),(3,4,20.2),(4,8,19.8),
    (13,3,18.5),(19,4,17.6),(8,13,17.5),(8,4,16.5),(6,4,15.5),
    (20,13,14.3),(18,19,13.8),(4,18,13.2),(0,13,12.7),(17,4,12.5),
    (7,4,12.0),(1,4,11.5),(0,20,10.8),(13,4,10.5),(18,2,10.2),
    (18,4,9.8),(3,8,9.5),(13,6,9.2),(8,2,8.8),(3,0,8.5),
    (4,12,8.2),(4,11,8.0),(21,4,7.8),(7,0,7.5),(0,11,7.2),
    (8,19,7.0),(8,18,6.8),(18,8,6.5),(18,14,6.2),(17,0,6.0),
    (18,18,5.8),(0,1,5.5),(17,8,5.3),(5,4,5.0),(12,8,4.8),
];

fn build_bigram_table(entries: &[(usize, usize, f32)]) -> [[f32; 26]; 26] {
    let mut t = [[0.0f32; 26]; 26];
    for &(a, b, f) in entries { t[a][b] = f; }
    t
}

fn calc_bigram(text: &[i32], table: &[[f32; 26]; 26]) -> f64 {
    if text.len() < 2 { return 0.0; }
    let sum: f32 = (0..text.len()-1)
        .map(|i| table[text[i] as usize][text[i+1] as usize])
        .sum();
    sum as f64 / (text.len() - 1) as f64
}

#[derive(Clone)]
struct Candidate {
    ioc: f64,
    bigram: f64,
    combo_idx: usize,
    lp: i32, mp: i32, rp: i32,
    lr: i32, mr: i32, rr: i32,
    plugboard: String,
    plaintext: Vec<i32>,
}

impl Candidate {
    fn new() -> Self {
        Candidate { ioc: 0.0, bigram: 0.0, combo_idx: 0, lp: 0, mp: 0, rp: 0,
                     lr: 0, mr: 0, rr: 0, plugboard: String::new(), plaintext: Vec::new() }
    }
}

fn combo(i: usize) -> &'static Combo { unsafe { &COMBOS[i] } }
fn num_combos() -> usize { unsafe { NUM_COMBOS } }

fn brute_force(ct: &[i32], refl: &[i32; 26], n_threads: usize) -> Vec<f32> {
    let total = num_combos() * 17576;
    let mut results = vec![0.0f32; total];
    let results_ptr = results.as_mut_ptr() as usize;
    let ct_arc = Arc::new(ct.to_vec());
    let refl_arc = Arc::new(*refl);

    let chunk = total / n_threads;
    let mut handles = vec![];
    for t in 0..n_threads {
        let start = t * chunk;
        let end = if t == n_threads - 1 { total } else { start + chunk };
        let ct_c = ct_arc.clone();
        let refl_c = refl_arc.clone();
        let rp = results_ptr;
        handles.push(thread::spawn(move || {
            let ct_len = ct_c.len();
            let mut pt = vec![0i32; ct_len];
            for idx in start..end {
                let ci = idx / 17576;
                let pi = idx % 17576;
                let c = unsafe { &COMBOS[ci] };
                let mut m = Machine::setup(c.r[0], c.r[1], c.r[2],
                    0, 0, 0, (pi / 676) as i32, ((pi / 26) % 26) as i32, (pi % 26) as i32,
                    &refl_c);
                m.process(&ct_c, &mut pt);
                unsafe { *(rp as *mut f32).add(idx) = calc_ioc(&pt) as f32; }
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    results
}

fn print_usage() {
    eprintln!("Usage: enigma-solver [options] <ciphertext>");
    eprintln!("  -f FILE   Read ciphertext from file");
    eprintln!("  -l LANG   english|german (default: german)");
    eprintln!("  -b N      Beam width (default: 50)");
    eprintln!("  -r REF    B|C (default: B)");
    eprintln!("  -p        Run plugboard hill climbing");
    eprintln!("  -o FILE   Save settings to JSON");
    eprintln!("  -n N      Results to show (default: 10)");
    eprintln!("  -t N      Threads (default: auto)");
    eprintln!("  -q        Quick pass: prune combos by peak IoC");
    eprintln!("  -Q N      Quick pass: keep top N% (default: 25)");
    eprintln!("  -s        Separate rings: beam search left×mid then right");
}

fn main() {
    init();
    let en_bg = build_bigram_table(&EN_BG);
    let de_bg = build_bigram_table(&DE_BG);

    let args: Vec<String> = env::args().collect();
    let mut ct_str = String::new();
    let mut lang_german = true;
    let mut beam = 50usize;
    let mut show = 10usize;
    let mut n_threads = thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let mut do_plugboard = false;
    let mut quick_pass = false;
    let mut quick_pass_pct = 25usize;
    let mut separate_rings = false;
    let mut output_file = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => { print_usage(); return; }
            "-f" => { i += 1; ct_str = fs::read_to_string(&args[i]).unwrap().trim().to_string(); }
            "-l" => { i += 1; lang_german = args[i] == "german"; }
            "-b" => { i += 1; beam = args[i].parse().unwrap(); }
            "-r" => { i += 1; /* only B supported in this version */ }
            "-p" => { do_plugboard = true; }
            "-o" => { i += 1; output_file = args[i].clone(); }
            "-n" => { i += 1; show = args[i].parse().unwrap(); }
            "-t" => { i += 1; n_threads = args[i].parse().unwrap(); }
            "-q" => { quick_pass = true; }
            "-Q" => { i += 1; quick_pass_pct = args[i].parse().unwrap(); }
            "-s" => { separate_rings = true; }
            s if !s.starts_with('-') && ct_str.is_empty() => { ct_str = s.to_string(); }
            _ => { eprintln!("Unknown option: {}", args[i]); print_usage(); return; }
        }
        i += 1;
    }

    if ct_str.is_empty() { eprintln!("Error: no ciphertext"); print_usage(); return; }

    let ct: Vec<i32> = ct_str.to_uppercase().chars()
        .filter(|c| c.is_ascii_uppercase())
        .map(|c| c as i32 - 65)
        .collect();
    let ct_len = ct.len();

    if ct_len < 50 {
        eprintln!("WARNING: {} chars is very short — IoC overlaps heavily with random. Historical messages were 200-250 chars.", ct_len);
    } else if ct_len < 100 {
        eprintln!("NOTE: {} chars is short. IoC separation from random is marginal.", ct_len);
    } else if ct_len < 150 {
        eprintln!("NOTE: {} chars — workable but below the 200-250 char historical norm.", ct_len);
    }

    let mode_str = if separate_rings { "separate-rings" } else if quick_pass { "quick-pass" } else { "full" };
    let ct_grouped: String = ct.iter().enumerate()
        .map(|(i, &c)| { let ch = (c as u8 + 65) as char; if i > 0 && i % 5 == 0 { format!(" {}", ch) } else { format!("{}", ch) } })
        .collect();
    println!("Ciphertext ({} chars): {:.72}", ct_len, ct_grouped);
    println!("Language: {} | Beam: {} | Threads: {} | Mode: {}",
        if lang_german { "german" } else { "english" }, beam, n_threads, mode_str);

    let refl = REFLECTOR_B;
    let bigrams = if lang_german { &de_bg } else { &en_bg };
    let t0 = Instant::now();
    let mut candidates: Vec<Candidate> = Vec::new();

    if separate_rings {
        let inter_beam = beam * 5;
        let n_trials = num_combos() * 676;
        println!("\n--- Phase 1a: {} combos × 676 left×mid = {} trials ({} threads) ---", num_combos(), n_trials, n_threads);
        let mut all_results: Vec<(f32, usize, i32, i32)> = Vec::with_capacity(n_trials);
        for ci in 0..num_combos() {
            let c = combo(ci);
            let mut pt = vec![0i32; ct_len];
            for l in 0..26i32 {
                for m in 0..26i32 {
                    let mut mach = Machine::setup(c.r[0], c.r[1], c.r[2], 0, 0, 0, l, m, 0, &refl);
                    mach.process(&ct, &mut pt);
                    all_results.push((calc_ioc(&pt) as f32, ci, l, m));
                }
            }
        }
        all_results.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
        all_results.truncate(inter_beam);
        println!("  Best IoC: {:.6}", all_results[0].0);

        println!("\n--- Phase 1b: top {} × 26 right positions ---", inter_beam);
        let mut expanded: Vec<Candidate> = Vec::new();
        let mut pt = vec![0i32; ct_len];
        for &(_, ci, l, m) in &all_results {
            for rp in 0..26i32 {
                let c = combo(ci);
                let mut mach = Machine::setup(c.r[0], c.r[1], c.r[2], 0, 0, 0, l, m, rp, &refl);
                mach.process(&ct, &mut pt);
                let mut cand = Candidate::new();
                cand.ioc = calc_ioc(&pt); cand.combo_idx = ci;
                cand.lp = l; cand.mp = m; cand.rp = rp;
                expanded.push(cand);
            }
        }
        expanded.sort_by(|a, b| b.ioc.partial_cmp(&a.ioc).unwrap());
        expanded.truncate(beam);
        println!("  Best IoC: {:.6}", expanded[0].ioc);
        candidates = expanded;
    } else {
        println!("\n--- Phase 1: {} combos × 17,576 = {} trials ({} threads) ---",
            num_combos(), num_combos() * 17576, n_threads);
        let ioc_results = brute_force(&ct, &refl, n_threads);
        let phase1_ms = t0.elapsed().as_secs_f64() * 1000.0;
        println!("  Done in {:.1} ms ({:.0} decryptions/sec)", phase1_ms,
            (num_combos() * 17576) as f64 / (phase1_ms / 1000.0));

        let total = num_combos() * 17576;
        let mut indices: Vec<usize> = (0..total).collect();
        indices.sort_by(|&a, &b| ioc_results[b].partial_cmp(&ioc_results[a]).unwrap());

        if quick_pass {
            let keep_n = std::cmp::max(1, num_combos() * quick_pass_pct / 100);
            println!("\n--- Quick pass: keeping top {}% ({} combos) by peak IoC ---", quick_pass_pct, keep_n);
            let mut peaks: Vec<(f32, usize)> = (0..num_combos()).map(|ci| {
                let base = ci * 17576;
                let peak = (0..17576).map(|p| ioc_results[base + p]).fold(0.0f32, f32::max);
                (peak, ci)
            }).collect();
            peaks.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
            let surviving: std::collections::HashSet<usize> = peaks[..keep_n].iter().map(|p| p.1).collect();
            println!("  Best: {} {} {} (peak {:.6})",
                ROTOR_NAMES[combo(peaks[0].1).r[0]], ROTOR_NAMES[combo(peaks[0].1).r[1]],
                ROTOR_NAMES[combo(peaks[0].1).r[2]], peaks[0].0);

            let mut found = 0;
            for &idx in &indices {
                if found >= beam { break; }
                let ci = idx / 17576;
                if surviving.contains(&ci) {
                    let pi = idx % 17576;
                    let mut cand = Candidate::new();
                    cand.ioc = ioc_results[idx] as f64; cand.combo_idx = ci;
                    cand.lp = (pi / 676) as i32; cand.mp = ((pi / 26) % 26) as i32; cand.rp = (pi % 26) as i32;
                    candidates.push(cand);
                    found += 1;
                }
            }
        } else {
            for j in 0..beam.min(total) {
                let idx = indices[j];
                let ci = idx / 17576;
                let pi = idx % 17576;
                let mut cand = Candidate::new();
                cand.ioc = ioc_results[idx] as f64; cand.combo_idx = ci;
                cand.lp = (pi / 676) as i32; cand.mp = ((pi / 26) % 26) as i32; cand.rp = (pi % 26) as i32;
                candidates.push(cand);
            }
        }

        let c0 = combo(candidates[0].combo_idx);
        println!("  Best IoC: {:.6}  ({} {} {} @ {}{}{})", candidates[0].ioc,
            ROTOR_NAMES[c0.r[0]], ROTOR_NAMES[c0.r[1]], ROTOR_NAMES[c0.r[2]],
            (candidates[0].lp as u8 + 65) as char, (candidates[0].mp as u8 + 65) as char,
            (candidates[0].rp as u8 + 65) as char);
    }

    // Ring refinement
    let names = ["left", "middle", "right"];
    let mut pt = vec![0i32; ct_len];
    for ring_idx in 0..3 {
        println!("\n--- Ring refinement: top {} × 26 {} ring settings ---", beam, names[ring_idx]);
        let mut expanded: Vec<Candidate> = Vec::new();
        for c in &candidates {
            let cb = combo(c.combo_idx);
            for r in 0..26i32 {
                let (lr, mr, rr) = match ring_idx {
                    0 => (r, c.mr, c.rr), 1 => (c.lr, r, c.rr), _ => (c.lr, c.mr, r),
                };
                let mut mach = Machine::setup(cb.r[0], cb.r[1], cb.r[2], lr, mr, rr, c.lp, c.mp, c.rp, &refl);
                mach.process(&ct, &mut pt);
                let mut nc = c.clone();
                nc.ioc = calc_ioc(&pt); nc.lr = lr; nc.mr = mr; nc.rr = rr;
                expanded.push(nc);
            }
        }
        expanded.sort_by(|a, b| b.ioc.partial_cmp(&a.ioc).unwrap());
        expanded.truncate(beam);
        println!("  Best IoC: {:.6}  (rings={},{},{})", expanded[0].ioc, expanded[0].lr, expanded[0].mr, expanded[0].rr);
        candidates = expanded;
    }

    // Bigram scoring
    for c in &mut candidates {
        let cb = combo(c.combo_idx);
        let mut mach = Machine::setup(cb.r[0], cb.r[1], cb.r[2], c.lr, c.mr, c.rr, c.lp, c.mp, c.rp, &refl);
        let mut pt_v = vec![0i32; ct_len];
        mach.process(&ct, &mut pt_v);
        c.bigram = calc_bigram(&pt_v, bigrams);
        c.plaintext = pt_v;
    }
    candidates.sort_by(|a, b| b.bigram.partial_cmp(&a.bigram).unwrap());

    // Plugboard hill climbing
    if do_plugboard && !candidates.is_empty() {
        println!("\n--- Plugboard hill climbing ---");
        let best = &mut candidates[0];
        let mut used = [false; 26];
        let mut pairs_found = 0;
        let mut best_score = best.bigram;
        while pairs_found < 13 {
            let mut improved = false;
            let mut best_a = 0usize;
            let mut best_b = 0usize;
            let mut best_new_score = best_score;
            for a in 0..26 {
                if used[a] { continue; }
                for b in (a+1)..26 {
                    if used[b] { continue; }
                    let test_plug = if best.plugboard.is_empty() {
                        format!("{}{}", (a as u8 + 65) as char, (b as u8 + 65) as char)
                    } else {
                        format!("{} {}{}", best.plugboard, (a as u8 + 65) as char, (b as u8 + 65) as char)
                    };
                    let cb = combo(best.combo_idx);
                    let mut mach = Machine::setup(cb.r[0], cb.r[1], cb.r[2], best.lr, best.mr, best.rr, best.lp, best.mp, best.rp, &refl);
                    mach.set_plugboard(&test_plug);
                    let mut pt_v = vec![0i32; ct_len];
                    mach.process(&ct, &mut pt_v);
                    let score = calc_bigram(&pt_v, bigrams);
                    if score > best_new_score {
                        best_new_score = score; best_a = a; best_b = b; improved = true;
                    }
                }
            }
            if !improved { break; }
            used[best_a] = true; used[best_b] = true;
            if best.plugboard.is_empty() {
                best.plugboard = format!("{}{}", (best_a as u8 + 65) as char, (best_b as u8 + 65) as char);
            } else {
                best.plugboard = format!("{} {}{}", best.plugboard, (best_a as u8 + 65) as char, (best_b as u8 + 65) as char);
            }
            best_score = best_new_score;
            pairs_found += 1;
            println!("  +{}{} (bigram: {:.2}, pairs: {})", (best_a as u8 + 65) as char, (best_b as u8 + 65) as char, best_score, pairs_found);
        }
        let cb = combo(best.combo_idx);
        let mut mach = Machine::setup(cb.r[0], cb.r[1], cb.r[2], best.lr, best.mr, best.rr, best.lp, best.mp, best.rp, &refl);
        mach.set_plugboard(&best.plugboard);
        let mut pt_v = vec![0i32; ct_len];
        mach.process(&ct, &mut pt_v);
        best.plaintext = pt_v;
        best.bigram = best_score;
    }

    let total_ms = t0.elapsed().as_secs_f64() * 1000.0;
    println!("\n{}", "=".repeat(90));
    println!("Done in {:.1} ms", total_ms);
    println!("{}", "=".repeat(90));

    println!("\n{:>3}  {:<12} {:>3} {:<10} {:<6} {:>7} {:>7}  Plaintext", "#", "Rotors", "Ref", "Rings", "Start", "IoC", "Bigram");
    println!("{}", "-".repeat(90));
    for (j, c) in candidates.iter().take(show).enumerate() {
        let cb = combo(c.combo_idx);
        let rotors = format!("{} {} {}", ROTOR_NAMES[cb.r[0]], ROTOR_NAMES[cb.r[1]], ROTOR_NAMES[cb.r[2]]);
        let rings = format!("{:>2},{:>2},{:>2}", c.lr, c.mr, c.rr);
        let start = format!("{}{}{}", (c.lp as u8+65) as char, (c.mp as u8+65) as char, (c.rp as u8+65) as char);
        let preview: String = c.plaintext.iter().take(35).map(|&v| (v as u8 + 65) as char).collect();
        let plug = if c.plugboard.is_empty() { ' ' } else { '*' };
        println!("{:>3}{}  {:<12}   B {:<10} {:<6} {:>7.5} {:>7.2}  {}", j+1, plug, rotors, rings, start, c.ioc, c.bigram, preview);
    }

    if !output_file.is_empty() && !candidates.is_empty() {
        let c = &candidates[0];
        let cb = combo(c.combo_idx);
        let pt_str: String = c.plaintext.iter().map(|&v| (v as u8 + 65) as char).collect();
        let json = format!("{{\n  \"rotors\": \"{} {} {}\",\n  \"reflector\": \"B\",\n  \"ring_settings\": [{}, {}, {}],\n  \"start_position\": \"{}{}{}\",\n  \"plugboard\": \"{}\",\n  \"ioc\": {:.6},\n  \"bigram_score\": {:.4},\n  \"plaintext\": \"{}\"\n}}\n",
            ROTOR_NAMES[cb.r[0]], ROTOR_NAMES[cb.r[1]], ROTOR_NAMES[cb.r[2]],
            c.lr, c.mr, c.rr,
            (c.lp as u8+65) as char, (c.mp as u8+65) as char, (c.rp as u8+65) as char,
            c.plugboard, c.ioc, c.bigram, pt_str);
        fs::write(&output_file, json).unwrap();
        println!("\nSettings saved to {}", output_file);
    }
}
