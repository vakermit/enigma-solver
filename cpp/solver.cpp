#include "enigma.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>
#include <numeric>
#include <thread>
#include <chrono>
#include <set>
#include <getopt.h>

static const int TOTAL_POSITIONS = 26 * 26 * 26;

struct Config {
    char ciphertext[4096];
    int ct_len;
    int ct_nums[4096];
    int beam;
    int show;
    int num_threads;
    bool use_german;
    bool do_plugboard;
    bool try_both_reflectors;
    bool quick_pass;
    bool separate_rings;
    int quick_pass_pct;
    int reflector;
    char output_file[256];
};

static float* g_ioc = nullptr;

void brute_force_worker(const int* ct, int ct_len, const int* reflector,
                        int start_idx, int end_idx) {
    int plaintext[4096];
    for (int idx = start_idx; idx < end_idx; idx++) {
        int combo = idx / TOTAL_POSITIONS;
        int pos_idx = idx % TOTAL_POSITIONS;
        int lp = pos_idx / 676;
        int mp = (pos_idx / 26) % 26;
        int rp = pos_idx % 26;

        enigma::Machine m;
        m.setup(enigma::COMBOS[combo].r[0],
                enigma::COMBOS[combo].r[1],
                enigma::COMBOS[combo].r[2],
                0, 0, 0, lp, mp, rp, reflector);
        m.process(ct, plaintext, ct_len);
        g_ioc[idx] = (float)enigma::calc_ioc(plaintext, ct_len);
    }
}

// Beam search worker: tests left×mid positions for a range of combos
struct BeamResult {
    float ioc;
    int combo_idx;
    int lp, mp;
};

static std::vector<BeamResult>* g_beam_results = nullptr;

void beam_worker(const int* ct, int ct_len, const int* reflector,
                 int combo_start, int combo_end, int thread_id) {
    int plaintext[4096];
    for (int ci = combo_start; ci < combo_end; ci++) {
        for (int l = 0; l < 26; l++) {
            for (int m = 0; m < 26; m++) {
                enigma::Machine mach;
                mach.setup(enigma::COMBOS[ci].r[0],
                           enigma::COMBOS[ci].r[1],
                           enigma::COMBOS[ci].r[2],
                           0, 0, 0, l, m, 0, reflector);
                mach.process(ct, plaintext, ct_len);
                float ioc = (float)enigma::calc_ioc(plaintext, ct_len);
                g_beam_results[thread_id].push_back({ioc, ci, l, m});
            }
        }
    }
}

struct Candidate {
    double ioc;
    double bigram;
    int combo_idx;
    int lp, mp, rp;
    int lr, mr, rr;
    char plugboard[128];
    int plaintext[4096];
    int pt_len;
};

void display_results(const std::vector<Candidate>& results, int show_n) {
    printf("\n%3s  %-12s %3s %-10s %-6s %7s %7s  Plaintext\n",
           "#", "Rotors", "Ref", "Rings", "Start", "IoC", "Bigram");
    printf("-------------------------------------------------------------------------------------------\n");
    for (int i = 0; i < show_n && i < (int)results.size(); i++) {
        auto& c = results[i];
        char rotors[32];
        snprintf(rotors, sizeof(rotors), "%s %s %s",
                 enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[0]],
                 enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[1]],
                 enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[2]]);
        char rings[16];
        snprintf(rings, sizeof(rings), "%2d,%2d,%2d", c.lr, c.mr, c.rr);
        char start[4] = {(char)('A' + c.lp), (char)('A' + c.mp), (char)('A' + c.rp), 0};
        char preview[40] = {};
        int plen = c.pt_len < 35 ? c.pt_len : 35;
        for (int j = 0; j < plen; j++) preview[j] = 'A' + c.plaintext[j];
        char plug_mark = c.plugboard[0] ? '*' : ' ';
        printf("%3d%c %-12s   B %s  %-6s %7.5f %7.2f  %s\n",
               i + 1, plug_mark, rotors, rings, start, c.ioc, c.bigram, preview);
    }
}

void save_json(const Candidate& c, const char* path) {
    FILE* f = fopen(path, "w");
    if (!f) { fprintf(stderr, "Error: cannot write %s\n", path); return; }
    char rotors[32];
    snprintf(rotors, sizeof(rotors), "%s %s %s",
             enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[0]],
             enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[1]],
             enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[2]]);
    char start[4] = {(char)('A' + c.lp), (char)('A' + c.mp), (char)('A' + c.rp), 0};
    char pt_str[4096];
    for (int i = 0; i < c.pt_len; i++) pt_str[i] = 'A' + c.plaintext[i];
    pt_str[c.pt_len] = 0;
    fprintf(f, "{\n");
    fprintf(f, "  \"rotors\": \"%s\",\n", rotors);
    fprintf(f, "  \"reflector\": \"B\",\n");
    fprintf(f, "  \"ring_settings\": [%d, %d, %d],\n", c.lr, c.mr, c.rr);
    fprintf(f, "  \"start_position\": \"%s\",\n", start);
    fprintf(f, "  \"plugboard\": \"%s\",\n", c.plugboard);
    fprintf(f, "  \"ioc\": %.6f,\n", c.ioc);
    fprintf(f, "  \"bigram_score\": %.4f,\n", c.bigram);
    fprintf(f, "  \"plaintext\": \"%s\"\n", pt_str);
    fprintf(f, "}\n");
    fclose(f);
    printf("\nSettings saved to %s\n", path);
}

void hill_climb_plugboard(Candidate& best, const int* ct, int ct_len,
                          const float bigrams[26][26], const int* reflector) {
    int used[26] = {};
    int pairs_found = 0;
    while (pairs_found < 13) {
        bool improved = false;
        int best_a = -1, best_b = -1;
        double best_score = best.bigram;
        for (int a = 0; a < 26; a++) {
            if (used[a]) continue;
            for (int b = a + 1; b < 26; b++) {
                if (used[b]) continue;
                char test_plug[128];
                snprintf(test_plug, sizeof(test_plug), "%s %c%c",
                         best.plugboard, 'A' + a, 'A' + b);
                if (!best.plugboard[0])
                    snprintf(test_plug, sizeof(test_plug), "%c%c", 'A' + a, 'A' + b);
                enigma::Machine m;
                m.setup(enigma::COMBOS[best.combo_idx].r[0],
                        enigma::COMBOS[best.combo_idx].r[1],
                        enigma::COMBOS[best.combo_idx].r[2],
                        best.lr, best.mr, best.rr,
                        best.lp, best.mp, best.rp, reflector);
                m.set_plugboard(test_plug);
                int pt[4096];
                m.process(ct, pt, ct_len);
                double score = enigma::calc_bigram(pt, ct_len, bigrams);
                if (score > best_score) {
                    best_score = score;
                    best_a = a; best_b = b;
                    improved = true;
                }
            }
        }
        if (!improved) break;
        used[best_a] = 1; used[best_b] = 1;
        if (best.plugboard[0])
            snprintf(best.plugboard + strlen(best.plugboard), 128 - strlen(best.plugboard),
                     " %c%c", 'A' + best_a, 'A' + best_b);
        else
            snprintf(best.plugboard, 128, "%c%c", 'A' + best_a, 'A' + best_b);
        pairs_found++;
        printf("  +%c%c (bigram: %.2f, pairs: %d)\n",
               'A' + best_a, 'A' + best_b, best_score, pairs_found);
    }
    enigma::Machine m;
    m.setup(enigma::COMBOS[best.combo_idx].r[0],
            enigma::COMBOS[best.combo_idx].r[1],
            enigma::COMBOS[best.combo_idx].r[2],
            best.lr, best.mr, best.rr,
            best.lp, best.mp, best.rp, enigma::REFLECTOR_B);
    m.set_plugboard(best.plugboard);
    m.process(ct, best.plaintext, ct_len);
    best.ioc = enigma::calc_ioc(best.plaintext, ct_len);
    best.bigram = enigma::calc_bigram(best.plaintext, ct_len,
                                       best.bigram > 0 ? enigma::EN_BIGRAMS : enigma::DE_BIGRAMS);
}

int main(int argc, char** argv) {
    Config cfg = {};
    cfg.beam = 50;
    cfg.show = 10;
    cfg.num_threads = (int)std::thread::hardware_concurrency();
    cfg.use_german = true;
    cfg.reflector = 0;
    cfg.quick_pass_pct = 25;

    int opt;
    while ((opt = getopt(argc, argv, "f:l:b:r:po:n:t:qQ:sh")) != -1) {
        switch (opt) {
        case 'f': {
            FILE* fp = fopen(optarg, "r");
            if (!fp) { fprintf(stderr, "Cannot open %s\n", optarg); return 1; }
            cfg.ct_len = (int)fread(cfg.ciphertext, 1, sizeof(cfg.ciphertext) - 1, fp);
            fclose(fp);
            break;
        }
        case 'l': cfg.use_german = (strcmp(optarg, "german") == 0); break;
        case 'b': cfg.beam = atoi(optarg); break;
        case 'r':
            if (strcmp(optarg, "C") == 0) cfg.reflector = 1;
            else if (strcmp(optarg, "both") == 0) cfg.try_both_reflectors = true;
            break;
        case 'p': cfg.do_plugboard = true; break;
        case 'o': strncpy(cfg.output_file, optarg, sizeof(cfg.output_file) - 1); break;
        case 'n': cfg.show = atoi(optarg); break;
        case 't': cfg.num_threads = atoi(optarg); break;
        case 'q': cfg.quick_pass = true; break;
        case 'Q': cfg.quick_pass_pct = atoi(optarg); break;
        case 's': cfg.separate_rings = true; break;
        case 'h':
            printf("Usage: solver [options] <ciphertext>\n"
                   "  -f FILE   Read ciphertext from file\n"
                   "  -l LANG   english|german (default: german)\n"
                   "  -b N      Beam width (default: 50)\n"
                   "  -r REF    B|C|both (default: B)\n"
                   "  -p        Run plugboard hill climbing\n"
                   "  -o FILE   Save settings to JSON\n"
                   "  -n N      Results to show (default: 10)\n"
                   "  -t N      Threads (default: auto)\n"
                   "  -q        Quick pass: prune combos by peak IoC before ring refinement\n"
                   "  -Q N      Quick pass: keep top N%% of combos (default: 25)\n"
                   "  -s        Separate rings: beam search left×mid then right (fast)\n");
            return 0;
        }
    }

    if (!cfg.ciphertext[0] && optind < argc)
        strncpy(cfg.ciphertext, argv[optind], sizeof(cfg.ciphertext) - 1);
    if (!cfg.ciphertext[0]) {
        fprintf(stderr, "Error: no ciphertext provided\n");
        return 1;
    }

    int j = 0;
    for (int i = 0; cfg.ciphertext[i]; i++) {
        char c = cfg.ciphertext[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        if (c >= 'A' && c <= 'Z') cfg.ciphertext[j++] = c;
    }
    cfg.ciphertext[j] = 0;
    cfg.ct_len = j;
    for (int i = 0; i < cfg.ct_len; i++)
        cfg.ct_nums[i] = cfg.ciphertext[i] - 'A';

    enigma::init();
    enigma::init_bigrams();

    const float (*bigrams)[26] = cfg.use_german ? enigma::DE_BIGRAMS : enigma::EN_BIGRAMS;
    const int* reflector = cfg.reflector == 0 ? enigma::REFLECTOR_B : enigma::REFLECTOR_C;

    const char* mode_str = cfg.separate_rings ? "separate-rings" :
                           cfg.quick_pass ? "quick-pass" : "full";
    printf("Ciphertext (%d chars): %.60s%s\n", cfg.ct_len, cfg.ciphertext,
           cfg.ct_len > 60 ? "..." : "");
    printf("Language: %s | Beam: %d | Reflector: %c | Threads: %d | Mode: %s\n",
           cfg.use_german ? "german" : "english", cfg.beam,
           cfg.reflector == 0 ? 'B' : 'C', cfg.num_threads, mode_str);
    if (cfg.ct_len < 50)
        fprintf(stderr, "WARNING: %d chars is very short — IoC overlaps heavily with random. "
                "Results unreliable. Historical messages were 200-250 chars.\n", cfg.ct_len);
    else if (cfg.ct_len < 100)
        fprintf(stderr, "NOTE: %d chars is short. IoC separation from random is marginal.\n", cfg.ct_len);
    else if (cfg.ct_len < 150)
        fprintf(stderr, "NOTE: %d chars — workable but below the 200-250 char historical norm.\n", cfg.ct_len);

    auto t0 = std::chrono::high_resolution_clock::now();
    std::vector<Candidate> candidates;
    double phase1_ms = 0;

    if (cfg.separate_rings) {
        // Phase 1a: all combos × left×mid (676 per combo), multi-threaded
        int n_combos = enigma::NUM_COMBOS;
        int intermediate_beam = cfg.beam * 5;
        int total_1a = n_combos * 676;
        printf("\n--- Phase 1a: %d combos × 676 left×mid = %d trials (%d threads) ---\n",
               n_combos, total_1a, cfg.num_threads);
        printf("  Intermediate beam: %d\n", intermediate_beam);

        g_beam_results = new std::vector<BeamResult>[cfg.num_threads];
        std::vector<std::thread> threads;
        int chunk = n_combos / cfg.num_threads;
        for (int t = 0; t < cfg.num_threads; t++) {
            int s = t * chunk;
            int e = (t == cfg.num_threads - 1) ? n_combos : s + chunk;
            threads.emplace_back(beam_worker, cfg.ct_nums, cfg.ct_len, reflector, s, e, t);
        }
        for (auto& t : threads) t.join();

        // Merge thread results
        std::vector<BeamResult> all_beam;
        for (int t = 0; t < cfg.num_threads; t++) {
            all_beam.insert(all_beam.end(), g_beam_results[t].begin(), g_beam_results[t].end());
            g_beam_results[t].clear();
        }
        delete[] g_beam_results;

        std::partial_sort(all_beam.begin(),
                          all_beam.begin() + std::min(intermediate_beam, (int)all_beam.size()),
                          all_beam.end(),
                          [](const BeamResult& a, const BeamResult& b) { return a.ioc > b.ioc; });
        all_beam.resize(std::min(intermediate_beam, (int)all_beam.size()));
        printf("  Best IoC: %.6f  (%s %s %s @ %c%cA)\n", all_beam[0].ioc,
               enigma::ROTOR_NAMES[enigma::COMBOS[all_beam[0].combo_idx].r[0]],
               enigma::ROTOR_NAMES[enigma::COMBOS[all_beam[0].combo_idx].r[1]],
               enigma::ROTOR_NAMES[enigma::COMBOS[all_beam[0].combo_idx].r[2]],
               'A' + all_beam[0].lp, 'A' + all_beam[0].mp);

        // Phase 1b: expand right position
        int n_1b = (int)all_beam.size() * 26;
        printf("\n--- Phase 1b: top %d × 26 right positions = %d trials ---\n",
               (int)all_beam.size(), n_1b);
        std::vector<Candidate> expanded;
        expanded.reserve(n_1b);
        int plaintext[4096];
        for (auto& br : all_beam) {
            for (int rp = 0; rp < 26; rp++) {
                enigma::Machine m;
                m.setup(enigma::COMBOS[br.combo_idx].r[0],
                        enigma::COMBOS[br.combo_idx].r[1],
                        enigma::COMBOS[br.combo_idx].r[2],
                        0, 0, 0, br.lp, br.mp, rp, reflector);
                m.process(cfg.ct_nums, plaintext, cfg.ct_len);
                Candidate c = {};
                c.ioc = enigma::calc_ioc(plaintext, cfg.ct_len);
                c.combo_idx = br.combo_idx;
                c.lp = br.lp; c.mp = br.mp; c.rp = rp;
                c.pt_len = cfg.ct_len;
                expanded.push_back(c);
            }
        }
        std::partial_sort(expanded.begin(),
                          expanded.begin() + std::min(cfg.beam, (int)expanded.size()),
                          expanded.end(),
                          [](const Candidate& a, const Candidate& b) { return a.ioc > b.ioc; });
        candidates.assign(expanded.begin(),
                          expanded.begin() + std::min(cfg.beam, (int)expanded.size()));

        auto t1 = std::chrono::high_resolution_clock::now();
        phase1_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        printf("  Best IoC: %.6f  (%s %s %s @ %c%c%c)\n", candidates[0].ioc,
               enigma::ROTOR_NAMES[enigma::COMBOS[candidates[0].combo_idx].r[0]],
               enigma::ROTOR_NAMES[enigma::COMBOS[candidates[0].combo_idx].r[1]],
               enigma::ROTOR_NAMES[enigma::COMBOS[candidates[0].combo_idx].r[2]],
               'A' + candidates[0].lp, 'A' + candidates[0].mp, 'A' + candidates[0].rp);
        printf("  Phase 1 done in %.1f ms\n", phase1_ms);

    } else {
        // Full brute force (with optional quick-pass post-processing)
        int total = enigma::NUM_COMBOS * TOTAL_POSITIONS;
        g_ioc = new float[total];
        printf("\n--- Phase 1: %d combos × %d positions = %d trials (%d threads) ---\n",
               enigma::NUM_COMBOS, TOTAL_POSITIONS, total, cfg.num_threads);

        std::vector<std::thread> threads;
        int chunk = total / cfg.num_threads;
        for (int t = 0; t < cfg.num_threads; t++) {
            int s = t * chunk;
            int e = (t == cfg.num_threads - 1) ? total : s + chunk;
            threads.emplace_back(brute_force_worker, cfg.ct_nums, cfg.ct_len, reflector, s, e);
        }
        for (auto& t : threads) t.join();

        auto t1 = std::chrono::high_resolution_clock::now();
        phase1_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        printf("  Done in %.1f ms (%.0f decryptions/sec)\n", phase1_ms,
               total / (phase1_ms / 1000.0));

        if (cfg.quick_pass) {
            // Rank combos by peak IoC, keep top N%
            int keep_n = std::max(1, enigma::NUM_COMBOS * cfg.quick_pass_pct / 100);
            printf("\n--- Quick pass: ranking %d combos by peak IoC, keeping top %d%% (%d) ---\n",
                   enigma::NUM_COMBOS, cfg.quick_pass_pct, keep_n);
            struct ComboScore { float peak; int idx; };
            std::vector<ComboScore> cscores(enigma::NUM_COMBOS);
            for (int ci = 0; ci < enigma::NUM_COMBOS; ci++) {
                float peak = 0;
                int base = ci * TOTAL_POSITIONS;
                for (int p = 0; p < TOTAL_POSITIONS; p++) {
                    if (g_ioc[base + p] > peak) peak = g_ioc[base + p];
                }
                cscores[ci] = {peak, ci};
            }
            std::partial_sort(cscores.begin(), cscores.begin() + keep_n, cscores.end(),
                              [](const ComboScore& a, const ComboScore& b) { return a.peak > b.peak; });

            printf("  Best: %s %s %s (peak %.6f)\n",
                   enigma::ROTOR_NAMES[enigma::COMBOS[cscores[0].idx].r[0]],
                   enigma::ROTOR_NAMES[enigma::COMBOS[cscores[0].idx].r[1]],
                   enigma::ROTOR_NAMES[enigma::COMBOS[cscores[0].idx].r[2]],
                   cscores[0].peak);
            printf("  Cutoff: %s %s %s (peak %.6f)\n",
                   enigma::ROTOR_NAMES[enigma::COMBOS[cscores[keep_n-1].idx].r[0]],
                   enigma::ROTOR_NAMES[enigma::COMBOS[cscores[keep_n-1].idx].r[1]],
                   enigma::ROTOR_NAMES[enigma::COMBOS[cscores[keep_n-1].idx].r[2]],
                   cscores[keep_n-1].peak);

            // Collect beam-width candidates only from surviving combos
            std::set<int> surviving;
            for (int i = 0; i < keep_n; i++) surviving.insert(cscores[i].idx);

            std::vector<int> indices(total);
            std::iota(indices.begin(), indices.end(), 0);
            std::partial_sort(indices.begin(), indices.begin() + total, indices.end(),
                              [](int a, int b) { return g_ioc[a] > g_ioc[b]; });

            int found = 0;
            for (int i = 0; i < total && found < cfg.beam; i++) {
                int ci = indices[i] / TOTAL_POSITIONS;
                if (surviving.count(ci)) {
                    int posidx = indices[i] % TOTAL_POSITIONS;
                    Candidate c = {};
                    c.ioc = g_ioc[indices[i]];
                    c.combo_idx = ci;
                    c.lp = posidx / 676;
                    c.mp = (posidx / 26) % 26;
                    c.rp = posidx % 26;
                    c.pt_len = cfg.ct_len;
                    candidates.push_back(c);
                    found++;
                }
            }
        } else {
            std::vector<int> indices(total);
            std::iota(indices.begin(), indices.end(), 0);
            std::partial_sort(indices.begin(), indices.begin() + cfg.beam, indices.end(),
                              [](int a, int b) { return g_ioc[a] > g_ioc[b]; });
            for (int i = 0; i < cfg.beam; i++) {
                int idx = indices[i];
                int ci = idx / TOTAL_POSITIONS;
                int posidx = idx % TOTAL_POSITIONS;
                Candidate c = {};
                c.ioc = g_ioc[idx];
                c.combo_idx = ci;
                c.lp = posidx / 676;
                c.mp = (posidx / 26) % 26;
                c.rp = posidx % 26;
                c.pt_len = cfg.ct_len;
                candidates.push_back(c);
            }
        }

        delete[] g_ioc;
        g_ioc = nullptr;

        printf("  Best IoC: %.6f  (%s %s %s @ %c%c%c)\n", candidates[0].ioc,
               enigma::ROTOR_NAMES[enigma::COMBOS[candidates[0].combo_idx].r[0]],
               enigma::ROTOR_NAMES[enigma::COMBOS[candidates[0].combo_idx].r[1]],
               enigma::ROTOR_NAMES[enigma::COMBOS[candidates[0].combo_idx].r[2]],
               'A' + candidates[0].lp, 'A' + candidates[0].mp, 'A' + candidates[0].rp);
    }

    // Ring refinement
    for (int ring_idx = 0; ring_idx < 3; ring_idx++) {
        const char* names[] = {"left", "middle", "right"};
        printf("\n--- Ring refinement: top %d × 26 %s ring settings ---\n",
               cfg.beam, names[ring_idx]);
        std::vector<Candidate> expanded;
        expanded.reserve(cfg.beam * 26);
        for (auto& c : candidates) {
            for (int r = 0; r < 26; r++) {
                Candidate nc = c;
                if (ring_idx == 0) nc.lr = r;
                else if (ring_idx == 1) nc.mr = r;
                else nc.rr = r;
                enigma::Machine m;
                m.setup(enigma::COMBOS[nc.combo_idx].r[0],
                        enigma::COMBOS[nc.combo_idx].r[1],
                        enigma::COMBOS[nc.combo_idx].r[2],
                        nc.lr, nc.mr, nc.rr,
                        nc.lp, nc.mp, nc.rp, reflector);
                m.process(cfg.ct_nums, nc.plaintext, cfg.ct_len);
                nc.ioc = enigma::calc_ioc(nc.plaintext, cfg.ct_len);
                expanded.push_back(nc);
            }
        }
        std::partial_sort(expanded.begin(),
                          expanded.begin() + std::min(cfg.beam, (int)expanded.size()),
                          expanded.end(),
                          [](const Candidate& a, const Candidate& b) { return a.ioc > b.ioc; });
        candidates.assign(expanded.begin(),
                          expanded.begin() + std::min(cfg.beam, (int)expanded.size()));
        printf("  Best IoC: %.6f  (rings=%d,%d,%d)\n",
               candidates[0].ioc, candidates[0].lr, candidates[0].mr, candidates[0].rr);
    }

    // Bigram scoring
    for (auto& c : candidates) {
        enigma::Machine m;
        m.setup(enigma::COMBOS[c.combo_idx].r[0],
                enigma::COMBOS[c.combo_idx].r[1],
                enigma::COMBOS[c.combo_idx].r[2],
                c.lr, c.mr, c.rr,
                c.lp, c.mp, c.rp, reflector);
        m.process(cfg.ct_nums, c.plaintext, cfg.ct_len);
        c.bigram = enigma::calc_bigram(c.plaintext, cfg.ct_len, bigrams);
    }
    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate& a, const Candidate& b) { return a.bigram > b.bigram; });

    if (cfg.do_plugboard && !candidates.empty()) {
        printf("\n--- Plugboard hill climbing ---\n");
        hill_climb_plugboard(candidates[0], cfg.ct_nums, cfg.ct_len, bigrams, reflector);
    }

    auto t2 = std::chrono::high_resolution_clock::now();
    double total_ms = std::chrono::duration<double, std::milli>(t2 - t0).count();
    printf("\n==========================================================================================\n");
    printf("Done in %.1f ms total (Phase 1: %.1f ms)\n", total_ms, phase1_ms);
    printf("==========================================================================================\n");

    display_results(candidates, cfg.show);

    if (cfg.do_plugboard && !candidates.empty() && candidates[0].plugboard[0]) {
        char pt_str[4096];
        for (int i = 0; i < candidates[0].pt_len; i++) pt_str[i] = 'A' + candidates[0].plaintext[i];
        pt_str[candidates[0].pt_len] = 0;
        printf("\nBest plugboard: %s\nFull plaintext: %s\n", candidates[0].plugboard, pt_str);
    }

    if (cfg.output_file[0] && !candidates.empty())
        save_json(candidates[0], cfg.output_file);

    return 0;
}
