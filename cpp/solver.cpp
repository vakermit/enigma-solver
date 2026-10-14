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
    bool navy;
    bool m4;
    int quick_pass_pct;
    int reflector;
    char output_file[256];
};

struct Candidate {
    double ioc;
    double bigram;
    int combo_idx;
    int lp, mp, rp;
    int lr, mr, rr;
    int greek_rotor;
    int thin_ref_idx;
    int gp;
    int gr;
    char plugboard[128];
    int plaintext[4096];
    int pt_len;
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

const int* get_reflector(int idx) {
    return idx == 0 ? enigma::REFLECTOR_B : enigma::REFLECTOR_C;
}

void get_reflector_for_candidate(const Candidate& c, int* out) {
    if (c.greek_rotor >= 0) {
        enigma::compute_composite_reflector(c.greek_rotor, c.thin_ref_idx,
                                            c.gp, c.gr, out);
    } else {
        const int* src = c.thin_ref_idx >= 0 ? get_reflector(c.thin_ref_idx)
                                              : enigma::REFLECTOR_B;
        memcpy(out, src, 26 * sizeof(int));
    }
}

void display_results(const std::vector<Candidate>& results, int show_n, bool m4_mode) {
    if (m4_mode) {
        printf("\n%3s  %-20s %-6s %-14s %-6s %7s %7s  Plaintext\n",
               "#", "Rotors", "Ref", "Rings", "Start", "IoC", "Bigram");
    } else {
        printf("\n%3s  %-12s %3s %-10s %-6s %7s %7s  Plaintext\n",
               "#", "Rotors", "Ref", "Rings", "Start", "IoC", "Bigram");
    }
    printf("-------------------------------------------------------------------------------------------\n");
    for (int i = 0; i < show_n && i < (int)results.size(); i++) {
        auto& c = results[i];
        char rotors[48];
        if (m4_mode && c.greek_rotor >= 0) {
            snprintf(rotors, sizeof(rotors), "%s %s %s %s",
                     enigma::GREEK_NAMES[c.greek_rotor],
                     enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[0]],
                     enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[1]],
                     enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[2]]);
        } else {
            snprintf(rotors, sizeof(rotors), "%s %s %s",
                     enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[0]],
                     enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[1]],
                     enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[2]]);
        }

        const char* ref_name = "B";
        if (c.greek_rotor >= 0)
            ref_name = enigma::THIN_REF_NAMES[c.thin_ref_idx];
        else if (c.thin_ref_idx == 1)
            ref_name = "C";

        char rings[20];
        if (m4_mode && c.greek_rotor >= 0)
            snprintf(rings, sizeof(rings), "%2d,%2d,%2d,%2d", c.gr, c.lr, c.mr, c.rr);
        else
            snprintf(rings, sizeof(rings), "%2d,%2d,%2d", c.lr, c.mr, c.rr);

        char start[8];
        if (m4_mode && c.greek_rotor >= 0)
            snprintf(start, sizeof(start), "%c%c%c%c",
                     'A' + c.gp, 'A' + c.lp, 'A' + c.mp, 'A' + c.rp);
        else
            snprintf(start, sizeof(start), "%c%c%c",
                     'A' + c.lp, 'A' + c.mp, 'A' + c.rp);

        char preview[40] = {};
        int plen = c.pt_len < 35 ? c.pt_len : 35;
        for (int j = 0; j < plen; j++) preview[j] = 'A' + c.plaintext[j];
        char plug_mark = c.plugboard[0] ? '*' : ' ';

        if (m4_mode)
            printf("%3d%c %-20s %-6s %-14s %-6s %7.5f %7.2f  %s\n",
                   i + 1, plug_mark, rotors, ref_name, rings, start,
                   c.ioc, c.bigram, preview);
        else
            printf("%3d%c %-12s %5s %s  %-6s %7.5f %7.2f  %s\n",
                   i + 1, plug_mark, rotors, ref_name, rings, start,
                   c.ioc, c.bigram, preview);
    }
}

void save_json(const Candidate& c, const char* path, bool m4_mode) {
    FILE* f = fopen(path, "w");
    if (!f) { fprintf(stderr, "Error: cannot write %s\n", path); return; }
    char rotors[48];
    if (m4_mode && c.greek_rotor >= 0) {
        snprintf(rotors, sizeof(rotors), "%s %s %s %s",
                 enigma::GREEK_NAMES[c.greek_rotor],
                 enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[0]],
                 enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[1]],
                 enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[2]]);
    } else {
        snprintf(rotors, sizeof(rotors), "%s %s %s",
                 enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[0]],
                 enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[1]],
                 enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[2]]);
    }

    const char* ref_name = "B";
    if (c.greek_rotor >= 0)
        ref_name = enigma::THIN_REF_NAMES[c.thin_ref_idx];

    char start[8];
    if (m4_mode && c.greek_rotor >= 0)
        snprintf(start, sizeof(start), "%c%c%c%c",
                 'A' + c.gp, 'A' + c.lp, 'A' + c.mp, 'A' + c.rp);
    else
        snprintf(start, sizeof(start), "%c%c%c",
                 'A' + c.lp, 'A' + c.mp, 'A' + c.rp);

    char pt_str[4096];
    for (int i = 0; i < c.pt_len; i++) pt_str[i] = 'A' + c.plaintext[i];
    pt_str[c.pt_len] = 0;

    fprintf(f, "{\n");
    fprintf(f, "  \"rotors\": \"%s\",\n", rotors);
    fprintf(f, "  \"reflector\": \"%s\",\n", ref_name);
    if (m4_mode && c.greek_rotor >= 0)
        fprintf(f, "  \"ring_settings\": [%d, %d, %d, %d],\n", c.gr, c.lr, c.mr, c.rr);
    else
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
                          const float bigrams[26][26]) {
    int comp_refl[26];
    get_reflector_for_candidate(best, comp_refl);

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
                        best.lp, best.mp, best.rp, comp_refl);
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
            best.lp, best.mp, best.rp, comp_refl);
    m.set_plugboard(best.plugboard);
    m.process(ct, best.plaintext, ct_len);
    best.ioc = enigma::calc_ioc(best.plaintext, ct_len);
    best.bigram = enigma::calc_bigram(best.plaintext, ct_len, bigrams);
}

void solve_3rotor(Config& cfg, std::vector<Candidate>& candidates,
                  const int* reflector, int ref_idx) {
    double phase1_ms = 0;

    if (cfg.separate_rings) {
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

        printf("\n--- Phase 1b: top %d × 26 right positions ---\n", (int)all_beam.size());
        std::vector<Candidate> expanded;
        expanded.reserve((int)all_beam.size() * 26);
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
                c.greek_rotor = -1; c.thin_ref_idx = ref_idx; c.gp = 0; c.gr = 0;
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

    } else {
        int total = enigma::NUM_COMBOS * TOTAL_POSITIONS;
        g_ioc = new float[total];
        printf("\n--- Phase 1: %d combos × %d positions = %d trials (%d threads) ---\n",
               enigma::NUM_COMBOS, TOTAL_POSITIONS, total, cfg.num_threads);

        auto t0 = std::chrono::high_resolution_clock::now();
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
            int keep_n = std::max(1, enigma::NUM_COMBOS * cfg.quick_pass_pct / 100);
            printf("\n--- Quick pass: keeping top %d%% (%d combos) ---\n",
                   cfg.quick_pass_pct, keep_n);
            struct ComboScore { float peak; int idx; };
            std::vector<ComboScore> cscores(enigma::NUM_COMBOS);
            for (int ci = 0; ci < enigma::NUM_COMBOS; ci++) {
                float peak = 0;
                int base = ci * TOTAL_POSITIONS;
                for (int p = 0; p < TOTAL_POSITIONS; p++)
                    if (g_ioc[base + p] > peak) peak = g_ioc[base + p];
                cscores[ci] = {peak, ci};
            }
            std::partial_sort(cscores.begin(), cscores.begin() + keep_n, cscores.end(),
                              [](const ComboScore& a, const ComboScore& b) { return a.peak > b.peak; });

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
                    c.greek_rotor = -1; c.thin_ref_idx = ref_idx; c.gp = 0; c.gr = 0;
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
                c.greek_rotor = -1; c.thin_ref_idx = ref_idx; c.gp = 0; c.gr = 0;
                c.pt_len = cfg.ct_len;
                candidates.push_back(c);
            }
        }

        delete[] g_ioc;
        g_ioc = nullptr;
    }

    printf("  Best IoC: %.6f  (%s %s %s @ %c%c%c)\n", candidates[0].ioc,
           enigma::ROTOR_NAMES[enigma::COMBOS[candidates[0].combo_idx].r[0]],
           enigma::ROTOR_NAMES[enigma::COMBOS[candidates[0].combo_idx].r[1]],
           enigma::ROTOR_NAMES[enigma::COMBOS[candidates[0].combo_idx].r[2]],
           'A' + candidates[0].lp, 'A' + candidates[0].mp, 'A' + candidates[0].rp);
}

void solve_m4(Config& cfg, std::vector<Candidate>& all_candidates) {
    // M4: for each (Greek, thin_ref) pair, search all 26 Greek positions
    // using composite reflector trick (Greek + thin_ref = modified reflector)
    int per_combo = TOTAL_POSITIONS;

    for (int greek = 0; greek < 2; greek++) {
        for (int tr = 0; tr < 2; tr++) {
            int total_pair = 26 * enigma::NUM_COMBOS * per_combo;
            printf("\n--- M4: %s + %s — %d combos × %d positions = %d ---\n",
                   enigma::GREEK_NAMES[greek], enigma::THIN_REF_NAMES[tr],
                   enigma::NUM_COMBOS, 26 * per_combo, total_pair);

            std::vector<Candidate> pair_candidates;

            for (int gp = 0; gp < 26; gp++) {
                int comp_refl[26];
                enigma::compute_composite_reflector(greek, tr, gp, 0, comp_refl);

                int total = enigma::NUM_COMBOS * per_combo;
                g_ioc = new float[total];

                std::vector<std::thread> threads;
                int chunk = total / cfg.num_threads;
                for (int t = 0; t < cfg.num_threads; t++) {
                    int s = t * chunk;
                    int e = (t == cfg.num_threads - 1) ? total : s + chunk;
                    threads.emplace_back(brute_force_worker, cfg.ct_nums, cfg.ct_len,
                                         comp_refl, s, e);
                }
                for (auto& t : threads) t.join();

                std::vector<int> indices(total);
                std::iota(indices.begin(), indices.end(), 0);
                std::partial_sort(indices.begin(),
                                  indices.begin() + std::min(cfg.beam, total),
                                  indices.end(),
                                  [](int a, int b) { return g_ioc[a] > g_ioc[b]; });

                for (int i = 0; i < cfg.beam && i < total; i++) {
                    int idx = indices[i];
                    int ci = idx / per_combo;
                    int posidx = idx % per_combo;
                    Candidate c = {};
                    c.ioc = g_ioc[idx];
                    c.combo_idx = ci;
                    c.lp = posidx / 676;
                    c.mp = (posidx / 26) % 26;
                    c.rp = posidx % 26;
                    c.greek_rotor = greek;
                    c.thin_ref_idx = tr;
                    c.gp = gp;
                    c.gr = 0;
                    c.pt_len = cfg.ct_len;
                    pair_candidates.push_back(c);
                }

                delete[] g_ioc;
                g_ioc = nullptr;

                if ((gp + 1) % 5 == 0)
                    printf("  ... %d/26 Greek positions done\n", gp + 1);
            }

            std::sort(pair_candidates.begin(), pair_candidates.end(),
                      [](const Candidate& a, const Candidate& b) { return a.ioc > b.ioc; });
            if ((int)pair_candidates.size() > cfg.beam)
                pair_candidates.resize(cfg.beam);

            printf("  Best IoC: %.6f  (%s %s %s %s @ %c%c%c%c)\n",
                   pair_candidates[0].ioc,
                   enigma::GREEK_NAMES[greek],
                   enigma::ROTOR_NAMES[enigma::COMBOS[pair_candidates[0].combo_idx].r[0]],
                   enigma::ROTOR_NAMES[enigma::COMBOS[pair_candidates[0].combo_idx].r[1]],
                   enigma::ROTOR_NAMES[enigma::COMBOS[pair_candidates[0].combo_idx].r[2]],
                   'A' + pair_candidates[0].gp,
                   'A' + pair_candidates[0].lp,
                   'A' + pair_candidates[0].mp,
                   'A' + pair_candidates[0].rp);

            all_candidates.insert(all_candidates.end(),
                                  pair_candidates.begin(), pair_candidates.end());
        }
    }

    std::sort(all_candidates.begin(), all_candidates.end(),
              [](const Candidate& a, const Candidate& b) { return a.ioc > b.ioc; });
    if ((int)all_candidates.size() > cfg.beam)
        all_candidates.resize(cfg.beam);
}

static struct option long_options[] = {
    {"file",               required_argument, 0, 'f'},
    {"lang",               required_argument, 0, 'l'},
    {"beam",               required_argument, 0, 'b'},
    {"reflector",          required_argument, 0, 'r'},
    {"plugboard",          no_argument,       0, 'p'},
    {"output",             required_argument, 0, 'o'},
    {"show",               required_argument, 0, 'n'},
    {"threads",            required_argument, 0, 't'},
    {"navy",               no_argument,       0, 'N'},
    {"m4",                 no_argument,       0, 'M'},
    {"quick-pass",         no_argument,       0, 'q'},
    {"quick-pass-pct",     required_argument, 0, 'Q'},
    {"test-separate-rings",no_argument,       0, 's'},
    {"help",               no_argument,       0, 'h'},
    {0, 0, 0, 0},
};

int main(int argc, char** argv) {
    Config cfg = {};
    cfg.beam = 50;
    cfg.show = 10;
    cfg.num_threads = (int)std::thread::hardware_concurrency();
    cfg.use_german = true;
    cfg.reflector = 0;
    cfg.quick_pass_pct = 25;

    int opt;
    while ((opt = getopt_long(argc, argv, "f:l:b:r:po:n:t:qQ:shNM", long_options, nullptr)) != -1) {
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
        case 'N': cfg.navy = true; break;
        case 'M': cfg.m4 = true; cfg.navy = true; break;
        case 'q': cfg.quick_pass = true; break;
        case 'Q': cfg.quick_pass_pct = atoi(optarg); break;
        case 's': cfg.separate_rings = true; break;
        case 'h':
            printf("Usage: solver [options] <ciphertext>\n"
                   "  -f, --file FILE         Read ciphertext from file\n"
                   "  -l, --lang LANG         english|german (default: german)\n"
                   "  -b, --beam N            Beam width (default: 50)\n"
                   "  -r, --reflector REF     B|C|both (default: B)\n"
                   "  -p, --plugboard         Run plugboard hill climbing\n"
                   "  -o, --output FILE       Save settings to JSON\n"
                   "  -n, --show N            Results to show (default: 10)\n"
                   "  -t, --threads N         Threads (default: auto)\n"
                   "      --navy              Navy mode: rotors I-VIII (336 combos)\n"
                   "      --m4                Navy M4 mode: 4 rotors + thin reflectors\n"
                   "  -q, --quick-pass        Prune combos by peak IoC before ring refinement\n"
                   "  -Q, --quick-pass-pct N  Keep top N%% of combos (default: 25)\n"
                   "  -s, --test-separate-rings  Beam search left×mid then right\n"
                   "  -h, --help              Show this help\n");
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

    int num_rotors = cfg.navy ? 8 : 5;
    enigma::init(num_rotors);
    enigma::init_bigrams();

    const float (*bigrams)[26] = cfg.use_german ? enigma::DE_BIGRAMS : enigma::EN_BIGRAMS;

    const char* mode_str = cfg.m4 ? "M4" :
                           cfg.separate_rings ? "separate-rings" :
                           cfg.quick_pass ? "quick-pass" : "full";
    printf("Ciphertext (%d chars): %.60s%s\n", cfg.ct_len, cfg.ciphertext,
           cfg.ct_len > 60 ? "..." : "");
    printf("Language: %s | Beam: %d | Reflector: %c | Threads: %d | Mode: %s\n",
           cfg.use_german ? "german" : "english", cfg.beam,
           cfg.reflector == 0 ? 'B' : 'C', cfg.num_threads, mode_str);
    printf("Rotors: %s (%d permutations)\n",
           cfg.navy ? "I-VIII" : "I-V", enigma::NUM_COMBOS);

    if (cfg.ct_len < 50)
        fprintf(stderr, "WARNING: %d chars is very short — IoC overlaps heavily with random.\n", cfg.ct_len);
    else if (cfg.ct_len < 100)
        fprintf(stderr, "NOTE: %d chars is short. IoC separation from random is marginal.\n", cfg.ct_len);
    else if (cfg.ct_len < 150)
        fprintf(stderr, "NOTE: %d chars — workable but below the 200-250 char historical norm.\n", cfg.ct_len);

    auto t0 = std::chrono::high_resolution_clock::now();
    std::vector<Candidate> candidates;

    if (cfg.m4) {
        solve_m4(cfg, candidates);
    } else {
        int* reflectors;
        int num_refs;
        int ref_list[2];
        if (cfg.try_both_reflectors) {
            ref_list[0] = 0; ref_list[1] = 1;
            num_refs = 2;
        } else {
            ref_list[0] = cfg.reflector;
            num_refs = 1;
        }
        reflectors = ref_list;

        for (int ri = 0; ri < num_refs; ri++) {
            if (num_refs > 1)
                printf("\n%s\n  Reflector %c\n%s\n",
                       "==================================================",
                       reflectors[ri] == 0 ? 'B' : 'C',
                       "==================================================");
            std::vector<Candidate> ref_cands;
            solve_3rotor(cfg, ref_cands, get_reflector(reflectors[ri]), reflectors[ri]);
            candidates.insert(candidates.end(), ref_cands.begin(), ref_cands.end());
        }
    }

    // Ring refinement
    for (int ring_idx = 0; ring_idx < 3; ring_idx++) {
        const char* names[] = {"left", "middle", "right"};
        printf("\n--- Ring refinement: top %d × 26 %s ring settings ---\n",
               cfg.beam, names[ring_idx]);
        std::vector<Candidate> expanded;
        expanded.reserve(cfg.beam * 26);
        for (auto& c : candidates) {
            int comp_refl[26];
            get_reflector_for_candidate(c, comp_refl);

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
                        nc.lp, nc.mp, nc.rp, comp_refl);
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
        int comp_refl[26];
        get_reflector_for_candidate(c, comp_refl);
        enigma::Machine m;
        m.setup(enigma::COMBOS[c.combo_idx].r[0],
                enigma::COMBOS[c.combo_idx].r[1],
                enigma::COMBOS[c.combo_idx].r[2],
                c.lr, c.mr, c.rr,
                c.lp, c.mp, c.rp, comp_refl);
        m.process(cfg.ct_nums, c.plaintext, cfg.ct_len);
        c.bigram = enigma::calc_bigram(c.plaintext, cfg.ct_len, bigrams);
    }
    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate& a, const Candidate& b) { return a.bigram > b.bigram; });

    if (cfg.do_plugboard && !candidates.empty()) {
        printf("\n--- Plugboard hill climbing ---\n");
        hill_climb_plugboard(candidates[0], cfg.ct_nums, cfg.ct_len, bigrams);
    }

    auto t2 = std::chrono::high_resolution_clock::now();
    double total_ms = std::chrono::duration<double, std::milli>(t2 - t0).count();
    printf("\n==========================================================================================\n");
    printf("Done in %.1f ms total\n", total_ms);
    printf("==========================================================================================\n");

    display_results(candidates, cfg.show, cfg.m4);

    if (cfg.do_plugboard && !candidates.empty() && candidates[0].plugboard[0]) {
        char pt_str[4096];
        for (int i = 0; i < candidates[0].pt_len; i++) pt_str[i] = 'A' + candidates[0].plaintext[i];
        pt_str[candidates[0].pt_len] = 0;
        printf("\nBest plugboard: %s\nFull plaintext: %s\n", candidates[0].plugboard, pt_str);
    }

    if (cfg.output_file[0] && !candidates.empty())
        save_json(candidates[0], cfg.output_file, cfg.m4);

    return 0;
}
