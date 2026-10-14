#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#include "enigma.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>
#include <string>
#include <fstream>
#include <chrono>
#include <numeric>
#include <getopt.h>

// Reuse the IoC kernel from metal_solver for GPU Phase 1
static const char* IOC_SHADER = R"(
#include <metal_stdlib>
using namespace metal;

struct RotorData {
    int forward[8][26];
    int reverse[8][26];
    int notch_a[8];
    int notch_b[8];
    int reflector[26];
    int combos[336][3];
};

struct Params {
    int ct_length;
    int num_combos;
};

kernel void enigma_solve(
    device const int* ciphertext [[buffer(0)]],
    constant RotorData& rotors [[buffer(1)]],
    constant Params& params [[buffer(2)]],
    device float* results [[buffer(3)]],
    uint tid [[thread_position_in_grid]])
{
    int total = params.num_combos * 17576;
    if ((int)tid >= total) return;

    int combo_idx = tid / 17576;
    int pos_idx = tid % 17576;
    int left_pos = pos_idx / 676;
    int mid_pos = (pos_idx / 26) % 26;
    int right_pos = pos_idx % 26;

    int lr = rotors.combos[combo_idx][0];
    int mr = rotors.combos[combo_idx][1];
    int rr = rotors.combos[combo_idx][2];

    int fwd_l[26], fwd_m[26], fwd_r[26];
    int rev_l[26], rev_m[26], rev_r[26];
    for (int i = 0; i < 26; i++) {
        fwd_l[i] = rotors.forward[lr][i];
        fwd_m[i] = rotors.forward[mr][i];
        fwd_r[i] = rotors.forward[rr][i];
        rev_l[i] = rotors.reverse[lr][i];
        rev_m[i] = rotors.reverse[mr][i];
        rev_r[i] = rotors.reverse[rr][i];
    }

    int notch_m_a = rotors.notch_a[mr];
    int notch_m_b = rotors.notch_b[mr];
    int notch_r_a = rotors.notch_a[rr];
    int notch_r_b = rotors.notch_b[rr];

    int pos_l = left_pos, pos_m = mid_pos, pos_r = right_pos;
    int freq[26];
    for (int i = 0; i < 26; i++) freq[i] = 0;

    for (int i = 0; i < params.ct_length; i++) {
        bool mn = (pos_m == notch_m_a) || (notch_m_b >= 0 && pos_m == notch_m_b);
        bool rn = (pos_r == notch_r_a) || (notch_r_b >= 0 && pos_r == notch_r_b);
        pos_r = (pos_r + 1) % 26;
        if (rn || mn) pos_m = (pos_m + 1) % 26;
        if (mn) pos_l = (pos_l + 1) % 26;

        int sig = ciphertext[i];
        sig = (fwd_r[(sig + pos_r) % 26] - pos_r + 26) % 26;
        sig = (fwd_m[(sig + pos_m) % 26] - pos_m + 26) % 26;
        sig = (fwd_l[(sig + pos_l) % 26] - pos_l + 26) % 26;
        sig = rotors.reflector[sig];
        sig = (rev_l[(sig + pos_l) % 26] - pos_l + 26) % 26;
        sig = (rev_m[(sig + pos_m) % 26] - pos_m + 26) % 26;
        sig = (rev_r[(sig + pos_r) % 26] - pos_r + 26) % 26;
        freq[sig]++;
    }

    int n = params.ct_length;
    float sum = 0.0f;
    for (int i = 0; i < 26; i++) sum += (float)(freq[i] * (freq[i] - 1));
    results[tid] = sum / (float)(n * (n - 1));
}
)";

struct RotorData {
    int forward[8][26];
    int reverse[8][26];
    int notch_a[8];
    int notch_b[8];
    int reflector[26];
    int combos[336][3];
};

struct Params {
    int ct_length;
    int num_combos;
};

struct CribWord {
    std::string text;
    int nums[16];
    int len;
};

struct CribEntry {
    int word[16];
    int len;
    int pos;
    int word_idx;
};

struct IoCSurvivor {
    float ioc;
    int combo_idx;
    int lp, mp, rp;
    int greek;
    int thin_ref;
    int gp;
};

std::vector<CribWord> load_cribs(const char* path) {
    std::vector<CribWord> words;
    std::ifstream f(path);
    if (!f.is_open()) { fprintf(stderr, "Cannot open crib file: %s\n", path); return words; }
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        CribWord w;
        w.text = line;
        w.len = 0;
        for (char c : line) {
            if (c >= 'A' && c <= 'Z' && w.len < 16) w.nums[w.len++] = c - 'A';
        }
        if (w.len >= 3 && w.len <= 16) words.push_back(w);
    }
    return words;
}

std::vector<CribEntry> build_entries(const std::vector<CribWord>& words,
                                     const int* ct, int ct_len, int min_len) {
    std::vector<CribEntry> entries;
    for (int wi = 0; wi < (int)words.size(); wi++) {
        auto& w = words[wi];
        if (w.len < min_len) continue;
        for (int p = 0; p <= ct_len - w.len; p++) {
            bool self_encrypt = false;
            for (int i = 0; i < w.len; i++) {
                if (w.nums[i] == ct[p + i]) { self_encrypt = true; break; }
            }
            if (self_encrypt) continue;
            CribEntry e = {};
            memcpy(e.word, w.nums, w.len * sizeof(int));
            e.len = w.len; e.pos = p; e.word_idx = wi;
            entries.push_back(e);
        }
    }
    return entries;
}

// CPU Bombe check: returns true if crib at given position is plugboard-consistent
bool bombe_check(int combo_idx, int sl, int sm, int sr,
                 const CribEntry& entry, const int* ct,
                 const int* refl, int* plug_out) {
    // Compute R_i permutation at each crib position
    int R[16][26];
    enigma::Machine mach;
    mach.setup(enigma::COMBOS[combo_idx].r[0], enigma::COMBOS[combo_idx].r[1],
               enigma::COMBOS[combo_idx].r[2], 0, 0, 0, sl, sm, sr, refl);
    for (int i = 0; i < entry.pos; i++) mach.step();
    for (int ci = 0; ci < entry.len; ci++) {
        mach.step();
        for (int x = 0; x < 26; x++) {
            int sig = x;
            int p0 = mach.pos[0], p1 = mach.pos[1], p2 = mach.pos[2];
            sig = (mach.fwd[2][(sig + p2) % 26] - p2 + 26) % 26;
            sig = (mach.fwd[1][(sig + p1) % 26] - p1 + 26) % 26;
            sig = (mach.fwd[0][(sig + p0) % 26] - p0 + 26) % 26;
            sig = refl[sig];
            sig = (mach.rev[0][(sig + p0) % 26] - p0 + 26) % 26;
            sig = (mach.rev[1][(sig + p1) % 26] - p1 + 26) % 26;
            sig = (mach.rev[2][(sig + p2) % 26] - p2 + 26) % 26;
            R[ci][x] = sig;
        }
    }

    for (int guess = 0; guess < 26; guess++) {
        int plug[26];
        for (int i = 0; i < 26; i++) plug[i] = -1;
        bool valid = true;

        int k0 = entry.word[0], c0 = ct[entry.pos];
        if (k0 == guess) plug[k0] = k0;
        else { plug[k0] = guess; plug[guess] = k0; }

        int pc0 = R[0][guess];
        if (c0 == pc0) {
            if (plug[c0] >= 0 && plug[c0] != c0) continue;
            plug[c0] = c0;
        } else {
            if (plug[c0] >= 0 && plug[c0] != pc0) continue;
            if (plug[pc0] >= 0 && plug[pc0] != c0) continue;
            plug[c0] = pc0; plug[pc0] = c0;
        }

        bool changed = true;
        int max_iter = entry.len;
        while (changed && valid && max_iter-- > 0) {
            changed = false;
            for (int ci = 1; ci < entry.len && valid; ci++) {
                int kj = entry.word[ci], cj = ct[entry.pos + ci];
                bool kk = plug[kj] >= 0, ck = plug[cj] >= 0;
                if (kk && ck) {
                    if (R[ci][plug[kj]] != plug[cj]) valid = false;
                } else if (kk) {
                    int exp = R[ci][plug[kj]];
                    if (plug[cj] >= 0 && plug[cj] != exp) valid = false;
                    else if (cj != exp && plug[exp] >= 0 && plug[exp] != cj) valid = false;
                    else { plug[cj] = exp; if (cj != exp) plug[exp] = cj; changed = true; }
                } else if (ck) {
                    int exp = R[ci][plug[cj]];
                    if (plug[kj] >= 0 && plug[kj] != exp) valid = false;
                    else if (kj != exp && plug[exp] >= 0 && plug[exp] != kj) valid = false;
                    else { plug[kj] = exp; if (kj != exp) plug[exp] = kj; changed = true; }
                }
            }
        }
        if (valid) {
            memcpy(plug_out, plug, 26 * sizeof(int));
            return true;
        }
    }
    return false;
}

static struct option long_options[] = {
    {"file",       required_argument, 0, 'f'},
    {"cribs",      required_argument, 0, 'c'},
    {"crib",       required_argument, 0, 'w'},
    {"beam",       required_argument, 0, 'b'},
    {"min-len",    required_argument, 0, 'L'},
    {"navy",       no_argument,       0, 'N'},
    {"m4",         no_argument,       0, 'M'},
    {"help",       no_argument,       0, 'h'},
    {0, 0, 0, 0},
};

int main(int argc, char** argv) {
    char ciphertext[4096] = {};
    int ct_len = 0, ct_nums[4096];
    char crib_file[256] = {}, single_crib[64] = {};
    bool navy = false, m4 = false;
    int beam = 5000, min_crib_len = 6;

    int opt;
    while ((opt = getopt_long(argc, argv, "f:c:w:b:L:hNM", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'f': {
            FILE* fp = fopen(optarg, "r");
            if (!fp) { fprintf(stderr, "Cannot open %s\n", optarg); return 1; }
            ct_len = (int)fread(ciphertext, 1, sizeof(ciphertext) - 1, fp);
            fclose(fp); break;
        }
        case 'c': strncpy(crib_file, optarg, sizeof(crib_file) - 1); break;
        case 'w': strncpy(single_crib, optarg, sizeof(single_crib) - 1); break;
        case 'b': beam = atoi(optarg); break;
        case 'L': min_crib_len = atoi(optarg); break;
        case 'N': navy = true; break;
        case 'M': m4 = true; navy = true; break;
        case 'h':
            printf("Usage: crib_solver [options]\n"
                   "  -f, --file FILE     Ciphertext file\n"
                   "  -c, --cribs FILE    Crib dictionary file\n"
                   "  -w, --crib WORD     Single crib word to try\n"
                   "  -b, --beam N        IoC beam width (default: 5000)\n"
                   "  -L, --min-len N     Minimum crib length (default: 6)\n"
                   "      --navy          Navy mode: rotors I-VIII\n"
                   "      --m4            Navy M4 mode\n"
                   "  -h, --help          Show this help\n\n"
                   "Two-phase hybrid: GPU IoC filter → CPU Bombe crib check\n");
            return 0;
        default: break;
        }
    }
    if (!ciphertext[0] && optind < argc) strncpy(ciphertext, argv[optind], sizeof(ciphertext) - 1);
    if (!ciphertext[0]) { fprintf(stderr, "Error: no ciphertext\n"); return 1; }

    int j = 0;
    for (int i = 0; ciphertext[i]; i++) {
        char c = ciphertext[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        if (c >= 'A' && c <= 'Z') ciphertext[j++] = c;
    }
    ciphertext[j] = 0; ct_len = j;
    for (int i = 0; i < ct_len; i++) ct_nums[i] = ciphertext[i] - 'A';

    enigma::init(navy ? 8 : 5);
    enigma::init_bigrams();

    std::vector<CribWord> words;
    if (single_crib[0]) {
        CribWord w; w.text = single_crib; w.len = 0;
        for (int i = 0; single_crib[i] && w.len < 16; i++) {
            char c = single_crib[i]; if (c >= 'a' && c <= 'z') c -= 32;
            if (c >= 'A' && c <= 'Z') w.nums[w.len++] = c - 'A';
        }
        if (w.len >= 3) words.push_back(w);
    }
    if (crib_file[0]) { auto fw = load_cribs(crib_file); words.insert(words.end(), fw.begin(), fw.end()); }
    if (words.empty()) { fprintf(stderr, "Error: no cribs. Use -c or -w\n"); return 1; }

    auto entries = build_entries(words, ct_nums, ct_len, min_crib_len);
    printf("Ciphertext (%d chars): %.60s%s\n", ct_len, ciphertext, ct_len > 60 ? "..." : "");
    printf("Mode: %s | Rotors: %s (%d combos) | Beam: %d\n",
           m4 ? "M4 Crib" : "Crib", navy ? "I-VIII" : "I-V", enigma::NUM_COMBOS, beam);
    printf("Cribs: %d words (%d with len>=%d), %d valid (word, position) entries\n",
           (int)words.size(), (int)std::count_if(words.begin(), words.end(),
           [&](const CribWord& w){ return w.len >= min_crib_len; }), min_crib_len, (int)entries.size());
    if (entries.empty()) { printf("No valid crib positions.\n"); return 0; }

    // Metal setup for Phase 1: IoC filter
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) { fprintf(stderr, "Error: Metal not available\n"); return 1; }
        printf("GPU: %s\n", [[device name] UTF8String]);

        NSError* error = nil;
        id<MTLLibrary> library = [device newLibraryWithSource:
            [NSString stringWithUTF8String:IOC_SHADER] options:nil error:&error];
        if (!library) { fprintf(stderr, "Shader error: %s\n", [[error description] UTF8String]); return 1; }
        id<MTLFunction> function = [library newFunctionWithName:@"enigma_solve"];
        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:function error:&error];
        if (!pipeline) { fprintf(stderr, "Pipeline error: %s\n", [[error description] UTF8String]); return 1; }

        int total_per_pass = enigma::NUM_COMBOS * 17576;
        id<MTLBuffer> ct_buf = [device newBufferWithBytes:ct_nums length:ct_len * sizeof(int)
                                                  options:MTLResourceStorageModeShared];
        Params params = { ct_len, enigma::NUM_COMBOS };
        id<MTLBuffer> params_buf = [device newBufferWithBytes:&params length:sizeof(params)
                                                      options:MTLResourceStorageModeShared];
        id<MTLBuffer> results_buf = [device newBufferWithLength:total_per_pass * sizeof(float)
                                                        options:MTLResourceStorageModeShared];

        RotorData rd; memset(&rd, 0, sizeof(rd));
        for (int r = 0; r < (navy ? 8 : 5); r++) {
            for (int i = 0; i < 26; i++) {
                rd.forward[r][i] = enigma::WIRING[r][i];
                rd.reverse[r][i] = enigma::INV_WIRING[r][i];
            }
            rd.notch_a[r] = enigma::NOTCH_A[r]; rd.notch_b[r] = enigma::NOTCH_B[r];
        }
        for (int i = 0; i < enigma::NUM_COMBOS; i++) {
            rd.combos[i][0] = enigma::COMBOS[i].r[0];
            rd.combos[i][1] = enigma::COMBOS[i].r[1];
            rd.combos[i][2] = enigma::COMBOS[i].r[2];
        }

        struct PassConfig { int greek, thin_ref, gp; };
        std::vector<PassConfig> passes;
        if (m4) {
            for (int g = 0; g < 2; g++)
                for (int tr = 0; tr < 2; tr++)
                    for (int gp = 0; gp < 26; gp++)
                        passes.push_back({g, tr, gp});
        } else {
            passes.push_back({-1, 0, 0});
        }

        auto t0 = std::chrono::high_resolution_clock::now();
        std::vector<IoCSurvivor> survivors;
        double total_gpu_ms = 0;

        printf("\n=== Phase 1: GPU IoC filter (%d passes) ===\n", (int)passes.size());

        for (int pi = 0; pi < (int)passes.size(); pi++) {
            auto& pass = passes[pi];
            if (pass.greek >= 0)
                enigma::compute_composite_reflector(pass.greek, pass.thin_ref, pass.gp, 0, rd.reflector);
            else
                memcpy(rd.reflector, enigma::REFLECTOR_B, sizeof(rd.reflector));

            id<MTLBuffer> rotor_buf = [device newBufferWithBytes:&rd length:sizeof(rd)
                                                         options:MTLResourceStorageModeShared];
            id<MTLCommandQueue> queue = [device newCommandQueue];
            id<MTLCommandBuffer> cmdBuf = [queue commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [cmdBuf computeCommandEncoder];
            [encoder setComputePipelineState:pipeline];
            [encoder setBuffer:ct_buf offset:0 atIndex:0];
            [encoder setBuffer:rotor_buf offset:0 atIndex:1];
            [encoder setBuffer:params_buf offset:0 atIndex:2];
            [encoder setBuffer:results_buf offset:0 atIndex:3];
            MTLSize gridSize = MTLSizeMake(total_per_pass, 1, 1);
            NSUInteger gs = [pipeline maxTotalThreadsPerThreadgroup];
            if (gs > 256) gs = 256;
            [encoder dispatchThreads:gridSize threadsPerThreadgroup:MTLSizeMake(gs, 1, 1)];
            [encoder endEncoding];
            auto gt0 = std::chrono::high_resolution_clock::now();
            [cmdBuf commit];
            [cmdBuf waitUntilCompleted];
            auto gt1 = std::chrono::high_resolution_clock::now();
            total_gpu_ms += std::chrono::duration<double, std::milli>(gt1 - gt0).count();

            float* ioc_results = (float*)[results_buf contents];
            std::vector<int> indices(total_per_pass);
            std::iota(indices.begin(), indices.end(), 0);
            int keep = std::min(beam, total_per_pass);
            std::partial_sort(indices.begin(), indices.begin() + keep, indices.end(),
                              [ioc_results](int a, int b) { return ioc_results[a] > ioc_results[b]; });

            for (int i = 0; i < keep; i++) {
                int idx = indices[i];
                int combo = idx / 17576, posidx = idx % 17576;
                survivors.push_back({ioc_results[idx], combo,
                                     posidx / 676, (posidx / 26) % 26, posidx % 26,
                                     pass.greek, pass.thin_ref, pass.gp});
            }

            if ((pi + 1) % 26 == 0 || passes.size() == 1) {
                printf("  Pass %d/%d done (%.1fs GPU, %d survivors so far)\n",
                       pi + 1, (int)passes.size(), total_gpu_ms / 1000.0, (int)survivors.size());
            }
        }

        // Global top beam
        std::sort(survivors.begin(), survivors.end(),
                  [](const IoCSurvivor& a, const IoCSurvivor& b) { return a.ioc > b.ioc; });
        if ((int)survivors.size() > beam) survivors.resize(beam);
        printf("  Kept top %d by IoC (best: %.6f, worst: %.6f)\n",
               (int)survivors.size(), survivors.front().ioc, survivors.back().ioc);

        // Phase 2: CPU Bombe check — collect stops, rank by combined score
        printf("\n=== Phase 2: CPU Bombe check (%d configs × %d cribs) ===\n",
               (int)survivors.size(), (int)entries.size());

        struct BombeStop {
            int survivor_idx;
            int entry_idx;
            double raw_ioc;
            double bigram;
            int plug[26];
            int crib_len;
        };

        std::vector<BombeStop> stops;
        int total_bombe_hits = 0;
        auto t1 = std::chrono::high_resolution_clock::now();

        for (int si = 0; si < (int)survivors.size(); si++) {
            auto& s = survivors[si];
            int comp_refl[26];
            if (s.greek >= 0)
                enigma::compute_composite_reflector(s.greek, s.thin_ref, s.gp, 0, comp_refl);
            else
                memcpy(comp_refl, enigma::REFLECTOR_B, sizeof(comp_refl));

            for (int ei = 0; ei < (int)entries.size(); ei++) {
                int plug[26];
                if (bombe_check(s.combo_idx, s.lp, s.mp, s.rp, entries[ei], ct_nums, comp_refl, plug)) {
                    total_bombe_hits++;

                    // Build plugboard string and decrypt
                    char plug_str[128] = {};
                    int ps = 0;
                    for (int a = 0; a < 26; a++) {
                        if (plug[a] > a) {
                            if (ps > 0) plug_str[ps++] = ' ';
                            plug_str[ps++] = 'A' + a;
                            plug_str[ps++] = 'A' + plug[a];
                        }
                    }

                    enigma::Machine mf;
                    mf.setup(enigma::COMBOS[s.combo_idx].r[0], enigma::COMBOS[s.combo_idx].r[1],
                             enigma::COMBOS[s.combo_idx].r[2], 0, 0, 0, s.lp, s.mp, s.rp, comp_refl);
                    mf.set_plugboard(plug_str);
                    int fpt[4096];
                    mf.process(ct_nums, fpt, ct_len);
                    double bigram = enigma::calc_bigram(fpt, ct_len, enigma::DE_BIGRAMS);

                    BombeStop bs;
                    bs.survivor_idx = si;
                    bs.entry_idx = ei;
                    bs.raw_ioc = s.ioc;
                    bs.bigram = bigram;
                    bs.crib_len = entries[ei].len;
                    memcpy(bs.plug, plug, sizeof(plug));
                    stops.push_back(bs);
                }
            }
            if ((si + 1) % 1000 == 0) {
                auto now = std::chrono::high_resolution_clock::now();
                double elapsed = std::chrono::duration<double>(now - t1).count();
                printf("  ... %d/%d configs (%.1fs, %d Bombe hits)\n",
                       si + 1, (int)survivors.size(), elapsed, total_bombe_hits);
            }
        }

        auto t2 = std::chrono::high_resolution_clock::now();

        // Rank by: longer crib + higher bigram + higher raw IoC
        std::sort(stops.begin(), stops.end(), [](const BombeStop& a, const BombeStop& b) {
            double sa = a.crib_len * 2.0 + a.bigram + a.raw_ioc * 50.0;
            double sb = b.crib_len * 2.0 + b.bigram + b.raw_ioc * 50.0;
            return sa > sb;
        });

        int show = std::min(20, (int)stops.size());
        printf("\n--- Top %d of %d Bombe stops (ranked by crib_len + bigram + IoC) ---\n\n",
               show, (int)stops.size());

        for (int i = 0; i < show; i++) {
            auto& bs = stops[i];
            auto& s = survivors[bs.survivor_idx];
            auto& entry = entries[bs.entry_idx];

            char plug_str[128] = {};
            int ps = 0;
            for (int a = 0; a < 26; a++) {
                if (bs.plug[a] > a) {
                    if (ps > 0) plug_str[ps++] = ' ';
                    plug_str[ps++] = 'A' + a;
                    plug_str[ps++] = 'A' + bs.plug[a];
                }
            }

            enigma::Machine mf;
            int comp_refl[26];
            if (s.greek >= 0)
                enigma::compute_composite_reflector(s.greek, s.thin_ref, s.gp, 0, comp_refl);
            else
                memcpy(comp_refl, enigma::REFLECTOR_B, sizeof(comp_refl));
            mf.setup(enigma::COMBOS[s.combo_idx].r[0], enigma::COMBOS[s.combo_idx].r[1],
                     enigma::COMBOS[s.combo_idx].r[2], 0, 0, 0, s.lp, s.mp, s.rp, comp_refl);
            mf.set_plugboard(plug_str);
            int fpt[4096];
            mf.process(ct_nums, fpt, ct_len);
            char pt_str[4096];
            for (int k = 0; k < ct_len; k++) pt_str[k] = 'A' + fpt[k];
            pt_str[ct_len] = 0;

            char rotors_str[48];
            if (s.greek >= 0)
                snprintf(rotors_str, sizeof(rotors_str), "%s %s %s %s",
                         enigma::GREEK_NAMES[s.greek],
                         enigma::ROTOR_NAMES[enigma::COMBOS[s.combo_idx].r[0]],
                         enigma::ROTOR_NAMES[enigma::COMBOS[s.combo_idx].r[1]],
                         enigma::ROTOR_NAMES[enigma::COMBOS[s.combo_idx].r[2]]);
            else
                snprintf(rotors_str, sizeof(rotors_str), "%s %s %s",
                         enigma::ROTOR_NAMES[enigma::COMBOS[s.combo_idx].r[0]],
                         enigma::ROTOR_NAMES[enigma::COMBOS[s.combo_idx].r[1]],
                         enigma::ROTOR_NAMES[enigma::COMBOS[s.combo_idx].r[2]]);

            char start[8];
            if (s.greek >= 0)
                snprintf(start, sizeof(start), "%c%c%c%c", 'A'+s.gp, 'A'+s.lp, 'A'+s.mp, 'A'+s.rp);
            else
                snprintf(start, sizeof(start), "%c%c%c", 'A'+s.lp, 'A'+s.mp, 'A'+s.rp);

            printf("%3d. \"%s\" @%d | %s %s", i + 1,
                   words[entry.word_idx].text.c_str(), entry.pos, rotors_str, start);
            if (s.greek >= 0) printf(" %s", enigma::THIN_REF_NAMES[s.thin_ref]);
            printf(" | IoC=%.4f bg=%.2f plug=%s\n", s.ioc, bs.bigram,
                   plug_str[0] ? plug_str : "none");
            printf("     %s\n", pt_str);
        }

        double total_s = std::chrono::duration<double>(t2 - t0).count();
        printf("\n==========================================================================================\n");
        printf("Done: GPU %.1fs + CPU %.1fs = %.1fs total\n",
               total_gpu_ms / 1000.0,
               std::chrono::duration<double>(t2 - t1).count(),
               total_s);
        printf("Phase 1: %d configs survived IoC filter\n", (int)survivors.size());
        printf("Phase 2: %d Bombe stops, top %d shown\n", (int)stops.size(), show);
        printf("==========================================================================================\n");
    }
    return 0;
}
