#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#include "enigma.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>
#include <numeric>
#include <chrono>
#include <set>
#include <getopt.h>

static const char* METAL_SHADER = R"(
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
        bool mid_notch = (pos_m == notch_m_a) ||
                         (notch_m_b >= 0 && pos_m == notch_m_b);
        bool right_notch = (pos_r == notch_r_a) ||
                           (notch_r_b >= 0 && pos_r == notch_r_b);
        pos_r = (pos_r + 1) % 26;
        if (right_notch || mid_notch) pos_m = (pos_m + 1) % 26;
        if (mid_notch) pos_l = (pos_l + 1) % 26;

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
    for (int i = 0; i < 26; i++) {
        sum += (float)(freq[i] * (freq[i] - 1));
    }
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

const int* get_reflector(int idx) {
    return idx == 0 ? enigma::REFLECTOR_B : enigma::REFLECTOR_C;
}

void get_reflector_for_candidate(const Candidate& c, int* out) {
    if (c.greek_rotor >= 0) {
        enigma::compute_composite_reflector(c.greek_rotor, c.thin_ref_idx,
                                            c.gp, c.gr, out);
    } else {
        const int* src = get_reflector(c.thin_ref_idx >= 0 ? c.thin_ref_idx : 0);
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

static struct option long_options[] = {
    {"file",               required_argument, 0, 'f'},
    {"lang",               required_argument, 0, 'l'},
    {"beam",               required_argument, 0, 'b'},
    {"reflector",          required_argument, 0, 'r'},
    {"plugboard",          no_argument,       0, 'p'},
    {"output",             required_argument, 0, 'o'},
    {"show",               required_argument, 0, 'n'},
    {"navy",               no_argument,       0, 'N'},
    {"m4",                 no_argument,       0, 'M'},
    {"quick-pass",         no_argument,       0, 'q'},
    {"quick-pass-pct",     required_argument, 0, 'Q'},
    {"help",               no_argument,       0, 'h'},
    {0, 0, 0, 0},
};

int main(int argc, char** argv) {
    char ciphertext[4096] = {};
    int ct_len = 0;
    int ct_nums[4096];
    int beam = 50, show_n = 10;
    bool use_german = true, do_plugboard = false;
    bool quick_pass = false, navy = false, m4 = false;
    int quick_pass_pct = 25;
    int reflector_idx = 0;
    char output_file[256] = {};

    int opt;
    while ((opt = getopt_long(argc, argv, "f:l:b:r:po:n:qQ:hNM", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'f': {
            FILE* fp = fopen(optarg, "r");
            if (!fp) { fprintf(stderr, "Cannot open %s\n", optarg); return 1; }
            ct_len = (int)fread(ciphertext, 1, sizeof(ciphertext) - 1, fp);
            fclose(fp);
            break;
        }
        case 'l': use_german = (strcmp(optarg, "german") == 0); break;
        case 'b': beam = atoi(optarg); break;
        case 'r':
            if (strcmp(optarg, "C") == 0) reflector_idx = 1;
            break;
        case 'p': do_plugboard = true; break;
        case 'o': strncpy(output_file, optarg, sizeof(output_file) - 1); break;
        case 'n': show_n = atoi(optarg); break;
        case 'N': navy = true; break;
        case 'M': m4 = true; navy = true; break;
        case 'q': quick_pass = true; break;
        case 'Q': quick_pass_pct = atoi(optarg); break;
        case 'h':
            printf("Usage: solver_gpu [options] <ciphertext>\n"
                   "  -f, --file FILE         Read ciphertext from file\n"
                   "  -l, --lang LANG         english|german (default: german)\n"
                   "  -b, --beam N            Beam width (default: 50)\n"
                   "  -r, --reflector REF     B|C (default: B)\n"
                   "  -p, --plugboard         Run plugboard hill climbing\n"
                   "  -o, --output FILE       Save settings to JSON\n"
                   "  -n, --show N            Results to show (default: 10)\n"
                   "      --navy              Navy mode: rotors I-VIII (336 combos)\n"
                   "      --m4                Navy M4 mode (uses composite reflectors on GPU)\n"
                   "  -q, --quick-pass        Prune combos by peak IoC\n"
                   "  -Q, --quick-pass-pct N  Keep top N%% (default: 25)\n"
                   "  -h, --help              Show this help\n");
            return 0;
        }
    }

    if (!ciphertext[0] && optind < argc)
        strncpy(ciphertext, argv[optind], sizeof(ciphertext) - 1);
    if (!ciphertext[0]) { fprintf(stderr, "Error: no ciphertext\n"); return 1; }

    int j = 0;
    for (int i = 0; ciphertext[i]; i++) {
        char c = ciphertext[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        if (c >= 'A' && c <= 'Z') ciphertext[j++] = c;
    }
    ciphertext[j] = 0;
    ct_len = j;
    for (int i = 0; i < ct_len; i++) ct_nums[i] = ciphertext[i] - 'A';

    int num_rotors = navy ? 8 : 5;
    enigma::init(num_rotors);
    enigma::init_bigrams();

    printf("Ciphertext (%d chars): %.60s%s\n", ct_len, ciphertext,
           ct_len > 60 ? "..." : "");
    printf("Language: %s | Beam: %d | Mode: Metal GPU%s\n",
           use_german ? "german" : "english", beam, m4 ? " (M4)" : "");
    printf("Rotors: %s (%d permutations)\n",
           navy ? "I-VIII" : "I-V", enigma::NUM_COMBOS);

    if (ct_len < 50)
        fprintf(stderr, "WARNING: %d chars is very short — IoC overlaps heavily with random.\n", ct_len);
    else if (ct_len < 100)
        fprintf(stderr, "NOTE: %d chars is short. IoC separation from random is marginal.\n", ct_len);

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) {
            fprintf(stderr, "Error: Metal not available\n");
            return 1;
        }
        printf("GPU: %s\n", [[device name] UTF8String]);

        NSError* error = nil;
        NSString* source = [NSString stringWithUTF8String:METAL_SHADER];
        id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
        if (!library) {
            fprintf(stderr, "Shader compile error: %s\n", [[error description] UTF8String]);
            return 1;
        }

        id<MTLFunction> function = [library newFunctionWithName:@"enigma_solve"];
        if (!function) {
            fprintf(stderr, "Error: kernel function not found\n");
            return 1;
        }

        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:function error:&error];
        if (!pipeline) {
            fprintf(stderr, "Pipeline error: %s\n", [[error description] UTF8String]);
            return 1;
        }

        printf("Max threads/group: %lu\n", (unsigned long)[pipeline maxTotalThreadsPerThreadgroup]);

        const float (*bigrams)[26] = use_german ? enigma::DE_BIGRAMS : enigma::EN_BIGRAMS;
        auto t0 = std::chrono::high_resolution_clock::now();

        // For M4: loop over (Greek, thin_ref, Greek_pos) with composite reflectors
        // For 3-rotor: single pass with standard reflector
        struct GpuPass {
            int greek_rotor;    // -1 for 3-rotor
            int thin_ref_idx;   // -1 for 3-rotor
            int gp;             // Greek position
            int reflector[26];
        };

        std::vector<GpuPass> passes;
        if (m4) {
            for (int greek = 0; greek < 2; greek++) {
                for (int tr = 0; tr < 2; tr++) {
                    for (int gp = 0; gp < 26; gp++) {
                        GpuPass p;
                        p.greek_rotor = greek;
                        p.thin_ref_idx = tr;
                        p.gp = gp;
                        enigma::compute_composite_reflector(greek, tr, gp, 0, p.reflector);
                        passes.push_back(p);
                    }
                }
            }
        } else {
            GpuPass p;
            p.greek_rotor = -1;
            p.thin_ref_idx = reflector_idx;
            p.gp = 0;
            memcpy(p.reflector, get_reflector(reflector_idx), 26 * sizeof(int));
            passes.push_back(p);
        }

        int total_per_pass = enigma::NUM_COMBOS * 17576;
        std::vector<Candidate> all_candidates;

        id<MTLBuffer> ct_buf = [device newBufferWithBytes:ct_nums
                                                   length:ct_len * sizeof(int)
                                                  options:MTLResourceStorageModeShared];

        RotorData rd;
        memset(&rd, 0, sizeof(rd));
        for (int r = 0; r < num_rotors; r++) {
            for (int i = 0; i < 26; i++) {
                rd.forward[r][i] = enigma::WIRING[r][i];
                rd.reverse[r][i] = enigma::INV_WIRING[r][i];
            }
            rd.notch_a[r] = enigma::NOTCH_A[r];
            rd.notch_b[r] = enigma::NOTCH_B[r];
        }
        for (int i = 0; i < enigma::NUM_COMBOS; i++) {
            rd.combos[i][0] = enigma::COMBOS[i].r[0];
            rd.combos[i][1] = enigma::COMBOS[i].r[1];
            rd.combos[i][2] = enigma::COMBOS[i].r[2];
        }

        Params params = { ct_len, enigma::NUM_COMBOS };
        id<MTLBuffer> params_buf = [device newBufferWithBytes:&params
                                                       length:sizeof(params)
                                                      options:MTLResourceStorageModeShared];
        id<MTLBuffer> results_buf = [device newBufferWithLength:total_per_pass * sizeof(float)
                                                        options:MTLResourceStorageModeShared];

        int pass_count = 0;
        int prev_greek = -2, prev_tr = -2;
        double total_gpu_ms = 0;

        for (auto& pass : passes) {
            if (m4 && (pass.greek_rotor != prev_greek || pass.thin_ref_idx != prev_tr)) {
                printf("\n--- M4: %s + %s — %d combos × %d positions on GPU ---\n",
                       enigma::GREEK_NAMES[pass.greek_rotor],
                       enigma::THIN_REF_NAMES[pass.thin_ref_idx],
                       enigma::NUM_COMBOS, 26 * 17576);
                prev_greek = pass.greek_rotor;
                prev_tr = pass.thin_ref_idx;
            } else if (!m4 && pass_count == 0) {
                printf("\n--- Phase 1: %d configurations on GPU ---\n", total_per_pass);
            }

            memcpy(rd.reflector, pass.reflector, sizeof(rd.reflector));
            id<MTLBuffer> rotor_buf = [device newBufferWithBytes:&rd
                                                          length:sizeof(rd)
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
            NSUInteger groupSize = [pipeline maxTotalThreadsPerThreadgroup];
            if (groupSize > 256) groupSize = 256;
            MTLSize threadgroupSize = MTLSizeMake(groupSize, 1, 1);

            auto gt0 = std::chrono::high_resolution_clock::now();
            [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadgroupSize];
            [encoder endEncoding];
            [cmdBuf commit];
            [cmdBuf waitUntilCompleted];
            auto gt1 = std::chrono::high_resolution_clock::now();
            double gpu_ms = std::chrono::duration<double, std::milli>(gt1 - gt0).count();
            total_gpu_ms += gpu_ms;

            if ([cmdBuf error]) {
                fprintf(stderr, "GPU error: %s\n", [[[cmdBuf error] description] UTF8String]);
                return 1;
            }

            float* ioc_results = (float*)[results_buf contents];

            std::vector<int> indices(total_per_pass);
            std::iota(indices.begin(), indices.end(), 0);
            std::partial_sort(indices.begin(),
                              indices.begin() + std::min(beam, total_per_pass),
                              indices.end(),
                              [ioc_results](int a, int b) { return ioc_results[a] > ioc_results[b]; });

            for (int i = 0; i < beam && i < total_per_pass; i++) {
                int idx = indices[i];
                int combo = idx / 17576;
                int posidx = idx % 17576;
                Candidate c = {};
                c.ioc = ioc_results[idx];
                c.combo_idx = combo;
                c.lp = posidx / 676;
                c.mp = (posidx / 26) % 26;
                c.rp = posidx % 26;
                c.greek_rotor = pass.greek_rotor;
                c.thin_ref_idx = pass.thin_ref_idx;
                c.gp = pass.gp;
                c.gr = 0;
                c.pt_len = ct_len;
                all_candidates.push_back(c);
            }

            pass_count++;
            if (m4 && pass_count % 26 == 0) {
                std::sort(all_candidates.begin(), all_candidates.end(),
                          [](const Candidate& a, const Candidate& b) { return a.ioc > b.ioc; });
                printf("  Best IoC: %.6f  (%s %s %s %s @ %c%c%c%c) [%.1f ms GPU]\n",
                       all_candidates[0].ioc,
                       enigma::GREEK_NAMES[all_candidates[0].greek_rotor],
                       enigma::ROTOR_NAMES[enigma::COMBOS[all_candidates[0].combo_idx].r[0]],
                       enigma::ROTOR_NAMES[enigma::COMBOS[all_candidates[0].combo_idx].r[1]],
                       enigma::ROTOR_NAMES[enigma::COMBOS[all_candidates[0].combo_idx].r[2]],
                       'A' + all_candidates[0].gp,
                       'A' + all_candidates[0].lp,
                       'A' + all_candidates[0].mp,
                       'A' + all_candidates[0].rp,
                       total_gpu_ms);
            }
        }

        if (!m4) {
            printf("  Done in %.2f ms (%.0f decryptions/sec)\n", total_gpu_ms,
                   total_per_pass / (total_gpu_ms / 1000.0));
        }

        // Keep global top beam
        std::sort(all_candidates.begin(), all_candidates.end(),
                  [](const Candidate& a, const Candidate& b) { return a.ioc > b.ioc; });
        if ((int)all_candidates.size() > beam)
            all_candidates.resize(beam);

        if (!m4) {
            printf("  Best IoC: %.6f  (%s %s %s @ %c%c%c)\n", all_candidates[0].ioc,
                   enigma::ROTOR_NAMES[enigma::COMBOS[all_candidates[0].combo_idx].r[0]],
                   enigma::ROTOR_NAMES[enigma::COMBOS[all_candidates[0].combo_idx].r[1]],
                   enigma::ROTOR_NAMES[enigma::COMBOS[all_candidates[0].combo_idx].r[2]],
                   'A' + all_candidates[0].lp, 'A' + all_candidates[0].mp,
                   'A' + all_candidates[0].rp);
        }

        // Quick pass filtering
        if (quick_pass && !m4) {
            int keep_n = std::max(1, enigma::NUM_COMBOS * quick_pass_pct / 100);
            printf("\n--- Quick pass: keeping top %d%% (%d combos) ---\n",
                   quick_pass_pct, keep_n);
            float* ioc_results = (float*)[results_buf contents];

            struct CS { float peak; int idx; };
            std::vector<CS> cscores(enigma::NUM_COMBOS);
            for (int ci = 0; ci < enigma::NUM_COMBOS; ci++) {
                float peak = 0;
                int base = ci * 17576;
                for (int p = 0; p < 17576; p++)
                    if (ioc_results[base + p] > peak) peak = ioc_results[base + p];
                cscores[ci] = {peak, ci};
            }
            std::partial_sort(cscores.begin(), cscores.begin() + keep_n, cscores.end(),
                              [](const CS& a, const CS& b) { return a.peak > b.peak; });

            std::set<int> surviving;
            for (int i = 0; i < keep_n; i++) surviving.insert(cscores[i].idx);

            std::vector<Candidate> filtered;
            for (auto& c : all_candidates) {
                if (surviving.count(c.combo_idx))
                    filtered.push_back(c);
            }
            if ((int)filtered.size() >= beam)
                all_candidates = filtered;
        }

        // Ring refinement (CPU)
        for (int ring_idx = 0; ring_idx < 3; ring_idx++) {
            const char* names[] = {"left", "middle", "right"};
            printf("\n--- Ring %s: top %d × 26 (CPU) ---\n", names[ring_idx], beam);

            std::vector<Candidate> expanded;
            expanded.reserve(beam * 26);

            for (auto& c : all_candidates) {
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
                    m.process(ct_nums, nc.plaintext, ct_len);
                    nc.ioc = enigma::calc_ioc(nc.plaintext, ct_len);
                    expanded.push_back(nc);
                }
            }

            std::partial_sort(expanded.begin(),
                              expanded.begin() + std::min(beam, (int)expanded.size()),
                              expanded.end(),
                              [](const Candidate& a, const Candidate& b) { return a.ioc > b.ioc; });
            all_candidates.assign(expanded.begin(),
                              expanded.begin() + std::min(beam, (int)expanded.size()));
            printf("  Best IoC: %.6f  (rings=%d,%d,%d)\n",
                   all_candidates[0].ioc, all_candidates[0].lr,
                   all_candidates[0].mr, all_candidates[0].rr);
        }

        // Final bigram scoring
        for (auto& c : all_candidates) {
            int comp_refl[26];
            get_reflector_for_candidate(c, comp_refl);
            enigma::Machine m;
            m.setup(enigma::COMBOS[c.combo_idx].r[0],
                    enigma::COMBOS[c.combo_idx].r[1],
                    enigma::COMBOS[c.combo_idx].r[2],
                    c.lr, c.mr, c.rr,
                    c.lp, c.mp, c.rp, comp_refl);
            m.process(ct_nums, c.plaintext, ct_len);
            c.bigram = enigma::calc_bigram(c.plaintext, ct_len, bigrams);
        }

        std::sort(all_candidates.begin(), all_candidates.end(),
                  [](const Candidate& a, const Candidate& b) { return a.bigram > b.bigram; });

        if (do_plugboard && !all_candidates.empty()) {
            printf("\n--- Plugboard hill climbing ---\n");
            hill_climb_plugboard(all_candidates[0], ct_nums, ct_len, bigrams);
        }

        auto t2 = std::chrono::high_resolution_clock::now();
        double total_ms = std::chrono::duration<double, std::milli>(t2 - t0).count();

        printf("\n==========================================================================================\n");
        printf("Done in %.1f ms total (GPU: %.2f ms)\n", total_ms, total_gpu_ms);
        printf("==========================================================================================\n");

        display_results(all_candidates, show_n, m4);

        if (do_plugboard && !all_candidates.empty() && all_candidates[0].plugboard[0]) {
            char pt_str[4096];
            for (int i = 0; i < all_candidates[0].pt_len; i++)
                pt_str[i] = 'A' + all_candidates[0].plaintext[i];
            pt_str[all_candidates[0].pt_len] = 0;
            printf("\nBest plugboard: %s\nFull plaintext: %s\n",
                   all_candidates[0].plugboard, pt_str);
        }

        if (output_file[0] && !all_candidates.empty()) {
            FILE* f = fopen(output_file, "w");
            if (f) {
                auto& c = all_candidates[0];
                char rotors[48];
                if (m4 && c.greek_rotor >= 0)
                    snprintf(rotors, sizeof(rotors), "%s %s %s %s",
                             enigma::GREEK_NAMES[c.greek_rotor],
                             enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[0]],
                             enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[1]],
                             enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[2]]);
                else
                    snprintf(rotors, sizeof(rotors), "%s %s %s",
                             enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[0]],
                             enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[1]],
                             enigma::ROTOR_NAMES[enigma::COMBOS[c.combo_idx].r[2]]);
                char pt_str[4096];
                for (int i = 0; i < c.pt_len; i++) pt_str[i] = 'A' + c.plaintext[i];
                pt_str[c.pt_len] = 0;
                fprintf(f, "{\n  \"rotors\": \"%s\",\n  \"ioc\": %.6f,\n  \"bigram_score\": %.4f,\n  \"plaintext\": \"%s\"\n}\n",
                        rotors, c.ioc, c.bigram, pt_str);
                fclose(f);
                printf("\nSettings saved to %s\n", output_file);
            }
        }
    }

    return 0;
}
