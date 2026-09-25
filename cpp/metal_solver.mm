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
    int forward[5][26];
    int reverse[5][26];
    int notch[5];
    int reflector[26];
    int combos[60][3];
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

    // Copy wiring to thread-local storage
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

    int notch_l = rotors.notch[lr];
    int notch_m = rotors.notch[mr];
    int notch_r = rotors.notch[rr];

    int pos_l = left_pos, pos_m = mid_pos, pos_r = right_pos;

    int freq[26];
    for (int i = 0; i < 26; i++) freq[i] = 0;

    for (int i = 0; i < params.ct_length; i++) {
        // Step rotors
        bool mid_notch = (pos_m == notch_m);
        bool right_notch = (pos_r == notch_r);
        pos_r = (pos_r + 1) % 26;
        if (right_notch || mid_notch) pos_m = (pos_m + 1) % 26;
        if (mid_notch) pos_l = (pos_l + 1) % 26;

        // Signal path (no plugboard for initial search)
        int sig = ciphertext[i];

        // Forward: right -> middle -> left
        sig = (fwd_r[(sig + pos_r) % 26] - pos_r + 26) % 26;
        sig = (fwd_m[(sig + pos_m) % 26] - pos_m + 26) % 26;
        sig = (fwd_l[(sig + pos_l) % 26] - pos_l + 26) % 26;

        // Reflector
        sig = rotors.reflector[sig];

        // Reverse: left -> middle -> right
        sig = (rev_l[(sig + pos_l) % 26] - pos_l + 26) % 26;
        sig = (rev_m[(sig + pos_m) % 26] - pos_m + 26) % 26;
        sig = (rev_r[(sig + pos_r) % 26] - pos_r + 26) % 26;

        freq[sig]++;
    }

    // IoC
    int n = params.ct_length;
    float sum = 0.0f;
    for (int i = 0; i < 26; i++) {
        sum += (float)(freq[i] * (freq[i] - 1));
    }
    results[tid] = sum / (float)(n * (n - 1));
}
)";

struct RotorData {
    int forward[5][26];
    int reverse[5][26];
    int notch[5];
    int reflector[26];
    int combos[60][3];
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

int main(int argc, char** argv) {
    char ciphertext[4096] = {};
    int ct_len = 0;
    int ct_nums[4096];
    int beam = 50, show_n = 10;
    bool use_german = true, do_plugboard = false;
    (void)do_plugboard;
    bool quick_pass = false;
    int quick_pass_pct = 25;
    char output_file[256] = {};

    int opt;
    while ((opt = getopt(argc, argv, "f:l:b:r:po:n:qQ:h")) != -1) {
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
        case 'p': do_plugboard = true; break;
        case 'o': strncpy(output_file, optarg, sizeof(output_file) - 1); break;
        case 'n': show_n = atoi(optarg); break;
        case 'q': quick_pass = true; break;
        case 'Q': quick_pass_pct = atoi(optarg); break;
        case 'h':
            printf("Usage: solver_gpu [options] <ciphertext>\n"
                   "  -q        Quick pass: prune combos by peak IoC before ring refinement\n"
                   "  -Q N      Quick pass: keep top N%% (default: 25)\n");
            return 0;
        }
    }

    if (!ciphertext[0] && optind < argc)
        strncpy(ciphertext, argv[optind], sizeof(ciphertext) - 1);
    if (!ciphertext[0]) { fprintf(stderr, "Error: no ciphertext\n"); return 1; }

    // Clean input
    int j = 0;
    for (int i = 0; ciphertext[i]; i++) {
        char c = ciphertext[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        if (c >= 'A' && c <= 'Z') ciphertext[j++] = c;
    }
    ciphertext[j] = 0;
    ct_len = j;
    for (int i = 0; i < ct_len; i++) ct_nums[i] = ciphertext[i] - 'A';

    enigma::init();
    enigma::init_bigrams();

    printf("Ciphertext (%d chars): %.60s%s\n", ct_len, ciphertext,
           ct_len > 60 ? "..." : "");
    printf("Language: %s | Beam: %d | Mode: Metal GPU\n",
           use_german ? "german" : "english", beam);

    // --- Metal setup ---
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) {
            fprintf(stderr, "Error: Metal not available\n");
            return 1;
        }
        printf("GPU: %s\n", [[device name] UTF8String]);

        // Compile shader at runtime
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

        // Prepare buffers
        int total = enigma::NUM_COMBOS * 17576;

        // Buffer 0: ciphertext (as int array)
        id<MTLBuffer> ct_buf = [device newBufferWithBytes:ct_nums
                                                   length:ct_len * sizeof(int)
                                                  options:MTLResourceStorageModeShared];

        // Buffer 1: RotorData
        RotorData rd;
        for (int r = 0; r < 5; r++) {
            for (int i = 0; i < 26; i++) {
                rd.forward[r][i] = enigma::WIRING[r][i];
                rd.reverse[r][i] = enigma::INV_WIRING[r][i];
            }
            rd.notch[r] = enigma::NOTCH[r];
        }
        memcpy(rd.reflector, enigma::REFLECTOR_B, sizeof(rd.reflector));
        for (int i = 0; i < enigma::NUM_COMBOS; i++) {
            rd.combos[i][0] = enigma::COMBOS[i].r[0];
            rd.combos[i][1] = enigma::COMBOS[i].r[1];
            rd.combos[i][2] = enigma::COMBOS[i].r[2];
        }

        id<MTLBuffer> rotor_buf = [device newBufferWithBytes:&rd
                                                      length:sizeof(rd)
                                                     options:MTLResourceStorageModeShared];

        // Buffer 2: Params
        Params params = { ct_len, enigma::NUM_COMBOS };
        id<MTLBuffer> params_buf = [device newBufferWithBytes:&params
                                                       length:sizeof(params)
                                                      options:MTLResourceStorageModeShared];

        // Buffer 3: Results
        id<MTLBuffer> results_buf = [device newBufferWithLength:total * sizeof(float)
                                                        options:MTLResourceStorageModeShared];

        // Dispatch
        id<MTLCommandQueue> queue = [device newCommandQueue];
        id<MTLCommandBuffer> cmdBuf = [queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [cmdBuf computeCommandEncoder];

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:ct_buf offset:0 atIndex:0];
        [encoder setBuffer:rotor_buf offset:0 atIndex:1];
        [encoder setBuffer:params_buf offset:0 atIndex:2];
        [encoder setBuffer:results_buf offset:0 atIndex:3];

        MTLSize gridSize = MTLSizeMake(total, 1, 1);
        NSUInteger groupSize = [pipeline maxTotalThreadsPerThreadgroup];
        if (groupSize > 256) groupSize = 256;
        MTLSize threadgroupSize = MTLSizeMake(groupSize, 1, 1);

        printf("\n--- Phase 1: %d configurations on GPU ---\n", total);
        auto t0 = std::chrono::high_resolution_clock::now();

        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadgroupSize];
        [encoder endEncoding];
        [cmdBuf commit];
        [cmdBuf waitUntilCompleted];

        auto t1 = std::chrono::high_resolution_clock::now();
        double gpu_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        if ([cmdBuf error]) {
            fprintf(stderr, "GPU error: %s\n", [[[cmdBuf error] description] UTF8String]);
            return 1;
        }

        float* ioc_results = (float*)[results_buf contents];
        printf("  Done in %.2f ms (%.0f decryptions/sec)\n", gpu_ms,
               total / (gpu_ms / 1000.0));

        // Sort top-N
        std::vector<int> indices(total);
        std::iota(indices.begin(), indices.end(), 0);
        std::partial_sort(indices.begin(), indices.begin() + beam, indices.end(),
                          [ioc_results](int a, int b) { return ioc_results[a] > ioc_results[b]; });

        int best_idx = indices[0];
        int best_combo = best_idx / 17576;
        int best_pos = best_idx % 17576;
        printf("  Best IoC: %.6f  (%s %s %s @ %c%c%c)\n", ioc_results[best_idx],
               enigma::ROTOR_NAMES[enigma::COMBOS[best_combo].r[0]],
               enigma::ROTOR_NAMES[enigma::COMBOS[best_combo].r[1]],
               enigma::ROTOR_NAMES[enigma::COMBOS[best_combo].r[2]],
               'A' + best_pos / 676, 'A' + (best_pos / 26) % 26, 'A' + best_pos % 26);

        // Build candidates (with optional quick-pass combo filtering)
        const float (*bigrams)[26] = use_german ? enigma::DE_BIGRAMS : enigma::EN_BIGRAMS;
        std::vector<Candidate> candidates;

        if (quick_pass) {
            int keep_n = std::max(1, enigma::NUM_COMBOS * quick_pass_pct / 100);
            printf("\n--- Quick pass: ranking %d combos by peak IoC, keeping top %d%% (%d) ---\n",
                   enigma::NUM_COMBOS, quick_pass_pct, keep_n);

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
            printf("  Best: %s %s %s (peak %.6f)\n",
                   enigma::ROTOR_NAMES[enigma::COMBOS[cscores[0].idx].r[0]],
                   enigma::ROTOR_NAMES[enigma::COMBOS[cscores[0].idx].r[1]],
                   enigma::ROTOR_NAMES[enigma::COMBOS[cscores[0].idx].r[2]], cscores[0].peak);

            std::set<int> surviving;
            for (int i = 0; i < keep_n; i++) surviving.insert(cscores[i].idx);

            int found = 0;
            for (int i = 0; i < total && found < beam; i++) {
                int ci = indices[i] / 17576;
                if (surviving.count(ci)) {
                    int posidx = indices[i] % 17576;
                    Candidate c = {};
                    c.ioc = ioc_results[indices[i]];
                    c.combo_idx = ci;
                    c.lp = posidx / 676;
                    c.mp = (posidx / 26) % 26;
                    c.rp = posidx % 26;
                    c.pt_len = ct_len;
                    candidates.push_back(c);
                    found++;
                }
            }
        } else {
            candidates.resize(beam);
            for (int i = 0; i < beam; i++) {
                int idx = indices[i];
                int combo = idx / 17576;
                int posidx = idx % 17576;
                candidates[i].ioc = ioc_results[idx];
                candidates[i].combo_idx = combo;
                candidates[i].lp = posidx / 676;
                candidates[i].mp = (posidx / 26) % 26;
                candidates[i].rp = posidx % 26;
                candidates[i].lr = candidates[i].mr = candidates[i].rr = 0;
                candidates[i].plugboard[0] = 0;
                candidates[i].pt_len = ct_len;
            }
        }

        printf("  Best IoC: %.6f  (%s %s %s @ %c%c%c)\n", candidates[0].ioc,
               enigma::ROTOR_NAMES[enigma::COMBOS[candidates[0].combo_idx].r[0]],
               enigma::ROTOR_NAMES[enigma::COMBOS[candidates[0].combo_idx].r[1]],
               enigma::ROTOR_NAMES[enigma::COMBOS[candidates[0].combo_idx].r[2]],
               'A' + candidates[0].lp, 'A' + candidates[0].mp, 'A' + candidates[0].rp);

        // Ring refinement (CPU)
        const int* reflector = enigma::REFLECTOR_B;
        for (int ring_idx = 0; ring_idx < 3; ring_idx++) {
            const char* names[] = {"left", "middle", "right"};
            printf("\n--- Phase %d: top %d × 26 %s ring settings (CPU) ---\n",
                   ring_idx + 2, beam, names[ring_idx]);

            std::vector<Candidate> expanded;
            expanded.reserve(beam * 26);

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
                    m.process(ct_nums, nc.plaintext, ct_len);
                    nc.ioc = enigma::calc_ioc(nc.plaintext, ct_len);
                    expanded.push_back(nc);
                }
            }

            std::partial_sort(expanded.begin(),
                              expanded.begin() + std::min(beam, (int)expanded.size()),
                              expanded.end(),
                              [](const Candidate& a, const Candidate& b) { return a.ioc > b.ioc; });
            candidates.assign(expanded.begin(),
                              expanded.begin() + std::min(beam, (int)expanded.size()));
            printf("  Best IoC: %.6f  (rings=%d,%d,%d)\n",
                   candidates[0].ioc, candidates[0].lr, candidates[0].mr, candidates[0].rr);
        }

        // Final bigram scoring
        for (auto& c : candidates) {
            enigma::Machine m;
            m.setup(enigma::COMBOS[c.combo_idx].r[0],
                    enigma::COMBOS[c.combo_idx].r[1],
                    enigma::COMBOS[c.combo_idx].r[2],
                    c.lr, c.mr, c.rr,
                    c.lp, c.mp, c.rp, reflector);
            m.process(ct_nums, c.plaintext, ct_len);
            c.bigram = enigma::calc_bigram(c.plaintext, ct_len, bigrams);
        }

        std::sort(candidates.begin(), candidates.end(),
                  [](const Candidate& a, const Candidate& b) { return a.bigram > b.bigram; });

        auto t2 = std::chrono::high_resolution_clock::now();
        double total_ms = std::chrono::duration<double, std::milli>(t2 - t0).count();

        printf("\n==========================================================================================\n");
        printf("Done in %.1f ms total (GPU: %.2f ms)\n", total_ms, gpu_ms);
        printf("==========================================================================================\n");

        display_results(candidates, show_n);
    }

    return 0;
}
