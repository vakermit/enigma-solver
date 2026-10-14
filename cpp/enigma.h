#pragma once
#include <cstdint>
#include <cstring>
#include <cmath>

namespace enigma {

static const int NUM_BASE_ROTORS = 8;

// Rotor forward wiring (A=0..Z=25): I-VIII
static const int WIRING[8][26] = {
    {4,10,12,5,11,6,3,16,21,25,13,19,14,22,24,7,23,20,18,15,0,8,1,17,2,9},
    {0,9,3,10,18,8,17,20,23,1,11,7,22,19,12,2,16,6,25,13,15,24,5,21,14,4},
    {1,3,5,7,9,11,2,15,17,19,23,21,25,13,24,4,8,22,6,0,10,12,20,18,16,14},
    {4,18,14,21,15,25,9,0,24,16,20,8,17,7,23,11,13,5,19,6,10,3,2,12,22,1},
    {21,25,1,17,6,8,19,24,20,15,18,3,13,7,11,23,0,22,12,9,16,14,5,4,2,10},
    {9,15,6,21,14,20,12,5,24,16,1,4,13,7,25,17,3,10,0,18,23,11,8,2,19,22},
    {13,25,9,7,6,17,2,23,12,24,18,22,1,14,20,5,0,8,21,11,15,4,10,16,3,19},
    {5,10,16,7,19,11,23,14,2,1,9,18,15,3,25,17,0,12,4,22,13,8,20,24,6,21},
};

static int INV_WIRING[8][26];

// Greek rotors for M4 (0=Beta, 1=Gamma)
static const int GREEK_WIRING[2][26] = {
    {11,4,24,9,21,2,13,8,23,22,15,1,16,12,3,17,19,0,10,25,6,5,20,7,14,18},
    {5,18,14,10,0,13,20,4,17,7,12,1,19,8,24,2,22,11,16,15,25,23,21,6,9,3},
};
static int INV_GREEK_WIRING[2][26];

// Turnover notches: I=Q(16), II=E(4), III=V(21), IV=J(9), V=Z(25)
// VI/VII/VIII have double notches at Z(25) and M(12)
static const int NOTCH_A[8] = {16, 4, 21, 9, 25, 25, 25, 25};
static const int NOTCH_B[8] = {-1, -1, -1, -1, -1, 12, 12, 12};

static const int REFLECTOR_B[26] = {24,17,20,7,16,18,11,3,15,23,13,6,14,10,12,8,4,1,5,25,2,22,21,9,0,19};
static const int REFLECTOR_C[26] = {5,21,15,9,8,0,14,24,4,3,17,25,23,22,6,2,19,10,20,16,18,1,13,12,7,11};

static const int REFLECTOR_B_THIN[26] = {4,13,10,16,0,20,24,22,9,8,2,14,15,1,11,12,3,23,25,21,5,19,7,17,6,18};
static const int REFLECTOR_C_THIN[26] = {17,3,14,1,9,13,19,10,21,4,7,12,11,5,2,22,25,0,23,6,24,8,15,18,20,16};

static const char* ROTOR_NAMES[] = {"I", "II", "III", "IV", "V", "VI", "VII", "VIII"};
static const char* GREEK_NAMES[] = {"Beta", "Gamma"};
static const char* THIN_REF_NAMES[] = {"B-Thin", "C-Thin"};

struct RotorCombo { int r[3]; };
static RotorCombo COMBOS[336];
static int NUM_COMBOS = 0;

inline void init(int num_rotors = 5) {
    for (int r = 0; r < 8; r++)
        for (int i = 0; i < 26; i++)
            INV_WIRING[r][WIRING[r][i]] = i;
    for (int r = 0; r < 2; r++)
        for (int i = 0; i < 26; i++)
            INV_GREEK_WIRING[r][GREEK_WIRING[r][i]] = i;

    NUM_COMBOS = 0;
    for (int a = 0; a < num_rotors; a++)
        for (int b = 0; b < num_rotors; b++) {
            if (b == a) continue;
            for (int c = 0; c < num_rotors; c++) {
                if (c == a || c == b) continue;
                COMBOS[NUM_COMBOS++] = {{a, b, c}};
            }
        }
}

inline void compute_composite_reflector(int greek, int thin_ref_idx,
                                        int gp, int gr, int* out) {
    const int* thin_ref = thin_ref_idx == 0 ? REFLECTOR_B_THIN : REFLECTOR_C_THIN;
    int eff = (gp - gr + 26) % 26;
    for (int s = 0; s < 26; s++) {
        int sig = (GREEK_WIRING[greek][(s + eff) % 26] - eff + 26) % 26;
        sig = thin_ref[sig];
        sig = (INV_GREEK_WIRING[greek][(sig + eff) % 26] - eff + 26) % 26;
        out[s] = sig;
    }
}

struct Machine {
    const int* fwd[3];
    const int* rev[3];
    const int* reflector;
    int plugboard[26];
    int pos[3];
    int notch_a[3];
    int notch_b[3];

    void setup(int lr, int mr, int rr,
               int l_ring, int m_ring, int r_ring,
               int l_start, int m_start, int r_start,
               const int* refl) {
        fwd[0] = WIRING[lr]; fwd[1] = WIRING[mr]; fwd[2] = WIRING[rr];
        rev[0] = INV_WIRING[lr]; rev[1] = INV_WIRING[mr]; rev[2] = INV_WIRING[rr];
        reflector = refl;
        pos[0] = (l_start - l_ring + 26) % 26;
        pos[1] = (m_start - m_ring + 26) % 26;
        pos[2] = (r_start - r_ring + 26) % 26;
        notch_a[0] = (NOTCH_A[lr] - l_ring + 26) % 26;
        notch_a[1] = (NOTCH_A[mr] - m_ring + 26) % 26;
        notch_a[2] = (NOTCH_A[rr] - r_ring + 26) % 26;
        notch_b[0] = NOTCH_B[lr] >= 0 ? (NOTCH_B[lr] - l_ring + 26) % 26 : -1;
        notch_b[1] = NOTCH_B[mr] >= 0 ? (NOTCH_B[mr] - m_ring + 26) % 26 : -1;
        notch_b[2] = NOTCH_B[rr] >= 0 ? (NOTCH_B[rr] - r_ring + 26) % 26 : -1;
        for (int i = 0; i < 26; i++) plugboard[i] = i;
    }

    void set_plugboard(const char* pairs) {
        for (int i = 0; i < 26; i++) plugboard[i] = i;
        if (!pairs || !pairs[0]) return;
        const char* p = pairs;
        while (*p) {
            while (*p == ' ') p++;
            if (!p[0] || !p[1]) break;
            int a = p[0] - 'A', b = p[1] - 'A';
            plugboard[a] = b;
            plugboard[b] = a;
            p += 2;
        }
    }

    inline void step() {
        bool mid_notch = (pos[1] == notch_a[1]) ||
                         (notch_b[1] >= 0 && pos[1] == notch_b[1]);
        bool right_notch = (pos[2] == notch_a[2]) ||
                           (notch_b[2] >= 0 && pos[2] == notch_b[2]);
        pos[2] = (pos[2] + 1) % 26;
        if (right_notch || mid_notch) pos[1] = (pos[1] + 1) % 26;
        if (mid_notch) pos[0] = (pos[0] + 1) % 26;
    }

    inline int encrypt_char(int c) {
        step();
        int sig = plugboard[c];
        for (int r = 2; r >= 0; r--) {
            int pin = (sig + pos[r]) % 26;
            sig = (fwd[r][pin] - pos[r] + 26) % 26;
        }
        sig = reflector[sig];
        for (int r = 0; r < 3; r++) {
            int contact = (sig + pos[r]) % 26;
            sig = (rev[r][contact] - pos[r] + 26) % 26;
        }
        return plugboard[sig];
    }

    void process(const int* input, int* output, int len) {
        for (int i = 0; i < len; i++)
            output[i] = encrypt_char(input[i]);
    }
};

inline double calc_ioc(const int* text, int len) {
    if (len <= 1) return 0.0;
    int freq[26] = {};
    for (int i = 0; i < len; i++) freq[text[i]]++;
    double sum = 0.0;
    for (int i = 0; i < 26; i++) sum += freq[i] * (freq[i] - 1);
    return sum / ((double)len * (len - 1));
}

static float EN_BIGRAMS[26][26] = {};
static float DE_BIGRAMS[26][26] = {};

inline void init_bigrams() {
    struct { int a, b; float f; } en[] = {
        {19,7,35.6},{7,4,30.7},{8,13,24.3},{4,17,20.5},{0,13,19.9},
        {17,4,18.5},{14,13,17.6},{0,19,14.9},{4,13,14.5},{13,3,13.5},
        {19,8,13.4},{4,18,13.4},{14,17,12.8},{19,4,12.0},{14,5,11.4},
        {4,3,11.2},{8,18,11.1},{8,19,11.0},{0,11,10.9},{0,17,10.7},
        {18,19,10.5},{19,14,10.5},{13,19,10.4},{13,6,9.5},{18,4,9.3},
        {7,0,9.3},{0,18,8.7},{14,20,8.7},{8,14,8.3},{11,4,8.3},
        {21,4,8.3},{2,14,7.9},{12,4,7.9},{3,4,7.6},{7,8,7.6},
        {17,8,7.3},{17,14,7.3},{8,2,7.0},{13,4,6.9},{4,0,6.9},
        {17,0,6.9},{2,4,6.5},{11,8,6.2},{2,7,5.9},{11,11,5.8},
        {1,4,5.8},{12,0,5.7},{18,8,5.5},{14,12,5.5},{20,17,5.4},
    };
    for (auto& e : en) EN_BIGRAMS[e.a][e.b] = e.f;

    struct { int a, b; float f; } de[] = {
        {4,13,39.5},{4,17,37.5},{2,7,27.5},{3,4,20.2},{4,8,19.8},
        {13,3,18.5},{19,4,17.6},{8,13,17.5},{8,4,16.5},{6,4,15.5},
        {20,13,14.3},{18,19,13.8},{4,18,13.2},{0,13,12.7},{17,4,12.5},
        {7,4,12.0},{1,4,11.5},{0,20,10.8},{13,4,10.5},{18,2,10.2},
        {18,4,9.8},{3,8,9.5},{13,6,9.2},{8,2,8.8},{3,0,8.5},
        {4,12,8.2},{4,11,8.0},{21,4,7.8},{7,0,7.5},{0,11,7.2},
        {8,19,7.0},{8,18,6.8},{18,8,6.5},{18,14,6.2},{17,0,6.0},
        {18,18,5.8},{0,1,5.5},{17,8,5.3},{5,4,5.0},{12,8,4.8},
    };
    for (auto& e : de) DE_BIGRAMS[e.a][e.b] = e.f;
}

inline double calc_bigram(const int* text, int len, const float bigrams[26][26]) {
    if (len < 2) return 0.0;
    double score = 0.0;
    for (int i = 0; i < len - 1; i++)
        score += bigrams[text[i]][text[i + 1]];
    return score / (len - 1);
}

} // namespace enigma
