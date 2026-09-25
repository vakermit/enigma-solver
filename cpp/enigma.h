#pragma once
#include <cstdint>
#include <cstring>
#include <cmath>

namespace enigma {

// Rotor forward wiring (A=0..Z=25)
// I: EKMFLGDQVZNTOWYHXUSPAIBRCJ
// II: AJDKSIRUXBLHWTMCQGZNPYFVOE
// III: BDFHJLCPRTXVZNYEIWGAKMUSQO
// IV: ESOVPZJAYQUIRHXLNFTGKDCMWB
// V: VZBRGITYUPSDNHLXAWMJQOFECK
static const int WIRING[5][26] = {
    {4,10,12,5,11,6,3,16,21,25,13,19,14,22,24,7,23,20,18,15,0,8,1,17,2,9},
    {0,9,3,10,18,8,17,20,23,1,11,7,22,19,12,2,16,6,25,13,15,24,5,21,14,4},
    {1,3,5,7,9,11,2,15,17,19,23,21,25,13,24,4,8,22,6,0,10,12,20,18,16,14},
    {4,18,14,21,15,25,9,0,24,16,20,8,17,7,23,11,13,5,19,6,10,3,2,12,22,1},
    {21,25,1,17,6,8,19,24,20,15,18,3,13,7,11,23,0,22,12,9,16,14,5,4,2,10},
};

// Inverse wiring (computed at init)
static int INV_WIRING[5][26];

// Notch letter indices: I=Q(16), II=E(4), III=V(21), IV=J(9), V=Z(25)
static const int NOTCH[5] = {16, 4, 21, 9, 25};

static const int REFLECTOR_B[26] = {24,17,20,7,16,18,11,3,15,23,13,6,14,10,12,8,4,1,5,25,2,22,21,9,0,19};
static const int REFLECTOR_C[26] = {5,21,15,9,8,0,14,24,4,3,17,25,23,22,6,2,19,10,20,16,18,1,13,12,7,11};

static const char* ROTOR_NAMES[] = {"I", "II", "III", "IV", "V"};

struct RotorCombo { int r[3]; };
static RotorCombo COMBOS[60];
static int NUM_COMBOS = 0;

inline void init() {
    // Inverse wiring
    for (int r = 0; r < 5; r++)
        for (int i = 0; i < 26; i++)
            INV_WIRING[r][WIRING[r][i]] = i;

    // All 3-of-5 permutations
    for (int a = 0; a < 5; a++)
        for (int b = 0; b < 5; b++) {
            if (b == a) continue;
            for (int c = 0; c < 5; c++) {
                if (c == a || c == b) continue;
                COMBOS[NUM_COMBOS++] = {{a, b, c}};
            }
        }
}

struct Machine {
    const int* fwd[3];
    const int* rev[3];
    const int* reflector;
    int plugboard[26];
    int pos[3];
    int notch_pos[3];

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
        notch_pos[0] = (NOTCH[lr] - l_ring + 26) % 26;
        notch_pos[1] = (NOTCH[mr] - m_ring + 26) % 26;
        notch_pos[2] = (NOTCH[rr] - r_ring + 26) % 26;
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
        bool mid_notch = (pos[1] == notch_pos[1]);
        bool right_notch = (pos[2] == notch_pos[2]);
        pos[2] = (pos[2] + 1) % 26;
        if (right_notch || mid_notch) pos[1] = (pos[1] + 1) % 26;
        if (mid_notch) pos[0] = (pos[0] + 1) % 26;
    }

    inline int encrypt_char(int c) {
        step();
        int sig = plugboard[c];

        // Forward: right → middle → left
        for (int r = 2; r >= 0; r--) {
            int pin = (sig + pos[r]) % 26;
            sig = (fwd[r][pin] - pos[r] + 26) % 26;
        }

        sig = reflector[sig];

        // Reverse: left → middle → right
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

// Bigram scoring tables (26x26, indexed as [first][second])
static float EN_BIGRAMS[26][26] = {};
static float DE_BIGRAMS[26][26] = {};

inline void init_bigrams() {
    // English top bigrams (frequency per 1000)
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

    // German top bigrams
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
