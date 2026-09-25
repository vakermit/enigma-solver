# The Mathematics of Breaking Enigma

## The Keyspace

Before getting into the methods used to break Enigma, it helps to understand what the attackers were up against. The Wehrmacht Enigma I with five available rotors and ten plugboard cables had:

| Component | Choices |
|-----------|---------|
| Rotor selection (3 from 5) | 60 |
| Rotor starting positions | 26^3 = 17,576 |
| Ring settings | 26^3 = 17,576 (effective: 26^2 = 676) |
| Plugboard (10 pairs from 26 letters) | 150,738,274,937,250 |
| **Total** | **~1.59 x 10^20** |

That last number is about 159 quintillion. The right rotor's ring setting is redundant with its starting position (both shift the same substitution, and the right rotor turns every keypress), so the effective ring settings are 676, not 17,576. But even with that reduction, the keyspace is enormous.

The plugboard formula is worth writing out because the number is so large:

```
26! / (6! x 10! x 2^10) = 150,738,274,937,250
```

That's: all arrangements of 26 letters (26!), divided by the 6 unplugged letters being unordered (6!), divided by the 10 cables being interchangeable (10!), divided by each cable's two ends being symmetric (2^10). The plugboard alone accounts for over 150 trillion combinations, dwarfing every other component combined.

Nobody broke Enigma by searching 159 quintillion configurations. They decomposed the problem.

## Index of Coincidence

In 1920, a 29-year-old American cryptanalyst named William F. Friedman wrote Riverbank Publication No. 22 (printed in France, released 1922). Historian David Kahn later called it "the most important single publication in cryptography." Friedman introduced a statistical measure he called the Index of Coincidence.

The formula measures the probability that two randomly chosen letters from a text are the same:

```
IC = sum(fi * (fi - 1)) / (N * (N - 1))
```

Where `fi` is the count of the i-th letter and N is the total number of letters.

The expected values tell the story:

- **English**: ~0.0667
- **German**: ~0.0762
- **Random (uniform)**: 1/26 = ~0.0385

English has an uneven letter distribution. E appears about 12.7% of the time, T about 9.1%, Z about 0.07%. This unevenness means coincidences happen more often than they would in random text. German is even more skewed (E at 17.4%), which pushes the IoC higher.

Friedman used the notation kappa-p for the language value and kappa-r for the random baseline. Some sources define a normalized form (multiply by the alphabet size) where random gives 1.0 and English gives about 1.73. Our solver uses the unnormalized form.

Here's why IoC works against Enigma: decrypt ciphertext with wrong rotor settings and the output is effectively random, with an IoC near 0.038. Get the rotors right, even without the correct plugboard, and the output preserves the source language's letter frequency distribution. The IoC jumps toward 0.067 or 0.076. That gap, almost double, is wide enough to pick correct settings out of a million candidates.

The plugboard doesn't affect IoC much. It swaps pairs of letters, which changes *which* letters are common but not *how uneven* the distribution is. A text with E appearing 12% of the time still has some letter appearing 12% of the time after the plugboard. The shape of the distribution, which is all IoC measures, stays the same.

## Bigram and Trigram Analysis

Single-letter frequency captures the overall shape of a distribution. Bigram analysis, counting consecutive letter pairs, captures something IoC misses: the internal structure of a language.

In English, TH appears about 2.71% of the time, HE about 2.33%, IN about 2.03%. In German, EN appears about 3.9%, ER about 3.7%, CH about 2.7%. These patterns are specific. When the plugboard incorrectly swaps T with X, every TH in the plaintext becomes XH, which barely registers in the bigram table. Correcting that one plug pair recovers every TH, TI, TE, and so on, producing a measurable score jump.

This is the practical difference between IoC and bigram scoring. IoC finds the right rotors but can't distinguish between plugboard configurations. Bigram scoring can, because it's sensitive to which specific letters appear together, not just their individual frequencies.

Trigram analysis (three-letter sequences) is even more discriminating but needs longer ciphertext. With 26^3 = 17,576 possible trigrams, short messages don't contain enough data for reliable scoring. Bigrams hit a useful middle ground: 676 possible pairs, most of which appear often enough in an 80-character message to produce a stable score.

The computational cost is small. IoC needs 26 frequency counts and one summation. Bigram scoring needs a 26x26 lookup table (676 entries) and one table lookup per consecutive pair. Trigrams need a 17,576-entry table. All are trivial on modern hardware.

## Banburismus

Alan Turing invented Banburismus in late 1940 for attacking the German naval Enigma, which was harder to break than Army or Air Force traffic because the Kriegsmarine used a different indicator system. The name came from Banbury, the town where the special punched sheets used in the process were printed.

The mathematical foundation was something Turing worked out independently, which Abraham Wald later published as sequential analysis. Instead of collecting a fixed sample and then deciding, you accumulate evidence piece by piece and stop as soon as you have enough.

Turing defined the weight of evidence in favor of one hypothesis over another as:

```
W = log10(P(evidence | H1) / P(evidence | H2))
```

The logarithm (base 10) of the likelihood ratio. He invented units for this: a **ban** equals one unit on the log-10 scale (an odds ratio of 10:1), and a **deciban** equals one-tenth of a ban (odds ratio of about 1.26:1). Turing chose the deciban because it was "about the smallest change in weight of evidence that is directly perceptible to human intuition," analogous to a decibel in acoustics.

The process worked like this: two intercepted messages encrypted on the same day (same rotor order, same ring settings) were written on the long Banbury sheets. The sheets were slid past each other at various offsets, and the number of coincidences (same letter in the same position) was counted at each offset. If two messages happened to share the same starting position, their rotor states were identical at each point, and the coincidence rate would be elevated (language-like, around 0.067) rather than random (around 0.038). Each coincidence count was converted into a weight in decibans. When the accumulated weight crossed a positive threshold (typically +20 to +30 decibans), the hypothesis was accepted. When it crossed a negative threshold, it was rejected.

Banburismus could determine the right-hand and middle rotor identities and their relative starting positions, reducing the number of Bombe runs needed from 60 rotor orders down to 2 or 3. That saved Bombe time by a factor of 20 to 30.

Jack Good (I.J. Good), who worked with Turing in Hut 8, later published on these methods. His 1979 paper in Biometrika documents Turing's anticipation of both empirical Bayes methods and sequential analysis. Banburismus was used from spring 1941 to mid-1943, when faster Bombes made the technique unnecessary.

## The Bombe

Turing designed the British Bombe in 1939, and Gordon Welchman improved it with the diagonal board. Harold "Doc" Keen's team at the British Tabulating Machine Company built them. About 200 were eventually constructed.

Each Bombe contained 36 Enigma-equivalent drum sets arranged in three rows of twelve. All the fast (right) drums were mechanically linked and driven together. A full revolution of the fast drums advanced the medium drums by one step, and a full cycle of mediums advanced the slow drums. This tested all 17,576 (26^3) positions in about 20 minutes.

The Bombe did not try to decrypt by brute force. It used a known-plaintext attack based on a crib. The method:

From the crib-ciphertext alignment, you construct a graph of letter relationships. If position 1 maps R to N, position 5 maps N to S, and position 9 maps S to R, you have a loop: R to N to S to R. These loops create over-determined systems of constraints.

For each of the 17,576 rotor positions, the Bombe assumes a particular letter (the "test register") is steckered (plugboard-connected) to a specific letter and propagates the implications through the loops. If the implications produce a contradiction, where a letter must connect to two different letters simultaneously, that rotor position is eliminated. With a good crib containing multiple loops, all but a handful of positions produce contradictions. The survivors ("stops") were tested by hand, typically 2 to 20 per run, of which one (if the crib was correct) would be the right setting.

Welchman's diagonal board exploited plugboard symmetry: if A connects to G, then G connects to A. Turing's original design didn't wire this reciprocal relationship into the circuit. The diagonal board did, and it reduced false stops by over 90%. This made it practical to use cribs that produced menus with fewer loops or even tree-structured menus with no loops at all.

What the Bombe did not do: it did not search over rotor orders (60 possibilities) or ring settings (676). Banburismus or operator habits narrowed the rotor order. Ring settings were deduced from the partial decrypt that survived.

## Hill Climbing for Plugboard Recovery

Modern ciphertext-only attacks on Enigma split the problem into two phases:

1. Find rotors, positions, and ring settings using IoC scoring (brute-force or beam search)
2. Recover plugboard settings using hill climbing with bigram scoring

The split works because IoC finds the right rotors but is insensitive to the plugboard (as discussed above), and bigram scoring is sensitive to exactly the substitution errors the plugboard introduces.

The plugboard recovery algorithm is a greedy search:

1. Start with no plugboard (identity mapping)
2. For each of the C(26,2) = 325 possible letter pairs, temporarily add the pair, decrypt, and score with bigram frequencies
3. Keep the single pair that gave the best improvement
4. Repeat with the remaining unused letters (24, then 22, and so on)
5. Stop when no pair improves the score, or when 13 pairs are reached

In practice, convergence happens in 10 to 12 iterations. Each iteration tests progressively fewer candidates as letters are consumed. The total number of plugboard tests per rotor setting is roughly 1,525 decryptions (325 + 276 + 231 + ...). That replaces a search through 150 trillion configurations with one through about 1,500. The reduction factor is on the order of 10^11.

According to Weierud and Zabell's 2017 paper "Modern Breaking of Enigma Ciphertexts," a full ciphertext-only break of a 3-rotor Enigma message on a single PC takes 10 to 60 hours depending on message length. With GPU parallelism (as in this project's Metal solver), the rotor search phase drops to milliseconds. The plugboard hill climbing is inherently sequential but fast because the search space is small.

A three-stage scoring progression works well: IoC for the initial rotor/position search, bigrams for plugboard recovery, and trigrams for final refinement if the ciphertext is long enough.

## Sources

- W.F. Friedman, "The Index of Coincidence and Its Applications to Cryptography," Riverbank Publication No. 22 (1922). Declassified: https://www.nsa.gov/portals/75/documents/news-features/declassified-documents/friedman-documents/publications/folder_233/41761039080018.pdf
- I.J. Good, "Studies in the History of Probability and Statistics. XXXVII," Biometrika (1979): https://languagelog.ldc.upenn.edu/myl/Good1979.pdf
- D.J.C. MacKay, "Information Theory, Inference, and Learning Algorithms," Chapter 18.4: https://www.inference.org.uk/mackay/itprnn/ps/265.280.pdf
- CryptoCellar, "Hillclimbing the Enigma Machine": https://cryptocellar.org/bgac/hillclimb-enigma.pdf
- CryptoCellar, "Modern Breaking of Enigma Ciphertexts": https://cryptocellar.org/pubs/enigma-modern-breaking.pdf
- Tony Sale, "Naval Enigma": https://www.codesandciphers.org.uk/virtualbp/navenigma/navenig4.htm
- Bombe.org.uk, "Enter Turing and Welchman": https://bombe.org.uk/enter-turing-and-welchman/
- Ellsbury, "How the Bombe was Plugged-Up": http://www.ellsbury.com/bombe3.htm
- University of Regina, "Theoretically Possible Enigma Configurations": https://uregina.ca/~kozdron/Teaching/Cornell/135Summer06/Handouts/enigma.pdf
- codesandciphers.org.uk, "The Stecker Count": https://www.codesandciphers.org.uk/enigma/steckercount.htm
