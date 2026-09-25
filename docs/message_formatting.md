# Enigma Message Length and Formatting

## The 250-Character Rule

German Army and Luftwaffe operators were forbidden from sending more than 250 letters in a single Enigma transmission. This limit was a security regulation, not a technical constraint. The three-rotor Enigma machine had an actual period of 16,900 keystrokes before the rotor alignment pattern repeated (26 x 25 x 26, accounting for the double-stepping anomaly that shortens the middle rotor's cycle from 26 to 25 positions). The naive calculation of 26^3 = 17,576 assumes the rotors step like an odometer; the double-stepping anomaly consumes 676 of those positions. Letting a single message run too long would give cryptanalysts a larger body of ciphertext produced under a predictably stepping mechanism, making statistical attacks easier.

An analysis of roughly 500 authentic messages from Heeresgruppe Nord by Ostwald and Weierud found that 2% violated the 250-letter limit, confirming it was a real regulation but not perfectly enforced.

The Kriegsmarine had no published hard character limit but emphasized brevity. Kurzsignale (short signals) for contact reports ran about 22 characters; weather reports about 25. Standard naval messages were split into separate transmissions, each encrypted with its own randomly chosen message key. In theory, this prevented codebreakers from linking parts together. In practice, operators sometimes left the rotors where the previous message ended instead of choosing a new key, or picked related keys for consecutive parts (ABC, ABD, ABE), creating exactly the patterns they were supposed to avoid.

## Why Message Length Matters for Cryptanalysis

The Index of Coincidence (IoC) measures how far a text's letter distribution deviates from random. For a correct decryption to stand out from the noise, the IoC confidence interval for language text needs to be statistically separable from the IoC of random text.

The standard error of IoC for a text of N characters with expected value kappa is approximately:

```
SE(IC) = sqrt(2 * kappa^2 / (N - 1))
```

This gives us concrete thresholds:

| Length | English IoC 95% CI | Random IoC 95% CI | Separation |
|--------|-------------------|-------------------|------------|
| 30 | 0.032 - 0.101 | 0.019 - 0.058 | Heavy overlap |
| 50 | 0.040 - 0.093 | 0.023 - 0.054 | Overlap |
| 75 | 0.045 - 0.088 | 0.026 - 0.051 | Marginal |
| 100 | 0.048 - 0.085 | 0.028 - 0.049 | Marginal |
| 150 | 0.052 - 0.082 | 0.030 - 0.047 | Clear |
| 200 | 0.054 - 0.080 | 0.031 - 0.046 | Good |
| 250 | 0.055 - 0.078 | 0.032 - 0.045 | Good |

German text has a higher IoC (~0.076) due to more skewed letter frequencies, which gives slightly better separation at the same message length. The confidence intervals for German stop overlapping with random at around 75 characters.

There is also a theoretical floor. Shannon's unicity distance for the full Enigma keyspace (~2^76.6 bits of key entropy) with German text redundancy of about 3.5 bits per character is roughly 76.6 / 3.5 = 22 characters. Below that, multiple valid decryptions exist and the correct one cannot be uniquely identified even in theory. Above it, the correct decryption is unique, though finding it computationally is a separate problem.

Modern Enigma-breaking research confirms these ranges. Friederes (2023) found messages under 20 characters "virtually unbreakable" by ciphertext-only methods. Weierud and Zabell (2017) demonstrated that 50-character messages without plugboard can be broken in seconds, but plugboard recovery via trigram hill climbing needs roughly 150 characters to converge reliably.

For the solver, these translate to practical guidance:

- **Under 50 characters**: IoC is unreliable. The confidence intervals overlap so heavily that the correct rotor settings may not produce a noticeably higher score than wrong ones. The solver warns about this.
- **50 to 100 characters**: Marginal. The correct answer may appear but won't always rank first. Wider beam widths help.
- **100 to 150 characters**: Workable. IoC separation is developing but still below optimal.
- **150 to 250 characters**: Reliable. This is the range where IoC-based attacks consistently identify the correct settings.
- **200 to 250 characters**: Optimal. Matches the historical message length the Germans used, and provides strong statistical separation.

The 250-character limit was a security measure against cryptanalysis, but ironically, it sits right at the length where ciphertext-only IoC attacks become effective. Shorter messages would have been harder to break statistically; longer messages would have given the codebreakers more data. The Germans chose a limit that was close to the worst of both worlds.

## Message Formatting

The Enigma keyboard had 26 letter keys and nothing else. No spaces, no numbers, no punctuation. Every message had to be converted into a continuous string of uppercase letters.

### Grouping

The Army and Luftwaffe formatted ciphertext into five-letter groups for transmission: `XMCFZ QHWTR KNBDL`. The Navy used four-letter groups: `XMCF ZQHW TRKN`. The last group was padded to the standard width if it came up short (typically with X).

### Punctuation Substitutions

The Army and Luftwaffe used these replacements:

| Symbol | Replacement |
|--------|-------------|
| Space | X (or omitted) |
| Period (.) | X |
| Comma (,) | ZZ |
| Question mark (?) | FRAGE or FRAQ |
| Parentheses () | KLAM (from Klammer) |
| Colon (:) | XX |
| CH digraph | Q |

The term FRAGE comes from the German word Fragezeichen (question mark, literally "question sign"). FRAQ was a common abbreviation. Some operators used FRAGEZ. The CH-to-Q substitution produced characteristic patterns like AQT (for "acht," eight) and NAQ (for "nach," after/toward) that cryptanalysts learned to recognize.

The Navy used different abbreviations to save space:

| Symbol | Navy Replacement |
|--------|-----------------|
| Comma (,) | Y |
| Question mark (?) | UD |

The Navy's formatting was more compressed because submarine operators had a stronger incentive to keep transmissions short: every second on the radio increased the risk of direction-finding.

### Numbers

All numbers had to be spelled out in German words. The standard spellings:

| Digit | Spelling |
|-------|----------|
| 0 | NULL |
| 1 | EINS |
| 2 | ZWO |
| 3 | DREI |
| 4 | VIER |
| 5 | FUENF |
| 6 | SECHS |
| 7 | SIEBEN |
| 8 | ACHT |
| 9 | NEUN |

The use of ZWO instead of ZWEI was deliberate. In spoken German, and especially over radio, ZWEI and DREI sound similar. The Bundeswehr and military organizations adopted ZWO as the standard pronunciation to prevent confusion. The same logic applied to written Enigma messages: ZWO was unambiguous.

Umlauts were spelled out: AE for a-umlaut, OE for o-umlaut, UE for u-umlaut. The letter combination CH was common enough in German that it appeared frequently, and some procedures used Q as a shorthand for CH.

### What This Meant in Practice

A message like:

> Feind um 08:30 bei Punkt 5 gesichtet. 3 Schiffe, Kurs West. Angriff?

Would be encoded as:

> FEINDUMACHTUHRDREINULLBEI PUNKTFUENFGESICHTETXDREISCHIFFEXKURSWESTXANGRIFFFRAQ

(Spaces shown for readability; the actual transmission was continuous five-letter groups.)

This encoding expanded the message considerably. The original German is 64 characters including spaces and punctuation. The Enigma-formatted version is about 75 characters. Numbers and punctuation substitutions added 15-20% to message length, which pushed messages toward the 250-character limit faster and meant they carried less information per character than raw text.

## Sources

- Cipher Machines and Cryptology, "Enigma Procedures" - https://www.ciphermachinesandcryptology.com/en/enigmaproc.htm
- Enigma World Code Group - https://enigmaworldcodegroup.freeforums.net/thread/259/numbers-messages-encoded-enigma-machine
- PBS NOVA, "How the Enigma Works" - https://www.pbs.org/wgbh/nova/article/how-enigma-works/
- University of Miami, "Enigma" - https://www.cs.miami.edu/home/harald/enigma/
- J.G. Andrews, "The Enigma Machine" - https://jgandrews.com/posts/the-enigma-machine/
- W.F. Friedman, "The Index of Coincidence and Its Applications to Cryptography," Riverbank Publication No. 22 (1922)
- Weierud & Zabell, "Modern Breaking of Enigma Ciphertexts" (2017) - https://cryptocellar.org/pubs/enigma-modern-breaking.pdf
- Friederes, "Breaking Enigma Ciphertext in 2023" - https://cdn.ciphereditor.com/archive/2023/breaking-enigma-ciphertext-in-2023.pdf
- James Grime, "Maths of the Enigma" - https://www.singingbanana.com/enigmaproject/maths.pdf
- Practical Cryptography, "Index of Coincidence" - http://practicalcryptography.com/cryptanalysis/text-characterisation/index-coincidence/
