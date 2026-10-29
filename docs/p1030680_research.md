# P1030680 — The Last Unbroken Enigma Message

## Summary

P1030680 is the last known unbroken historical Enigma message. It was transmitted on 1 May 1945 from German submarine U-534, encrypted on an Enigma M4 machine, likely on the M-Thetis key network. Despite decades of effort — including distributed computing, brute-force search, crib attacks, and recent AI-assisted cryptanalysis — no valid decryption has ever been produced.

## The Message

**Designation:** P1030680
**Date:** 1 May 1945
**Origin:** U-534 (Type IXC/40 submarine, Kriegsmarine)
**Machine:** Enigma M4 (four-rotor naval variant)
**Key network:** Likely M-Thetis (never broken by WWII codebreakers)
**Indicator groups:** VROL NMKA

**Ciphertext (73 characters):**
```
JCRSA JTGSJ EYEXY KKZZS
HVUOC TRFRC RPFVY PLKPP
LGRHV VBBTB RSXSW XGGTY
TVKQN GSCHV GF
```

**All machine settings remain unknown:**
- Reflector: unknown
- Greek wheel: unknown
- Wheel order: unknown
- Wheel positions: unknown
- Ring settings: unknown
- Plugboard: unknown

## U-534: The Submarine

U-534 was a Type IXC/40 U-boat, built in 1942 and commissioned in December of that year. It was sunk on 5 May 1945 (some sources say 6 May) by British aircraft in the Kattegat strait, four days after this message was sent. 49 of 52 crew survived. The wreck was discovered in 1986 by Danish wreck hunter Aage Jensen and later raised and preserved at the U-Boat Story museum in Birkenhead, UK.

Approximately 55 encrypted messages (P1030659 through P1030713) were recovered from the wreck. The operators used M4 Enigma machines with Schreibmax printer attachments, which printed encrypted output directly onto paper ribbons. Many documents were water-damaged, partially illegible, or missing their opening groups.

## The Breaking of the Other U-534 Messages

Starting in July 2012, German researcher Michael Horenberg used distributed computing with 112 Intel CPU cores, a modified software Turing Bombe, and brute-force attacks to decrypt the recovered messages. By 20 October 2012, 46 of the approximately 50 messages had been broken.

The most historically significant was **P1030681** — a Donitz succession message transmitted 1 May 1945 at 06:55, announcing that the Fuhrer had appointed Grand Admiral Donitz as his successor. Its settings were:

| Setting | Value |
|---------|-------|
| Reflector | C |
| Greek wheel | Beta |
| Wheel order | 5-6-8 |
| Ring setting | EPEL |
| Start position | NAEM |
| Plugboard | AE BF CM DQ HU JN LX PR SZ VW |
| Message key | CDSZ |

P1030681 was sent the same day as P1030680. This is significant — they likely shared the same daily key settings (reflector, wheel order, ring settings, plugboard), differing only in message key. Yet P1030680 resists all attempts while P1030681 yielded to analysis.

## Why P1030680 Remains Unbroken

### 1. Transmission Corruption

The strongest theory from Hacker News and expert analysis: **the message was received corrupted**. The indicator groups show inconsistencies (VA vs. VR in different positions), suggesting the original receiving operator couldn't decrypt it either. If the ciphertext as recovered doesn't match what was actually encrypted, no amount of correct key recovery will produce intelligible plaintext. Dan Girard documented evidence that the original operator likely encountered decryption difficulties and abandoned the attempt, possibly because U-534 lacked the required Thetis key configuration.

### 2. Short Length

At 73 characters, P1030680 is extremely short for statistical attack. Index of Coincidence becomes unreliable below ~100 characters — the signal-to-noise ratio is too low to distinguish correct settings from random. This eliminates the primary tool used in brute-force approaches.

### 3. Missing Grund Tables

The initial Grund tables (daily starting settings) for the M-Thetis network on 1 May 1945 are no longer available. Without these as a starting point, the full M4 keyspace must be searched from scratch.

### 4. The M-Thetis Network

The Thetis key network was a separate Kriegsmarine cipher network that was never broken during WWII. If P1030680 was encrypted on Thetis rather than the more common Triton network, no known cribs or partial key information exists to constrain the search.

### 5. Operational Collapse

The date matters: 1 May 1945 — the day after Hitler's suicide, six days before German surrender. Communications discipline was collapsing. Operators were under extreme stress, procedures were breaking down, and the normal cryptographic practices that provide footholds for cryptanalysis (standard headers, weather report formats, repeated phrases) may not have been followed.

## Statistical Anomaly: The Missing Z

An observation noted in cryptographic circles: the ciphertext contains no letter Z. For a 73-character German Enigma message, the probability of Z never appearing is low but not astronomically so. The observation recalls a famous Bletchley Park anecdote where a message lacking Z entirely was found to be a bored operator pressing only the Z key repeatedly — since Enigma never encrypts a letter to itself, an all-Z input would produce ciphertext with every letter except Z. However, 73 characters is too short for this observation alone to be conclusive.

Letter frequency of P1030680 ciphertext:
```
A:1 B:3 C:3 D:0 E:2 F:2 G:5 H:3 I:0 J:2 K:4 L:2 M:1 N:1 O:1 P:4
Q:1 R:4 S:4 T:4 U:1 V:5 W:2 X:3 Y:3 Z:0
```

Notable: no D, no I, no Z. Five each of G and V. The distribution is irregular but within statistical noise for a 73-character sample.

## Decryption Efforts

### Enigma@Home (2018–present)

The Enigma@Home distributed computing project (BOINC-based) has been systematically searching the M4 keyspace. As of May 2024, the P1030680 GPU batch had completed 25,126,123 workunits with 1,753,877 remaining (~93.5% complete). Despite this massive computational effort, no valid decryption has emerged. The project exhaustively tests rotor combinations, ring settings, and start positions, scoring candidates by IoC and other statistical measures.

### Veritasium Challenge (2023)

The YouTube science channel Veritasium featured P1030680 in a video about Enigma, challenging viewers to decrypt it. This was done without permission from the Hoerenberg research website and generated substantial traffic and inquiry volume. The challenge brought public attention but no breakthrough. The Hoerenberg site notes: individuals claiming successful decryption must provide complete Enigma settings for independent verification.

### AI-Assisted Cryptanalysis (September 2026)

A new era of AI-driven Enigma breaking began in September 2026, though it has not yet reached P1030680:

**GPT-6 Astra (OpenAI) — 22 September 2026:**
Carter Leffer directed GPT-6 Astra to autonomously analyze unbroken messages from the Crypto Cellar Research website. The AI selected message Nr. 172 (MVUEH, a 1941 transmission) as the most promising target, identified the crib "ROSENOW ROSENOW" from contextual research, then independently wrote Python and C++ Enigma simulator and Bombe software to execute the attack. The plaintext: "Please specify the route of march. I am in Rosenow, Rosenow. Immediate reply by radio." — sent by a German transport operator to SS Death's Head division headquarters. This was confirmed by cryptography expert Frode Weierud and covered on Bruce Schneier's blog.

**Claude Opus 5 (Anthropic) — 20 September 2026:**
Cryptanalyst Jack Willis used Anthropic's Claude Opus 5 to break message Nr. 205/285 (FMNGI) using the signature "XHARTJENSTEINX" as a crib.

These AI breakthroughs targeted 1941-era messages — typically Army/Luftwaffe Enigma with known network keys and available contextual cribs. P1030680's challenges (M4 naval, unknown network, no cribs, possible corruption) represent a harder class of problem that AI has not yet addressed.

## What Would It Take to Break P1030680

Given the analysis above, the realistic paths are:

1. **New historical evidence.** Discovery of the M-Thetis key sheets for 1 May 1945 in archives (Bundesarchiv, NARA, GCHQ) would allow immediate decryption if the ciphertext is intact.

2. **Sister-message crib.** If P1030680 shares the daily key with P1030681 (which is known), the search space collapses to just the message key (3 letters = 17,576 possibilities). However, attempts using P1030681's daily settings have presumably been tried and failed — reinforcing the corruption theory.

3. **Contextual crib discovery.** Archival research revealing what U-534 was communicating about on that date could provide a crib. The Donitz succession announcement (P1030681) was sent the same day — P1030680 may have been a related operational message.

4. **Full Enigma@Home completion.** The remaining ~7% of the keyspace search may still contain the answer, assuming the ciphertext is intact. Expected completion: sometime in 2025-2026.

5. **AI-assisted contextual attack.** Following the GPT-6 Astra methodology — using AI to research historical context, generate plausible cribs from period documents, and execute targeted attacks — may be the most promising modern approach, but requires overcoming the corruption problem.

6. **Accepting it may be permanently lost.** If the ciphertext was corrupted in transmission (before recovery from the wreck), no correct decryption exists. The message would be a historical artifact of wartime communications breakdown — itself a meaningful finding.

## Relationship to This Project

The `unknown_message.txt` file in this repository contains P1030680. The solvers built here — IoC brute force, Metal GPU crib solver, Z3 SAT solver — represent the same class of attack that Enigma@Home and other projects have applied. The M4 GPU solver can search 613M configurations in ~20 seconds on an M1 Max. The crib solver adds Bombe-style plugboard consistency checking. The Z3 SAT solver uses constraint propagation rather than brute force, which can be effective with even partial cribs on short messages.

The challenge remains: without a valid crib and with possible corruption, all approaches hit the same wall.

## Sources

- [Enigma Message Breaking Project — Unbroken Messages](https://enigma.hoerenberg.com/index.php?cat=Unbroken)
- [Enigma Message Breaking Project — U-534 Messages](https://enigma.hoerenberg.com/index.php?cat=The+U534+messages)
- [Crypto Museum — U-534 Enigma Messages](https://www.cryptomuseum.com/crypto/enigma/msg/u534.htm)
- [Crypto Museum — P1030681 (Donitz Message)](https://cryptomuseum.com/crypto/enigma/msg/p1030681.htm)
- [Schneier on Security — GPT-6 Astra Breaks an Old Enigma Message](https://www.schneier.com/blog/archives/2026/09/gpt-6-astra-breaks-an-old-enigma-message.html)
- [Techstrong AI — AI Reveals Nazi Secrets](https://techstrong.ai/articles/ai-reveals-nazi-secrets/)
- [IFLScience — Only One Enigma Code Has Never Been Broken](https://www.iflscience.com/only-one-enigma-code-has-never-been-broken-69540)
- [Hacker News Discussion — P1030680](https://news.ycombinator.com/item?id=36483445)
- [Enigma@Home Project Status](http://www.enigmaathome.net/server_status)
- [Rijmenants — U-534 Enigma M4 Messages Cracked](https://rijmenants.blogspot.com/2012/08/u-534-enigma-m4-messages-cracked.html)
- [Enigma Message Breaking Project — News](https://enigma.hoerenberg.com/index.php?cat=Welcome&page=News)
