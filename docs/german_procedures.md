# German Enigma Procedures and Variations

## Networks

The Germans operated separate Enigma key networks for different units and purposes. Each network had its own daily settings. Bletchley Park assigned codenames to track them, starting with colors (pencil marks on intercepts) and moving to animals and birds when the colors ran out.

The main Luftwaffe network was **Red**, the most-read Enigma traffic of the war. Bletchley first broke Red consistently on 22 May 1940. **Light Blue** covered Luftwaffe training. **Brown** was the radio research regiment's key, tracked from 1940 to 7 May 1945.

The Army used **Green** (administrative, the first key broken at Bletchley on 20 January 1940), **Yellow** (operational), and later **Vulture**, **Kestrel**, and **Kite** for various Eastern Front and supply networks.

The Navy's networks were more specialized. **Dolphin** (German: Heimisch) was the principal U-boat and surface ship cipher for Home Waters and the Atlantic. **Shark** (German: Triton) replaced it for U-boats on 1 February 1942 when the four-rotor M4 entered service. **Porpoise** covered Mediterranean naval surface traffic. **Turtle**, **Narwhale**, **Grampus**, and **Sunfish** handled sub-regions. **Oyster** was a surface ship key.

By war's end, Bletchley tracked dozens of separate Enigma networks simultaneously.

## The Key Sheet

Each network distributed monthly key sheets (Schlusseltafel) specifying daily settings. The sheet was a printed table with one row per day, numbered 31 at the top down to 1 at the bottom. Operators cut off each day's row after use, so only current and future settings remained.

Army and Luftwaffe sheets listed five columns: the day number (Tag), rotor selection and order (Walzenlage), ring settings (Ringstellung), plugboard pairs (Steckerverbindungen), and, before May 1940, a common ground setting (Grundstellung).

Navy sheets split the information across two separate documents. The inner settings (Innere Einstellung) specified rotors and ring settings, changing only on odd days. The outer settings (Aussere Einstellung) specified plugboard pairs and ground settings, changing daily.

The sheets were printed in soluble ink. If capture was imminent, operators were supposed to dip the sheet in water, dissolving everything. Used sheets were destroyed. Distribution was by courier.

## Army and Luftwaffe Message Procedure

### Before May 1940

The pre-war indicator system gave the Polish mathematicians their opening. It worked like this:

1. The operator set up the machine with the day's settings from the key sheet, including the common ground setting.
2. The operator chose a random three-letter message key, for example MCK.
3. With the machine set to the ground setting, the operator typed the message key twice: MCKMCK. The machine encrypted this into a six-letter indicator.
4. The operator transmitted the six-letter indicator.
5. The operator then set the rotors to MCK and encrypted the actual message.
6. The recipient, using the same ground setting, decrypted the six-letter indicator, verified the repetition, set the rotors to the recovered message key, and decrypted the body.

Encrypting the same three letters twice created a mathematical relationship between positions 1 and 4, 2 and 5, 3 and 6. This relationship was deterministic for a given daily setting and was the exact weakness Rejewski used to break the machine in 1932.

### After May 1940

On 1 May 1940, the Germans dropped the repeated indicator. The new procedure:

1. The operator chose a random three-letter ground setting and a random three-letter message key.
2. The operator set the rotors to the ground setting.
3. The operator typed the message key once. The machine encrypted it into three letters.
4. The operator transmitted the ground setting in the clear, followed by the three-letter encrypted message key.
5. The operator set the rotors to the message key and encrypted the body.

### Message Format

A transmitted Enigma message had a fixed structure:

- **Preamble (clear)**: call sign, time of origin, letter count of the encrypted text.
- **Kenngruppe (discriminant)**: a five-letter group containing two padding letters and a three-letter discriminant identifying the network and key.
- **Indicator**: the encrypted message key (six letters before May 1940, three letters after).
- **Message body**: always in five-letter groups. Short final groups were padded with X.

Messages were limited to 250 characters. Longer messages were split into parts, each with its own message key.

## Navy Kenngruppen System

The Kriegsmarine used a more complex indicator system that layered additional encryption on top of the Enigma itself.

Two secret documents were required beyond the key sheet:

- The **Kenngruppenbuch** (K-Book): a codebook listing trigraphs in random order. Each entry was used once and crossed off.
- The **Doppelbuchstabentauschtafel**: a set of nine bigram substitution tables, labeled A through J. A calendar determined which table applied on a given day. The tables were reciprocal: if AB encoded to KW, then KW decoded back to AB.

The procedure:

1. The operator selected two trigrams from the K-Book: one to identify the key/network (Schluesselkenngruppe) and one to derive the message key (Verfahrenkenngruppe).
2. With the Enigma set to the day's ground setting, the operator typed the Verfahrenkenngruppe. The encrypted output became the message key.
3. The two trigrams were arranged vertically, padded with a random dummy letter each, creating four bigrams.
4. Each bigram was substituted using the day's bigram table.
5. The substituted result was transmitted as the message indicator.

The ground setting never appeared in the clear. The additional bigram substitution layer sat on top of the Enigma encryption. Without captured K-Books and bigram tables, the system was opaque to analysis. This is why the captures from U-110 (May 1941) and U-559 (October 1942) were so important.

## Weather Ciphers and Short Signals

### Short Weather Cipher (Wetterkurzschluessel)

U-boats sent weather reports compressed through a codebook into a fixed seven-letter message. Each letter position represented a specific value: wind direction, wind force, air pressure, temperature, visibility, cloud cover. The same weather conditions always produced the same encoding.

The seven letters were then encrypted with the naval Enigma and transmitted. Shore stations decrypted and expanded them into full weather reports.

Bletchley's weather section in Hut 10 broke manual weather ciphers, which gave them the decoded observations. Since the same data was also sent through the Enigma-encrypted Wetterkurzschluessel, they had known plaintext for the naval Enigma settings. Atlantic U-boats reported weather frequently, providing a steady supply of cribs.

### Short Signal Book (Kurzsignalheft)

A separate codebook for tactical messages: convoy sightings, position reports, engagement status. It compressed standard military messages into short coded groups for brief radio bursts, reducing the time a U-boat was transmitting and vulnerable to direction-finding.

The rigid format made the content predictable, which was exactly the opposite of the intended effect. Both the Kurzsignalheft and Wetterkurzschluessel captured from U-559 were critical to breaking the four-rotor M4 cipher.

## Machine Variations

### Enigma I (Army/Luftwaffe)

Three rotors chosen from five (I through V). Standard reflectors B and C. Ten plugboard cables. One notch per rotor. 60 possible rotor orderings. In service from 1930 and the most widely used variant.

### M3 (Navy)

Three rotors chosen from eight (I through VIII). Same reflectors and plugboard. Rotors VI, VII, and VIII each had two notches (at Z and M), stepping twice as frequently as the single-notch rotors. 336 possible rotor orderings. The Navy added rotors VI and VII in 1938, VIII in 1939.

### M4 (Four-Rotor Navy)

Four rotors total. The leftmost was a thin fourth rotor, either Beta or Gamma, paired with thin reflectors B-Thin or C-Thin. The fourth rotor did not step mechanically; it was set to one of 26 fixed positions. The other three rotors were chosen from the standard eight. The thin reflector plus thin fourth rotor occupied the same physical space as the standard thick reflector, so the M4 fit in the same case as the M3.

Entered service 1 February 1942 on the Triton (Shark) network. Caused a ten-month blackout at Bletchley until captured codebooks from U-559 enabled the break in December 1942.

### Abwehr Enigma (Enigma G)

The intelligence service's version was mechanically different. Four rotors with multiple notches each. The reflector rotated during encryption, unlike every other variant. No plugboard. A gearbox drove the rotation instead of the standard pawl-and-ratchet. A mechanical counter on the front panel incremented with each keypress. Dilly Knox broke it in 1941.

### Other Variants

The **Railway Enigma** ("Rocket") was a standard Enigma K with rewired rotors, used by the Reichsbahn. No plugboard. The **Enigma T** ("Tirpitz") was built for Japanese forces in 1942, with eight cipher wheels each having five rotation notches. The **Swiss-K** was used by the Swiss military and diplomats, a standard K with rewired wheels and an external lamp panel.

## Procedural Failures

The machine's cryptographic strength was repeatedly undermined by operator behavior.

**Cillies** were predictable message keys. The name came from a German operator in southern Italy who used his girlfriend's initials, CILLI, as his message key repeatedly. Other common patterns: adjacent keyboard letters (QWE, ASD, ZXC), repeated letters (AAA), sequential letters (ABC), or reusing the final rotor position from the previous message.

**The Herivel Tip** exploited lazy setup. John Herivel realized in February 1940 that operators who set ring settings while the rotor was already in the machine would leave the window showing a position close to the ring setting itself. If they used that visible position as the ground setting for the first message of the day instead of choosing a random one, the ground settings would cluster around the ring settings. Herivel proposed plotting these on a grid (the "Herivel square") to spot the clusters.

From May 1940, when the doubled indicator was eliminated, the Herivel tip combined with Cillies was the primary method for breaking Luftwaffe traffic. It held the line until the first Bombes arrived in August.

**Re-encipherments** ("kisses") happened when the same message was sent using two different ciphers or on two different networks. If one version had been broken, its content served as a crib for the other.

**Test messages** were sometimes all one letter (AAAA... or RRRR...) or keyboard runs (QWERTZ...). Routine reports used predictable formulas: "KEINE BESONDEREN EREIGNISSE" ("nothing to report"), "WETTER VORHERSAGE" at the start of weather reports, "HEIL HITLER" at the end. The 250-character limit forced long messages into multiple parts, and operators who chose related keys for the parts created additional attack surface.

## Sources

- Cipher Machines and Cryptology, "Enigma Procedures" - https://www.ciphermachinesandcryptology.com/en/enigmaproc.htm
- Cipher Machines and Cryptology, "Enigma on U-Boats" - https://www.ciphermachinesandcryptology.com/en/enigmauboats.htm
- Bletchley Park, "Enigma Red Messages" - https://www.bletchleypark.org.uk/our-story/enigma-red-messages/
- GCHQ, "The BROWN Network" - https://www.gchq.gov.uk/information/the-brown-network
- Tony Sale, "Lecture on Naval Enigma" - https://www.codesandciphers.org.uk/lectures/naval1.htm
- University of Arizona, "Enigma Message Procedures" - https://archive.math.arizona.edu/mbbush/enigma/Enigma%20message%20proceedures.pdf
- CryptoCellar, "Enigma Variations: An Extended Family of Machines" - https://cryptocellar.org/pubs/enigvar.pdf
- CryptoCellar, "Enigma Keys June-October 1941" - https://cryptocellar.org/bgac/e-keys-jun-oct-1941.html
- Bonhams, "German Weather Report Codebook for Enigma Use" - https://www.bonhams.com/auction/24895/lot/269/
- Taylor & Francis, "Human Factors and Missed Solutions to Enigma Design Weaknesses" - https://www.tandfonline.com/doi/full/10.1080/01611194.2015.1028680
