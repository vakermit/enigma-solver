# The Enigma Machine

## Origins

On 23 February 1918, a German electrical engineer named Arthur Scherbius filed patent DE416219 for a "Cipher apparatus." He was 39 years old and running a small firm called Scherbius & Ritter. The device used rotating discs with internal wiring to scramble text. In the patent filing, Scherbius noted that "with ten wheels, one gets more than 95 trillion" possible keys.

He wasn't the only one working on rotor-based cipher machines. Hugo Koch filed a similar patent in the Netherlands seven months later. Arvid Damm filed in Sweden three days after Koch. Edward Hebern was building comparable machines in the United States around the same time. The idea was in the air. Scherbius got there first, and in 1927, he bought Koch's patent rights to consolidate his position.

By 1923, Scherbius was marketing his machine under the name "Enigma" through a new company, Chiffriermaschinen Aktiengesellschaft. The early models were large and impractical. Model A weighed roughly 50 kilograms, about the size of a cash register. Subsequent versions shrank the design and replaced the printing mechanism with a lamp panel, but the core problem remained commercial: banks and businesses could buy an Enigma on the open market, and almost nobody did.

Scherbius had a colleague named Willi Korn, who made two contributions that mattered more than any of the commercial sales. Around 1924, Korn invented the reflector (Umkehrwalze), a stationary wiring that bounced the electrical signal back through the rotors a second time. This made the machine self-reciprocal: the same settings could encrypt and decrypt. In 1928, Korn added the ring settings (Ringstellung), which shifted the internal wiring relative to the outer letter ring on each rotor.

On 13 May 1929, Scherbius died in a horse-drawn carriage accident in Berlin. He was 50. He never saw the military adopt his machine at scale.

## Military Adoption

The German Navy moved first, purchasing commercial Enigma machines for military use in 1926. The Army (Reichswehr) followed on 15 July 1928 with the Enigma G, a 12-kilogram version with a counter on the front panel. The Abwehr, Germany's military intelligence service, also adopted the G in 1928.

The important change came in June 1930, when the Army's version was revised to the Enigma I. The difference was the plugboard (Steckerbrett), a panel of sockets on the front of the machine connected by cables. Each cable swapped a pair of letters before and after the signal passed through the rotors. Ten cables meant ten swapped pairs and six unswapped letters. The plugboard alone contributed over 150 trillion additional combinations, more than every other component of the machine put together.

The Navy initially resisted the Army's plugboard design but adopted it in 1934, designating their version the M3. While the Army used three rotors chosen from a set of three, the Navy specified three from a set of five, increasing the possible rotor orderings from 6 to 60.

The Luftwaffe adopted the Enigma in 1935. By that point, it was standard equipment across the German military.

The Navy kept adding rotors. Two more in 1938, a third in 1939, bringing their available set to eight. In February 1942, Admiral Karl Donitz pushed through the M4, a four-rotor machine for U-boat communications. The fourth rotor (Beta or Gamma) was thin and paired with thin reflectors. It did not step mechanically, acting as a fixed additional scrambling layer.

Total wartime production estimates range from 37,000 to 50,000 machines across all models and services. No complete production records survived the war. Approximately 20,306 Army machines were produced by Konski & Kruger in Berlin, with an additional 3,000 by Geyer in Nuremberg.

## How It Worked

Each rotor was a disc about 10 centimeters in diameter, made from hard rubber or Bakelite. Twenty-six brass spring-loaded pins on one face and twenty-six flat contacts on the other. Inside, twenty-six wires connected pins to contacts in a scrambled pattern unique to each rotor.

The signal path for a single keypress: the plugboard swapped the letter, the signal passed through three rotors right to left, hit the reflector, bounced back through the three rotors left to right, and passed through the plugboard again. Each rotor applied a different substitution at each position, and the rightmost rotor advanced one step with every keypress. The middle rotor advanced when the right rotor hit a notch. The left rotor advanced when the middle rotor hit its notch.

There was a mechanical quirk in the stepping. When the middle rotor sat at its own notch position, the pawl would push through the notch a second time on the next keypress, causing what cryptanalysts called "double-stepping." This was a manufacturing side-effect, not a design choice. It shortened the middle rotor's effective cycle and introduced an irregularity that slightly reduced the machine's theoretical period.

The reflector gave the Enigma its self-reciprocal property: type A and get G, type G and get A. This meant the same machine settings worked for both encryption and decryption, which was operationally convenient. But it also meant no letter could ever encrypt to itself. That constraint proved fatal.

## Operational Procedures

Monthly code books (Schlusseltafel) specified daily settings for each radio network: which rotors to use, their order, ring settings, and plugboard connections. Before May 1940, the code books also specified a common ground setting (Grundstellung) for the entire network.

The pre-1940 indicator system worked like this: the operator chose a random three-letter message key, set the machine to the day's ground setting, and typed the message key twice. So if the message key was MCK, the operator typed MCKMCK. The encrypted result, six letters long, was transmitted as the message indicator. The recipient decoded it using the same ground setting, recovered the doubled message key, and verified it by the repetition.

This procedure was, as the Polish mathematicians proved, both unnecessary and catastrophic. Encrypting the same three letters twice from the same starting position created a mathematical relationship between positions 1 and 4, 2 and 5, 3 and 6. Marian Rejewski exploited exactly this relationship to reconstruct the machine's internal wiring.

On 1 May 1940, the Germans abandoned the repeated indicator. Operators now chose a random ground setting per message and a random message key. The ground setting was sent in the clear. The message key was encrypted once, not twice. The Navy used an even more complex system: a Kenngruppe (identifier group) selected from a codebook and enciphered using bigram substitution tables before being embedded in the message at a specified position.

## Vulnerabilities

The reflector's guarantee that no letter encrypts to itself is a property called a fixed-point-free permutation, or derangement. Every position in the substitution is displaced. When codebreakers had a suspected plaintext (a "crib"), they could slide it along the ciphertext and instantly eliminate any alignment where a plaintext letter matched the ciphertext letter at the same position. A 20-letter crib might eliminate 80% of possible alignments before any serious computation began.

Operator habits made things worse. Some operators chose predictable message keys: their girlfriend's initials, adjacent keyboard letters like QWE or ASD, or repeated letters like AAA. A German operator in southern Italy used "CILLI" so often that the British named all such predictable keys "Cillies" after the discovery.

Known plaintext came from predictable message formats. Daily weather reports from fixed stations began with "WETTER VORHERSAGE" (weather forecast). Messages often ended with "HEIL HITLER." The Short Weather Cipher compressed meteorological data into formats that were regular enough to guess. These predictable fragments provided the cribs that fed the Bombe machines.

Physical captures provided the rest. In May 1941, HMS Somali boarded the weather ship Munchen southeast of Iceland and recovered codebooks. On 9 May 1941, U-110 was captured intact with an M3 Enigma and Short Weather Cipher codebook. On 30 October 1942, three Royal Navy sailors boarded the sinking U-559 and recovered Wetterkurzschluessel and short signal books. Two of them, Able Seaman Colin Grazier and Lieutenant Anthony Fasson, drowned during the recovery. Their materials reached Bletchley Park on 24 November 1942 and were instrumental in breaking the four-rotor M4 Triton cipher.

## Timeline

| Date | Event |
|------|-------|
| 23 Feb 1918 | Scherbius files patent DE416219 |
| 1923 | Commercial Enigma marketed as "Enigma" |
| 1926 | German Navy adopts commercial Enigma |
| Jun 1930 | Enigma I with plugboard enters Army service |
| Late 1932 | Rejewski reconstructs Enigma wiring mathematically |
| Jan 1933 | Polish Cipher Bureau reads German Enigma traffic |
| Dec 1938 | Germany adds rotors IV and V; Polish methods break |
| 25 Jul 1939 | Poles hand over Enigma replicas and methods at Pyry |
| 1 Sep 1939 | Germany invades Poland |
| 1 May 1940 | Germans stop repeating the message key |
| 1 Feb 1942 | M4 four-rotor Enigma enters U-boat service; Bletchley goes dark on naval traffic |
| 30 Oct 1942 | U-559 captured; codebooks recovered |
| 13 Dec 1942 | Bletchley breaks M4 Triton using U-559 material |

## Sources

- German Patent Office (DPMA), "Enigma" - https://www.dpma.de/english/our_office/publications/milestones/computerpioneers/enigma/index.html
- Crypto Museum, "Enigma Patents" - https://www.cryptomuseum.com/crypto/enigma/patents/index.htm
- Cipher Machines and Cryptology, "Enigma" - https://www.ciphermachinesandcryptology.com/en/enigma.htm
- Cipher Machines and Cryptology, "Enigma Technical Details" - https://www.ciphermachinesandcryptology.com/en/enigmatech.htm
- Cipher Machines and Cryptology, "Enigma Procedures" - https://www.ciphermachinesandcryptology.com/en/enigmaproc.htm
- IEEE ETHW, "First Breaking of Enigma Code by the Team of Polish Cipher Bureau" - https://ethw.org/Milestones:First_Breaking_of_Enigma_Code_by_the_Team_of_Polish_Cipher_Bureau,_1932-1939
- uboat.net, "Allied Breaking of Naval Enigma" - https://uboat.net/technical/enigma_breaking.htm
- CryptoCellar, "Enigma Production History" - https://cryptocellar.org/enigma/e-prod-history/index.html
