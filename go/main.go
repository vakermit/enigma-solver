package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var wiring = [5][26]int{
	{4, 10, 12, 5, 11, 6, 3, 16, 21, 25, 13, 19, 14, 22, 24, 7, 23, 20, 18, 15, 0, 8, 1, 17, 2, 9},
	{0, 9, 3, 10, 18, 8, 17, 20, 23, 1, 11, 7, 22, 19, 12, 2, 16, 6, 25, 13, 15, 24, 5, 21, 14, 4},
	{1, 3, 5, 7, 9, 11, 2, 15, 17, 19, 23, 21, 25, 13, 24, 4, 8, 22, 6, 0, 10, 12, 20, 18, 16, 14},
	{4, 18, 14, 21, 15, 25, 9, 0, 24, 16, 20, 8, 17, 7, 23, 11, 13, 5, 19, 6, 10, 3, 2, 12, 22, 1},
	{21, 25, 1, 17, 6, 8, 19, 24, 20, 15, 18, 3, 13, 7, 11, 23, 0, 22, 12, 9, 16, 14, 5, 4, 2, 10},
}

var invWiring [5][26]int
var notch = [5]int{16, 4, 21, 9, 25}
var reflectorB = [26]int{24, 17, 20, 7, 16, 18, 11, 3, 15, 23, 13, 6, 14, 10, 12, 8, 4, 1, 5, 25, 2, 22, 21, 9, 0, 19}
var rotorNames = [5]string{"I", "II", "III", "IV", "V"}

type combo struct{ r [3]int }

var combos []combo

func init() {
	for r := 0; r < 5; r++ {
		for i := 0; i < 26; i++ {
			invWiring[r][wiring[r][i]] = i
		}
	}
	for a := 0; a < 5; a++ {
		for b := 0; b < 5; b++ {
			if b == a {
				continue
			}
			for c := 0; c < 5; c++ {
				if c == a || c == b {
					continue
				}
				combos = append(combos, combo{r: [3]int{a, b, c}})
			}
		}
	}
}

func m26(x int) int { return ((x % 26) + 26) % 26 }

type machine struct {
	fwd, rev  [3][26]int
	reflector [26]int
	plugboard [26]int
	pos       [3]int
	notchPos  [3]int
}

func newMachine(lr, mr, rr, lRing, mRing, rRing, lStart, mStart, rStart int, refl [26]int) machine {
	var m machine
	m.fwd = [3][26]int{wiring[lr], wiring[mr], wiring[rr]}
	m.rev = [3][26]int{invWiring[lr], invWiring[mr], invWiring[rr]}
	m.reflector = refl
	m.pos = [3]int{m26(lStart - lRing), m26(mStart - mRing), m26(rStart - rRing)}
	m.notchPos = [3]int{m26(notch[lr] - lRing), m26(notch[mr] - mRing), m26(notch[rr] - rRing)}
	for i := 0; i < 26; i++ {
		m.plugboard[i] = i
	}
	return m
}

func (m *machine) step() {
	midNotch := m.pos[1] == m.notchPos[1]
	rightNotch := m.pos[2] == m.notchPos[2]
	m.pos[2] = (m.pos[2] + 1) % 26
	if rightNotch || midNotch {
		m.pos[1] = (m.pos[1] + 1) % 26
	}
	if midNotch {
		m.pos[0] = (m.pos[0] + 1) % 26
	}
}

func (m *machine) encryptChar(c int) int {
	m.step()
	sig := m.plugboard[c]
	for r := 2; r >= 0; r-- {
		pin := (sig + m.pos[r]) % 26
		sig = m26(m.fwd[r][pin] - m.pos[r])
	}
	sig = m.reflector[sig]
	for r := 0; r < 3; r++ {
		contact := (sig + m.pos[r]) % 26
		sig = m26(m.rev[r][contact] - m.pos[r])
	}
	return m.plugboard[sig]
}

func (m *machine) process(input, output []int) {
	for i, c := range input {
		output[i] = m.encryptChar(c)
	}
}

func (m *machine) setPlugboard(pairs string) {
	for i := 0; i < 26; i++ {
		m.plugboard[i] = i
	}
	for _, p := range strings.Fields(pairs) {
		if len(p) == 2 {
			a, b := int(p[0]-'A'), int(p[1]-'A')
			m.plugboard[a] = b
			m.plugboard[b] = a
		}
	}
}

func calcIoC(text []int) float64 {
	n := len(text)
	if n <= 1 {
		return 0
	}
	var freq [26]int
	for _, c := range text {
		freq[c]++
	}
	sum := 0
	for _, f := range freq {
		sum += f * (f - 1)
	}
	return float64(sum) / (float64(n) * float64(n-1))
}

var enBigrams [26][26]float32
var deBigrams [26][26]float32

func initBigrams() {
	en := [][3]float32{
		{19, 7, 35.6}, {7, 4, 30.7}, {8, 13, 24.3}, {4, 17, 20.5}, {0, 13, 19.9},
		{17, 4, 18.5}, {14, 13, 17.6}, {0, 19, 14.9}, {4, 13, 14.5}, {13, 3, 13.5},
		{19, 8, 13.4}, {4, 18, 13.4}, {14, 17, 12.8}, {19, 4, 12.0}, {14, 5, 11.4},
		{4, 3, 11.2}, {8, 18, 11.1}, {8, 19, 11.0}, {0, 11, 10.9}, {0, 17, 10.7},
		{18, 19, 10.5}, {19, 14, 10.5}, {13, 19, 10.4}, {13, 6, 9.5}, {18, 4, 9.3},
		{7, 0, 9.3}, {0, 18, 8.7}, {14, 20, 8.7}, {8, 14, 8.3}, {11, 4, 8.3},
		{21, 4, 8.3}, {2, 14, 7.9}, {12, 4, 7.9}, {3, 4, 7.6}, {7, 8, 7.6},
		{17, 8, 7.3}, {17, 14, 7.3}, {8, 2, 7.0}, {13, 4, 6.9}, {4, 0, 6.9},
		{17, 0, 6.9}, {2, 4, 6.5}, {11, 8, 6.2}, {2, 7, 5.9}, {11, 11, 5.8},
		{1, 4, 5.8}, {12, 0, 5.7}, {18, 8, 5.5}, {14, 12, 5.5}, {20, 17, 5.4},
	}
	for _, e := range en {
		enBigrams[int(e[0])][int(e[1])] = e[2]
	}
	de := [][3]float32{
		{4, 13, 39.5}, {4, 17, 37.5}, {2, 7, 27.5}, {3, 4, 20.2}, {4, 8, 19.8},
		{13, 3, 18.5}, {19, 4, 17.6}, {8, 13, 17.5}, {8, 4, 16.5}, {6, 4, 15.5},
		{20, 13, 14.3}, {18, 19, 13.8}, {4, 18, 13.2}, {0, 13, 12.7}, {17, 4, 12.5},
		{7, 4, 12.0}, {1, 4, 11.5}, {0, 20, 10.8}, {13, 4, 10.5}, {18, 2, 10.2},
		{18, 4, 9.8}, {3, 8, 9.5}, {13, 6, 9.2}, {8, 2, 8.8}, {3, 0, 8.5},
		{4, 12, 8.2}, {4, 11, 8.0}, {21, 4, 7.8}, {7, 0, 7.5}, {0, 11, 7.2},
		{8, 19, 7.0}, {8, 18, 6.8}, {18, 8, 6.5}, {18, 14, 6.2}, {17, 0, 6.0},
		{18, 18, 5.8}, {0, 1, 5.5}, {17, 8, 5.3}, {5, 4, 5.0}, {12, 8, 4.8},
	}
	for _, e := range de {
		deBigrams[int(e[0])][int(e[1])] = e[2]
	}
}

func calcBigram(text []int, table *[26][26]float32) float64 {
	if len(text) < 2 {
		return 0
	}
	var sum float32
	for i := 0; i < len(text)-1; i++ {
		sum += table[text[i]][text[i+1]]
	}
	return float64(sum) / float64(len(text)-1)
}

type candidate struct {
	ioc      float64
	bigram   float64
	comboIdx int
	lp, mp, rp int
	lr, mr, rr int
	plugboard string
	plaintext []int
}

func bruteForce(ct []int, refl [26]int, nThreads int) []float32 {
	total := len(combos) * 17576
	results := make([]float32, total)
	var wg sync.WaitGroup
	chunk := total / nThreads

	for t := 0; t < nThreads; t++ {
		start := t * chunk
		end := start + chunk
		if t == nThreads-1 {
			end = total
		}
		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			pt := make([]int, len(ct))
			for idx := s; idx < e; idx++ {
				ci := idx / 17576
				pi := idx % 17576
				lp, mp, rp := pi/676, (pi/26)%26, pi%26
				c := combos[ci]
				m := newMachine(c.r[0], c.r[1], c.r[2], 0, 0, 0, lp, mp, rp, refl)
				m.process(ct, pt)
				results[idx] = float32(calcIoC(pt))
			}
		}(start, end)
	}
	wg.Wait()
	return results
}

func groupText(text string, size int) string {
	var b strings.Builder
	for i, c := range text {
		if i > 0 && i%size == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	return b.String()
}

func main() {
	initBigrams()

	var (
		fileFlag      = flag.String("f", "", "Read ciphertext from file")
		langFlag      = flag.String("l", "german", "Target language: english|german")
		beamFlag      = flag.Int("b", 50, "Beam width")
		plugFlag      = flag.Bool("p", false, "Run plugboard hill climbing")
		outputFlag    = flag.String("o", "", "Save settings to JSON file")
		showFlag      = flag.Int("n", 10, "Results to show")
		threadsFlag   = flag.Int("t", runtime.NumCPU(), "Threads")
		quickFlag     = flag.Bool("q", false, "Quick pass: prune combos by peak IoC")
		quickPctFlag  = flag.Int("Q", 25, "Quick pass: keep top N%")
		separateFlag  = flag.Bool("s", false, "Separate rings: beam search left×mid then right")
	)
	flag.Parse()

	ctStr := ""
	if *fileFlag != "" {
		data, err := os.ReadFile(*fileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open %s\n", *fileFlag)
			os.Exit(1)
		}
		ctStr = strings.TrimSpace(string(data))
	} else if flag.NArg() > 0 {
		ctStr = flag.Arg(0)
	} else {
		fmt.Fprintln(os.Stderr, "Error: no ciphertext provided")
		os.Exit(1)
	}

	var ct []int
	for _, c := range strings.ToUpper(ctStr) {
		if c >= 'A' && c <= 'Z' {
			ct = append(ct, int(c-'A'))
		}
	}
	ctLen := len(ct)

	if ctLen < 50 {
		fmt.Fprintf(os.Stderr, "WARNING: %d chars is very short — IoC overlaps heavily with random. Historical messages were 200-250 chars.\n", ctLen)
	} else if ctLen < 100 {
		fmt.Fprintf(os.Stderr, "NOTE: %d chars is short. IoC separation from random is marginal.\n", ctLen)
	} else if ctLen < 150 {
		fmt.Fprintf(os.Stderr, "NOTE: %d chars — workable but below the 200-250 char historical norm.\n", ctLen)
	}

	german := *langFlag == "german"
	beam := *beamFlag
	nThreads := *threadsFlag
	refl := reflectorB
	bigrams := &deBigrams
	if !german {
		bigrams = &enBigrams
	}

	modeStr := "full"
	if *separateFlag {
		modeStr = "separate-rings"
	} else if *quickFlag {
		modeStr = "quick-pass"
	}

	var ctChars strings.Builder
	for _, c := range ct {
		ctChars.WriteByte(byte(c) + 'A')
	}
	fmt.Printf("Ciphertext (%d chars): %.72s\n", ctLen, groupText(ctChars.String(), 5))
	fmt.Printf("Language: %s | Beam: %d | Threads: %d | Mode: %s\n",
		*langFlag, beam, nThreads, modeStr)

	t0 := time.Now()
	var candidates []candidate

	if *separateFlag {
		interBeam := beam * 5
		nTrials := len(combos) * 676
		fmt.Printf("\n--- Phase 1a: %d combos × 676 left×mid = %d trials ---\n", len(combos), nTrials)

		type beamResult struct {
			ioc float32
			ci  int
			l, m int
		}
		var all []beamResult
		pt := make([]int, ctLen)
		for ci, c := range combos {
			for l := 0; l < 26; l++ {
				for m := 0; m < 26; m++ {
					mach := newMachine(c.r[0], c.r[1], c.r[2], 0, 0, 0, l, m, 0, refl)
					mach.process(ct, pt)
					all = append(all, beamResult{float32(calcIoC(pt)), ci, l, m})
				}
			}
			if (ci+1)%20 == 0 {
				fmt.Printf("  ... %d/%d combos done\n", ci+1, len(combos))
			}
		}
		sort.Slice(all, func(i, j int) bool { return all[i].ioc > all[j].ioc })
		if len(all) > interBeam {
			all = all[:interBeam]
		}
		fmt.Printf("  Best IoC: %.6f\n", all[0].ioc)

		fmt.Printf("\n--- Phase 1b: top %d × 26 right positions ---\n", len(all))
		var expanded []candidate
		for _, br := range all {
			c := combos[br.ci]
			for rp := 0; rp < 26; rp++ {
				mach := newMachine(c.r[0], c.r[1], c.r[2], 0, 0, 0, br.l, br.m, rp, refl)
				mach.process(ct, pt)
				expanded = append(expanded, candidate{ioc: calcIoC(pt), comboIdx: br.ci, lp: br.l, mp: br.m, rp: rp})
			}
		}
		sort.Slice(expanded, func(i, j int) bool { return expanded[i].ioc > expanded[j].ioc })
		if len(expanded) > beam {
			expanded = expanded[:beam]
		}
		fmt.Printf("  Best IoC: %.6f\n", expanded[0].ioc)
		candidates = expanded

	} else {
		total := len(combos) * 17576
		fmt.Printf("\n--- Phase 1: %d combos × 17,576 = %d trials (%d threads) ---\n",
			len(combos), total, nThreads)
		iocResults := bruteForce(ct, refl, nThreads)
		phase1 := time.Since(t0).Seconds() * 1000
		fmt.Printf("  Done in %.1f ms (%.0f decryptions/sec)\n", phase1, float64(total)/(phase1/1000))

		indices := make([]int, total)
		for i := range indices {
			indices[i] = i
		}
		sort.Slice(indices, func(i, j int) bool { return iocResults[indices[i]] > iocResults[indices[j]] })

		if *quickFlag {
			keepN := int(math.Max(1, float64(len(combos))*float64(*quickPctFlag)/100))
			fmt.Printf("\n--- Quick pass: keeping top %d%% (%d combos) by peak IoC ---\n", *quickPctFlag, keepN)
			type cs struct {
				peak float32
				idx  int
			}
			peaks := make([]cs, len(combos))
			for ci := range combos {
				base := ci * 17576
				var peak float32
				for p := 0; p < 17576; p++ {
					if iocResults[base+p] > peak {
						peak = iocResults[base+p]
					}
				}
				peaks[ci] = cs{peak, ci}
			}
			sort.Slice(peaks, func(i, j int) bool { return peaks[i].peak > peaks[j].peak })
			surviving := make(map[int]bool)
			for i := 0; i < keepN; i++ {
				surviving[peaks[i].idx] = true
			}
			c0 := combos[peaks[0].idx]
			fmt.Printf("  Best: %s %s %s (peak %.6f)\n",
				rotorNames[c0.r[0]], rotorNames[c0.r[1]], rotorNames[c0.r[2]], peaks[0].peak)

			found := 0
			for _, idx := range indices {
				if found >= beam {
					break
				}
				ci := idx / 17576
				if surviving[ci] {
					pi := idx % 17576
					candidates = append(candidates, candidate{
						ioc: float64(iocResults[idx]), comboIdx: ci,
						lp: pi / 676, mp: (pi / 26) % 26, rp: pi % 26,
					})
					found++
				}
			}
		} else {
			n := beam
			if n > total {
				n = total
			}
			for j := 0; j < n; j++ {
				idx := indices[j]
				ci := idx / 17576
				pi := idx % 17576
				candidates = append(candidates, candidate{
					ioc: float64(iocResults[idx]), comboIdx: ci,
					lp: pi / 676, mp: (pi / 26) % 26, rp: pi % 26,
				})
			}
		}

		c0 := combos[candidates[0].comboIdx]
		fmt.Printf("  Best IoC: %.6f  (%s %s %s @ %c%c%c)\n", candidates[0].ioc,
			rotorNames[c0.r[0]], rotorNames[c0.r[1]], rotorNames[c0.r[2]],
			rune(candidates[0].lp+'A'), rune(candidates[0].mp+'A'), rune(candidates[0].rp+'A'))
	}

	// Ring refinement
	names := [3]string{"left", "middle", "right"}
	pt := make([]int, ctLen)
	for ringIdx := 0; ringIdx < 3; ringIdx++ {
		fmt.Printf("\n--- Ring refinement: top %d × 26 %s ring settings ---\n", beam, names[ringIdx])
		var expanded []candidate
		for _, c := range candidates {
			cb := combos[c.comboIdx]
			for r := 0; r < 26; r++ {
				lr, mr, rr := c.lr, c.mr, c.rr
				switch ringIdx {
				case 0:
					lr = r
				case 1:
					mr = r
				case 2:
					rr = r
				}
				mach := newMachine(cb.r[0], cb.r[1], cb.r[2], lr, mr, rr, c.lp, c.mp, c.rp, refl)
				mach.process(ct, pt)
				nc := c
				nc.ioc = calcIoC(pt)
				nc.lr, nc.mr, nc.rr = lr, mr, rr
				expanded = append(expanded, nc)
			}
		}
		sort.Slice(expanded, func(i, j int) bool { return expanded[i].ioc > expanded[j].ioc })
		if len(expanded) > beam {
			expanded = expanded[:beam]
		}
		fmt.Printf("  Best IoC: %.6f  (rings=%d,%d,%d)\n", expanded[0].ioc, expanded[0].lr, expanded[0].mr, expanded[0].rr)
		candidates = expanded
	}

	// Bigram scoring
	for i := range candidates {
		c := &candidates[i]
		cb := combos[c.comboIdx]
		mach := newMachine(cb.r[0], cb.r[1], cb.r[2], c.lr, c.mr, c.rr, c.lp, c.mp, c.rp, refl)
		ptv := make([]int, ctLen)
		mach.process(ct, ptv)
		c.bigram = calcBigram(ptv, bigrams)
		c.plaintext = ptv
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].bigram > candidates[j].bigram })

	// Plugboard hill climbing
	if *plugFlag && len(candidates) > 0 {
		fmt.Println("\n--- Plugboard hill climbing ---")
		best := &candidates[0]
		var used [26]bool
		pairsFound := 0
		bestScore := best.bigram
		for pairsFound < 13 {
			improved := false
			bestA, bestB := 0, 0
			bestNewScore := bestScore
			for a := 0; a < 26; a++ {
				if used[a] {
					continue
				}
				for b := a + 1; b < 26; b++ {
					if used[b] {
						continue
					}
					pair := fmt.Sprintf("%c%c", rune(a+'A'), rune(b+'A'))
					testPlug := pair
					if best.plugboard != "" {
						testPlug = best.plugboard + " " + pair
					}
					cb := combos[best.comboIdx]
					mach := newMachine(cb.r[0], cb.r[1], cb.r[2], best.lr, best.mr, best.rr, best.lp, best.mp, best.rp, refl)
					mach.setPlugboard(testPlug)
					ptv := make([]int, ctLen)
					mach.process(ct, ptv)
					score := calcBigram(ptv, bigrams)
					if score > bestNewScore {
						bestNewScore = score
						bestA, bestB = a, b
						improved = true
					}
				}
			}
			if !improved {
				break
			}
			used[bestA] = true
			used[bestB] = true
			pair := fmt.Sprintf("%c%c", rune(bestA+'A'), rune(bestB+'A'))
			if best.plugboard == "" {
				best.plugboard = pair
			} else {
				best.plugboard += " " + pair
			}
			bestScore = bestNewScore
			pairsFound++
			fmt.Printf("  +%s (bigram: %.2f, pairs: %d)\n", pair, bestScore, pairsFound)
		}
		cb := combos[best.comboIdx]
		mach := newMachine(cb.r[0], cb.r[1], cb.r[2], best.lr, best.mr, best.rr, best.lp, best.mp, best.rp, refl)
		mach.setPlugboard(best.plugboard)
		ptv := make([]int, ctLen)
		mach.process(ct, ptv)
		best.plaintext = ptv
		best.bigram = bestScore
	}

	totalMs := float64(time.Since(t0).Nanoseconds()) / 1e6
	fmt.Printf("\n%s\n", strings.Repeat("=", 90))
	fmt.Printf("Done in %.1f ms\n", totalMs)
	fmt.Println(strings.Repeat("=", 90))

	show := *showFlag
	if show > len(candidates) {
		show = len(candidates)
	}
	fmt.Printf("\n%3s  %-12s %3s %-10s %-6s %7s %7s  Plaintext\n", "#", "Rotors", "Ref", "Rings", "Start", "IoC", "Bigram")
	fmt.Println(strings.Repeat("-", 90))
	for j := 0; j < show; j++ {
		c := candidates[j]
		cb := combos[c.comboIdx]
		rotors := fmt.Sprintf("%s %s %s", rotorNames[cb.r[0]], rotorNames[cb.r[1]], rotorNames[cb.r[2]])
		rings := fmt.Sprintf("%2d,%2d,%2d", c.lr, c.mr, c.rr)
		start := fmt.Sprintf("%c%c%c", rune(c.lp+'A'), rune(c.mp+'A'), rune(c.rp+'A'))
		n := 35
		if n > len(c.plaintext) {
			n = len(c.plaintext)
		}
		var preview strings.Builder
		for _, v := range c.plaintext[:n] {
			preview.WriteByte(byte(v) + 'A')
		}
		plug := ' '
		if c.plugboard != "" {
			plug = '*'
		}
		fmt.Printf("%3d%c  %-12s   B %s  %-6s %7.5f %7.2f  %s\n",
			j+1, plug, rotors, rings, start, c.ioc, c.bigram, preview.String())
	}

	if *outputFlag != "" && len(candidates) > 0 {
		c := candidates[0]
		cb := combos[c.comboIdx]
		var ptStr strings.Builder
		for _, v := range c.plaintext {
			ptStr.WriteByte(byte(v) + 'A')
		}
		settings := map[string]interface{}{
			"rotors":         fmt.Sprintf("%s %s %s", rotorNames[cb.r[0]], rotorNames[cb.r[1]], rotorNames[cb.r[2]]),
			"reflector":      "B",
			"ring_settings":  []int{c.lr, c.mr, c.rr},
			"start_position": fmt.Sprintf("%c%c%c", rune(c.lp+'A'), rune(c.mp+'A'), rune(c.rp+'A')),
			"plugboard":      c.plugboard,
			"ioc":            c.ioc,
			"bigram_score":   c.bigram,
			"plaintext":      ptStr.String(),
		}
		data, _ := json.MarshalIndent(settings, "", "  ")
		os.WriteFile(*outputFlag, data, 0644)
		fmt.Printf("\nSettings saved to %s\n", *outputFlag)
	}
}
