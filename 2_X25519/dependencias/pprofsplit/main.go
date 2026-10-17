package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/pprof/profile"
)

type category struct {
	name string
	re   *regexp.Regexp
}

// A ordem define a precedência quando uma pilha contém chamadas aninhadas:
// 1. Se a execução entrou no alocador/GC do runtime, o custo é de memória/GC.
// 2. Se dh/x25519 invocou funções de corpo finito em math/fp25519, o custo é de fp25519.
// 3. Caso contrário, se está em dh/x25519 (escada/tabelas/rotinas integradas), o custo é de x25519_ladder.
var categories = []category{
	{"runtime_alloc_gc", regexp.MustCompile(`^(runtime\.(mallocgc|newobject|gcBgMarkWorker|gcDrain|gcAssistAlloc|bgsweep|bgscavenge|scanobject|markroot|wbBufFlush)|gcWriteBarrier)`)},
	{"fp25519", regexp.MustCompile(`cloudflare/circl/math/fp25519\.`)},
	{"x25519_ladder", regexp.MustCompile(`cloudflare/circl/dh/x25519\.`)},
}

var columns = []string{"fp25519", "x25519_ladder", "runtime_alloc_gc", "other"}

func classify(s *profile.Sample) string {
	hit := make([]bool, len(categories))
	for _, loc := range s.Location {
		for _, ln := range loc.Line { // inclui frames inlined e chamadas
			if ln.Function == nil {
				continue
			}
			for i, c := range categories {
				if !hit[i] && c.re.MatchString(ln.Function.Name) {
					hit[i] = true
				}
			}
		}
	}
	for i, c := range categories {
		if hit[i] {
			return c.name
		}
	}
	return "other"
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "uso: pprofsplit saida.csv perfil_sym.pb.gz [...]")
		os.Exit(2)
	}
	out, err := os.Create(os.Args[1])
	check(err)
	w := csv.NewWriter(out)

	header := []string{"binary", "op", "samples", "cpu_ms"}
	fmt.Printf("%-9s %-16s %8s %9s", "binary", "op", "samples", "cpu_ms")
	for _, c := range columns {
		header = append(header, c+"_pct")
		fmt.Printf(" %17s", c+"%")
	}
	fmt.Println()
	check(w.Write(header))

	for _, path := range os.Args[2:] {
		f, err := os.Open(path)
		check(err)
		p, err := profile.Parse(f)
		f.Close()
		check(err)

		cpuIdx := -1
		for i, st := range p.SampleType {
			if st.Type == "cpu" {
				cpuIdx = i
				break
			}
		}
		if cpuIdx < 0 {
			if len(p.SampleType) > 0 {
				cpuIdx = len(p.SampleType) - 1
			} else {
				check(fmt.Errorf("%s: perfil sem amostras do tipo cpu", path))
			}
		}

		byCat := map[string]int64{}
		var total, samples int64
		for _, s := range p.Sample {
			v := s.Value[cpuIdx]
			byCat[classify(s)] += v
			total += v
			samples += s.Value[0]
		}

		name := filepath.Base(path)
		name = strings.TrimSuffix(name, ".pb.gz")
		name = strings.TrimSuffix(name, ".prof")
		name = strings.TrimSuffix(name, "_sym")
		bin, op, _ := strings.Cut(name, "_")
		cpuMs := float64(total) / 1e6
		row := []string{bin, op, strconv.FormatInt(samples, 10), fmt.Sprintf("%.1f", cpuMs)}
		fmt.Printf("%-9s %-16s %8d %9.1f", bin, op, samples, cpuMs)
		for _, c := range columns {
			pct := 0.0
			if total > 0 {
				pct = 100 * float64(byCat[c]) / float64(total)
			}
			row = append(row, fmt.Sprintf("%.2f", pct))
			fmt.Printf(" %17.2f", pct)
		}
		fmt.Println()
		check(w.Write(row))
	}
	w.Flush()
	check(w.Error())
	check(out.Close())
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		os.Exit(1)
	}
}
