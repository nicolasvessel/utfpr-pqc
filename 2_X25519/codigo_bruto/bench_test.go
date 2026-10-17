package x25519bench

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/dh/x25519"
	"golang.org/x/sys/cpu"
)

// Sink global: impede que o compilador descarte o trabalho medido.
var sinkByte byte

// fixture concentra todo o material pré-computado FORA do cronômetro:
// chaves privadas determinísticas, chaves públicas derivadas, segredo compartilhado
// e um ponto público de baixa ordem (inválido segundo a RFC 7748).
type fixture struct {
	aliceSec x25519.Key
	alicePub x25519.Key
	bobSec   x25519.Key
	bobPub   x25519.Key
	sharedAB x25519.Key
	badPub   x25519.Key
}

// detBytes preenche buf deterministicamente (SHA-256 em modo contador).
// Sem syscalls de entropia e com entradas idênticas nos binários A e B.
func detBytes(buf []byte, label string) {
	var ctr [4]byte
	for off, i := 0, uint32(0); off < len(buf); i++ {
		binary.BigEndian.PutUint32(ctr[:], i)
		h := sha256.New()
		h.Write([]byte(label))
		h.Write(ctr[:])
		off += copy(buf[off:], h.Sum(nil))
	}
}

func newFixture(tb testing.TB) *fixture {
	tb.Helper()
	f := new(fixture)
	detBytes(f.aliceSec[:], "utfpr-pqc/x25519-alice-sec")
	detBytes(f.bobSec[:], "utfpr-pqc/x25519-bob-sec")

	x25519.KeyGen(&f.alicePub, &f.aliceSec)
	x25519.KeyGen(&f.bobPub, &f.bobSec)

	okAB := x25519.Shared(&f.sharedAB, &f.aliceSec, &f.bobPub)
	if !okAB {
		tb.Fatal("Shared(aliceSec, bobPub) retornou false para chave pública válida")
	}

	var sharedBA x25519.Key
	okBA := x25519.Shared(&sharedBA, &f.bobSec, &f.alicePub)
	if !okBA {
		tb.Fatal("Shared(bobSec, alicePub) retornou false para chave pública válida")
	}

	if f.sharedAB != sharedBA {
		tb.Fatal("Shared(Alice, Bob) diverge de Shared(Bob, Alice)")
	}

	// Ponto público de baixa ordem canônico (32 bytes zero, RFC 7748 Seção 6.1):
	// deve produzir segredo nulo e retornar ok == false após executar a escada em tempo constante.
	f.badPub = x25519.Key{}
	var sharedBad x25519.Key
	if okBad := x25519.Shared(&sharedBad, &f.aliceSec, &f.badPub); okBad {
		tb.Fatal("rejeição de ponto de baixa ordem falhou (retornou true para ponto nulo)")
	}

	return f
}

// ---------------------------------------------------------------- testes

func TestEnvironment(t *testing.T) {
	t.Logf("ENV build=%s HasBMI2=%v HasADX=%v HasAVX2=%v", buildMode, cpu.X86.HasBMI2, cpu.X86.HasADX, cpu.X86.HasAVX2)
	if buildMode == "default" && (!cpu.X86.HasBMI2 || !cpu.X86.HasADX) {
		t.Fatal("binário padrão em CPU sem BMI2/ADX: o caminho otimizado em Assembly do X25519 não seria usado")
	}
}

// TestDigest emite um digest das saídas; os binários A (purego) e B (default)
// devem imprimir exatamente o mesmo valor.
func TestDigest(t *testing.T) {
	f := newFixture(t)

	var sharedBad x25519.Key
	_ = x25519.Shared(&sharedBad, &f.aliceSec, &f.badPub)

	h := sha256.New()
	h.Write(f.alicePub[:])
	h.Write(f.bobPub[:])
	h.Write(f.sharedAB[:])
	h.Write(sharedBad[:])
	t.Logf("DIGEST=%s", hex.EncodeToString(h.Sum(nil)))
}

// ----------------------------------------------------------- benchmarks

// Geração de chave pública a partir da chave privada (multiplicação escalar do ponto base G).
func BenchmarkKeyGen(b *testing.B) {
	f := newFixture(b)
	sec := f.aliceSec
	var pub x25519.Key
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		x25519.KeyGen(&pub, &sec)
	}
	sinkByte ^= pub[0]
}

// Derivação do segredo compartilhado (multiplicação escalar do ponto público do par).
func BenchmarkShared(b *testing.B) {
	f := newFixture(b)
	sec, peerPub := f.aliceSec, f.bobPub
	var shared x25519.Key
	var ok bool
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		ok = x25519.Shared(&shared, &sec, &peerPub)
	}
	if !ok {
		b.Fatal("Shared falhou para chave pública válida")
	}
	sinkByte ^= shared[0]
}

// Ponto público de baixa ordem (inválido): deve custar o mesmo que BenchmarkShared,
// pois a escada de Montgomery no X25519 opera em tempo constante.
func BenchmarkSharedInvalid(b *testing.B) {
	f := newFixture(b)
	sec, badPub := f.aliceSec, f.badPub
	var shared x25519.Key
	var ok bool
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		ok = x25519.Shared(&shared, &sec, &badPub)
	}
	if ok {
		b.Fatal("Shared aceitou ponto de baixa ordem inválido")
	}
	sinkByte ^= shared[0]
}
