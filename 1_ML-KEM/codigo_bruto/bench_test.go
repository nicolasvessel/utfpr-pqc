package mlkembench

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/sys/cpu"
)

// Sinks globais: impedem que o compilador descarte o trabalho medido.
var (
	sinkPK   *mlkem768.PublicKey
	sinkSK   *mlkem768.PrivateKey
	sinkByte byte
)

// fixture concentra todo o material pré-computado FORA do cronômetro:
// sementes determinísticas, chaves (em cache e serializadas) e ciphertexts.
type fixture struct {
	keySeed [mlkem768.KeySeedSize]byte
	encSeed [mlkem768.EncapsulationSeedSize]byte
	pk      *mlkem768.PublicKey
	sk      *mlkem768.PrivateKey
	pkBytes [mlkem768.PublicKeySize]byte
	skBytes [mlkem768.PrivateKeySize]byte
	ct      [mlkem768.CiphertextSize]byte
	ctBad   [mlkem768.CiphertextSize]byte
	ss      [mlkem768.SharedKeySize]byte
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
	detBytes(f.keySeed[:], "utfpr-pqc/keygen-seed")
	detBytes(f.encSeed[:], "utfpr-pqc/encaps-seed")

	f.pk, f.sk = mlkem768.NewKeyFromSeed(f.keySeed[:])
	f.pk.Pack(f.pkBytes[:])
	f.sk.Pack(f.skBytes[:])
	f.pk.EncapsulateTo(f.ct[:], f.ss[:], f.encSeed[:])

	var ss2 [mlkem768.SharedKeySize]byte
	f.sk.DecapsulateTo(ss2[:], f.ct[:])
	if ss2 != f.ss {
		tb.Fatal("Decaps(Encaps) não recupera o segredo compartilhado")
	}

	f.ctBad = f.ct
	f.ctBad[0] ^= 0x01
	f.sk.DecapsulateTo(ss2[:], f.ctBad[:])
	if bytes.Equal(ss2[:], f.ss[:]) {
		tb.Fatal("rejeição implícita falhou para ciphertext adulterado")
	}
	return f
}

// ---------------------------------------------------------------- testes

func TestEnvironment(t *testing.T) {
	t.Logf("ENV build=%s HasAVX2=%v", buildMode, cpu.X86.HasAVX2)
	if buildMode == "default" && !cpu.X86.HasAVX2 {
		t.Fatal("binário padrão em CPU sem AVX2: o caminho vetorizado não seria usado")
	}
}

// TestDigest valida os caminhos 'FromBytes' e emite um digest das saídas;
// os binários A e B devem imprimir exatamente o mesmo valor.
func TestDigest(t *testing.T) {
	f := newFixture(t)

	var pk2 mlkem768.PublicKey
	if err := pk2.Unpack(f.pkBytes[:]); err != nil {
		t.Fatal(err)
	}
	var ct2 [mlkem768.CiphertextSize]byte
	var ss2 [mlkem768.SharedKeySize]byte
	pk2.EncapsulateTo(ct2[:], ss2[:], f.encSeed[:])
	if ct2 != f.ct || ss2 != f.ss {
		t.Fatal("Encaps a partir de bytes diverge do caminho em cache")
	}

	var sk2 mlkem768.PrivateKey
	if err := sk2.Unpack(f.skBytes[:]); err != nil {
		t.Fatal(err)
	}
	sk2.DecapsulateTo(ss2[:], f.ct[:])
	if ss2 != f.ss {
		t.Fatal("Decaps a partir de bytes diverge do caminho em cache")
	}

	h := sha256.New()
	h.Write(f.pkBytes[:])
	h.Write(f.skBytes[:])
	h.Write(f.ct[:])
	h.Write(f.ss[:])
	t.Logf("DIGEST=%s", hex.EncodeToString(h.Sum(nil)))
}

// ----------------------------------------------------------- benchmarks

func BenchmarkKeyGen(b *testing.B) {
	f := newFixture(b)
	seed := f.keySeed[:]
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		sinkPK, sinkSK = mlkem768.NewKeyFromSeed(seed)
	}
}

// Cenário IoT realista: a chave pública do par chega serializada, então
// o Unpack (que expande a matriz A via SHAKE128) faz parte do custo.
func BenchmarkEncapsFromBytes(b *testing.B) {
	f := newFixture(b)
	pkb, seed := f.pkBytes[:], f.encSeed[:]
	var pk mlkem768.PublicKey
	var ct [mlkem768.CiphertextSize]byte
	var ss [mlkem768.SharedKeySize]byte
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := pk.Unpack(pkb); err != nil {
			b.Fatal(err)
		}
		pk.EncapsulateTo(ct[:], ss[:], seed)
	}
	sinkByte ^= ct[0] ^ ss[0]
}

// Chave pública já desempacotada: a matriz Aᵀ está em cache na CIRCL.
func BenchmarkEncapsCached(b *testing.B) {
	f := newFixture(b)
	pk, seed := f.pk, f.encSeed[:]
	var ct [mlkem768.CiphertextSize]byte
	var ss [mlkem768.SharedKeySize]byte
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		pk.EncapsulateTo(ct[:], ss[:], seed)
	}
	sinkByte ^= ct[0] ^ ss[0]
}

func benchDecapsCached(b *testing.B, f *fixture, ct []byte) {
	sk := f.sk
	var ss [mlkem768.SharedKeySize]byte
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		sk.DecapsulateTo(ss[:], ct)
	}
	sinkByte ^= ss[0]
}

// Chave privada residente em memória (cenário realista do dispositivo).
func BenchmarkDecapsCached(b *testing.B) {
	f := newFixture(b)
	benchDecapsCached(b, f, f.ct[:])
}

// Ciphertext inválido (rejeição implícita): deve custar o mesmo que o
// válido, pois o ML-KEM é de tempo constante.
func BenchmarkDecapsInvalid(b *testing.B) {
	f := newFixture(b)
	benchDecapsCached(b, f, f.ctBad[:])
}

// Chave privada carregada de armazenamento a cada operação.
func BenchmarkDecapsFromBytes(b *testing.B) {
	f := newFixture(b)
	skb, ct := f.skBytes[:], f.ct[:]
	var sk mlkem768.PrivateKey
	var ss [mlkem768.SharedKeySize]byte
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := sk.Unpack(skb); err != nil {
			b.Fatal(err)
		}
		sk.DecapsulateTo(ss[:], ct)
	}
	sinkByte ^= ss[0]
}
