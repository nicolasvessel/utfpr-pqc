package hybridbench

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/sys/cpu"
)

const (
	// Tamanhos dos payloads híbridos (mlkem768x25519-sha256):
	// ClientInit envia pk_mlkem (1184 B) || pub_x25519 (32 B) = 1216 B.
	// ServerRespond envia ct_mlkem (1088 B) || pub_x25519 (32 B) = 1120 B.
	HybridClientInitSize    = mlkem768.PublicKeySize + x25519.Size
	HybridServerRespondSize = mlkem768.CiphertextSize + x25519.Size
	HybridSharedSecretSize  = sha256.Size
)

// Sinks globais: impedem que o compilador descarte o trabalho medido.
var (
	sinkPK   *mlkem768.PublicKey
	sinkSK   *mlkem768.PrivateKey
	sinkByte byte
)

// fixture concentra todo o material pré-computado FORA do cronômetro:
// sementes determinísticas e artefatos intermediários do handshake.
type fixture struct {
	mlkemKeySeed [mlkem768.KeySeedSize]byte
	mlkemEncSeed [mlkem768.EncapsulationSeedSize]byte
	clientXSec   x25519.Key
	serverXSec   x25519.Key

	// Estado pré-computado para testar etapas isoladas do handshake híbrido
	clientMLKEMPK *mlkem768.PublicKey
	clientMLKEMSK *mlkem768.PrivateKey
	clientXPub    x25519.Key
	clientInitMsg [HybridClientInitSize]byte

	serverReplyMsg [HybridServerRespondSize]byte
	hybridSecret   [HybridSharedSecretSize]byte
	mlkemSecret    [mlkem768.SharedKeySize]byte
	x25519Secret   x25519.Key
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

// combineHybridSecret implementa a derivação KDF do mlkem768x25519-sha256:
// K = SHA-256(K_PQ || K_CL) sem alocações no heap.
func combineHybridSecret(out *[HybridSharedSecretSize]byte, pqSecret *[mlkem768.SharedKeySize]byte, clSecret *x25519.Key) {
	var buf [mlkem768.SharedKeySize + x25519.Size]byte
	copy(buf[:mlkem768.SharedKeySize], pqSecret[:])
	copy(buf[mlkem768.SharedKeySize:], clSecret[:])
	*out = sha256.Sum256(buf[:])
}

func newFixture(tb testing.TB) *fixture {
	tb.Helper()
	f := new(fixture)
	detBytes(f.mlkemKeySeed[:], "utfpr-pqc/hybrid-mlkem-keygen-seed")
	detBytes(f.mlkemEncSeed[:], "utfpr-pqc/hybrid-mlkem-encaps-seed")
	detBytes(f.clientXSec[:], "utfpr-pqc/hybrid-x25519-client-sec")
	detBytes(f.serverXSec[:], "utfpr-pqc/hybrid-x25519-server-sec")

	// 1. Etapa ClientInit (Híbrido)
	f.clientMLKEMPK, f.clientMLKEMSK = mlkem768.NewKeyFromSeed(f.mlkemKeySeed[:])
	f.clientMLKEMPK.Pack(f.clientInitMsg[:mlkem768.PublicKeySize])
	x25519.KeyGen(&f.clientXPub, &f.clientXSec)
	copy(f.clientInitMsg[mlkem768.PublicKeySize:], f.clientXPub[:])

	// 2. Etapa ServerRespond (Híbrido)
	var srvPK mlkem768.PublicKey
	if err := srvPK.Unpack(f.clientInitMsg[:mlkem768.PublicKeySize]); err != nil {
		tb.Fatal(err)
	}
	srvPK.EncapsulateTo(
		f.serverReplyMsg[:mlkem768.CiphertextSize],
		f.mlkemSecret[:],
		f.mlkemEncSeed[:],
	)

	var srvXPub, cliXPubRecv x25519.Key
	copy(cliXPubRecv[:], f.clientInitMsg[mlkem768.PublicKeySize:])
	x25519.KeyGen(&srvXPub, &f.serverXSec)
	if ok := x25519.Shared(&f.x25519Secret, &f.serverXSec, &cliXPubRecv); !ok {
		tb.Fatal("X25519 Shared falhou no servidor")
	}
	copy(f.serverReplyMsg[mlkem768.CiphertextSize:], srvXPub[:])

	var srvHybridSecret [HybridSharedSecretSize]byte
	combineHybridSecret(&srvHybridSecret, &f.mlkemSecret, &f.x25519Secret)

	// 3. Etapa ClientFinish (Híbrido)
	var cliPQSecret [mlkem768.SharedKeySize]byte
	f.clientMLKEMSK.DecapsulateTo(cliPQSecret[:], f.serverReplyMsg[:mlkem768.CiphertextSize])
	if cliPQSecret != f.mlkemSecret {
		tb.Fatal("ML-KEM Decaps diverge do segredo encapsulado pelo servidor")
	}

	var cliXSecret, srvXPubRecv x25519.Key
	copy(srvXPubRecv[:], f.serverReplyMsg[mlkem768.CiphertextSize:])
	if ok := x25519.Shared(&cliXSecret, &f.clientXSec, &srvXPubRecv); !ok {
		tb.Fatal("X25519 Shared falhou no cliente")
	}
	if cliXSecret != f.x25519Secret {
		tb.Fatal("X25519 Shared(cliente) diverge de Shared(servidor)")
	}

	combineHybridSecret(&f.hybridSecret, &cliPQSecret, &cliXSecret)
	if f.hybridSecret != srvHybridSecret {
		tb.Fatal("segredo híbrido final do cliente diverge do servidor")
	}

	return f
}

// ---------------------------------------------------------------- testes

func TestEnvironment(t *testing.T) {
	t.Logf("ENV build=%s HasAVX2=%v HasBMI2=%v HasADX=%v", buildMode, cpu.X86.HasAVX2, cpu.X86.HasBMI2, cpu.X86.HasADX)
	if buildMode == "default" && (!cpu.X86.HasAVX2 || !cpu.X86.HasBMI2 || !cpu.X86.HasADX) {
		t.Fatal("binário padrão em CPU sem AVX2/BMI2/ADX: os caminhos otimizados de ML-KEM e X25519 não seriam todos usados")
	}
}

// TestDigest valida os fluxos completos e emite um digest determinístico;
// os binários A (purego) e B (default) devem imprimir exatamente o mesmo valor.
func TestDigest(t *testing.T) {
	f := newFixture(t)

	h := sha256.New()
	h.Write(f.clientInitMsg[:])
	h.Write(f.serverReplyMsg[:])
	h.Write(f.mlkemSecret[:])
	h.Write(f.x25519Secret[:])
	h.Write(f.hybridSecret[:])
	t.Logf("DIGEST=%s", hex.EncodeToString(h.Sum(nil)))
}

// ----------------------------------------------------------- benchmarks: ciclos completos comparativos

// Ciclo Completo 1 — Apenas ML-KEM-768 (Pós-Quântico puro):
// Cliente (KeyGen + Pack) -> Servidor (Unpack + Encaps) -> Cliente (DecapsCached).
func BenchmarkMLKEM768_Cycle(b *testing.B) {
	f := newFixture(b)
	kSeed := f.mlkemKeySeed[:]
	eSeed := f.mlkemEncSeed[:]
	var pkBytes [mlkem768.PublicKeySize]byte
	var srvPK mlkem768.PublicKey
	var ct [mlkem768.CiphertextSize]byte
	var ssSrv, ssCli [mlkem768.SharedKeySize]byte

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		// 1. Cliente gera par efêmero e serializa chave pública
		pk, sk := mlkem768.NewKeyFromSeed(kSeed)
		pk.Pack(pkBytes[:])

		// 2. Servidor desempacota chave pública e encapsula segredo
		if err := srvPK.Unpack(pkBytes[:]); err != nil {
			b.Fatal(err)
		}
		srvPK.EncapsulateTo(ct[:], ssSrv[:], eSeed)

		// 3. Cliente desencapsula usando a chave privada residente em RAM
		sk.DecapsulateTo(ssCli[:], ct[:])

		sinkPK = pk
		sinkSK = sk
	}
	sinkByte ^= ssSrv[0] ^ ssCli[0]
}

// Ciclo Completo 2 — Apenas X25519 (Clássico puro):
// Cliente (KeyGen) -> Servidor (KeyGen + Shared) -> Cliente (Shared).
func BenchmarkX25519_Cycle(b *testing.B) {
	f := newFixture(b)
	cliSec, srvSec := f.clientXSec, f.serverXSec
	var cliPub, srvPub, ssSrv, ssCli x25519.Key
	var ok1, ok2 bool

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		// 1. Cliente gera chave pública efêmera
		x25519.KeyGen(&cliPub, &cliSec)

		// 2. Servidor gera chave pública efêmera e deriva segredo compartilhado
		x25519.KeyGen(&srvPub, &srvSec)
		ok1 = x25519.Shared(&ssSrv, &srvSec, &cliPub)

		// 3. Cliente deriva segredo compartilhado
		ok2 = x25519.Shared(&ssCli, &cliSec, &srvPub)
	}
	if !ok1 || !ok2 {
		b.Fatal("X25519 Shared falhou")
	}
	sinkByte ^= ssSrv[0] ^ ssCli[0]
}

// Ciclo Completo 3 — Híbrido mlkem768x25519-sha256 (ML-KEM-768 + X25519 + SHA-256):
// Executa o handshake criptográfico completo (Cliente + Servidor) em memória.
func BenchmarkHybrid_Cycle(b *testing.B) {
	f := newFixture(b)
	kSeed := f.mlkemKeySeed[:]
	eSeed := f.mlkemEncSeed[:]
	cliXSec, srvXSec := f.clientXSec, f.serverXSec

	var clientInit [HybridClientInitSize]byte
	var serverReply [HybridServerRespondSize]byte
	var srvPK mlkem768.PublicKey
	var cliXPub, srvXPub, cliXPubRecv, srvXPubRecv x25519.Key
	var pqSrv, pqCli [mlkem768.SharedKeySize]byte
	var clSrv, clCli x25519.Key
	var hybSrv, hybCli [HybridSharedSecretSize]byte
	var ok1, ok2 bool

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		// 1. ClientInit: ML-KEM KeyGen+Pack || X25519 KeyGen (1216 bytes)
		pk, sk := mlkem768.NewKeyFromSeed(kSeed)
		pk.Pack(clientInit[:mlkem768.PublicKeySize])
		x25519.KeyGen(&cliXPub, &cliXSec)
		copy(clientInit[mlkem768.PublicKeySize:], cliXPub[:])

		// 2. ServerRespond: ML-KEM Unpack+Encaps || X25519 KeyGen+Shared + SHA-256 (1120 bytes)
		if err := srvPK.Unpack(clientInit[:mlkem768.PublicKeySize]); err != nil {
			b.Fatal(err)
		}
		srvPK.EncapsulateTo(serverReply[:mlkem768.CiphertextSize], pqSrv[:], eSeed)
		copy(cliXPubRecv[:], clientInit[mlkem768.PublicKeySize:])
		x25519.KeyGen(&srvXPub, &srvXSec)
		ok1 = x25519.Shared(&clSrv, &srvXSec, &cliXPubRecv)
		copy(serverReply[mlkem768.CiphertextSize:], srvXPub[:])
		combineHybridSecret(&hybSrv, &pqSrv, &clSrv)

		// 3. ClientFinish: ML-KEM DecapsCached + X25519 Shared + SHA-256
		sk.DecapsulateTo(pqCli[:], serverReply[:mlkem768.CiphertextSize])
		copy(srvXPubRecv[:], serverReply[mlkem768.CiphertextSize:])
		ok2 = x25519.Shared(&clCli, &cliXSec, &srvXPubRecv)
		combineHybridSecret(&hybCli, &pqCli, &clCli)

		sinkPK = pk
		sinkSK = sk
	}
	if !ok1 || !ok2 {
		b.Fatal("X25519 Shared falhou no ciclo híbrido")
	}
	sinkByte ^= hybSrv[0] ^ hybCli[0]
}

// ----------------------------------------------------------- benchmarks: etapas isoladas do híbrido

// Etapa 1 do Híbrido (Lado Cliente — Inicialização):
// Gera par ML-KEM-768 + par X25519 e serializa os 1.216 bytes de envio.
func BenchmarkHybrid_ClientInit(b *testing.B) {
	f := newFixture(b)
	kSeed := f.mlkemKeySeed[:]
	cliXSec := f.clientXSec
	var cliXPub x25519.Key
	var clientInit [HybridClientInitSize]byte

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		pk, sk := mlkem768.NewKeyFromSeed(kSeed)
		pk.Pack(clientInit[:mlkem768.PublicKeySize])
		x25519.KeyGen(&cliXPub, &cliXSec)
		copy(clientInit[mlkem768.PublicKeySize:], cliXPub[:])
		sinkPK = pk
		sinkSK = sk
	}
	sinkByte ^= clientInit[0] ^ clientInit[HybridClientInitSize-1]
}

// Etapa 2 do Híbrido (Lado Servidor — Resposta):
// Recebe os 1.216 bytes do cliente, executa Unpack+Encaps (ML-KEM) + KeyGen+Shared (X25519),
// monta os 1.120 bytes de resposta e deriva o segredo híbrido com SHA-256.
func BenchmarkHybrid_ServerRespond(b *testing.B) {
	f := newFixture(b)
	clientInit := f.clientInitMsg
	eSeed := f.mlkemEncSeed[:]
	srvXSec := f.serverXSec

	var srvPK mlkem768.PublicKey
	var srvXPub, cliXPubRecv x25519.Key
	var serverReply [HybridServerRespondSize]byte
	var pqSrv [mlkem768.SharedKeySize]byte
	var clSrv x25519.Key
	var hybSrv [HybridSharedSecretSize]byte
	var ok bool

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := srvPK.Unpack(clientInit[:mlkem768.PublicKeySize]); err != nil {
			b.Fatal(err)
		}
		srvPK.EncapsulateTo(serverReply[:mlkem768.CiphertextSize], pqSrv[:], eSeed)
		copy(cliXPubRecv[:], clientInit[mlkem768.PublicKeySize:])
		x25519.KeyGen(&srvXPub, &srvXSec)
		ok = x25519.Shared(&clSrv, &srvXSec, &cliXPubRecv)
		copy(serverReply[mlkem768.CiphertextSize:], srvXPub[:])
		combineHybridSecret(&hybSrv, &pqSrv, &clSrv)
	}
	if !ok {
		b.Fatal("X25519 Shared falhou em Hybrid_ServerRespond")
	}
	sinkByte ^= serverReply[0] ^ hybSrv[0]
}

// Etapa 3 do Híbrido (Lado Cliente — Finalização):
// Recebe os 1.120 bytes do servidor, executa DecapsCached (ML-KEM) + Shared (X25519)
// e deriva o segredo híbrido final com SHA-256 (0 B/op, 0 allocs/op).
func BenchmarkHybrid_ClientFinish(b *testing.B) {
	f := newFixture(b)
	sk := f.clientMLKEMSK
	cliXSec := f.clientXSec
	serverReply := f.serverReplyMsg

	var srvXPubRecv, clCli x25519.Key
	var pqCli [mlkem768.SharedKeySize]byte
	var hybCli [HybridSharedSecretSize]byte
	var ok bool

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		sk.DecapsulateTo(pqCli[:], serverReply[:mlkem768.CiphertextSize])
		copy(srvXPubRecv[:], serverReply[mlkem768.CiphertextSize:])
		ok = x25519.Shared(&clCli, &cliXSec, &srvXPubRecv)
		combineHybridSecret(&hybCli, &pqCli, &clCli)
	}
	if !ok {
		b.Fatal("X25519 Shared falhou em Hybrid_ClientFinish")
	}
	sinkByte ^= hybCli[0]
}
