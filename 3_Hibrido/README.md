# Handshake Híbrido (`mlkem768x25519-sha256`): Comparativo Pareado ML-KEM-768 vs. X25519 vs. Híbrido

*Microbenchmarks em software puro vs. Assembly (AVX2 + BMI2/ADX) · CIRCL v1.6.5 · Go 1.26.0 · Xeon 2,2 GHz (Google Colab)*

## 1. Objetivo e Desenho Experimental Pareado

Enquanto os diretórios `1_ML-KEM/` e `2_X25519/` dissecam isoladamente as primitivas pós-quântica e clássica, este diretório avalia o custo computacional completo da **troca de chaves efêmera em um handshake** — comparando, dentro da mesma sessão e das mesmas rodadas intercaladas (ABBA), três esquemas:

1. **Pós-Quântico puro (`MLKEM768_Cycle`):** ciclo completo de encapsulamento efêmero apenas com ML-KEM-768.
2. **Clássico puro (`X25519_Cycle`):** ciclo completo Diffie-Hellman efêmero apenas com X25519.
3. **Híbrido (`Hybrid_Cycle` e etapas `ClientInit`, `ServerRespond`, `ClientFinish`):** composição `mlkem768x25519-sha256` (`draft-kampanakis-curdle-ssh-pq-ke`), que executa ambos os algoritmos e deriva o segredo compartilhado final via $K = \text{SHA-256}(K_{\text{PQ}} \parallel K_{\text{CL}})$.

Medir os três esquemas no mesmo binário e dentro do mesmo laço de cada rodada ABBA elimina o viés de variação temporal da máquina virtual entre sessões distintas.

## 2. Assimetria Funcional entre KEM e ECDH no Handshake Efêmero

Em uma troca de chaves efêmera (Cliente $\leftrightarrow$ Servidor), o ML-KEM-768 e o X25519 possuem fluxos operacionais diferentes:

| Fase do Handshake | O que executa no ML-KEM-768 | O que executa no X25519 | O que executa no Híbrido (`mlkem768x25519-sha256`) |
| --- | --- | --- | --- |
| **1. `ClientInit` (Cliente)** | `NewKeyFromSeed` + `pk.Pack` ($1.184\text{ B}$) | `x25519.KeyGen` ($32\text{ B}$) | Ambos + concatenação ($1.216\text{ B}$) |
| **2. `ServerRespond` (Servidor)** | `pk.Unpack` + `EncapsulateTo` ($1.088\text{ B}$) | `x25519.KeyGen` ($32\text{ B}$) + `x25519.Shared` | Ambos + concatenação ($1.120\text{ B}$) + `SHA-256` |
| **3. `ClientFinish` (Cliente)** | `sk.DecapsulateTo` (chave `sk` já em cache na RAM) | `x25519.Shared` | Ambos + `SHA-256` |
| **Total no Ciclo (`Cycle`)** | `1x KeyGen` + `1x Unpack+Encaps` + `1x DecapsCached` | **`2x KeyGen` + `2x Shared`** | Soma integral + `2x SHA-256` |

## 3. Categorias de Perfilamento (`pprofsplit`)

O classificador `pprofsplit` deste diretório divide o tempo de CPU em cinco categorias ortogonais:
- `mlkem_keccak`: funções de hash SHA-3/SHAKE do ML-KEM (`internal/sha3` e `simd/keccakf1600`).
- `mlkem_poly_ntt`: álgebra polinomial, NTT e amostragem do ML-KEM (`pke/kyber`).
- `x25519_ecc`: escada de Montgomery/Joye e aritmética de corpo finito $\mathbb{F}_{2^{255}-19}$ do X25519 (`dh/x25519` e `math/fp25519`).
- `kdf_sha256`: derivação do segredo híbrido via `crypto/sha256`.
- `runtime_alloc_gc`: alocação no heap, coleta de lixo e barreiras de escrita do runtime do Go.
- `other`: funções fora das categorias anteriores (ex.: `ConstantTimeCompare` e cópias de memória).

## 4. Resultados

> *Status: Estrutura validada localmente; aguardando coleta da sessão no Google Colab para preenchimento das tabelas abaixo.*

### Tabela 1: Desempenho absoluto por operação (Ciclos e Etapas do Híbrido)

| Operação | Software puro — Mediana (µs) | Hardware (AVX2 + BMI2/ADX) — Mediana (µs) | Speedup (mediana) | Software puro — Q25 (µs) | Hardware — Q25 (µs) | Speedup (Q25, IC 95%) |
| --- | --- | --- | --- | --- | --- | --- |
| `MLKEM768_Cycle` | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* |
| `X25519_Cycle` | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* |
| `Hybrid_Cycle` | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* |
| `Hybrid_ClientInit` | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* |
| `Hybrid_ServerRespond` | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* |
| `Hybrid_ClientFinish` | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* |

### Tabela 2: Decomposição de CPU no Modo Híbrido (`pprof`)

| Operação / Modo | `mlkem_keccak` | `mlkem_poly_ntt` | `x25519_ecc` | `kdf_sha256` | `runtime_alloc_gc` |
| --- | --- | --- | --- | --- | --- |
| `Hybrid_Cycle` (SW) | *(pendente)* | *(pendente)* | *(pendente)* | *(pendente)* | *(pendente)* |
| `Hybrid_Cycle` (HW) | *(pendente)* | *(pendente)* | *(pendente)* | *(pendente)* | *(pendente)* |
| `Hybrid_ClientInit` (SW / HW) | *(pendente)* | *(pendente)* | *(pendente)* | *(pendente)* | *(pendente)* |
| `Hybrid_ServerRespond` (SW / HW) | *(pendente)* | *(pendente)* | *(pendente)* | *(pendente)* | *(pendente)* |
| `Hybrid_ClientFinish` (SW / HW) | *(pendente)* | *(pendente)* | *(pendente)* | *(pendente)* | *(pendente)* |

## 5. Como reproduzir

### Opção A: No Google Colab
1. Abra `3_Hibrido/colab_runner.ipynb` no Google Colab.
2. Confira `REPO_URL`, `BRANCH_NAME` e `SUBDIR = "3_Hibrido"`.
3. Execute todas as células na ordem.

### Opção B: Em máquina Linux local (`x86_64` com `AVX2`, `BMI2` e `ADX`)
```bash
cd 3_Hibrido
chmod +x dependencias/run_all.sh
./dependencias/run_all.sh
```
