# X25519: Linha de Base Clássica (Go Puro vs. Assembly BMI2/ADX)

*Microbenchmarks em software puro vs. Assembly x86_64 (BMI2/ADX) · CIRCL v1.6.5 · Go 1.26.0 · Xeon 2,2 GHz (Google Colab)*

## 1. Objetivo e Papel no Estudo

Este diretório estabelece a linha de base clássica de troca de chaves Diffie-Hellman sobre a curva elíptica Curve25519 (`X25519`, RFC 7748), utilizando a mesma biblioteca (`github.com/cloudflare/circl/dh/x25519` v1.6.5) e o mesmo protocolo experimental aplicado ao ML-KEM-768 em `1_ML-KEM/`.

Importante: o X25519 e o ML-KEM-768 pertencem a categorias criptográficas distintas (segurança clássica baseada no problema do logaritmo discreto elíptico vs. segurança pós-quântica baseada em reticulados MLWE). O objetivo desta medição isolada é fornecer a referência do custo atual de troca de chaves clássica e preparar a avaliação da composição híbrida (`X25519 + ML-KEM-768`) no diretório `3_Hibrido/`.

### Diferença Arquitetural de Aceleração: ML-KEM (SIMD AVX2) vs. X25519 (Assembly Escalar BMI2/ADX)

Enquanto o ML-KEM-768 opera sobre polinômios de 256 coeficientes independentes de 16 bits — permitindo que instruções vetoriais SIMD (**AVX2**) processem 16 coeficientes simultaneamente —, uma operação de X25519 realiza uma sequência encadeada de passos (*Montgomery ladder*) sobre inteiros grandes no corpo primo $\mathbb{F}_{2^{255}-19}$.

Por essa razão, a implementação Assembly de `x86_64` do X25519 na CIRCL (`curve_amd64.s` e `fp_amd64.s`) **não utiliza AVX2**, mas sim instruções escalares de 64 bits das extensões **BMI2** e **ADX**:
- **BMI2 (`MULXQ`):** multiplicação inteira de 64×64 para 128 bits sem modificar as flags de *carry*.
- **ADX (`ADCXQ` e `ADOXQ`):** duas cadeias paralelas e independentes de propagação de *carry* usando as flags `CF` e `OF` do processador.

| Modo de Build | Tag de Compilação | Arquivos Compilados (`dh/x25519` e `math/fp25519`) | Símbolos Principais |
| --- | --- | --- | --- |
| **Software puro (Binário A)** | `-tags purego` | `curve_noasm.go`, `fp_noasm.go` (`SFiles: []`) | `ladderStepGeneric`, `doubleGeneric`, `diffAddGeneric`, `mulGeneric`, `sqrGeneric`, `modpGeneric` |
| **Assembly BMI2/ADX (Binário B)** | *(padrão)* | `curve_amd64.go`, `curve_amd64.s`, `fp_amd64.go`, `fp_amd64.s` | `ladderStepAmd64`, `doubleAmd64`, `diffAddAmd64`, `mulAmd64`, `sqrAmd64`, `modpAmd64` |

## 2. Os Três Benchmarks

Diferentemente do ML-KEM-768, onde chaves públicas serializadas exigem desempacotamento e reexpansão da matriz $A$ via SHAKE128, uma chave X25519 na CIRCL é um array bruto de 32 bytes (`x25519.Key`) sem etapa de *unpack* ou alocação no heap (`0 B/op`, `0 allocs/op`).

| Benchmark | O que mede |
| --- | --- |
| `KeyGen` | Geração da chave pública de 32 bytes a partir da chave privada (`x25519.KeyGen`, multiplicação escalar do ponto base $G$). |
| `Shared` | Derivação do segredo compartilhado de 32 bytes a partir da chave privada local e da chave pública válida do par (`x25519.Shared`). |
| `SharedInvalid` | Derivação com um ponto público de baixa ordem canônico (vetor nulo, RFC 7748 Seção 6.1), na qual `x25519.Shared` retorna `false`. Verifica a execução em tempo constante na rejeição de pontos inválidos. |

## 3. Categorias de Perfilamento (`pprofsplit`)

- `fp25519`: tempo gasto diretamente nas funções de aritmética de corpo finito $\mathbb{F}_{2^{255}-19}$ do pacote `cloudflare/circl/math/fp25519` (como inversão modular, multiplicações e quadraturas chamadas pela camada de curva).
- `x25519_ladder`: tempo gasto nas rotinas do pacote `cloudflare/circl/dh/x25519` (incluindo `ladderStepAmd64` em Assembly, onde a aritmética do passo da escada é integrada diretamente em `curve_amd64.s`, e consultas à tabela do ponto base no `KeyGen`).
- `runtime_alloc_gc`: alocação de memória, coleta de lixo e barreiras de escrita do runtime do Go.
- `other`: funções fora das categorias anteriores.

## 4. Resultados

> *Status: Estrutura validada localmente; aguardando coleta da sessão no Google Colab para preenchimento das tabelas abaixo.*

### Tabela 1: Desempenho absoluto por operação

| Operação | Software puro (µs) | Assembly BMI2/ADX (µs) | Speedup (mediana) | Speedup (Q25, IC 95%) |
| --- | --- | --- | --- | --- |
| KeyGen | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* |
| Shared | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* |
| SharedInvalid | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* |
| **Média geométrica** | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | n/d |

### Tabela 2: Distribuição de CPU (`pprof`)

| Operação | `fp25519` (SW) | `fp25519` (ASM) | `x25519_ladder` (SW) | `x25519_ladder` (ASM) |
| --- | --- | --- | --- | --- |
| KeyGen | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* |
| Shared | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* |
| SharedInvalid | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* | *(pendente Colab)* |

## 5. Como reproduzir

### Opção A: No Google Colab
1. Abra `2_X25519/colab_runner.ipynb` no Google Colab.
2. Confira `REPO_URL`, `BRANCH_NAME` e `SUBDIR = "2_X25519"`.
3. Execute todas as células na ordem.

### Opção B: Em máquina Linux local (`x86_64` com `BMI2` e `ADX`)
```bash
cd 2_X25519
chmod +x dependencias/run_all.sh
./dependencias/run_all.sh
```
