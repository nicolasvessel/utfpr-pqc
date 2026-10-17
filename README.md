# Criptografia Pós-Quântica e Híbrida em Go: Análise Experimental de Custo Computacional (ML-KEM-768, X25519 e Modo Híbrido)

*Microbenchmarks Reprodutíveis em Software Puro vs. Assembly (AVX2 e BMI2/ADX) · CIRCL v1.6.5 · Go 1.26.0 · Intel Xeon 2,2 GHz*

---

## 1. Problemática e Motivação da Pesquisa

A padronização de mecanismos pós-quânticos de encapsulamento de chaves (KEM), liderada pelo **ML-KEM** (FIPS 203, derivado do CRYSTALS-Kyber), responde à ameaça de computadores quânticos criptograficamente relevantes capazes de solucionar o problema do logaritmo discreto sobre curvas elípticas (como o **X25519**, RFC 7748) em tempo polinomial via algoritmo de Shor. Durante o período de transição, protocolos de segurança de transporte como o **SSH** (`draft-kampanakis-curdle-ssh-pq-ke`) e o **TLS 1.3** adotaram esquemas **híbridos** — notadamente o `mlkem768x25519-sha256` —, que combinam a segurança clássica consolidada do X25519 com a segurança pós-quântica baseada em reticulados (*Module-Learning With Errors* — MLWE) do ML-KEM-768.

Essa transição impõe, contudo, três questões fundamentais de engenharia de desempenho que motivam esta pesquisa:

1. **Onde reside o verdadeiro gargalo de CPU do ML-KEM-768?** Uma hipótese recorrente na literatura aplicada é que a geração de matrizes públicas e polinômios de ruído via funções esponja **Keccak/SHA-3** (SHAKE128/SHAKE256) domina o tempo de execução do ML-KEM, enquanto outra aponta a aritmética polinomial sobre $\mathbb{Z}_{3329}$ e a *Number-Theoretic Transform* (**NTT**). Determinar a fração exata de CPU consumida por cada componente — tanto quando a chave pública chega serializada da rede (*FromBytes*) quanto quando permanece em cache na memória RAM (*Cached*) — é requisito básico para direcionar otimizações de software e de silício.
2. **Qual é o impacto real de instruções vetoriais (SIMD) vs. instruções escalares sobre primitivas pós-quânticas e clássicas?** Em dispositivos de borda (IoT), microcontroladores ou arquiteturas sem extensões vetoriais ativas, a criptografia executa em software puro. Já em servidores e processadores modernos `x86_64`, bibliotecas como a CIRCL exploram instruções vetoriais **AVX2** (256 bits) e instruções escalares de grandes inteiros (**BMI2/ADX**). É necessário distinguir rigorosamente o ganho proveniente de paralelismo de dados SIMD genérico (AVX2) do ganho de instruções criptográficas dedicadas em silício (como extensões SHA-3 nativas, ausentes na maioria dos processadores `x86_64` atuais).
3. **Qual é o custo computacional relativo entre o ciclo clássico (X25519), o ciclo pós-quântico (ML-KEM-768) e o handshake híbrido completo?** Embora o ML-KEM-768 trafegue chaves e textos cifrados ordens de grandeza maiores na rede ($2.272\text{ B}$ no total contra $64\text{ B}$ do X25519), a percepção intuitiva de que a criptografia pós-quântica também seria mais pesada para o processador precisa ser testada empiricamente sob condições controladas, avaliando o ciclo completo de troca de chaves (Cliente + Servidor).

---

## 2. Arquitetura do Repositório e Frentes Experimentais

O repositório está organizado em três diretórios experimentais independentes e autocontidos. Cada diretório possui seu próprio módulo Go travado (`go.mod`/`go.sum`), orquestrador reprodutível (`dependencias/run_all.sh`), classificador de perfis de CPU (`dependencias/pprofsplit/main.go`), caderno de execução para o Google Colab (`colab_runner.ipynb`), documentação analítica (`README.md`) e artefatos brutos auditáveis (`resultados/`).

| Diretório | Escopo Experimental | Primitivas e Operações Medidas | Instruções Assembly Ativas (Binário B) |
| --- | --- | --- | --- |
| **[`1_ML-KEM/`](./1_ML-KEM/)** | Dissecação interna do **ML-KEM-768** (Álgebra Kyber/NTT vs. Hash Keccak, chaves em bytes vs. em cache e rejeição implícita) | `KeyGen`, `EncapsFromBytes`, `EncapsCached`, `DecapsCached`, `DecapsInvalid`, `DecapsFromBytes` | **SIMD Vetorial (`AVX2`)**: aritmética polinomial 16-way (`nttAVX2`, `invNttAVX2`, `mulHatAVX2`) e Keccak 4-way (`f1600x4AVX2`) |
| **[`2_X25519/`](./2_X25519/)** | Linha de base clássica **X25519** (RFC 7748) e análise dos limites da aceleração escalar sobre $\mathbb{F}_{2^{255}-19}$ | `KeyGen` (escada de Joye), `Shared` (escada de Montgomery), `SharedInvalid` (rejeição de ponto de baixa ordem) | **Escalar 64 bits (`BMI2` + `ADX`)**: `MULXQ`, `ADCXQ` e `ADOXQ` em `diffAddAmd64`, `ladderStepAmd64`, `sqrAmd64`, `mulAmd64` |
| **[`3_Hibrido/`](./3_Hibrido/)** | Comparativo pareado intra-rodada entre o ciclo completo **ML-KEM-768**, **X25519** e o handshake **Híbrido (`mlkem768x25519-sha256`)** | `MLKEM768_Cycle`, `X25519_Cycle`, `Hybrid_Cycle`, `Hybrid_ClientInit`, `Hybrid_ServerRespond`, `Hybrid_ClientFinish` | **Conjunto completo (`AVX2` + `BMI2` + `ADX`)** auditado simultaneamente no mesmo binário |

---

## 3. Síntese dos Resultados e Principais Descobertas

Todos os experimentos foram executados sob protocolo intercalado **ABBA** (20 rodadas válidas de `1s` por operação após aquecimento descartado, afinidade de CPU em núcleo único `PIN_CPU=0`, `GOMAXPROCS=1`, `CGO_ENABLED=0`, `GOAMD64=v1`, sementes determinísticas pré-computadas fora do cronômetro e verificação de corretude por digest SHA-256).

### Tabela Consolidada de Desempenho (Mediana `benchstat` e Q25 Calculado)

Os valores de **Mediana** e **Memória** provêm diretamente dos relatórios `02_benchstat_speedup.txt` de cada diretório (dados brutos medidos); os valores de **Q25** (primeiro quartil, utilizado para isolar o regime sem contenção do hipervisor da nuvem) são **calculados a partir das 20 amostras brutas** preservadas em `05_dados_brutos_e_logs.zip` de cada experimento.

| Experimento | Operação | Software Puro (`purego`) — Mediana (µs) | Hardware (Assembly) — Mediana (µs) | Speedup (Mediana) | Software Puro — Q25 (µs, calculado) | Hardware — Q25 (µs, calculado) | Speedup (Q25, calculado) | Memória (`B/op` · `allocs`) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **`1_ML-KEM`** | `KeyGen` | 88,16 | 41,90 | **2,10x** | 86,84 | 41,52 | **2,09x** | 8,00 KiB · 4 |
| **`1_ML-KEM`** | `EncapsFromBytes` | 105,55 | 49,52 | **2,13x** | 103,63 | 46,14 | **2,25x** | 6,38 KiB · 1 |
| **`1_ML-KEM`** | `EncapsCached` | 61,67 | 17,61 | **3,50x** | 60,73 | 17,05 | **3,56x** | 0 B · 0 |
| **`1_ML-KEM`** | `DecapsCached` | 91,37 | 29,80 | **3,07x** | 90,35 | 29,37 | **3,08x** | 0 B · 0 |
| **`1_ML-KEM`** | `DecapsInvalid` | 91,99 | 29,70 | **3,10x** | 90,33 | 29,38 | **3,07x** | 0 B · 0 |
| **`1_ML-KEM`** | `DecapsFromBytes` | 138,67 | 60,31 | **2,30x** | 135,61 | 59,35 | **2,28x** | 7,88 KiB · 2 |
| **`2_X25519`** | `KeyGen` | 58,03 | 57,84 *(bimodal)* | 1,00x | 57,93 | 42,30 | **1,37x** | 0 B · 0 |
| **`2_X25519`** | `Shared` | 90,41 | 88,76 *(bimodal)* | 1,02x | 90,20 | 62,86 | **1,43x** | 0 B · 0 |
| **`2_X25519`** | `SharedInvalid` | 91,13 | 75,18 | **1,21x** | 90,38 | 62,38 | **1,45x** | 0 B · 0 |
| **`3_Hibrido`** | `MLKEM768_Cycle` | 292,71 | 121,01 | **2,42x** | 279,43 | 118,36 | **2,36x** | 14,38 KiB · 5 |
| **`3_Hibrido`** | `X25519_Cycle` | 307,48 | 208,54 | **1,47x** | 298,13 | 207,37 | **1,44x** | 0 B · 0 |
| **`3_Hibrido`** | `Hybrid_Cycle` | 615,50 | 332,81 | **1,85x** | 581,11 | 330,23 | **1,76x** | 14,38 KiB · 5 |
| **`3_Hibrido`** | `Hybrid_ClientInit` | 155,51 | 85,32 | **1,82x** | 145,74 | 84,99 | **1,71x** | 8,00 KiB · 4 |
| **`3_Hibrido`** | `Hybrid_ServerRespond` | 254,22 | 152,37 | **1,67x** | 252,56 | 151,63 | **1,67x** | 6,38 KiB · 1 |
| **`3_Hibrido`** | `Hybrid_ClientFinish` | 184,01 | 94,31 | **1,95x** | 182,70 | 93,13 | **1,96x** | 0 B · 0 |

### Cinco Conclusões Experimentais Centrais

1. **Em software puro (`purego`), a álgebra polinomial — e não o Keccak — é o principal gargalo do ML-KEM-768.** Nos perfis de CPU de `1_ML-KEM/`, a aritmética polinomial/NTT consome de **54,3% a 87,3%** do tempo total, contra **12,5% a 41,1%** do Keccak. Para processadores embarcados sem SIMD, otimizar a representação polinomial e as reduções modulares traz maior retorno do que acelerar o hash.
2. **A vetorização AVX2 comprime a álgebra do ML-KEM em 3,0x a 5,6x e inverte o gargalo para o Keccak.** Como o AVX2 opera sobre 16 coeficientes de 16 bits simultaneamente, 70% a 99,9% da economia de tempo do ML-KEM provém da álgebra. No Keccak, o AVX2 só acelera as etapas que executam 4 esponjas independentes em paralelo (`f1600x4AVX2` durante a expansão da matriz $\mathbf{A}$ em `KeyGen` e `Unpack`, com ganho de 1,4x a 1,6x), mantendo ganho de **1,0x** nos hashes sequenciais (`EncapsCached` e `DecapsCached`). Com a álgebra comprimida, o Keccak passa a representar **44,2% a 53,5%** do tempo no binário AVX2.
3. **O Assembly do X25519 (BMI2/ADX) oferece ganho moderado (~1,4x) frente ao salto vetorial do ML-KEM (2,1x–3,5x).** A escada de Montgomery/Joye sobre $\mathbb{F}_{2^{255}-19}$ é estritamente sequencial (cada passo depende do anterior) e opera sobre palavras de 64 bits nas quais o compilador Go puro já emite instruções nativas (`MULQ`/`ADCQ`). O Assembly manual (`MULXQ`/`ADCXQ`/`ADOXQ` e *inlining* da escada em `curve_amd64.s`) reduz o tempo em ~30% (1,37x a 1,47x), sem o fator multiplicativo de 16 vias do SIMD.
4. **No ciclo completo com Assembly ativo, o ML-KEM-768 é 1,72x mais rápido em CPU que o X25519.** Em um handshake efêmero completo (`3_Hibrido/`), o X25519 exige duas gerações de chave e duas derivações Diffie-Hellman (`2x KeyGen + 2x Shared` = `208,54 µs` na mediana / `207,37 µs` no Q25), enquanto o ML-KEM-768 executa `KeyGen + Unpack/Encaps + DecapsCached` em **`121,01 µs`** na mediana (`118,36 µs` no Q25).
5. **No handshake híbrido (`mlkem768x25519-sha256`) acelerado, 60% da CPU é consumida pela parte clássica (X25519).** Enquanto em software puro o custo do `Hybrid_Cycle` divide-se quase igualmente (48,62% ML-KEM vs. 49,66% X25519), com Assembly ativo o X25519 passa a consumir **60,07%** de todo o tempo de CPU do handshake híbrido (chegando a **66,40%** no servidor em `Hybrid_ServerRespond`), contra **36,85%** do ML-KEM-768 e **0,40%** do combinador `SHA-256`.

---

## 4. Validação do Desligamento de Assembly (`-tags purego`) na CIRCL e na Stdlib

Para garantir que o Binário A (`software`) represente fielmente código Go puro sem vazamento de rotinas em Assembly (`.s`), foi realizada uma auditoria estática (`GOOS=linux GOARCH=amd64 go list`) e uma inspeção da tabela de símbolos (`go tool nm`) cobrindo todos os pacotes internos da CIRCL `v1.6.5` e da biblioteca padrão do Go (`crypto/ecdh`):

| Pacote Inspecionado | Arquivos `.s` no Modo Padrão (`default`) | Arquivos `.s` com `-tags purego` | Mecanismo de Despacho Auditado |
| --- | --- | --- | --- |
| `circl/pke/kyber/internal/common` | `[amd64.s]` (`nttAVX2`, `invNttAVX2`, `mulHatAVX2`, `addAVX2`) | `[]` *(100% removido)* | Tag `//go:build amd64 && !purego` + flag `cpu.X86.HasAVX2` |
| `circl/simd/keccakf1600` | `[f1600x4_amd64.s]` (`f1600x4AVX2`) | `[]` *(100% removido)* | Tag `//go:build amd64 && !purego` + flag `cpu.X86.HasAVX2` |
| `circl/dh/x25519` | `[curve_amd64.s]` (`ladderStepAmd64`, `diffAddAmd64`, `doubleAmd64`) | `[]` *(100% removido)* | Tag `//go:build amd64 && !purego` + flags `HasBMI2 && HasADX` |
| `circl/math/fp25519` | `[fp_amd64.s]` (`mulAmd64`, `sqrAmd64`, `modpAmd64`) | `[]` *(100% removido)* | Tag `//go:build amd64 && !purego` + flags `HasBMI2 && HasADX` |
| `crypto/internal/fips140/edwards25519/field` *(usado por `crypto/ecdh` da stdlib)* | `[fe_amd64.s]` (`feMul`, `feSquare`) | `[]` *(100% removido, ativa `fe_amd64_noasm.go`)* | Tag `//go:build amd64 && !purego` |

---

## 5. Levantamento de Estado da Arte e Trabalhos Futuros (HQC e Híbridos Pós-Quânticos)

Como preparação para as próximas etapas da pesquisa (avaliação do **HQC** — *Hamming Quasi-Cyclic*, selecionado pelo NIST como KEM alternativo baseado em códigos corretores de erros — e de combinações híbridas **ML-KEM + HQC**), registram-se os seguintes pontos técnicos verificados:

1. **Disponibilidade do HQC em Go:**
   - **CIRCL (`[github.com/cloudflare/circl](https://github.com/cloudflare/circl)` v1.6.5):** Não possui implementação do HQC (a solicitação consta em aberto na Issue #539 do repositório oficial da Cloudflare).
   - **Alternativas no ecossistema Go:** O HQC (`HQC-128`, `HQC-192`, `HQC-256`) encontra-se implementado na biblioteca `[github.com/katzenpost/hpqc](https://github.com/katzenpost/hpqc)` (que adota a mesma interface `kem.Scheme` da CIRCL) e via *bindings* C (`CGO_ENABLED=1`) na biblioteca `[github.com/open-quantum-safe/liboqs-go](https://github.com/open-quantum-safe/liboqs-go)` (`liboqs`).
2. **Composição de chaves, textos cifrados e segredos no modo híbrido:**
   - **No padrão SSH (`mlkem768x25519-sha256`, implementado em `3_Hibrido/`):** A chave pública do cliente e a resposta do servidor são formadas por concatenação direta de arrays de tamanho fixo ($pk_{\text{ML-KEM}} \parallel pub_{\text{X25519}}$ com $1.216\text{ B}$ e $ct_{\text{ML-KEM}} \parallel pub_{\text{X25519}}$ com $1.120\text{ B}$), e o segredo compartilhado é derivado via $K = \text{SHA-256}(K_{\text{PQ}} \parallel K_{\text{CL}})$.
   - **Em combinadores genéricos KEM+KEM (ex.: `ML-KEM + HQC` ou pacote `circl/kem/hybrid`):** Para preservar a segurança IND-CCA2 mesmo se um dos KEMs falhar, os combinadores modernos (como o *Split-PRF* ou a construção X-Wing / IETF) incorporam não apenas os segredos compartilhados ($K_1, K_2$), mas também os textos cifrados e/ou chaves públicas no hash de derivação (ex.: $\text{SHAKE256}(K_1 \parallel K_2 \parallel ct_1 \parallel ct_2 \parallel pk_1 \parallel pk_2)$).

---

## 6. Como Reproduzir os Experimentos

Cada subpasta pode ser executada de forma independente no Google Colab (abrindo o respectivo `colab_runner.ipynb`) ou em uma máquina Linux `x86_64` com Go 1.26.0 e suporte às instruções `AVX2`, `BMI2` e `ADX`:

```bash
# Experimento 1: Dissecação do ML-KEM-768
cd 1_ML-KEM && chmod +x dependencias/run_all.sh && ./dependencias/run_all.sh

# Experimento 2: Linha de base clássica X25519
cd ../2_X25519 && chmod +x dependencias/run_all.sh && ./dependencias/run_all.sh

# Experimento 3: Comparativo pareado ML-KEM-768 vs. X25519 vs. Híbrido
cd ../3_Hibrido && chmod +x dependencias/run_all.sh && ./dependencias/run_all.sh
```

## Aviso sobre o Uso de Inteligência Artificial

O código-fonte dos microbenchmarks, a ferramenta analítica `pprofsplit`, os scripts de automação e a documentação técnica deste repositório foram desenvolvidos e auditados com auxílio dos modelos Gemini 4 Pro e Gemini 3.8 Flash, sob revisão e validação experimental do autor. Todos os resultados numéricos provêm exclusivamente das execuções reais preservadas nas pastas `resultados/` de cada experimento.
