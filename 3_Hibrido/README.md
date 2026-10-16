# Handshake Híbrido (`mlkem768x25519-sha256`): Comparativo Pareado ML-KEM-768 vs. X25519 vs. Híbrido

*Microbenchmarks em software puro vs. Assembly (AVX2 + BMI2/ADX) · CIRCL v1.6.5 · Go 1.26.0 · Xeon 2,2 GHz (Google Colab)*

## Resumo

Este experimento fecha a série de microbenchmarks avaliando, de forma pareada dentro da mesma sessão e das mesmas rodadas intercaladas (ABBA), o custo computacional completo de um handshake efêmero de troca de chaves em três configurações: **Pós-Quântico puro (`MLKEM768_Cycle`)**, **Clássico puro (`X25519_Cycle`)** e **Híbrido (`Hybrid_Cycle` — `mlkem768x25519-sha256`)**, além de dissecar individualmente as três fases do protocolo híbrido (`ClientInit`, `ServerRespond` e `ClientFinish`).

Os resultados revelam uma inversão de protagonismo computacional quando se passa de software puro (`-tags purego`) para o código com Assembly otimizado (`AVX2` no ML-KEM e `BMI2/ADX` no X25519):
- **Em software puro**, o ciclo completo do ML-KEM-768 (mediana: 292,71 µs; Q25: 279,43 µs) e o ciclo completo do X25519 (mediana: 307,48 µs; Q25: 298,13 µs) possuem custos praticamente equivalentes, dividindo meio a meio o tempo de CPU do handshake híbrido (48,62% no ML-KEM vs. 49,66% no X25519, para um total mediano de 615,50 µs e Q25 de 581,11 µs).
- **Com Assembly ativo**, a vetorização SIMD (AVX2) acelera o ciclo do ML-KEM-768 em **2,42x** (caindo para **121,01 µs** na mediana e **118,36 µs** no Q25), enquanto o Assembly escalar (BMI2/ADX) acelera o ciclo do X25519 em **1,47x** (**208,54 µs** na mediana e **207,37 µs** no Q25). Como consequência, **o ciclo pós-quântico ML-KEM-768 torna-se 1,72x mais rápido em CPU do que o ciclo clássico X25519**, e a curva clássica X25519 passa a consumir **60,07% de todo o tempo de CPU do handshake híbrido** (contra 36,85% do ML-KEM-768 e 0,40% do combinador SHA-256), que finaliza em 332,81 µs na mediana (Q25: 330,23 µs; speedup de 1,85x).

## 1. Objetivo e Desenho Experimental Pareado

Enquanto os diretórios `1_ML-KEM/` e `2_X25519/` analisaram isoladamente as operações elementares de cada primitiva em sessões separadas, este diretório responde a duas perguntas práticas de engenharia de protocolos (como SSH e TLS 1.3):
1. **Qual é o custo total de CPU de uma troca de chaves efêmera completa (Cliente + Servidor)** quando comparamos o algoritmo clássico (`X25519`), o pós-quântico (`ML-KEM-768`) e a combinação híbrida (`mlkem768x25519-sha256`) sob o exato mesmo estado da máquina virtual?
2. **Como esse custo se distribui entre Cliente e Servidor** em cada etapa da negociação híbrida?

### Assimetria Funcional entre KEM e ECDH em um Handshake Efêmero

Para comparar de forma justa um mecanismo de encapsulamento de chaves (KEM) com uma troca Diffie-Hellman de curva elíptica (ECDH), é essencial observar o trabalho real executado pelas duas pontas da conexão (conforme especificado em `draft-kampanakis-curdle-ssh-pq-ke` para `mlkem768x25519-sha256`):

| Fase do Handshake | Trabalho no ML-KEM-768 | Trabalho no X25519 | Trabalho no Híbrido (`mlkem768x25519-sha256`) | Payload de Rede Gerado |
| --- | --- | --- | --- | --- |
| **1. `ClientInit` (Cliente)** | `NewKeyFromSeed` + `pk.Pack` | `x25519.KeyGen` (1ª geração) | Executa ambos e concatena $pk_{\text{PQ}} \parallel pub_{C}$ | $1.184 + 32 = 1.216\text{ B}$ |
| **2. `ServerRespond` (Servidor)** | `pk.Unpack` + `EncapsulateTo` | `x25519.KeyGen` (2ª geração) + `x25519.Shared` (1ª derivação) | Executa ambos, concatena $ct_{\text{PQ}} \parallel pub_{S}$ e calcula $K = \text{SHA-256}(K_{\text{PQ}} \parallel K_{\text{CL}})$ | $1.088 + 32 = 1.120\text{ B}$ |
| **3. `ClientFinish` (Cliente)** | `sk.DecapsulateTo` (usando `sk` já em cache na RAM do cliente) | `x25519.Shared` (2ª derivação) | Executa ambos sobre a resposta do servidor e calcula $K = \text{SHA-256}(K_{\text{PQ}} \parallel K_{\text{CL}})$ | — *(segredo derivado)* |
| **Ciclo Completo (`Cycle`)** | `1x KeyGen` + `1x Unpack+Encaps` + `1x DecapsCached` | **`2x KeyGen` + `2x Shared`** | Soma integral dos dois ciclos + `2x SHA-256` | $2.336\text{ B}$ trocados |

Note a assimetria estrutural: enquanto o ML-KEM-768 realiza uma geração de chave, um encapsulamento (com *unpack* da chave pública recebida) e um desencapsulamento (com a chave privada já desempacotada na memória do cliente), o X25519 exige **duas** gerações de chave efêmera e **duas** multiplicações escalares de ponto variável (`4` exponenciações em $\mathbb{F}_{2^{255}-19}$ no total).

## 2. Metodologia e Controles Experimentais

- **Execução pareada intra-rodada:** Os 6 benchmarks (`MLKEM768_Cycle`, `X25519_Cycle`, `Hybrid_Cycle`, `Hybrid_ClientInit`, `Hybrid_ServerRespond`, `Hybrid_ClientFinish`) compõem o mesmo executável e rodam sequencialmente dentro de cada uma das 20 rodadas intercaladas ABBA (`BENCHTIME=1s`, `PIN_CPU=0`, `GOMAXPROCS=1`).
- **Validação dupla de instruções e símbolos (`go tool nm`):** O script `run_all.sh` verifica a presença simultânea de `avx2`, `bmi2` e `adx` em `/proc/cpuinfo` e audita os binários compilados garantindo que `bench_software.test` (`-tags purego`) não contenha nenhum símbolo `*avx2` nem `*Amd64`, e que `bench_hardware.test` contenha ambas as famílias de rotinas Assembly.
- **Verificação de corretude fim a fim (`TestDigest`):** Antes de iniciar as medições, ambos os binários executam o handshake completo, verificam que cliente e servidor derivam exatamente o mesmo segredo híbrido de 32 bytes e comprovam a igualdade do digest SHA-256 (`DIGEST=7eac12b21ed5e4fd92314dbb8b2ddfeb4d2bc2188c0ca9162f48d1cd13b0291f`).

### Categorias de perfilamento (`pprofsplit`)

O classificador analítico (`dependencias/pprofsplit/main.go`) particiona as amostras de CPU em seis colunas:
1. `mlkem_keccak`: permutações e absorção/extração SHA-3/SHAKE do ML-KEM (`internal/sha3` e `simd/keccakf1600`).
2. `mlkem_poly_ntt`: aritmética polinomial, NTT e amostragem do ML-KEM (`pke/kyber`).
3. `x25519_ecc`: escadas de Joye/Montgomery e aritmética em $\mathbb{F}_{2^{255}-19}$ do X25519 (`dh/x25519` e `math/fp25519`).
4. `kdf_sha256`: combinador criptográfico `crypto/sha256` que funde os segredos pós-quântico e clássico.
5. `runtime_alloc_gc`: alocação no heap, coleta de lixo e barreiras de escrita do runtime do Go.
6. `other`: funções fora das categorias anteriores (ex.: `ConstantTimeCompare` e cópias de memória).

## 3. Resultados

### Tabela 1: Desempenho absoluto por operação e memória alocada

Tempos em microssegundos (µs) coletados na sessão do Google Colab (Data UTC: `2026-10-15T14:10:00Z`). Os valores de mediana, dispersão, p-valor (`p=0,000` em todas as comparações, n = 20) e alocações de memória provêm diretamente de `02_benchstat_speedup.txt` (dados brutos medidos); os valores de Q25 e seus intervalos de confiança de 95% (bootstrap, 10.000 reamostragens) são **calculados a partir das 20 amostras brutas** de `software.txt` e `hardware.txt` preservadas em `05_dados_brutos_e_logs.zip`.

| Operação | Software puro — Mediana (µs) | Hardware (AVX2 + BMI2/ADX) — Mediana (µs) | Speedup (mediana, `benchstat`) | Software puro — Q25 (µs, calculado) | Hardware — Q25 (µs, calculado) | Speedup (Q25, IC 95%, calculado) | Memória (`B/op` · `allocs/op`) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `MLKEM768_Cycle` | 292,71 (±81%) | 121,01 (±71%) | **2,42x** (−58,66%, p=0,000) | 279,43 | 118,36 | **2,36x** [2,32–2,44] (−57,6%) | 14,38 KiB · 5 allocs |
| `X25519_Cycle` | 307,48 (±85%) | 208,54 (±36%) | **1,47x** (−32,18%, p=0,000) | 298,13 | 207,37 | **1,44x** [1,41–1,47] (−30,4%) | 0 B · 0 allocs |
| `Hybrid_Cycle` | 615,50 (±45%) | 332,81 (±27%) | **1,85x** (−45,93%, p=0,000) | 581,11 | 330,23 | **1,76x** [1,75–1,86] (−43,2%) | 14,38 KiB · 5 allocs |
| `Hybrid_ClientInit` | 155,51 (±36%) | 85,32 (±21%) | **1,82x** (−45,13%, p=0,000) | 145,74 | 84,99 | **1,71x** [1,71–1,81] (−41,7%) | 8,00 KiB · 4 allocs |
| `Hybrid_ServerRespond` | 254,22 (±39%) | 152,37 (±12%) | **1,67x** (−40,06%, p=0,000) | 252,56 | 151,63 | **1,67x** [1,65–1,68] (−40,0%) | 6,38 KiB · 1 alloc |
| `Hybrid_ClientFinish` | 184,01 (±86%) | 94,31 (±54%) | **1,95x** (−48,75%, p=0,000) | 182,70 | 93,13 | **1,96x** [1,94–1,98] (−49,0%) | 0 B · 0 allocs |
| **Média geométrica** | **271,78** | **147,50** | **1,84x (−45,73%)** | **262,28** *(calculado)* | **146,10** *(calculado)* | **1,80x (−44,3%)** *(calculado)* | — |

### Verificação de Aditividade (Consistência Interna das Medições)

Como os benchmarks foram medidos de forma independente, a soma das partes permite auditar a precisão experimental da sessão:
- **Soma das 3 fases híbridas (`ClientInit + ServerRespond + ClientFinish`) vs. `Hybrid_Cycle` medido diretamente:**
  - Software (Q25, calculado): $145,74 + 252,56 + 182,70 = \mathbf{581,00\text{ }\mu\text{s}}$ vs. **`581,11 µs`** em `Hybrid_Cycle` (desvio de **0,02%**).
  - Hardware (Q25, calculado): $84,99 + 151,63 + 93,13 = \mathbf{329,75\text{ }\mu\text{s}}$ vs. **`330,23 µs`** em `Hybrid_Cycle` (desvio de **0,15%**).
  - Hardware (Mediana, `benchstat`): $85,32 + 152,37 + 94,31 = \mathbf{332,00\text{ }\mu\text{s}}$ vs. **`332,81 µs`** em `Hybrid_Cycle` (desvio de **0,24%**).
- **Soma dos ciclos independentes (`MLKEM768_Cycle + X25519_Cycle`) vs. `Hybrid_Cycle`:**
  - Software (Q25, calculado): $279,43 + 298,13 = \mathbf{577,56\text{ }\mu\text{s}}$ vs. **`581,11 µs`** em `Hybrid_Cycle` (a diferença de `3,55 µs` reflete as 2 chamadas ao combinador `SHA-256` e cópias de buffer).
  - Hardware (Mediana, `benchstat`): $121,01 + 208,54 = \mathbf{329,55\text{ }\mu\text{s}}$ vs. **`332,81 µs`** em `Hybrid_Cycle` (diferença de `3,26 µs`).

### Tabela 2: Distribuição percentual de CPU por categoria (`03_matematica_pprof.csv`)

Dados brutos medidos em execuções de perfilamento dedicadas (`PROFILE_BENCHTIME=20s` por operação e binário).

| Binário | Operação | `mlkem_keccak` | `mlkem_poly_ntt` | **Total ML-KEM** *(calculado)* | `x25519_ecc` | `kdf_sha256` | `runtime_alloc_gc` | `other` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Software** | `MLKEM768_Cycle` | 30,86% | 66,99% | **97,85%** | 0,00% | 0,00% | 1,42% | 0,73% |
| **Hardware** | `MLKEM768_Cycle` | 51,59% | 42,72% | **94,31%** | 0,00% | 0,00% | 4,38% | 1,31% |
| **Software** | `X25519_Cycle` | 0,00% | 0,00% | **0,00%** | 99,93% | 0,00% | 0,00% | 0,07% |
| **Hardware** | `X25519_Cycle` | 0,00% | 0,00% | **0,00%** | 100,00% | 0,00% | 0,00% | 0,00% |
| **Software** | `Hybrid_Cycle` | 15,89% | 32,73% | **48,62%** | 49,66% | 0,45% | 1,09% | 0,18% |
| **Hardware** | `Hybrid_Cycle` | 20,43% | 16,42% | **36,85%** | 60,07% | 0,40% | 2,20% | 0,48% |
| **Software** | `Hybrid_ClientInit` | 24,88% | 33,86% | **58,74%** | 39,07% | 0,00% | 2,15% | 0,04% |
| **Hardware** | `Hybrid_ClientInit` | 27,38% | 22,98% | **50,36%** | 45,71% | 0,00% | 3,79% | 0,14% |
| **Software** | `Hybrid_ServerRespond` | 12,73% | 23,58% | **36,31%** | 62,46% | 0,61% | 0,53% | 0,08% |
| **Hardware** | `Hybrid_ServerRespond` | 15,92% | 15,77% | **31,69%** | 66,40% | 0,57% | 1,26% | 0,08% |
| **Software** | `Hybrid_ClientFinish` | 8,09% | 40,11% | **48,20%** | 50,54% | 0,53% | 0,00% | 0,74% |
| **Hardware** | `Hybrid_ClientFinish` | 17,86% | 15,30% | **33,16%** | 64,67% | 0,70% | 0,00% | 1,48% |

### Tabela 3: Tempo estimado por componente (µs, SW → HW)

Os valores abaixo são **estimativas calculadas** multiplicando o tempo Q25 de cada operação (Tabela 1) pelos respectivos percentuais do perfilamento `pprof` (Tabela 2).

| Operação | Keccak ML-KEM (estimado) | Álgebra ML-KEM (estimado) | Curva X25519 (estimado) | KDF SHA-256 (estimado) | Alocação/GC (estimado) |
| --- | --- | --- | --- | --- | --- |
| `MLKEM768_Cycle` | 86,2 → 61,1 µs (1,4x) | 187,2 → 50,6 µs (3,7x) | 0,0 → 0,0 µs | 0,0 → 0,0 µs | 4,0 → 5,2 µs |
| `X25519_Cycle` | 0,0 → 0,0 µs | 0,0 → 0,0 µs | 297,9 → 207,4 µs (1,4x) | 0,0 → 0,0 µs | 0,0 → 0,0 µs |
| `Hybrid_Cycle` | 92,3 → 67,5 µs (1,4x) | 190,2 → 54,2 µs (3,5x) | 288,6 → 198,4 µs (1,5x) | 2,6 → 1,3 µs | 6,3 → 7,3 µs |
| `Hybrid_ClientInit` | 36,3 → 23,3 µs (1,6x) | 49,3 → 19,5 µs (2,5x) | 56,9 → 38,8 µs (1,5x) | 0,0 → 0,0 µs | 3,1 → 3,2 µs |
| `Hybrid_ServerRespond` | 32,2 → 24,1 µs (1,3x) | 59,6 → 23,9 µs (2,5x) | 157,7 → 100,7 µs (1,6x) | 1,5 → 0,9 µs | 1,3 → 1,9 µs |
| `Hybrid_ClientFinish` | 14,8 → 16,6 µs (0,9x) | 73,3 → 14,2 µs (5,1x) | 92,3 → 60,2 µs (1,5x) | 1,0 → 0,7 µs | 0,0 → 0,0 µs |

## 4. Análise

**1. Em CPUs com AVX2, a criptografia pós-quântica (ML-KEM-768) é mais rápida em CPU do que a criptografia clássica (X25519) no ciclo completo.** Existe uma percepção comum de que algoritmos pós-quânticos são mais pesados em processamento que curvas elípticas clássicas. Enquanto o ML-KEM-768 de fato trafega chaves e *ciphertexts* maiores na rede ($2.272\text{ B}$ vs. $64\text{ B}$ do X25519), no custo puro de CPU ocorre o oposto quando há suporte a SIMD: como o AVX2 reduz a álgebra polinomial do ML-KEM em 3,5x a 5,1x (`190,2 → 54,2 µs` no ciclo híbrido), o `MLKEM768_Cycle` completo leva **121,01 µs** (Q25: 118,36 µs), contra **208,54 µs** (Q25: 207,37 µs) do `X25519_Cycle`.

**2. O X25519 domina 60% do tempo de CPU do handshake híbrido acelerado.** Em software puro, o custo do `Hybrid_Cycle` é dividido de forma quase simétrica entre o ML-KEM-768 (48,62%) e o X25519 (49,66%). Com Assembly habilitado, como o X25519 acelera apenas 1,44x–1,47x via BMI2/ADX (contra 2,36x–2,42x do ML-KEM via AVX2), a parte clássica passa a representar **60,07%** de todo o processamento do `Hybrid_Cycle` (`198,4 µs` dos `330,23 µs` no Q25), chegando a **66,40%** no servidor (`Hybrid_ServerRespond`) e **64,67%** na finalização do cliente (`Hybrid_ClientFinish`).

**3. Distribuição do custo entre Cliente e Servidor no modo híbrido.** Somando as duas etapas do cliente (`Hybrid_ClientInit + Hybrid_ClientFinish`) e comparando com a etapa única do servidor (`Hybrid_ServerRespond`):
- **Lado Cliente (`ClientInit + ClientFinish`):** consome **339,52 µs** na mediana em software (Q25: 328,44 µs, **56,5%** do handshake) e **179,63 µs** na mediana em hardware (Q25: 178,12 µs, **54,0%** do handshake).
- **Lado Servidor (`ServerRespond`):** consome **254,22 µs** na mediana em software (Q25: 252,56 µs, **43,5%** do handshake) e **152,37 µs** na mediana em hardware (Q25: 151,63 µs, **46,0%** do handshake).
O servidor arca com a etapa individual mais cara (`152,37 µs` em hardware) porque precisa executar simultaneamente o `Unpack` da chave pública ML-KEM (reexpandindo a matriz $\mathbf{A}$ via SHAKE128), o `Encaps` do ML-KEM e **ambas** as operações do X25519 (`KeyGen` + `Shared`).

**4. O combinador SHA-256 e a sobrecarga de memória do modo híbrido são mínimos.** A derivação $K = \text{SHA-256}(K_{\text{PQ}} \parallel K_{\text{CL}})$ consome apenas 0,40% a 0,70% da CPU (~1,3 µs no ciclo completo em hardware), e toda a parte X25519 + KDF opera com **zero alocações no heap** (`0 B/op`), fazendo com que o `Hybrid_Cycle` aloque exatamente os mesmos `14,38 KiB` (5 allocs) do `MLKEM768_Cycle` isolado (`8,00 KiB` / 4 allocs em `ClientInit` e `6,38 KiB` / 1 alloc em `ServerRespond`).

## 5. Limitações

- **Foco exclusivo em tempo de CPU (sem latência de rede):** Este benchmark mede todas as etapas em memória RAM para isolar o custo aritmético e de hash. Em redes reais (especialmente enlaces congestionados ou com alto RTT), o impacto do tamanho das chaves do ML-KEM-768 ($1.216\text{ B}$ no `ClientInit` e $1.120\text{ B}$ no `ServerRespond`) sobre a fragmentação de pacotes TCP/SSH deve ser avaliado separadamente em testes de transporte.
- **Ambiente virtualizado em nuvem:** Assim como nos diretórios `1_ML-KEM/` e `2_X25519/`, os tempos absolutos refletem uma instância Xeon virtualizada no Google Colab; as razões pareadas dentro da mesma rodada ABBA e o primeiro quartil (Q25) mitigam o efeito da contenção do hipervisor.

## 6. Reprodutibilidade e artefatos

- **Ambiente fixado:** Go 1.26.0, CIRCL v1.6.5, `golang.org/x/sys` v0.26.0, `GOAMD64=v1`, `CGO_ENABLED=0`, `GOMAXPROCS=1`, `PIN_CPU=0`.
- **Integridade verificada:** Os hashes SHA-256 de todos os arquivos-fonte e dos binários `bench_software.test` (`658655112ac5...`) e `bench_hardware.test` (`7891443ee545...`) estão registrados em `resultados/01_relatorio_auditoria.txt`.

### 6.1 Como reproduzir

#### Opção A: No Google Colab
1. Abra `3_Hibrido/colab_runner.ipynb` no Google Colab.
2. Confira `REPO_URL`, `BRANCH_NAME` e `SUBDIR = "3_Hibrido"`.
3. Execute todas as células na ordem.

#### Opção B: Em máquina Linux local (`x86_64` com `AVX2`, `BMI2` e `ADX`)
```bash
cd 3_Hibrido
chmod +x dependencias/run_all.sh
./dependencias/run_all.sh
```

### 6.2 Artefatos gerados (`3_Hibrido/resultados/`)

| Arquivo | Conteúdo |
| --- | --- |
| `01_relatorio_auditoria.txt` | Inventário da VM, hashes SHA-256, validação dupla de símbolos (`AVX2` + `Amd64`), digest e Top 30 do `pprof` |
| `02_benchstat_speedup.txt` | Comparação estatística Software vs. Hardware (`benchstat`, n = 20) |
| `03_matematica_pprof.csv` | Percentuais de CPU nas 6 categorias (`mlkem_keccak`, `mlkem_poly_ntt`, `x25519_ecc`, `kdf_sha256`, `runtime_alloc_gc`, `other`) |
| `04_telemetria_ruido.csv` | Monitoramento de *steal time* do host (`/proc/stat`) |
| `05_dados_brutos_e_logs.zip` | Perfis simbolizados (`*_sym.pb.gz`) e logs brutos das 20 rodadas (`software.txt` e `hardware.txt`) |

## Aviso sobre o uso de inteligência artificial

O código-fonte dos benchmarks, a ferramenta `pprofsplit`, os scripts de orquestração e a redação analítica deste documento foram desenvolvidos e revisados com auxílio dos modelos Gemini 3.1 Pro e Gemini 3.8 Flash. Todos os dados numéricos reportados provêm exclusivamente dos artefatos de execução preservados em `resultados/`.
