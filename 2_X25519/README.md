# X25519: Linha de Base Clássica e o Limite da Aceleração Escalar (BMI2/ADX)

*Microbenchmarks em software puro vs. Assembly x86_64 (BMI2/ADX) · CIRCL v1.6.5 · Go 1.26.0 · Xeon 2,2 GHz (Google Colab)*

## Resumo

Este estudo mede o custo computacional da troca de chaves elípticas X25519 (RFC 7748) na biblioteca CIRCL v1.6.5, comparando o código compilado em Go puro (`-tags purego`) com a implementação em Assembly `x86_64` otimizada com as extensões escalares BMI2 e ADX. O experimento segue exatamente o mesmo controle metodológico aplicado ao ML-KEM-768 em `1_ML-KEM/` e cumpre dois objetivos: estabelecer a referência clássica de desempenho no mesmo hardware e investigar como a ausência de paralelismo vetorial (SIMD) altera o ganho obtido pelo Assembly manual.

Em Go puro, o X25519 executa `KeyGen` em 58,03 µs (Q25: 57,93 µs) e `Shared` em 90,41 µs (Q25: 90,20 µs), com zero alocações no heap (`0 B/op`, `0 allocs/op`). No binário com Assembly BMI2/ADX, a oscilação bimodal da máquina virtual do Google Colab mascarou o ganho nas medianas brutas de `KeyGen` e `Shared` (empatadas estatisticamente em 57,84 µs e 88,76 µs), mas a análise pelo primeiro quartil (Q25) — que isola a faixa de execução sem contenção do hipervisor — revela tempos de 42,30 µs para `KeyGen` (speedup de 1,37x) e 62,86 µs para `Shared` (speedup de 1,43x), com média geométrica no Q25 de 54,94 µs contra 77,87 µs no software puro (speedup de 1,42x, redução de 29,5%).

O ganho moderado (~1,4x no X25519 contra 2,1x a 3,5x no ML-KEM-768) explica-se pela arquitetura tanto do algoritmo quanto do compilador Go: enquanto a álgebra de reticulados do ML-KEM vetoriza 16 coeficientes de 16 bits por instrução AVX2, a escada de Montgomery do X25519 é estritamente sequencial sobre inteiros de 255 bits, onde o compilador Go moderno já emite instruções nativas de 64 bits em código puro, restando ao Assembly manual apenas o ganho incremental de `MULXQ`, `ADCXQ` e `ADOXQ`.

## 1. Premissa, objetivo e diferença arquitetural de aceleração

O X25519 e o ML-KEM-768 pertencem a famílias matemáticas distintas (problema do logaritmo discreto sobre a curva elíptica Curve25519 vs. aprendizado com erros em módulos sobre reticulados). Portanto, esta bateria não visa eleger um substituto direto entre os dois, mas sim:

1. Medir o custo de CPU de referência da primitiva clássica hoje empregada na indústria (TLS 1.3 e SSH);
2. Preparar a avaliação do modo híbrido (`X25519 + ML-KEM-768`) no diretório `3_Hibrido/`;
3. Contrastar o efeito do Assembly escalar de grandes inteiros (**BMI2/ADX**) com o efeito da vetorização SIMD (**AVX2**) observada no ML-KEM-768.

### Por que o X25519 usa BMI2/ADX e não AVX2 em uma operação isolada?

No ML-KEM-768, os polinômios possuem 256 coeficientes independentes em $`\mathbb{Z}_{3329}`$ (16 bits cada), permitindo que um registrador `YMM` de 256 bits do AVX2 processe 16 coeficientes simultaneamente. Já uma operação do X25519 executa 255 iterações sequenciais da escada de Montgomery (*Montgomery ladder*) ou de Joye sobre elementos de um único corpo primo grande, $`\mathbb{F}_{2^{255}-19}`$, representados em 4 palavras de 64 bits (*limbs*). Como cada passo da escada depende diretamente da saída do passo anterior, não há paralelismo horizontal para preencher vetores SIMD de 16 vias em uma única troca de chaves.

Por isso, em `x86_64`, a CIRCL (`dh/x25519/curve_amd64.go` e `math/fp25519/fp_amd64.go`) verifica `cpu.X86.HasBMI2 && cpu.X86.HasADX` e utiliza instruções escalares de 64 bits:

| Modo de Build | Tag de Compilação | Arquivos Compilados (`dh/x25519` e `math/fp25519`) | Símbolos Principais |
| --- | --- | --- | --- |
| **Software puro (Binário A)** | `-tags purego` | `curve_noasm.go`, `fp_noasm.go` (`SFiles: []`) | `ladderStepGeneric`, `doubleGeneric`, `diffAddGeneric`, `mulGeneric`, `sqrGeneric`, `modpGeneric`, `red64` |
| **Assembly BMI2/ADX (Binário B)** | *(padrão)* | `curve_amd64.go`, `curve_amd64.s`, `fp_amd64.go`, `fp_amd64.s` | `ladderStepAmd64`, `doubleAmd64`, `diffAddAmd64`, `mulAmd64`, `sqrAmd64`, `modpAmd64` |

- **BMI2 (`MULXQ`):** multiplica dois registradores de 64 bits produzindo 128 bits sem alterar as flags de *carry* da CPU.
- **ADX (`ADCXQ` e `ADOXQ`):** executa duas cadeias paralelas de adição com *carry* utilizando de forma independente as flags `CF` e `OF`.

## 2. Metodologia e os três benchmarks

Os controles experimentais são idênticos aos de `1_ML-KEM/`: afinidade no núcleo lógico 0 (`taskset -c 0`, `GOMAXPROCS=1`), sementes determinísticas pré-computadas via SHA-256 fora do cronômetro, 20 rodadas intercaladas no protocolo ABBA (`BENCHTIME=1s` por rodada após aquecimento descartado), validação de símbolos via `go tool nm` e verificação de corretude por digest SHA-256 (`DIGEST=542c8903aae146cab9318bf37e1e189053fd1326283f47ead06daba21f486a06` idêntico nos dois binários).

Diferentemente do ML-KEM-768, uma chave X25519 na CIRCL é um array bruto de 32 bytes (`x25519.Key`) sem etapa de *unpack* ou expansão de matriz por hash, operando com alocação zero no heap (`0 B/op`, `0 allocs/op`).

| Benchmark | Cenário | O que mede |
| --- | --- | --- |
| `KeyGen` | Geração de chave pública | Multiplicação escalar do ponto base canônico $G$ pela chave privada (`x25519.KeyGen`), implementada na CIRCL via escada de Joye (`ladderJoye`) com tabela pré-computada. |
| `Shared` | Segredo compartilhado válido | Multiplicação escalar da chave pública válida do par pela chave privada local (`x25519.Shared`), implementada via escada de Montgomery (`ladderMontgomery`). |
| `SharedInvalid` | Rejeição de ponto de baixa ordem | Recebe o ponto público nulo de 32 bytes (RFC 7748, Seção 6.1), para o qual `x25519.Shared` retorna `false`. Avalia se o custo de tempo permanece constante diante de entradas inválidas. |

### Categorias de perfilamento (`pprofsplit`)

- `fp25519`: tempo gasto diretamente nas funções do pacote `cloudflare/circl/math/fp25519` (`mul`, `sqr`, `red64`, `addsub`, `Inv`).
- `x25519_ladder`: tempo gasto nas funções do pacote `cloudflare/circl/dh/x25519` (`ladderJoye`, `ladderMontgomery`, `diffAdd`, `ladderStep`, `toAffine`).
- `runtime_alloc_gc`: alocação de memória e coleta de lixo do runtime do Go (0,00% em todos os cenários).
- `other`: funções fora das categorias anteriores (máximo de 0,04%).

## 3. Resultados

### Tabela 1: Desempenho absoluto por operação

Tempos em microssegundos (µs) coletados na sessão do Google Colab (Data UTC: `2026-10-14T14:46:49Z`). Os valores de mediana e p-valor provêm diretamente de `02_benchstat_speedup.txt` (dado bruto medido); os valores de Q25 e seus intervalos de confiança de 95% (bootstrap, 10.000 reamostragens) são **calculados a partir das 20 amostras brutas** de `software.txt` e `hardware.txt` preservadas em `05_dados_brutos_e_logs.zip`.

| Operação | Software puro — Mediana (µs) | Assembly BMI2/ADX — Mediana (µs) | Speedup (mediana, `benchstat`) | Software puro — Q25 (µs, calculado) | Assembly BMI2/ADX — Q25 (µs, calculado) | Speedup (Q25, IC 95%, calculado) |
| --- | --- | --- | --- | --- | --- | --- |
| `KeyGen` | 58,03 (±0%) | 57,84 (±27%) | 1,00x (−0,34%, p=0,883) | 57,93 | 42,30 | 1,37x [1,04–1,39] (−27,0%) |
| `Shared` | 90,41 (±1%) | 88,76 (±29%) | 1,02x (−1,83%, p=0,355) | 90,20 | 62,86 | 1,43x [1,05–1,45] (−30,3%) |
| `SharedInvalid` | 91,13 (±16%) | 75,18 (±21%) | 1,21x (−17,50%, p=0,001) | 90,38 | 62,38 | 1,45x [1,26–1,46] (−31,0%) |
| **Média geométrica** | **78,19** | **72,81** | **1,07x (−6,89%)** | **77,87** *(calculado)* | **54,94** *(calculado)* | **1,42x (−29,5%)** *(calculado)* |

Todas as operações registraram **0 B/op** e **0 allocs/op** nos dois binários (`02_benchstat_speedup.txt`).

### Tabela 2: Onde a CPU é gasta (perfilamento `pprof`)

Percentuais extraídos diretamente de `03_matematica_pprof.csv` (dados medidos em execuções dedicadas de 20s por operação). As colunas `runtime_alloc_gc_pct` (0,00% em todos os testes) e `other_pct` (0,00% a 0,04%) foram omitidas.

| Operação | `fp25519` (SW) | `fp25519` (ASM) | `x25519_ladder` (SW) | `x25519_ladder` (ASM) |
| --- | --- | --- | --- | --- |
| `KeyGen` | 93,80% | 15,96% | 6,17% | 84,04% |
| `Shared` | 90,08% | 10,79% | 9,92% | 89,21% |
| `SharedInvalid` | 89,93% | 8,93% | 10,04% | 91,04% |

### Tabela 3: Decomposição estimada por fase algorítmica (µs, SW → ASM)

Como no binário Assembly a aritmética de corpo finito dos 255 passos da escada fica embutida diretamente nos símbolos `diffAddAmd64` e `ladderStepAmd64` (dentro de `dh/x25519/curve_amd64.s`), a divisão funcional mais fiel separa o custo da **Escada Principal** (multiplicação escalar em coordenadas projetivas) do custo da **Inversão Modular Final** (`toAffine` $\rightarrow$ `fp25519.Inv`, que calcula $`Z^{p-2} \pmod{2^{255}-19}`$ ao final da operação).

Os valores abaixo são **estimativas calculadas** multiplicando os tempos do Q25 (Tabela 1) pelos percentuais cumulativos de `toAffine` vs. restante da operação registrados nos relatórios Top 30 do `pprof` em `01_relatorio_auditoria.txt` (`toAffine`: 14,45% SW / 16,00% ASM em `KeyGen`; 8,05% SW / 10,79% ASM em `Shared`; 6,66% SW / 8,89% ASM em `SharedInvalid`).

| Operação | Escada Principal (`ladderJoye` / `ladderMontgomery`) (estimado) | Inversão Modular Final (`toAffine` / `fp25519.Inv`) (estimado) |
| --- | --- | --- |
| `KeyGen` | 49,6 → 35,5 µs (1,39x) | 8,4 → 6,8 µs (1,24x) |
| `Shared` | 82,9 → 56,1 µs (1,48x) | 7,3 → 6,8 µs (1,07x) |
| `SharedInvalid` | 84,4 → 56,8 µs (1,48x) | 6,0 → 5,5 µs (1,09x) |

## 4. Análise

**1. O comportamento bimodal na nuvem explica a divergência entre a mediana e o Q25.** Nas 20 rodadas intercaladas de `hardware.txt` (`05_dados_brutos_e_logs.zip`), o binário Assembly operou em dois patamares nítidos: nas rodadas sem interferência da VM, `KeyGen` estabilizou entre 41,60 µs e 42,30 µs (6 amostras) e `Shared` entre 62,08 µs e 62,93 µs (6 amostras); já nas rodadas sob contenção de hipervisor/SMT, o tempo do binário Assembly subiu para ~58,7–60,2 µs (`KeyGen`) e ~91,1–93,3 µs (`Shared`). Como cerca de metade das amostras caiu no patamar degradado, a mediana global (`benchstat`) deslocou-se para 57,84 µs e 88,76 µs, enquanto o Q25 capturou de forma consistente o regime limpo (42,30 µs e 62,86 µs).

**2. Por que o Assembly BMI2/ADX ganha ~1,4x no X25519, contra 2,1x–3,5x do AVX2 no ML-KEM-768.** Em Go puro (`-tags purego`), o perfil de CPU (`01_relatorio_auditoria.txt`) mostra que ~90% a 94% do tempo do X25519 concentra-se em `mulGeneric` (37,2% a 39,0%), `sqrGeneric` (28,8% a 35,4%), `red64` (26,8% a 29,0%) e `addsubGeneric` (14,0% a 14,5%). Como essas rotinas operam sobre palavras inteiras de 64 bits, o compilador Go já gera código de máquina escalar eficiente. O Assembly manual (`diffAddAmd64`, `ladderStepAmd64`, `sqrAmd64`, `mulAmd64`) elimina o *overhead* de chamadas de função no laço interno e explora `MULXQ`/`ADCXQ`/`ADOXQ`, reduzindo o tempo em ~30% (1,37x a 1,45x no Q25), mas sem o fator multiplicador de 16 vias paralelas que o SIMD AVX2 proporciona à álgebra polinomial do ML-KEM.

**3. A inversão de percentuais na Tabela 2 reflete o *inlining* em Assembly, não uma mudança algorítmica.** Em Go puro, `dh/x25519` delega cada multiplicação e quadratura da escada ao pacote `math/fp25519`, fazendo `fp25519` responder por 90,1% a 93,8% das amostras. No build Assembly, o arquivo `dh/x25519/curve_amd64.s` implementa a aritmética de corpo finito diretamente dentro dos símbolos `diffAddAmd64` (77,90% flat no `KeyGen`) e `ladderStepAmd64` (87,88% a 89,38% flat no `Shared`), transferindo a contabilização do `pprof` para `x25519_ladder`. O tempo residual em `fp25519` no modo Assembly (8,93% a 15,96%) corresponde exatamente à inversão modular final (`toAffine` $\rightarrow$ `fp25519.Inv`), cujo custo absoluto estimado permanece estável em ~6,8 µs (Tabela 3).

**4. Comportamento em tempo constante na rejeição de pontos inválidos.** No Q25, `Shared` (90,20 µs SW / 62,86 µs ASM) e `SharedInvalid` (90,38 µs SW / 62,38 µs ASM) apresentaram tempos praticamente idênticos, confirmando que a rejeição do ponto de baixa ordem ocorre apenas após a execução completa da escada de Montgomery e da conversão afim.

## 5. Limitações

Aplicam-se as mesmas limitações documentadas em `1_ML-KEM/README.md`:

- **Ruído de nuvem compartilhada:** A presença de bimodalidade nas amostras do binário Assembly reforça que os tempos absolutos em microssegundos servem apenas como ordem de grandeza da sessão, sendo o Q25 uma métrica complementar para isolar a faixa rápida da distribuição, e não um substituto para medições em *bare-metal* com *turbo boost* e SMT desativados.
- **Compilação Go pura com `GOAMD64=v1`:** O binário `software` foi compilado com `GOAMD64=v1` para manter simetria estrita com `1_ML-KEM/`.
- **Estimativas da Tabela 3:** Combinam o Q25 das 20 rodadas ABBA com os percentuais cumulativos extraídos da etapa dedicada de perfilamento (`pprof`).

## 6. Reprodutibilidade e artefatos

- **Ambiente fixado:** Go 1.26.0, CIRCL v1.6.5, `golang.org/x/sys` v0.26.0, `GOAMD64=v1`, `CGO_ENABLED=0`, `GOMAXPROCS=1`, `PIN_CPU=0`.
- **Integridade verificada:** Os hashes SHA-256 de todos os arquivos-fonte e dos binários `bench_software.test` (`02f4f7bbfb1d...`) e `bench_hardware.test` (`2bf1c7c0b4a6...`) estão registrados em `resultados/01_relatorio_auditoria.txt`.

### 6.1 Como reproduzir

#### Opção A: No Google Colab

1. Abra `2_X25519/colab_runner.ipynb` no Google Colab.
2. Confira `REPO_URL`, `BRANCH_NAME` e `SUBDIR = "2_X25519"`.
3. Execute todas as células na ordem.

#### Opção B: Em máquina Linux local (`x86_64` com `BMI2` e `ADX`)

```bash
cd 2_X25519
chmod +x dependencias/run_all.sh
./dependencias/run_all.sh
```

### 6.2 Artefatos gerados (`2_X25519/resultados/`)

| Arquivo | Conteúdo |
| --- | --- |
| `01_relatorio_auditoria.txt` | Inventário da VM, hashes SHA-256, validação de símbolos `Amd64`, digest e Top 30 do `pprof` |
| `02_benchstat_speedup.txt` | Comparação estatística Software vs. Assembly BMI2/ADX (`benchstat`, n = 20) |
| `03_matematica_pprof.csv` | Percentuais de CPU por pacote (`fp25519` vs. `x25519_ladder`) |
| `04_telemetria_ruido.csv` | Monitoramento de *steal time* do host (`/proc/stat`) |
| `05_dados_brutos_e_logs.zip` | Perfis simbolizados (`*_sym.pb.gz`) e logs brutos das 20 rodadas (`software.txt` e `hardware.txt`) |

## Aviso sobre o uso de inteligência artificial

O código-fonte dos benchmarks, a ferramenta `pprofsplit`, os scripts de orquestração e a redação analítica deste documento foram desenvolvidos e revisados com auxílio dos modelos Gemini 4 Pro (high) e Gemini 3.8 Flash. Todos os dados numéricos reportados provêm exclusivamente dos artefatos de execução preservados em `resultados/`.
