# ML-KEM-768: Onde o tempo é gasto e o que a aceleração realmente muda

*Microbenchmarks em software puro vs. AVX2 · CIRCL v1.6.5 · Go 1.26.0 · Xeon 2,2 GHz (Google Colab)*

## Resumo

Este trabalho mede o custo computacional do ML-KEM-768, algoritmo pós-quântico de encapsulamento de chaves, em duas variantes do mesmo código-fonte: uma em software puro, sem Assembly otimizado, e outra com vetorização AVX2. A hipótese inicial era que as funções de hash Keccak/SHAKE fossem o principal gargalo de desempenho. Os dados refutam isso em parte: em software puro, a aritmética polinomial (que inclui a NTT) consome de 56,2% a 87,4% da CPU, e o Keccak, de 12,5% a 40,8%.

A vetorização AVX2 reduziu o tempo em 61,2% (média geométrica), com speedups de 1,86x a 3,24x na mediana (2,06x a 3,55x no Q25). Entre 71,9% e 100% desse ganho veio da álgebra, não do hash. Como efeito colateral, no build acelerado o Keccak passa a ocupar de 44,9% a 53,5% do tempo e se torna o novo gargalo.

## 1. Premissa e objetivo

A hipótese de partida era que a geração de ruído pseudoaleatório e a expansão da matriz pública via Keccak/SHAKE seriam o principal custo do ML-KEM em dispositivos de borda (IoT), isto é, processadores sem instruções avançadas em silício: microcontroladores simples, chips RISC-V básicos ou ARM sem extensões criptográficas. Nesses casos, não há rotinas vetorizadas disponíveis, e a criptografia roda em software puro. Neste estudo, a CIRCL compilada sem Assembly serve como *proxy* desse cenário.

O objetivo era medir quanto do tempo total vai para o hash e quanto vai para o restante do algoritmo, e verificar o que muda quando o processador oferece aceleração.

### Dois tipos de aceleração

É importante separar dois conceitos que costumam ser confundidos:

| Tipo | O que é | Exemplos | Usado neste teste? |
| --- | --- | --- | --- |
| Aceleração criptográfica nativa | Instruções dedicadas ao algoritmo, como "execute uma permutação SHA-3" | Extensão SHA-3 opcional do ARMv8.2 | Não |
| Aceleração vetorial genérica (SIMD) | Instruções que operam sobre vários dados ao mesmo tempo, sem conhecer criptografia | AVX2 (x86), NEON (ARM), Helium (Cortex-M) | Sim (AVX2) |

No build "hardware" deste estudo não há nenhuma instrução nativa de SHA-3. A CIRCL usa o AVX2 para duas coisas: acelerar a aritmética polinomial (NTT e correlatas) e processar quatro permutações Keccak em paralelo (`keccakf1600x4AVX2`), o que ainda é software, apenas vetorizado. Portanto, o teste mede o efeito do SIMD, e não o de uma instrução dedicada de hash.

## 2. Metodologia

### 2.1 As duas variantes

O mesmo código-fonte foi compilado de duas formas:

- **Software puro (Binário A):** compilado com `-tags purego`, que desativa todo o Assembly otimizado. Serve de proxy para processadores sem extensões vetoriais ou criptográficas.
- **Hardware AVX2 (Binário B):** compilação padrão, com as rotinas vetorizadas da CIRCL ativas no x86.

### 2.2 Controles experimentais

- **Afinidade de CPU:** execução restrita ao núcleo lógico 0 (`taskset -c 0`, `GOMAXPROCS=1`), reduzindo migrações entre CPUs e favorecendo a localidade de cache. Isso não elimina trocas de contexto.
- **Entropia isolada:** sementes e ruído vêm de um gerador determinístico criado antes de o cronômetro iniciar, de modo que o tempo de `/dev/urandom` não entra na medição.
- **Ordem intercalada (ABBA):** os binários alternam a ordem de execução (A-B, B-A, A-B, B-A) para que nenhum deles rode sempre por último, quando a CPU está mais quente e sujeita a *throttling* (redução de clock).
- **Amostragem:** 20 rodadas, cada uma em laço contínuo por 1 segundo (`BENCHTIME=1s`), precedidas por uma rodada de aquecimento descartada.
- **Sessão:** todos os resultados deste relatório vêm de uma única sessão do Colab (Data UTC: `2026-10-14T16:28:16Z`). Os artefatos correspondentes estão descritos na seção 8.
- **Barreira anti-otimização:** variáveis globais ("sinks") impedem que o compilador elimine código cujo resultado não é usado.
- **Verificação de corretude:** antes de qualquer medição, os dois binários calculam um digest de validação. Se divergirem em um byte, a execução é abortada.
- **Perfilamento:** um perfil de CPU (`pprof`) é analisado por uma ferramenta própria (`pprofsplit`), que classifica o tempo em três categorias: `keccak` (permutações, absorb e squeeze), `poly_ntt` (aritmética e amostragem Kyber fora do Keccak) e `runtime_alloc_gc` (alocação, coleta de lixo e barreiras de escrita).

Nas tabelas e no texto, a categoria `poly_ntt` aparece como **álgebra Kyber**: ela agrega toda a matemática do ML-KEM fora do hash (amostragem, reduções de Barrett/Montgomery, multiplicação de matrizes e a NTT, a *Number-Theoretic Transform*), e não apenas a NTT.

### 2.3 Estatística

As medianas e os p-valores foram calculados com `benchstat` (n = 20; teste U de Mann-Whitney, padrão do `benchstat`; p < 0,001 em todas as comparações). O speedup baseado no primeiro quartil (Q25) usa as amostras brutas e intervalo de confiança de 95% por bootstrap. O Q25 dá maior peso à faixa rápida das medições; é uma análise complementar à mediana, não uma medição direta de um tempo de CPU sem ruído.

## 3. Os seis benchmarks

O ML-KEM expande uma matriz pública **A** (cerca de 3 KB) a partir de uma semente de 32 bytes, usando SHAKE128. Essa expansão é um dos maiores consumidores de Keccak. Por isso, os benchmarks se dividem principalmente pelo tratamento dado a essa matriz: reconstruí-la a cada operação (cenário *FromBytes*) ou mantê-la pronta na RAM (cenário *Cached*).

| Benchmark | Cenário | O que mede |
| --- | --- | --- |
| KeyGen | Geração a partir de semente | Geração do par de chaves pública e privada. Envolve intensa geração de ruído via hash. |
| EncapsFromBytes | Sem cache | Encapsulamento do segredo. A chave pública chega serializada e a matriz A é reexpandida via SHAKE128 antes da matemática principal. |
| DecapsFromBytes | Sem cache | Desencapsulamento pelo receptor, arcando com a desserialização (*unpack*) da chave privada e os hashes associados. |
| EncapsCached | Com cache | Encapsulamento com a chave pública já desempacotada e a matriz A residente na RAM. Pula a expansão com SHAKE128. |
| DecapsCached | Com cache | Desencapsulamento com a chave privada já desempacotada na RAM. Representa a resposta rápida de um servidor ou dispositivo. |
| DecapsInvalid | Rejeição implícita | Recebe propositalmente um *ciphertext* adulterado. Uma implementação segura deve evitar que a validade do *ciphertext* seja revelada por diferenças de tempo observáveis. Os tempos próximos aos de DecapsCached são compatíveis com custo semelhante, mas este benchmark não comprova, por si só, ausência de canais laterais. |

### Como interpretar os dois cenários

- **FromBytes** representa o pior caso para o hash e a realidade de dispositivos com pouca RAM, que não conseguem manter a chave expandida em memória e precisam reexpandir a matriz A a cada operação.
- **Cached** retira a expansão da matriz A. O que sobra do Keccak são os hashes menores do algoritmo (G, H, PRF e KDF), e o teste mostra se a aceleração ainda compensa sem a etapa mais pesada de SHAKE128.

## 4. Resultados

### Tabela 1: Desempenho absoluto por operação

Tempos medianos em microssegundos (µs), da sessão do Google Colab (Data UTC: `2026-10-14T16:28:16Z`).

| Operação | Software puro (µs) | Hardware AVX2 (µs) | Speedup (mediana) | Speedup (Q25, IC 95%) |
| --- | --- | --- | --- | --- |
| KeyGen | 86,96 | 46,87 | 1,86x | 2,06x [1,94–2,09] |
| EncapsFromBytes | 103,99 | 51,24 | 2,03x | 2,22x [2,19–2,25] |
| EncapsCached | 60,80 | 18,74 | 3,24x | 3,55x [3,47–3,58] |
| DecapsCached | 90,50 | 29,37 | 3,08x | 3,07x [3,05–3,10] |
| DecapsInvalid | 90,25 | 29,36 | 3,07x | 3,08x [3,04–3,10] |
| DecapsFromBytes | 155,00 | 61,06 | 2,54x | 2,26x [2,23–2,46] |
| **Média geométrica** | **94,14** | **36,51** | **2,58x (−61,2%)** | n/d |

O speedup de 1,86x significa que a versão AVX2 executa a operação 1,86 vezes mais rápido que a de software puro. O relatório de `benchstat` mostra dispersão considerável em algumas amostras. Por isso, a tabela apresenta tanto o speedup baseado nas medianas quanto o speedup baseado no Q25, com IC de 95% por bootstrap. O uso de memória (B/op) e as alocações (allocs/op) foram idênticos nos dois modos (por exemplo, KeyGen com 8 KiB (8.192 B) e 4 allocs; operações em cache com 0 bytes), o que indica que a diferença de tempo vem do processamento, e não de mudanças nessas duas métricas de memória.

### Tabela 2: Onde a CPU é gasta (perfilamento pprof)

Percentual do tempo de CPU na sessão `ML-KEM`. Alocação/coleta de lixo (até 6,7% em KeyGen devido à instanciação de chaves no heap) e outras funções (como comparação em tempo constante no Decaps) somam no máximo 4,8% e foram omitidas da tabela principal (presentes em `03_matematica_pprof.csv`).

| Operação | Keccak (SW) | Keccak (AVX2) | Álgebra Kyber (SW) | Álgebra Kyber (AVX2) |
| --- | --- | --- | --- | --- |
| KeyGen | 40,8% | 53,5% | 56,2% | 39,4% |
| EncapsFromBytes | 35,6% | 49,8% | 62,0% | 45,1% |
| EncapsCached | 12,5% | 44,9% | 87,4% | 54,8% |
| DecapsCached | 16,6% | 49,9% | 82,3% | 46,0% |
| DecapsInvalid | 16,6% | 49,6% | 81,7% | 45,5% |
| DecapsFromBytes | 30,1% | 49,1% | 65,7% | 44,5% |

### Tabela 3: Tempo estimado por componente (µs, SW → AVX2)

| Operação | Keccak | Álgebra Kyber |
| --- | --- | --- |
| KeyGen | 35,3 → 22,4 (1,6x) | 48,5 → 16,5 (2,9x) |
| EncapsFromBytes | 36,8 → 23,1 (1,6x) | 64,0 → 21,0 (3,1x) |
| EncapsCached | 7,5 → 7,6 (1,0x) | 52,6 → 9,3 (5,7x) |
| DecapsCached | 14,9 → 14,5 (1,0x) | 73,7 → 13,4 (5,5x) |
| DecapsInvalid | 14,9 → 14,5 (1,0x) | 73,3 → 13,3 (5,5x) |
| DecapsFromBytes | 40,6 → 29,3 (1,4x) | 88,6 → 26,5 (3,3x) |

Estes valores são **estimativas**: multiplicam os tempos do Q25 da sessão `teste-ML-KEM` pelos percentuais das colunas `keccak` e `poly_ntt` do pprof (Tabela 2), obtidos em execuções de perfilamento dedicadas. Coleta de lixo e outras funções não entram em nenhuma das duas colunas.

## 5. Análise

**1. Em software puro, o hash não é o maior custo.** A álgebra Kyber responde por 56,2% a 87,4% do tempo, e o Keccak por 12,5% a 40,8%. O hash é relevante, principalmente nas operações que expandem a matriz A (KeyGen e FromBytes, onde passa de 30%), mas não é o maior ofensor isolado.

**2. O ganho veio sobretudo do SIMD sobre a álgebra.** O AVX2 acelerou a álgebra de 2,9x a 5,7x. O Keccak melhorou de 1,4x a 1,6x apenas nas operações em que a CIRCL consegue processar quatro permutações em paralelo (KeyGen, EncapsFromBytes e DecapsFromBytes). Nas operações com cache, o Keccak ficou em 1,0x. No total, de 71,9% (KeyGen) a ~100% (EncapsCached) da economia de tempo veio da álgebra.

**3. O cache amplia o ganho.** O pico de aceleração (3,24x na mediana; 3,55x no Q25) ocorre em EncapsCached, onde a matriz A já está na RAM e o SHAKE128 pesado é dispensado. Sem essa etapa, a álgebra domina o tempo em software puro e é justamente ela que o AVX2 comprime mais.

**4. O gargalo se inverte.** Depois que a álgebra é vetorizada, o Keccak passa a ocupar de 44,9% a 53,5% do tempo. Em parte, isso reflete o fato de o Keccak ter melhorado pouco; em parte, de o restante ter encolhido. O resultado é que, num processador que já tenha SIMD, o hash é o próximo alvo natural de otimização.

## 6. Conclusão

A hipótese inicial foi parcialmente refutada. O hash Keccak é um custo relevante do ML-KEM, mas, em software puro, a álgebra de reticulados é o maior consumidor de CPU. A vetorização SIMD (AVX2) reduziu o tempo total em 61,2% (1,86x a 3,24x por operação na mediana; 2,06x a 3,55x no Q25), e a maior parte desse ganho veio da álgebra, não do hash.

Para dispositivos de borda sem extensões vetoriais, o cenário da premissa, o achado mais relevante é que a álgebra polinomial, e não o hash, deve ser o primeiro alvo de otimização. Já em processadores com SIMD ocorre uma inversão: com a álgebra acelerada, o Keccak passa a ocupar cerca de metade do tempo de CPU. Isso sugere que, nesses processadores, uma instrução dedicada de SHA-3 em silício seria o próximo passo mais promissor. É uma inferência a partir da distribuição do tempo: **este estudo não mediu nenhum processador com aceleração SHA-3 nativa**, portanto o ganho concreto dessa extensão continua a ser testado.

## 7. Limitações

- **Ambiente de nuvem e tempos absolutos.** A cauda superior das amostras individuais sofre forte impacto do ambiente compartilhado (cerca de 1/3 das amostras pode ficar mais de 30% acima da mediana). O *steal time* medido foi baixo e não parece explicar, sozinho, a oscilação. Os dados não isolam a causa exata do *jitter*; disputas de cache e o estado do hipervisor são explicações possíveis. Por esse motivo, os tempos absolutos (µs) documentados neste repositório devem ser lidos apenas como referência aproximada, enquanto as razões de aceleração tendem a ser menos sensíveis a esse ruído, já que os dois binários são medidos de forma intercalada na mesma sessão.
- **Sessão única.** Os resultados vêm de uma única sessão; a estabilidade dos valores entre sessões diferentes não é avaliada neste relatório.
- **O proxy de software não é um microcontrolador.** `-tags purego` em um Xeon desliga o Assembly e o SIMD, mas o chip continua com pipeline superescalar, caches grandes, 64 bits e clock de 2,2 GHz. Ele representa a ausência de otimizações, não o comportamento de um Cortex-M ou ESP32.
- **Apenas x86 com AVX2.** A extrapolação dos ganhos para ARMv8 (NEON), RISC-V ou microcontroladores exige compilações específicas e testes em hardware real.
- **Categoria `poly_ntt`.** Ela agrega toda a aritmética e amostragem Kyber fora do Keccak, e não mede a NTT isoladamente.
- **Tabela 3 é estimada.** Ela combina o Q25 com percentuais de perfis de execuções dedicadas, e não com medições diretas por componente.

## 8. Reprodutibilidade e artefatos

- **Ambiente fixado:** Go 1.26.0 (`GOTOOLCHAIN=auto`), CIRCL v1.6.5, `golang.org/x/sys` v0.26.0 e `golang.org/x/crypto` v0.28.0, compilação com `-mod=mod -trimpath -buildvcs=false`, `GOAMD64=v1`, `CGO_ENABLED=0`. O script aborta se a CPU não reportar AVX2.
- **Integridade:** o hash SHA-256 de todo o código-fonte, scripts, `go.mod`/`go.sum` e dos executáveis finais (`bench_software.test`: `2400e0832140...` e `bench_hardware.test`: `d587e2d06429...`) é registrado no relatório de auditoria (`01_relatorio_auditoria.txt`).
- **Alcance da reprodutibilidade:** refere-se à corretude funcional e à integridade das dependências, e não à identidade dos tempos absolutos, pois a nuvem introduz ruído.

### 8.1 Como reproduzir

#### Opção A: No Google Colab (Recomendado)

1. Abra o arquivo `colab_runner.ipynb` no Google Colab.
2. Na primeira célula, preencha os campos do formulário interativo com o link do seu repositório/fork e a pasta de destino no seu Google Drive.
3. Execute as células em ordem sequencial (`Ambiente de execução` → `Executar tudo`).

#### Opção B: Em máquina Linux local
>
> Requisitos: Processador x86_64 com suporte a AVX2 e Go 1.26.0 instalado.

```bash
cd 1_ML-KEM
chmod +x dependencias/run_all.sh
./dependencias/run_all.sh
```

### 8.2 Artefatos gerados por execução

| Arquivo | Conteúdo |
| --- | --- |
| `01_relatorio_auditoria.txt` | Logs, hashes e validações da VM |
| `02_benchstat_speedup.txt` | Comparação estatística Software vs. Hardware |
| `03_matematica_pprof.csv` | Percentuais por função (Keccak vs. álgebra) |
| `04_telemetria_ruido.csv` | Oscilação do host (`/proc/stat`) |
| `05_dados_brutos_e_logs.zip` | Perfis e saídas brutas |

## Aviso sobre o uso de inteligência artificial

O código dos benchmarks e das ferramentas de apoio (incluindo o `pprofsplit` e os scripts de orquestração) foi gerado com auxílio de IA, especificamente o Gemini 3.1 Pro (high). O refino da redação deste texto foi feito com o Gemini 3.8 Flash. Os resultados devem ser lidos considerando esse contexto e podem ser reproduzidos com os artefatos descritos na seção 8.
