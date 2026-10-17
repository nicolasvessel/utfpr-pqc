#!/usr/bin/env bash
# Script de Orquestração Reprodutível do Microbenchmark ML-KEM-768
set -euo pipefail

# ==========================================
# 1. FIXAÇÃO DO AMBIENTE E VARIÁVEIS
# ==========================================
export GO_VERSION="1.26.0"
export GOTOOLCHAIN="auto"
export CIRCL_VERSION="v1.6.5"
export BENCHSTAT_VERSION="v0.0.0-20260929162123-406019bb8b68"
export PPROF_VERSION="v0.0.0-20261002000307-77d3b59017a0"

export ROUNDS=20
export BENCHTIME="1s"
export PROFILE_BENCHTIME="20s"
export PIN_CPU="0"

export CGO_ENABLED=0
export GOAMD64=v1
export GOFLAGS="-mod=readonly"
export GOMAXPROCS=1

# Adicionar dependências ao PATH (Colab/Linux)
export PATH="/usr/local/go/bin:/root/go/bin:/root/go/bin/linux_amd64:$PATH"

BASEDIR="$(pwd)"
SRC_DIR="$BASEDIR/codigo_bruto"
DEP_DIR="$BASEDIR/dependencias"
OUT_DIR="$BASEDIR/resultados"
PROF_DIR="$BASEDIR/prof_tmp"

mkdir -p "$OUT_DIR" "$PROF_DIR"
rm -f "$OUT_DIR"/* "$PROF_DIR"/*

LOG_AUDIT="$OUT_DIR/01_relatorio_auditoria.txt"
HASH_INPUT="$OUT_DIR/input_sha256.txt"
HASH_BIN="$OUT_DIR/binaries_sha256.txt"

# ==========================================
# 2. VERIFICAÇÃO E INSTALAÇÃO DO GO
# ==========================================
echo "Verificando ambiente Go..."

check_go() {
  if command -v go >/dev/null 2>&1; then
    local v
    v="$(go version | awk '{print $3}')"
    if [[ "$v" == "go${GO_VERSION}" ]]; then
      return 0
    fi
  fi
  return 1
}

if ! check_go; then
  echo "Go ${GO_VERSION} ausente ou incorreto. Baixando e instalando (requer root no Colab)..."
  curl -sSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o go.tar.gz || { echo "ERRO: Falha ao baixar Go"; exit 1; }
  rm -rf /usr/local/go
  tar -C /usr/local -xzf go.tar.gz || { echo "ERRO: Falha ao extrair Go"; exit 1; }
  rm go.tar.gz
fi

actual_go="$(go version | awk '{print $3}' || echo 'none')"
if [[ "$actual_go" != "go${GO_VERSION}" ]]; then
    echo "ERRO CRÍTICO: versão do Go incompatível: $actual_go (esperado go${GO_VERSION})"
    exit 1
fi

# ==========================================
# 3. AUDITORIA DE AMBIENTE (Hardware/Variáveis)
# ==========================================
echo "Auditando hardware e ambiente..."
echo "========================================" > "$LOG_AUDIT"
echo " INVENTÁRIO DE HARDWARE E AMBIENTE      " >> "$LOG_AUDIT"
echo "========================================" >> "$LOG_AUDIT"
echo "Data UTC: $(date -u +%FT%TZ)" >> "$LOG_AUDIT"
echo "uname: $(uname -a)" >> "$LOG_AUDIT"
echo "NProc: $(nproc)" >> "$LOG_AUDIT"
go version >> "$LOG_AUDIT"
go env >> "$LOG_AUDIT"

echo "" >> "$LOG_AUDIT"
echo "--- VARIÁVEIS EXPERIMENTAIS EXPLICITAS ---" >> "$LOG_AUDIT"
echo "GO_VERSION=$GO_VERSION" >> "$LOG_AUDIT"
echo "GOTOOLCHAIN=$GOTOOLCHAIN" >> "$LOG_AUDIT"
echo "GOAMD64=$GOAMD64" >> "$LOG_AUDIT"
echo "CGO_ENABLED=$CGO_ENABLED" >> "$LOG_AUDIT"
echo "GOFLAGS=$GOFLAGS" >> "$LOG_AUDIT"
echo "GOMAXPROCS=$GOMAXPROCS" >> "$LOG_AUDIT"
echo "CIRCL_VERSION=$CIRCL_VERSION" >> "$LOG_AUDIT"
echo "BENCHSTAT_VERSION=$BENCHSTAT_VERSION" >> "$LOG_AUDIT"
echo "PPROF_VERSION=$PPROF_VERSION" >> "$LOG_AUDIT"
echo "ROUNDS=$ROUNDS" >> "$LOG_AUDIT"
echo "BENCHTIME=$BENCHTIME" >> "$LOG_AUDIT"
echo "PROFILE_BENCHTIME=$PROFILE_BENCHTIME" >> "$LOG_AUDIT"
echo "PIN_CPU=$PIN_CPU" >> "$LOG_AUDIT"

echo "" >> "$LOG_AUDIT"
echo "--- LSCPU E EXTENSÕES ---" >> "$LOG_AUDIT"
lscpu >> "$LOG_AUDIT" 2>/dev/null || echo "AVISO: lscpu não disponível" >> "$LOG_AUDIT"
cat /proc/cpuinfo >> "$LOG_AUDIT" 2>/dev/null || { echo "ERRO CRÍTICO: /proc/cpuinfo não disponível"; exit 1; }

# Aborta se a CPU não tiver AVX2 (o benchmark B usa o caminho vetorizado explicitamente)
if ! grep -q "avx2" /proc/cpuinfo; then
    echo "ERRO CRÍTICO: CPU não possui instruções AVX2. O benchmark 'hardware' seria inválido." | tee -a "$LOG_AUDIT"
    exit 1
fi

# Validar que a configuração declarada realmente afeta a toolchain
if [[ "$(go env GOAMD64)" != "$GOAMD64" ]]; then echo "ERRO CRÍTICO: GOAMD64 em uso não é $GOAMD64"; exit 1; fi
if [[ "$(go env CGO_ENABLED)" != "$CGO_ENABLED" ]]; then echo "ERRO CRÍTICO: CGO_ENABLED em uso não é $CGO_ENABLED"; exit 1; fi

# ==========================================
# 4. HASH DOS FONTES ANTES DA COMPILAÇÃO
# ==========================================
echo "Gerando manifesto de integridade dos arquivos-fonte..."
find "$SRC_DIR" "$DEP_DIR" -type f \( -name "*.go" -o -name "go.mod" -o -name "go.sum" -o -name "*.sh" \) | sort | xargs sha256sum > "$HASH_INPUT"
echo "" >> "$LOG_AUDIT"
echo "--- SHA-256 INPUT FILES ---" >> "$LOG_AUDIT"
cat "$HASH_INPUT" >> "$LOG_AUDIT"

# ==========================================
# 5. PREPARAÇÃO DE FERRAMENTAS (SEM DEPENDÊNCIAS DINÂMICAS)
# ==========================================
echo "Instalando benchstat fixo na versão ${BENCHSTAT_VERSION}..."
go install "golang.org/x/perf/cmd/benchstat@${BENCHSTAT_VERSION}" || { echo "ERRO: Falha ao instalar benchstat"; exit 1; }

echo "Compilando ferramenta analítica pprofsplit..."
cd "$DEP_DIR/pprofsplit"
go mod download || { echo "ERRO: Falha ao baixar deps de pprofsplit"; exit 1; }
go mod verify || { echo "ERRO: Dependências de pprofsplit corrompidas (go mod verify falhou)"; exit 1; }
go build -trimpath -buildvcs=false -mod=readonly -o "$DEP_DIR/pprofsplit_bin" main.go || { echo "ERRO: Falha ao compilar pprofsplit"; exit 1; }

# ==========================================
# 6. COMPILAÇÃO DOS BINÁRIOS DE TESTE
# ==========================================
echo "Compilando binários do microbenchmark (Software e Hardware)..."
cd "$SRC_DIR"
go mod download || { echo "ERRO: Falha ao baixar dependências do benchmark"; exit 1; }
go mod verify || { echo "ERRO: Dependências do benchmark corrompidas (go.sum mismatch)"; exit 1; }

go test -c -trimpath -buildvcs=false -mod=mod -tags purego -o "$BASEDIR/bench_software.test" . || { echo "ERRO: Falha ao compilar benchmark purego"; exit 1; }
go test -c -trimpath -buildvcs=false -mod=mod              -o "$BASEDIR/bench_hardware.test" . || { echo "ERRO: Falha ao compilar benchmark hardware"; exit 1; }


echo "Validando caminhos de compilação..."
echo "========================================" >> "$LOG_AUDIT"
echo " VALIDAÇÃO DOS CAMINHOS DE BUILD" >> "$LOG_AUDIT"
echo "========================================" >> "$LOG_AUDIT"

if go tool nm "$BASEDIR/bench_software.test" | grep -iE "circl.*avx2|keccak.*avx2" >/dev/null 2>&1; then
    echo "ERRO CRÍTICO: Binário software (purego) contém símbolos AVX2!" | tee -a "$LOG_AUDIT"
    exit 1
else
    echo "OK: Binário software não contém símbolos AVX2." >> "$LOG_AUDIT"
fi

if ! go tool nm "$BASEDIR/bench_hardware.test" | grep -iE "circl.*avx2|keccak.*avx2" >/dev/null 2>&1; then
    echo "ERRO CRÍTICO: Binário hardware não contém símbolos AVX2!" | tee -a "$LOG_AUDIT"
    exit 1
else
    echo "OK: Binário hardware contém símbolos AVX2." >> "$LOG_AUDIT"
fi


echo "Gerando hashes dos binários compilados..."
cd "$BASEDIR"
sha256sum bench_software.test bench_hardware.test > "$HASH_BIN"
echo "" >> "$LOG_AUDIT"
echo "--- SHA-256 BINARIES ---" >> "$LOG_AUDIT"
cat "$HASH_BIN" >> "$LOG_AUDIT"

# ==========================================
# 7. VALIDAÇÃO DE CORRETUDE (DIGEST E LÓGICA)
# ==========================================
echo "========================================" >> "$LOG_AUDIT"
echo " VALIDAÇÃO DE CORRETUDE E SAÍDAS        " >> "$LOG_AUDIT"
echo "========================================" >> "$LOG_AUDIT"

declare -A DIGESTS
for bin in software hardware; do
  echo "--- Rodando testes unitários e extraindo Digest Hash: $bin ---" >> "$LOG_AUDIT"
  OUT_TEST=$(taskset -c "$PIN_CPU" "$BASEDIR/bench_${bin}.test" -test.run='^Test' -test.v 2>&1) || {
    echo "$OUT_TEST" >> "$LOG_AUDIT"
    echo "ERRO CRÍTICO: FALHA NOS TESTES UNITÁRIOS DO $bin!" | tee -a "$LOG_AUDIT"
    exit 1
  }
  echo "$OUT_TEST" >> "$LOG_AUDIT"
  
  d=$(echo "$OUT_TEST" | grep -oP 'DIGEST=\K[0-9a-f]+' || true)
  if [ -z "$d" ]; then
    echo "ERRO CRÍTICO: Digest ausente ou inválido no binário $bin!" | tee -a "$LOG_AUDIT"
    exit 1
  fi
  DIGESTS[$bin]="$d"
done

if [ "${DIGESTS[software]}" != "${DIGESTS[hardware]}" ]; then
  echo "ERRO CRÍTICO: Divergência de digest!" | tee -a "$LOG_AUDIT"
  echo "Software: ${DIGESTS[software]}" | tee -a "$LOG_AUDIT"
  echo "Hardware: ${DIGESTS[hardware]}" | tee -a "$LOG_AUDIT"
  exit 1
fi
echo "Digests validados com sucesso e são iguais: ${DIGESTS[software]}" | tee -a "$LOG_AUDIT"

# ==========================================
# 8. PERFILAMENTO (PPROF E TOP30)
# ==========================================
echo "Gerando perfis matemáticos de CPU (pprof)..."
OPS="KeyGen EncapsFromBytes EncapsCached DecapsCached DecapsFromBytes DecapsInvalid"

echo "" >> "$LOG_AUDIT"
echo "========================================" >> "$LOG_AUDIT"
echo " TOP 30 FUNÇÕES CUMULATIVAS (PPROF)     " >> "$LOG_AUDIT"
echo "========================================" >> "$LOG_AUDIT"

for bin in software hardware; do
  for op in $OPS; do
    echo "  > Perfilando $bin / $op..."
    taskset -c "$PIN_CPU" "$BASEDIR/bench_${bin}.test" \
      -test.run='^$' -test.bench="^Benchmark${op}\$" -test.benchtime="$PROFILE_BENCHTIME" \
      -test.cpuprofile="$PROF_DIR/${bin}_${op}.prof" > /dev/null || { echo "ERRO: Falha ao rodar pprof para $bin $op"; exit 1; }
    
    go tool pprof -proto -output="$PROF_DIR/${bin}_${op}_sym.pb.gz" "$BASEDIR/bench_${bin}.test" "$PROF_DIR/${bin}_${op}.prof" 2>/dev/null || { echo "ERRO: Falha ao simbolizar perfil $bin $op"; exit 1; }
    
    echo ">> Top 30 para $bin / $op" >> "$LOG_AUDIT"
    # Falhas no relatório textual top 30 não abortam a execução matemática, pois é apenas formatação para o txt.
    go tool pprof -top -cum -nodecount=30 "$BASEDIR/bench_${bin}.test" "$PROF_DIR/${bin}_${op}.prof" >> "$LOG_AUDIT" 2>/dev/null || echo "Aviso: Falha ao extrair top30 de $bin $op" >> "$LOG_AUDIT"
    echo "" >> "$LOG_AUDIT"
  done
done

echo "Processando CSV de gargalos com pprofsplit..."
"$DEP_DIR/pprofsplit_bin" "$OUT_DIR/03_matematica_pprof.csv" "$PROF_DIR"/*_sym.pb.gz || { echo "ERRO: Falha ao processar CSV pprofsplit"; exit 1; }

echo "Empacotando evidências matemáticas brutas..."
cd "$PROF_DIR"
zip -q "$OUT_DIR/05_dados_brutos_e_logs.zip" *.pb.gz || { echo "ERRO: Falha ao criar zip"; exit 1; }
cd "$BASEDIR"


rm -rf "$PROF_DIR"

# ==========================================
# 9. EXECUÇÃO ABBA (ROUNDS DE BENCHMARK)
# ==========================================
echo "Iniciando execuções intercaladas (ABBA)..."
echo "round,order,binary,start_utc,end_utc,cpu_id,steal_before,steal_after,steal_delta" > "$OUT_DIR/04_telemetria_ruido.csv"

# Gravar inventario de CPU adicional
echo "========================================" >> "$LOG_AUDIT"
echo " INVENTÁRIO DE CPU " >> "$LOG_AUDIT"
echo "========================================" >> "$LOG_AUDIT"
lscpu >> "$LOG_AUDIT" 2>/dev/null || echo "lscpu indisponível" >> "$LOG_AUDIT"

run() {
  local bin=$1 output=$2 round=$3 order=$4
  local t0 t1
  
  # Coletar steal times antes (para todas as CPUs online)
  declare -A steal_before
  while read -r cpu_id user nice system idle iowait irq softirq steal guest guest_nice; do
    steal_before[$cpu_id]=$steal
  done < <(awk '/^cpu[0-9]+/ {print $0}' /proc/stat)
  
  t0=$(date -u +%FT%TZ)
  
  # Confirmar GOMAXPROCS=1
  export GOMAXPROCS=1
  
  taskset -c "$PIN_CPU" "$BASEDIR/bench_${bin}.test" -test.run='^$' -test.bench=. -test.benchtime="$BENCHTIME" -test.count=1 >> "$output" || { echo "ERRO: Falha no benchmark $bin no round $round"; exit 1; }
  t1=$(date -u +%FT%TZ)

  # Coletar steal times depois
  while read -r cpu_id user nice system idle iowait irq softirq steal guest guest_nice; do
    local s0=${steal_before[$cpu_id]:-0}
    local s1=$steal
    local delta=$((s1 - s0))
    echo "$round,$order,$bin,$t0,$t1,$cpu_id,$s0,$s1,$delta" >> "$OUT_DIR/04_telemetria_ruido.csv"
  done < <(awk '/^cpu[0-9]+/ {print $0}' /proc/stat)
  
  
}

# Warm-up (Descartado estatisticamente)
run software /dev/null 0 AB
run hardware /dev/null 0 AB

for r in $(seq 1 "$ROUNDS"); do
  if (( r % 2 == 1 )); then order=AB; first=software; second=hardware
  else                      order=BA; first=hardware; second=software; fi
  run "$first"  "$OUT_DIR/$first.txt"  "$r" "$order"
  run "$second" "$OUT_DIR/$second.txt" "$r" "$order"
done

# ==========================================
# 10. RESULTADOS FINAIS
# ==========================================
echo "Consolidando banco de dados Benchstat..."
benchstat "$OUT_DIR/software.txt" "$OUT_DIR/hardware.txt" > "$OUT_DIR/02_benchstat_speedup.txt" || { echo "ERRO: benchstat falhou em analisar os resultados"; exit 1; }

rm -f "$BASEDIR/bench_software.test" "$BASEDIR/bench_hardware.test" "$DEP_DIR/pprofsplit_bin"


echo "Validando protocolo ABBA e resultados..."
python3 -c "
import csv, sys
rounds = []
seen = set()
with open('$OUT_DIR/04_telemetria_ruido.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row['round'] != '0':
            key = (row['round'], row['order'], row['binary'])
            if key not in seen:
                seen.add(key)
                rounds.append(row)


if len(rounds) != $ROUNDS * 2:
    print(f'ERRO: Numero de execuções incorreto. Esperado: {$ROUNDS * 2}, Encontrado: {len(rounds)}')
    sys.exit(1)

for i in range(0, len(rounds), 2):
    r1, r2 = rounds[i], rounds[i+1]
    if r1['round'] != r2['round']:
        print('ERRO: Rodadas incompatíveis')
        sys.exit(1)
    
    order = r1['order']
    if order == 'AB' and not (r1['binary'] == 'software' and r2['binary'] == 'hardware'):
        print('ERRO: Ordem AB violada')
        sys.exit(1)
    if order == 'BA' and not (r1['binary'] == 'hardware' and r2['binary'] == 'software'):
        print('ERRO: Ordem BA violada')
        sys.exit(1)

print('Protocolo ABBA validado com sucesso.')
" || { echo "ERRO CRÍTICO na validação ABBA"; exit 1; }



echo "Empacotando logs textuais..."
zip -qj "$OUT_DIR/05_dados_brutos_e_logs.zip" "$OUT_DIR/software.txt" "$OUT_DIR/hardware.txt" || { echo "ERRO: Falha ao add txts ao zip"; exit 1; }
rm -f "$OUT_DIR/software.txt" "$OUT_DIR/hardware.txt" "$HASH_INPUT" "$HASH_BIN"

echo "TUDO PRONTO"

