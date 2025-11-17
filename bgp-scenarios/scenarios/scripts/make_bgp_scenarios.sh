#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <raw_routeviews_file> [label] [out_root]" >&2
    echo "Example: $0 scenarios/raw/rv2_20230101_1h_raw.txt rv2_20230101_1h" >&2
    exit 1
fi

RAW="$1"
LABEL="${2:-$(basename "$RAW")}"
LABEL="${LABEL%_raw.txt}"
LABEL="${LABEL%.txt}"
OUT_ROOT="${3:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/generated}"

OUTDIR="${OUT_ROOT}/${LABEL}"
mkdir -p "$OUTDIR"

rm -f "$OUTDIR"/*.scenario "$OUTDIR"/all.scenario 2>/dev/null || true

echo "[make] Input RAW : $RAW"
echo "[make] Output dir: $OUTDIR"

awk -F'|' -v outdir="$OUTDIR" '
NR == 1 { t0 = $3 }

$1 != "U" { next }

{
    t_rel = $3 - t0

    project    = $4
    collector  = $5
    peer_asn   = $8
    peer_ip    = $9
    msg_type   = $2
    prefix     = $10
    as_path    = $12
    origin_as  = $13
    comms      = $14

    line = sprintf("%.6f|%s|%s|%s|%s|%s|%s|%s|%s|%s",
                   t_rel, project, collector, peer_asn, peer_ip,
                   msg_type, prefix, as_path, origin_as, comms)

    key_node = peer_asn "|" line
    key_all  = line

    if (!(key_node in seen_node)) {
        fname = sprintf("%s/node_%s.scenario", outdir, peer_asn)
        print line >> fname
        seen_node[key_node] = 1
    }

    if (!(key_all in seen_all)) {
        print line >> (outdir "/all.scenario")
        seen_all[key_all] = 1
    }
}
' "$RAW"

echo "[make] Scenarios written under $OUTDIR"
