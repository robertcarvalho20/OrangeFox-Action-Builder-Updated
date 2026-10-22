#!/system/bin/sh
# fstab_adapt.sh
# Adapta a linha /data (e /metadata) do recovery.fstab ao esquema de
# criptografia da ROM instalada, lendo o fstab da particao vendor.
# Se algo falhar, o recovery.fstab original e mantido (nunca piora).

LOG=/tmp/fstab_adapt.log
FSTAB=/system/etc/recovery.fstab
BAK=/tmp/recovery.fstab.orig
MNT=/mnt/fstab_probe
VEND=/dev/block/bootdevice/by-name/vendor
TAB="$(printf '\t')"

mkdir -p /tmp
: > "$LOG"
log() { echo "[fstab_adapt] $*" >> "$LOG"; }

[ -f "$FSTAB" ] || { log "recovery.fstab nao encontrado"; exit 0; }
cp "$FSTAB" "$BAK" 2>/dev/null

# 1) esperar a particao vendor aparecer (ate ~12s)
i=0
while [ ! -e "$VEND" ] && [ "$i" -lt 12 ]; do sleep 1; i=$((i+1)); done
[ -e "$VEND" ] || { log "particao vendor nao encontrada, mantendo fstab padrao"; exit 0; }

# 2) montar vendor somente leitura (tenta varios sistemas de arquivos)
mkdir -p "$MNT"
MOUNTED=0
for t in ext4 erofs f2fs; do
  if mount -t "$t" -o ro "$VEND" "$MNT" 2>>"$LOG"; then
    MOUNTED=1; log "vendor montado como $t"; break
  fi
done
[ "$MOUNTED" = 1 ] || { log "nao foi possivel montar vendor, mantendo fstab padrao"; exit 0; }

# 3) achar a linha /data no fstab da ROM
ROMLINE=""
for f in "$MNT"/etc/fstab.qcom "$MNT"/etc/fstab.*; do
  [ -f "$f" ] || continue
  L="$(grep -E '^[^#]*[[:space:]]/data[[:space:]]' "$f" | head -n 1)"
  if [ -n "$L" ]; then ROMLINE="$L"; log "fstab da ROM: $f"; break; fi
done
umount "$MNT" 2>>"$LOG"
[ -n "$ROMLINE" ] || { log "linha /data nao encontrada no fstab da ROM, mantendo fstab padrao"; exit 0; }
log "linha ROM: $ROMLINE"

# 4) extrair parametros de criptografia da ROM
set -f
set -- $ROMLINE
ROM_MNTFLAGS="$4"
ROM_FSFLAGS="$5"
FE=""; ME=""; KD=""; WK=0; INL=0
OLDIFS="$IFS"; IFS=','
for t in $ROM_FSFLAGS; do
  case "$t" in
    fileencryption=*) FE="$t" ;;
    metadata_encryption=*) ME="$t" ;;
    keydirectory=*) KD="$t" ;;
    wrappedkey|wrappedkey_v0) WK=1 ;;
  esac
done
for t in $ROM_MNTFLAGS; do
  [ "$t" = "inlinecrypt" ] && INL=1
done
IFS="$OLDIFS"
log "FE=[$FE] ME=[$ME] KD=[$KD] wrappedkey=$WK inlinecrypt=$INL"

# 5) reescrever o recovery.fstab
TMP=/tmp/recovery.fstab.new
: > "$TMP"
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    \#*|"") echo "$line" >> "$TMP"; continue ;;
  esac
  set -- $line
  if [ "$2" = "/data" ]; then
    SRC="$1"; MP="$2"; FS="$3"; MF="$4"; FF="$5"
    NMF=""; OLDIFS="$IFS"; IFS=','
    for t in $MF; do [ "$t" = "inlinecrypt" ] || NMF="${NMF:+$NMF,}$t"; done
    [ "$INL" = 1 ] && NMF="${NMF:+$NMF,}inlinecrypt"
    NFF=""
    for t in $FF; do
      case "$t" in
        fileencryption=*|metadata_encryption=*|keydirectory=*|wrappedkey|wrappedkey_v0) ;;
        *) NFF="${NFF:+$NFF,}$t" ;;
      esac
    done
    IFS="$OLDIFS"
    if [ -n "$FE" ]; then
      NFF="$NFF,$FE"
      [ -n "$ME" ] && NFF="$NFF,$ME"
      [ "$WK" = 1 ] && NFF="$NFF,wrappedkey"
      [ -n "$KD" ] && NFF="$NFF,$KD"
    fi
    echo "$SRC$TAB$MP$TAB$FS$TAB$NMF$TAB$NFF" >> "$TMP"
  elif [ "$2" = "/metadata" ]; then
    SRC="$1"; MP="$2"; FS="$3"; MF="$4"; FF="$5"
    NFF=""; OLDIFS="$IFS"; IFS=','
    for t in $FF; do
      case "$t" in wrappedkey|wrappedkey_v0) ;; *) NFF="${NFF:+$NFF,}$t" ;; esac
    done
    IFS="$OLDIFS"
    [ "$WK" = 1 ] && NFF="$NFF,wrappedkey"
    echo "$SRC$TAB$MP$TAB$FS$TAB$MF$TAB$NFF" >> "$TMP"
  else
    echo "$line" >> "$TMP"
  fi
done < "$BAK"

# 6) validar antes de aplicar
if grep -qE '[[:space:]]/data[[:space:]]' "$TMP" && [ -s "$TMP" ]; then
  cat "$TMP" > "$FSTAB"
  log "recovery.fstab atualizado:"
  grep -E '[[:space:]]/(data|metadata)[[:space:]]' "$FSTAB" >> "$LOG"
else
  log "validacao falhou, mantendo fstab padrao"
fi
exit 0
