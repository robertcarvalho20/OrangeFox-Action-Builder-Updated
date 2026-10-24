#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apply_visual.py - aplica as personalizacoes visuais (RC20) numa imagem do OrangeFox (ginkgo).

O que faz (tudo dentro do ramdisk da imagem ja compilada):
  1. About: troca o cartao "Testing build (unofficial)" pelo nome RC20 com a foto (author_rc20.png)
  2. Creditos: adiciona a entrada no Change Log (ex.: "== 12.0_1 ==" / "- Fix decryption ...")
  3. Log da tela inicial: "[Support] : RC20" (mantem as linhas de sites)
  4. Opcional: --about-version "R12.1" escreve a versao fixa no About
Depois refaz o bloco de verificacao AVB (hash correto, sem assinatura), senao o bootloader
mostra "The system has been destroyed" em aparelhos com a verificacao ligada.

Uso:
  python3 apply_visual.py --image OrangeFox-xxx.img [--zip OrangeFox-xxx.zip] [--png author_rc20.png]
Somente biblioteca padrao do Python 3.
"""
import argparse, base64, gzip, hashlib, lzma, os, re, struct, sys, tempfile, zipfile

# bloco vbmeta modelo (AVB0, algoritmo NONE, hash descriptor "recovery"), 832 bytes
VBMETA_TEMPLATE_B64 = (
    "QVZCMAAAAAEAAAAAAAAAAAAAAAAAAAAAAAACQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAIQAAAAAAAAAAAAAAAAAAACEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACEAAA"
    "AAAAAAABAAAAAAAAAABhdmJ0b29sIDEuMi4wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAMAAAAAAApUgAHNoYTI1"
    "NgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAACAAAAAgAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHJlY292ZXJ5O4J8"
    "MzymWPYm7T7Nsmvsd2UMDrQJeHICpJtZv5Pen854/lviQvuEM+tk3/1i4i5cbsSbMpWDu8dsWOjQ"
    "SBioywAAAAAAAAAAAAAAAAAAAAAAAACIAAAAAAAAACYAAAAAAAAAUGNvbS5hbmRyb2lkLmJ1aWxk"
    "LnJlY292ZXJ5LmZpbmdlcnByaW50AFhpYW9taS90d3JwX2dpbmtnby9naW5rZ286MTYuMS4wL1NQ"
    "MkEuMjIwNDA1LjAwNC90ZWphczEwMWswNjE1MTUyMDplbmcvdGVzdC1rZXlzAAAAAAAAAAAAAAAA"
    "AAAAAEAAAAAAAAAAIQAAAAAAAAAGY29tLmFuZHJvaWQuYnVpbGQuYm9vdC5vc192ZXJzaW9uADE2"
    "LjEuMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASAAAAAAAAAAlAAAAAAAAAApjb20uYW5kcm9pZC5i"
    "dWlsZC5ib290LnNlY3VyaXR5X3BhdGNoADIwOTktMTItMzEAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)
AVB_MAJOR, AVB_MINOR = 1, 0
PS_DEFAULT = 4096
WARNINGS = []


def say(msg):
    print(msg, flush=True)


def warn(msg):
    WARNINGS.append(msg)
    say("AVISO: " + msg)
    if os.environ.get("GITHUB_ACTIONS"):
        print("::warning::" + msg, flush=True)


# ----------------------------------------------------------------- cpio (newc)
def cpio_parse(data):
    ents, i = [], 0
    while True:
        h = data[i:i + 110]
        if h[:6] != b"070701":
            raise ValueError("ramdisk nao e cpio newc")
        f = lambda k: int(h[6 + 8 * k:14 + 8 * k], 16)
        fsz, nsz = f(6), f(11)
        name = data[i + 110:i + 110 + nsz - 1].decode()
        s = (i + 110 + nsz + 3) & ~3
        ents.append([name, bytearray(h), data[i + 110:s], data[s:s + fsz]])
        i = (s + fsz + 3) & ~3
        if name == "TRAILER!!!":
            break
    return ents, data[i:]


def cpio_pack(ents, tail=b""):
    out = bytearray()
    for name, h, nm, body in ents:
        h = bytearray(h)
        h[6 + 8 * 6:14 + 8 * 6] = b"%08X" % len(body)
        out += h + nm + body + b"\0" * ((-len(body)) % 4)
    return bytes(out) + tail


# ----------------------------------------------------------------- boot image
def parse_boot(img):
    if img[:8] != b"ANDROID!":
        raise ValueError("nao e uma boot image Android")
    f = struct.unpack("<8s10I", img[:48])
    ks, rs, ss, ps, hv = f[1], f[3], f[5], f[8], f[9]
    if hv > 2:
        raise ValueError("header_version %d nao suportado" % hv)
    rp = lambda n: ((n + ps - 1) // ps) * ps
    o = ps
    kernel = img[o:o + ks]; o += rp(ks)
    ramdisk = img[o:o + rs]; o += rp(rs)
    second = img[o:o + ss]; o += rp(ss)
    dtbo = b""
    dtb = b""
    if hv >= 1:
        dsz, doff, _ = struct.unpack("<IQI", img[1632:1648])
        dtbo = img[doff:doff + dsz]
        o = doff + rp(dsz)
    if hv >= 2:
        dtbsz = struct.unpack("<I", img[1648:1652])[0]
        dtb = img[o:o + dtbsz]
    return dict(hv=hv, ps=ps, header=bytearray(img[:ps]), kernel=kernel, ramdisk=ramdisk, second=second, dtbo=dtbo, dtb=dtb)


def decompress_ramdisk(raw):
    if raw[:2] == b"\x1f\x8b":
        return gzip.decompress(raw), "gzip"
    if raw[:1] == b"\x5d":
        return lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(raw), "lzma"
    raise ValueError("compressao do ramdisk nao suportada (esperado gzip ou lzma)")


def compress_ramdisk(data, kind):
    if kind == "gzip":
        return gzip.compress(data, 9, mtime=0)
    return lzma.compress(data, format=lzma.FORMAT_ALONE,
                         filters=[{"id": lzma.FILTER_LZMA1, "preset": 9, "dict_size": 1 << 23}])


def build_boot(p, ramdisk):
    ps, hv = p["ps"], p["hv"]
    rp = lambda n: ((n + ps - 1) // ps) * ps
    h = bytearray(p["header"])
    h[16:20] = struct.pack("<I", len(ramdisk))
    pos = ps + rp(len(p["kernel"])) + rp(len(ramdisk)) + rp(len(p["second"]))
    if hv >= 1:
        h[1636:1644] = struct.pack("<Q", pos)
    sh = hashlib.sha1()
    sh.update(p["kernel"]); sh.update(struct.pack("<I", len(p["kernel"])))
    sh.update(ramdisk); sh.update(struct.pack("<I", len(ramdisk)))
    sh.update(p["second"]); sh.update(struct.pack("<I", len(p["second"])))
    if hv >= 1:
        sh.update(p["dtbo"]); sh.update(struct.pack("<I", len(p["dtbo"])))
    if hv >= 2:
        sh.update(p["dtb"]); sh.update(struct.pack("<I", len(p["dtb"])))
    h[576:608] = sh.digest().ljust(32, b"\0")
    c = bytes(h) + p["kernel"] + b"\0" * (rp(len(p["kernel"])) - len(p["kernel"]))
    c += ramdisk + b"\0" * (rp(len(ramdisk)) - len(ramdisk))
    c += p["second"] + b"\0" * (rp(len(p["second"])) - len(p["second"]))
    if hv >= 1:
        c += p["dtbo"] + b"\0" * (rp(len(p["dtbo"])) - len(p["dtbo"]))
    if hv >= 2:
        c += p["dtb"]
    return c


# ----------------------------------------------------------------- AVB
def make_avb(content, total, ps=PS_DEFAULT):
    vb = bytearray(base64.b64decode("".join(VBMETA_TEMPLATE_B64)))
    assert vb[:4] == b"AVB0"
    auth_sz, aux_sz = struct.unpack(">QQ", vb[12:28])
    assert auth_sz == 0
    desc_off, desc_sz = struct.unpack(">QQ", vb[100:116])
    d = 256 + auth_sz + desc_off
    tag, _ = struct.unpack(">QQ", vb[d:d + 16])
    assert tag == 2
    b0 = d + 16
    nl, sl, dl = struct.unpack(">III", vb[b0 + 40:b0 + 52])
    salt = bytes(vb[b0 + 116 + nl:b0 + 116 + nl + sl])
    size = ((len(content) + ps - 1) // ps) * ps
    data = content + b"\0" * (size - len(content))
    vb[b0:b0 + 8] = struct.pack(">Q", size)
    vb[b0 + 116 + nl + sl:b0 + 116 + nl + sl + dl] = hashlib.sha256(salt + data).digest()
    out = bytearray(data) + vb
    if len(out) > total - 64:
        raise ValueError("imagem grande demais para a particao (%d > %d)" % (len(out), total - 64))
    out += b"\0" * (total - 64 - len(out))
    foot = bytearray(64)
    foot[:4] = b"AVBf"
    foot[4:36] = struct.pack(">IIQQQ", AVB_MAJOR, AVB_MINOR, size, size, len(vb))
    return bytes(out + foot)


def avb_check(img):
    """True se o rodape AVB da imagem aponta para um vbmeta cujo hash bate com o conteudo."""
    f = img[-64:]
    if f[:4] != b"AVBf":
        return None
    _, _, osz, voff, vsz = struct.unpack(">IIQQQ", f[4:36])
    vb = img[voff:voff + vsz]
    if vb[:4] != b"AVB0":
        return False
    auth_sz, aux_sz = struct.unpack(">QQ", vb[12:28])
    desc_off, desc_sz = struct.unpack(">QQ", vb[100:116])
    aux = vb[256 + auth_sz:256 + auth_sz + aux_sz]
    descs = aux[desc_off:desc_off + desc_sz]
    p = 0
    while p < len(descs):
        tag, nb = struct.unpack(">QQ", descs[p:p + 16])
        body = descs[p + 16:p + 16 + nb]
        if tag == 2:
            isz, = struct.unpack(">Q", body[:8])
            nl, sl, dl = struct.unpack(">III", body[40:52])
            salt = body[116 + nl:116 + nl + sl]
            dig = body[116 + nl + sl:116 + nl + sl + dl]
            return hashlib.sha256(salt + img[:isz]).digest() == dig
        p += 16 + ((nb + 7) // 8) * 8
    return False


# ----------------------------------------------------------------- edicoes visuais
def sub_once(text, old, new, what):
    if text.count(old) != 1:
        warn("%s: padrao esperado nao encontrado (%d ocorrencias)" % (what, text.count(old)))
        return text, False
    return text.replace(old, new, 1), True


def apply_edits(ents, args, png):
    by = {e[0]: e for e in ents}
    done = []

    # --- avatar (novo arquivo png + recurso)
    avatar_ok = False
    tmpl = next((e for e in ents if e[0].startswith("twres/images/Default/About/") and e[0].endswith(".png")), None)
    imgs = by.get("twres/resources/images.xml")
    if tmpl is not None and imgs is not None and png:
        t = imgs[3].decode("utf-8")
        if 'name="author_rc20"' in t:
            avatar_ok = True
        else:
            m = re.search(r'([ \t]*)<image name="maintainer_img"[^>]*/>\n', t)
            if m:
                t = t.replace(m.group(0), m.group(0) + m.group(1) +
                              '<image name="author_rc20" filename="Default/About/author_rc20" retainaspect="1"/>\n', 1)
                imgs[3] = t.encode("utf-8")
                max_ino = max(int(e[1][6:14], 16) for e in ents)
                nn = b"twres/images/Default/About/author_rc20.png\0"
                h = bytearray(tmpl[1])
                h[6:14] = b"%08X" % (max_ino + 1)
                h[6 + 8 * 4:14 + 8 * 4] = b"%08X" % 1
                h[6 + 8 * 11:14 + 8 * 11] = b"%08X" % len(nn)
                new = ["twres/images/Default/About/author_rc20.png", h, nn + b"\0" * ((-(110 + len(nn))) % 4), png]
                ents.insert(len(ents) - 1, new)  # antes do TRAILER
                avatar_ok = True
                done.append("avatar")
            else:
                warn("images.xml: recurso maintainer_img nao encontrado; avatar nao adicionado")
    else:
        warn("avatar: faltam twres/images/Default/About/*.png, images.xml ou o arquivo png")

    # --- About: cartao do maintainer
    st = by.get("twres/pages/settings.xml")
    if st is not None:
        t = st[3].decode("utf-8")
        if avatar_ok:
            t, ok = sub_once(t, '<image resource="maintainer_img"/>', '<image resource="author_rc20"/>', "About/avatar")
            if ok: done.append("about-avatar")
        t, ok = sub_once(t, "<text>%of_maintainer%</text>", "<text>%s</text>" % args.name, "About/nome")
        if ok: done.append("about-nome")
        if args.about_version:
            t, ok = sub_once(t, "<text>{@version}: %fox_actual_build%</text>",
                             "<text>{@version}: %s</text>" % args.about_version, "About/versao")
            if ok: done.append("about-versao")
        st[3] = t.encode("utf-8")
    else:
        warn("twres/pages/settings.xml nao encontrado")

    # --- Creditos: Change Log
    cl = by.get("twres/changelog.txt")
    if cl is not None:
        t = cl[3].decode("utf-8")
        head = "== %s ==" % args.changelog_version
        if head in t:
            say("changelog: entrada %s ja existe" % args.changelog_version)
        else:
            m = re.search(r"^== [^=\n]+ ==$", t, re.M)
            if m:
                block = "%s\n- %s\n\n" % (head, args.changelog_text)
                cl[3] = (t[:m.start()] + block + t[m.start():]).encode("utf-8")
                done.append("changelog")
            else:
                warn("changelog: nenhum titulo '== ... ==' encontrado")
    else:
        warn("twres/changelog.txt nao encontrado")

    # --- Log da tela inicial: [Support]
    n_lang = 0
    for e in ents:
        if not (e[0].startswith("twres/languages/") and e[0].endswith(".xml")):
            continue
        if args.languages != "all" and os.path.basename(e[0]) != args.languages + ".xml":
            continue
        t = e[3].decode("utf-8", "replace")
        t2 = re.sub(r'(<string name="fox_support">[^<]*?[:\uff1a]\s*)\{1\}(</string>)', r"\g<1>%s\g<2>" % args.support, t)
        t2 = re.sub(r'(<string name="fox_nosupport">[^<]*?[:\uff1a]\s*)[^<]*(</string>)', r"\g<1>%s\g<2>" % args.support, t2)
        if t2 != t:
            e[3] = t2.encode("utf-8")
            n_lang += 1
    if n_lang:
        done.append("support(%d idiomas)" % n_lang)
    else:
        warn("nenhuma string fox_support/fox_nosupport alterada")
    return done


# ----------------------------------------------------------------- principal
def patch_image(path_in, path_out, args, png):
    img = open(path_in, "rb").read()
    total = len(img)
    had_avb = img[-64:-60] == b"AVBf"
    say("imagem: %s (%d bytes) | rodape AVB: %s" % (path_in, total,
        {True: "valido", False: "INVALIDO", None: "ausente"}[avb_check(img)]))
    p = parse_boot(img)
    rd, kind = decompress_ramdisk(p["ramdisk"])
    say("boot header v%d | ramdisk %s | %d bytes de cpio" % (p["hv"], kind, len(rd)))
    ents, tail = cpio_parse(rd)
    done = apply_edits(ents, args, png)
    new_rd = compress_ramdisk(cpio_pack(ents, tail), kind)
    content = build_boot(p, new_rd)
    out = make_avb(content, total) if had_avb else content + b"\0" * (total - len(content))
    if len(out) != total:
        raise ValueError("tamanho final difere do original")
    # conferencia relendo o resultado
    q = parse_boot(out)
    rd2, _ = decompress_ramdisk(q["ramdisk"])
    assert rd2 == cpio_pack(ents, tail)
    assert q["kernel"] == p["kernel"] and q["dtbo"] == p["dtbo"] and q["dtb"] == p["dtb"]
    if had_avb and avb_check(out) is not True:
        raise ValueError("rodape AVB gerado nao confere")
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path_out)) or ".")
    with os.fdopen(fd, "wb") as fh:
        fh.write(out)
    os.replace(tmp, path_out)
    say("OK: aplicado: " + ", ".join(done) if done else "nada aplicado")
    say("kernel, dtbo, dtb, fstab e scripts de criptografia: intocados | AVB: %s" % ("valido (sem assinatura)" if had_avb else "n/a"))
    return out


def patch_zip(path_zip, new_img):
    """Troca recovery.img dentro do zip do OrangeFox e remove as assinaturas antigas (ficariam invalidas)."""
    tmp = path_zip + ".tmp"
    with zipfile.ZipFile(path_zip) as zin, zipfile.ZipFile(tmp, "w") as zout:
        names = zin.namelist()
        if "recovery.img" not in names:
            raise ValueError("zip sem recovery.img")
        for zi in zin.infolist():
            if zi.filename in ("META-INF/MANIFEST.MF", "META-INF/CERT.SF", "META-INF/CERT.RSA"):
                continue
            data = new_img if zi.filename == "recovery.img" else zin.read(zi.filename)
            zout.writestr(zi, data, compress_type=zi.compress_type)
    os.replace(tmp, path_zip)
    say("OK: zip atualizado: %s (assinatura antiga removida)" % path_zip)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="Personalizacao visual RC20 para imagens do OrangeFox")
    ap.add_argument("--image", required=True, help="OrangeFox*.img (sobrescrito no lugar)")
    ap.add_argument("--zip", help="OrangeFox*.zip da mesma build (recovery.img interno e trocado)")
    ap.add_argument("--png", default=os.path.join(here, "author_rc20.png"), help="avatar 192x192 (png)")
    ap.add_argument("--name", default="RC20", help="nome no cartao do About")
    ap.add_argument("--support", default="RC20", help="texto da linha [Support]")
    ap.add_argument("--changelog-version", default="12.0_1")
    ap.add_argument("--changelog-text", default="Fix decryption of internal memory starting from Android 17")
    ap.add_argument("--about-version", default="", help="se informado, escreve esta versao fixa no About (ex.: R12.1)")
    ap.add_argument("--languages", default="all", help="'all' ou o nome do arquivo de idioma sem .xml (ex.: en)")
    args = ap.parse_args()
    png = open(args.png, "rb").read() if os.path.exists(args.png) else b""
    if not png:
        warn("avatar %s nao encontrado" % args.png)
    out = patch_image(args.image, args.image, args, png)
    if args.zip:
        patch_zip(args.zip, out)
    if WARNINGS:
        say("RESUMO: %d aviso(s) - revise acima" % len(WARNINGS))


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:  # a imagem original so e substituida no final com sucesso
        print("ERRO: %s" % ex, file=sys.stderr)
        sys.exit(1)
