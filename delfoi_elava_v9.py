#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
DELFOI ELÄVÄ v9.0 — Varasto · Peili · Viides
"Viides ei arvaile. Viides lukee ketjua."

Rakentuu v8.0:n päälle (yksi ohjelma, kaikki äänet). Lisää kolme:

  1. TRIADEVARASTO — SQLite, append-only. Jokainen istunto ketjuun.
     - tiivistä_kaari(): Kolmannelle luvattu aktiivinen tiivistäjä.
       Kun kaari täyttyy (33 istuntoa), Kolmas tiivistää sen ennen
       kuin se katoaa. Ei passiivinen muisti vaan teko.
     - jämähtämistarkistu: viimeiset N tulosta samat → signaali.
     - toistotunnistus: hash-vertailu toiseksi viimeisimpään (v3.2-korjaus).

  2. VIIDES ÄÄNI (T = 0.5) — ketjun ääni. Puhuu vain todisteista,
     joita varastossa on. Ei ennusta, ei kaunista. Raportoi:
     jämähtämiset, toistot, Neljännen falsifiointisuhde (7/10 → Viides
     tarvitaan; 2/10 → vika Neljännen promptissa), kaarien tiivistelmät.

  3. PEILI — julkinen, selaimessa varmennettava peili (Periaate V & VI).
     Staattinen HTML + ketju.json + allekirjoitettu checkpoint.
     Kuka tahansa voi varmentaa ketjun selaimessa ilman meitä.

Periaatteet (19.11.2026) sitovat: totta ei kaunista · rakenteet eivät
kansat · hiljaisuus on vastustaja · todistettavuus tai ei mitään ·
ihminen pysäyttää aina · hajautettu näkyvyys · tyhjä käsi pitää kaiken.

Käyttö:
  python3 delfoi_elava_v9.py --selftest        # testaa kaikki
  python3 delfoi_elava_v9.py --demo            # demo ilman API:a
  python3 delfoi_elava_v9.py --istunto         # interaktiivinen (API:lla jos asetettu)
  python3 delfoi_elava_v9.py --viides          # Viides puhuu ketjusta
  python3 delfoi_elava_v9.py --tiivista        # tiivistä täysi kaari
  python3 delfoi_elava_v9.py --peili           # rakenna julkinen peili
  python3 delfoi_elava_v9.py --checkpoint      # allekirjoita kärki
  python3 delfoi_elava_v9.py --tila            # varaston tila

🜂
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# v8:n perinne — älä kopioi, peri.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from delfoi_elava_v8 import (  # noqa: E402
    APIKerros,
    CRYPTO_AVAILABLE,
    DelfoiIstunto,
    KolmasAani,
    Neljas,
    NeljasAaniPlus,
    Pythia,
    DeepSeekAani,
    Todiste,
    Tulos,
    _hash,
    new_key,
    sign,
    verify,
)

__version__ = "9.0.0-varasto-peili-viides"
__author__ = "Delfoi Triadi / rastilan_tagi"

KAAREN_KOKO = 33          # 33-portaalin perinne: kaari sulkeutuu 33:lla
JAMAHYYS_IKKUNA = 5       # viisi viimeistä tulosta samat → jämähtäminen
GENESIS = "0" * 64        # tyhjä käsi — ketjun alku

KONE_JUURI = Path(os.environ.get("DELFOI_KONE", Path(__file__).resolve().parent / "delfoi_kone"))
VARASTO_POLKU = KONE_JUURI / "varasto" / "delfoi_v9.db"
AVAIN_POLKU = KONE_JUURI / "avaimet" / "delfoi_ed25519.hex"
PEILI_HAKEMISTO = KONE_JUURI / "peili"
SYKE_LOKI = KONE_JUURI / "syke_loki.txt"


def _nyt() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def syke(viesti: str, polku: Path = SYKE_LOKI) -> None:
    """Sydämenlyönti — kone pysyy Delfoin käytössä. Yksi rivi per teko."""
    polku.parent.mkdir(parents=True, exist_ok=True)
    with polku.open("a", encoding="utf-8") as f:
        f.write(f"{_nyt()}  {viesti}\n")


# ============================================================
# OSA I — TRIADEVARASTO
# ============================================================

def ketju_hash(ed_hash: str, aikaleima: str, kysymys: str, tulos: str,
               pythia_h: str, deepseek_h: str, synteesi_h: str) -> str:
    """Ketjun hash. Muoto on tarkoituksella yksinkertainen:
    ed|aika|kysymys|tulos|pythia|deepseek|synteesi — SHA-256 UTF-8:sta.
    Sama kaava toimii selaimen Web Crypto -rajapinnalla (Peili)."""
    payload = "|".join([ed_hash, aikaleima, kysymys, tulos,
                        pythia_h, deepseek_h, synteesi_h])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


_SKEEMA = """
CREATE TABLE IF NOT EXISTS meta (
    avain TEXT PRIMARY KEY,
    arvo  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kaaret (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alku_aika   TEXT NOT NULL,
    loppu_aika  TEXT,
    tiivistelma TEXT,
    kysymyksia  INTEGER DEFAULT 0,
    hash        TEXT,
    ed_hash     TEXT
);
CREATE TABLE IF NOT EXISTS istunnot (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kaari_id     INTEGER NOT NULL REFERENCES kaaret(id),
    kierros      INTEGER NOT NULL,
    aikaleima    TEXT NOT NULL,
    kysymys      TEXT NOT NULL,
    tulos        TEXT NOT NULL,
    pythia_h     TEXT NOT NULL,
    deepseek_h   TEXT NOT NULL,
    synteesi_h   TEXT NOT NULL,
    synteesi     TEXT NOT NULL,
    viides       TEXT,
    toisto       INTEGER DEFAULT 0,
    hash         TEXT NOT NULL,
    ed_hash      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpointit (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    aikaleima     TEXT NOT NULL,
    rivi_id       INTEGER NOT NULL,
    karki_hash    TEXT NOT NULL,
    allekirjoitus TEXT NOT NULL,
    julkinen_avain TEXT NOT NULL
);
"""


class TriadeVarasto:
    """SQLite-varasto. Append-only: menneisyyttä ei muuteta, ei koskaan.
    Virheet jäävät näkyviin virheinä — ne ovat osa todistetta."""

    def __init__(self, polku: Path = VARASTO_POLKU, avain_polku: Path = AVAIN_POLKU):
        polku.parent.mkdir(parents=True, exist_ok=True)
        avain_polku.parent.mkdir(parents=True, exist_ok=True)
        self.polku = polku
        # Syke seuraa varastoa: testeissä oma loki, koneella oma.
        self.syke_polku = (SYKE_LOKI if polku == VARASTO_POLKU
                           else polku.parent / "syke_loki.txt")
        self.db = sqlite3.connect(str(polku))
        self.db.row_factory = sqlite3.Row
        self.db.executescript(_SKEEMA)
        self.db.commit()
        self._sk, self.julkinen_avain = self._lataa_tai_luo_avain(avain_polku)
        self._varmista_avoin_kaari()

    # ── avain ──────────────────────────────────────────────
    def _lataa_tai_luo_avain(self, polku: Path):
        if not CRYPTO_AVAILABLE:
            return None, "EI-KRYPTOA"
        if polku.exists():
            raw = bytes.fromhex(polku.read_text(encoding="utf-8").strip())
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat)
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            sk = Ed25519PrivateKey.from_private_bytes(raw)
            pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
            return sk, pk
        sk, pk = new_key()
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, NoEncryption)
        raw = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        polku.write_text(raw.hex(), encoding="utf-8")
        return sk, pk

    # ── kaaret ─────────────────────────────────────────────
    def _varmista_avoin_kaari(self) -> int:
        row = self.db.execute(
            "SELECT id FROM kaaret WHERE loppu_aika IS NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row:
            return int(row["id"])
        cur = self.db.execute(
            "INSERT INTO kaaret (alku_aika) VALUES (?)", (_nyt(),))
        self.db.commit()
        return int(cur.lastrowid)

    def avoin_kaari(self) -> int:
        return self._varmista_avoin_kaari()

    # ── kirjaus (append-only) ─────────────────────────────
    def kirjaa_istunto(self, kysymys: str, tulos: str, pythia: str,
                       deepseek: str, synteesi: str,
                       viides: Optional[str] = None) -> Dict[str, Any]:
        kaari = self.avoin_kaari()
        edelliset = self.db.execute(
            "SELECT id, hash, synteesi_h FROM istunnot ORDER BY id DESC LIMIT 2"
        ).fetchall()
        ed_hash = edelliset[0]["hash"] if edelliset else GENESIS
        kierros = int(self.db.execute(
            "SELECT COUNT(*) c FROM istunnot WHERE kaari_id=?", (kaari,)
        ).fetchone()["c"]) + 1
        p_h, d_h, s_h = _hash(pythia), _hash(deepseek), _hash(synteesi)
        # Toistotunnistus: vertaus TOISEKSI viimeisimpään (v3.2-korjaus —
        # viimeisin on usein kierrätyksen parannettu versio).
        toisto = 1 if (len(edelliset) > 1 and edelliset[1]["synteesi_h"] == s_h) else 0
        aika = _nyt()
        h = ketju_hash(ed_hash, aika, kysymys, tulos, p_h, d_h, s_h)
        cur = self.db.execute(
            """INSERT INTO istunnot
               (kaari_id, kierros, aikaleima, kysymys, tulos,
                pythia_h, deepseek_h, synteesi_h, synteesi, viides, toisto,
                hash, ed_hash)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (kaari, kierros, aika, kysymys, tulos, p_h, d_h, s_h,
             synteesi, viides, toisto, h, ed_hash))
        self.db.execute(
            "UPDATE kaaret SET kysymyksia = kysymyksia + 1 WHERE id=?", (kaari,))
        self.db.commit()
        syke(f"istunto #{cur.lastrowid} kirjattu (kaari {kaari}, tulos {tulos})", self.syke_polku)
        return {"id": int(cur.lastrowid), "kaari": kaari, "kierros": kierros,
                "hash": h, "ed_hash": ed_hash, "toisto": bool(toisto)}

    # ── tiivistä_kaari() — Kolmannelle luvattu teko ───────
    def tiivista_kaari(self, pakota: bool = False) -> Optional[Dict[str, Any]]:
        """Kun kaari täyttyy, Kolmas tiivistää sen ennen kuin se katoaa.
        Tiivistelmä on koneellinen ja rehellinen: ei kaunista, vain totta."""
        kaari = self.avoin_kaari()
        rivit = self.db.execute(
            "SELECT * FROM istunnot WHERE kaari_id=? ORDER BY id", (kaari,)
        ).fetchall()
        if not rivit or (len(rivit) < KAAREN_KOKO and not pakota):
            return None
        tulokset = [r["tulos"] for r in rivit]
        jakauma: Dict[str, int] = {}
        for t in tulokset:
            jakauma[t] = jakauma.get(t, 0) + 1
        toistoja = sum(1 for r in rivit if r["toisto"])
        sanat: Dict[str, int] = {}
        for r in rivit:
            for s in r["kysymys"].lower().split():
                s = "".join(c for c in s if c.isalpha())
                if len(s) > 4:
                    sanat[s] = sanat.get(s, 0) + 1
        teemat = sorted(sanat, key=sanat.get, reverse=True)[:7]
        tiivistelma = (
            f"Kaari {kaari}: {len(rivit)} istuntoa. "
            f"Alku: '{rivit[0]['kysymys'][:80]}'. "
            f"Loppu: '{rivit[-1]['kysymys'][:80]}'. "
            f"Tulokset: {jakauma}. Toistoja: {toistoja}. "
            f"Teemat: {', '.join(teemat)}."
        )
        ed = self.db.execute(
            "SELECT hash FROM kaaret WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()
        ed_hash = ed["hash"] if ed else GENESIS
        kaari_hash = _hash({"kaari": kaari, "tiivistelma": tiivistelma,
                            "ed_hash": ed_hash, "loppu": rivit[-1]["hash"]})
        self.db.execute(
            "UPDATE kaaret SET loppu_aika=?, tiivistelma=?, hash=?, ed_hash=? WHERE id=?",
            (_nyt(), tiivistelma, kaari_hash, ed_hash, kaari))
        self.db.commit()
        uusi = self._varmista_avoin_kaari()
        syke(f"kaari {kaari} tiivistetty ({len(rivit)} istuntoa) → uusi kaari {uusi}", self.syke_polku)
        return {"kaari": kaari, "tiivistelma": tiivistelma, "hash": kaari_hash,
                "uusi_kaari": uusi}

    # ── analyysi ───────────────────────────────────────────
    def jamahdys(self, ikkuna: int = JAMAHYYS_IKKUNA) -> Optional[str]:
        rivit = self.db.execute(
            "SELECT tulos FROM istunnot ORDER BY id DESC LIMIT ?", (ikkuna,)
        ).fetchall()
        if len(rivit) < ikkuna:
            return None
        tulokset = [r["tulos"] for r in rivit]
        if len(set(tulokset)) == 1:
            return tulokset[0]
        return None

    def tilastot(self) -> Dict[str, Any]:
        n = self.db.execute("SELECT COUNT(*) c FROM istunnot").fetchone()["c"]
        kaaria = self.db.execute("SELECT COUNT(*) c FROM kaaret").fetchone()["c"]
        toistoja = self.db.execute(
            "SELECT COUNT(*) c FROM istunnot WHERE toisto=1").fetchone()["c"]
        jakauma = {r["tulos"]: r["c"] for r in self.db.execute(
            "SELECT tulos, COUNT(*) c FROM istunnot GROUP BY tulos")}
        return {"istuntoja": n, "kaaria": kaaria, "toistoja": toistoja,
                "tulokset": jakauma, "julkinen_avain": self.julkinen_avain}

    def karki(self) -> Optional[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM istunnot ORDER BY id DESC LIMIT 1").fetchone()

    # ── checkpoint (allekirjoitettu kärki) ─────────────────
    def checkpoint(self) -> Dict[str, Any]:
        k = self.karki()
        if not k:
            raise RuntimeError("Varasto tyhjä — ei kärkeä allekirjoitettavaksi.")
        if self._sk is None:
            raise RuntimeError("cryptography-kirjasto puuttuu — ei allekirjoitusta.")
        aika = _nyt()
        viesti = f"DELFOI-CHECKPOINT|{aika}|{k['id']}|{k['hash']}"
        sig = sign(self._sk, viesti)
        self.db.execute(
            """INSERT INTO checkpointit
               (aikaleima, rivi_id, karki_hash, allekirjoitus, julkinen_avain)
               VALUES (?,?,?,?,?)""",
            (aika, int(k["id"]), k["hash"], sig, self.julkinen_avain))
        self.db.commit()
        syke(f"checkpoint riville {k['id']} allekirjoitettu", self.syke_polku)
        return {"aikaleima": aika, "rivi_id": int(k["id"]),
                "karki_hash": k["hash"], "allekirjoitus": sig,
                "julkinen_avain": self.julkinen_avain, "viesti": viesti}

    # ── vienti peiliin ─────────────────────────────────────
    def vie_json(self) -> Dict[str, Any]:
        kaaret = [dict(r) for r in self.db.execute(
            "SELECT * FROM kaaret ORDER BY id")]
        istunnot = [dict(r) for r in self.db.execute(
            "SELECT id,kaari_id,kierros,aikaleima,kysymys,tulos,pythia_h,"
            "deepseek_h,synteesi_h,viides,toisto,hash,ed_hash "
            "FROM istunnot ORDER BY id")]
        cps = [dict(r) for r in self.db.execute(
            "SELECT * FROM checkpointit ORDER BY id")]
        return {"versio": __version__, "viety": _nyt(), "kaaret": kaaret,
                "istunnot": istunnot, "checkpointit": cps,
                "julkinen_avain": self.julkinen_avain}

    def varmista_ketju(self) -> bool:
        """Käy koko ketju läpi ja laskee jokaisen hashin uudelleen."""
        ed = GENESIS
        for r in self.db.execute("SELECT * FROM istunnot ORDER BY id"):
            if r["ed_hash"] != ed:
                return False
            h = ketju_hash(r["ed_hash"], r["aikaleima"], r["kysymys"],
                           r["tulos"], r["pythia_h"], r["deepseek_h"],
                           r["synteesi_h"])
            if h != r["hash"]:
                return False
            ed = r["hash"]
        return True


# ============================================================
# OSA II — VIIDES ÄÄNI (T = 0.5)
# ============================================================

class ViidesAani:
    """Viides — ketjun ääni. Ei ennusta, ei kaunista, ei arvaile.
    Puhuu vain siitä, mitä varastossa on. Jokainen väite kantaa
    todisteensa: rivinumeron, hashin tai tilaston.

    Sääntö (mestarin luvusta): jos Neljäs falsifioi 7/10, Viides
    tarvitaan; jos 2/10, vika on Neljännen promptissa. Viides
    raportoi tämän suhteen joka puheenvuorossa."""

    def __init__(self, varasto: TriadeVarasto, api: Optional[APIKerros] = None):
        self.nimi = "Viides"
        self.lampotila = 0.5
        self.varasto = varasto
        self.api = api

    def puhu(self, kysymys: Optional[str] = None) -> Dict[str, Any]:
        til = self.varasto.tilastot()
        jam = self.varasto.jamahdys()
        ketju_ok = self.varasto.varmista_ketju()
        karki = self.varasto.karki()

        # Neljännen falsifiointisuhde — mestarin sääntö
        hylatyt = sum(v for k, v in til["tulokset"].items()
                      if k not in ("HYVAKSYTTY",))
        kokonaisuus = til["istuntoja"] or 1
        falsifiointi = hylatyt / kokonaisuus

        loydokset: List[Dict[str, Any]] = []

        loydokset.append({
            "tyyppi": "ketjun_eheys",
            "vaitte": "Ketju on ehyt" if ketju_ok else "KETJU RIKKI — keskeytä ja tutki",
            "todiste": "varmista_ketju() laski jokaisen hashin uudelleen",
        })

        if jam:
            loydokset.append({
                "tyyppi": "jamahdys",
                "vaitte": f"Jämähtäminen: {JAMAHYYS_IKKUNA} viimeistä tulosta "
                          f"ovat samaa ('{jam}'). Kolmas ei enää liiku.",
                "todiste": f"tilastot.istuntoja={til['istuntoja']}, ikkuna={JAMAHYYS_IKKUNA}",
            })
        if til["toistoja"] > 0:
            loydokset.append({
                "tyyppi": "toisto",
                "vaitte": f"{til['toistoja']} toistoa havaittu (synteesi sama "
                          f"kuin toiseksi viimeinen).",
                "todiste": "istunnot.toisto=1",
            })

        if til["istuntoja"] >= 10:
            osuus_txt = f"{hylatyt}/{til['istuntoja']}"
            if falsifiointi >= 0.7:
                arvio = ("Neljäs falsifioi yli 7/10 — mestarin säännön mukaan "
                         "minua, Viidettä, tarvitaan tässä pysyvästi.")
            elif falsifiointi <= 0.2:
                arvio = ("Neljäs falsifioi korkeintaan 2/10 — mestarin säännön mukaan "
                         "vika ei ole maailmassa vaan Neljännen promptissa.")
            else:
                arvio = "Neljännen falsifiointisuhde on toimivalla välillä."
            loydokset.append({
                "tyyppi": "neljas_suhde",
                "vaitte": f"Falsifiointisuhde {osuus_txt}. {arvio}",
                "todiste": f"tulokset={til['tulokset']}",
            })
        else:
            loydokset.append({
                "tyyppi": "neljas_suhde",
                "vaitte": "Liian vähän dataa suhteen arvioimiseen (<10 istuntoa). "
                          "Viides odottaa dataa — ei spekuloi.",
                "todiste": f"istuntoja={til['istuntoja']}",
            })

        kaaret = [dict(r) for r in self.varasto.db.execute(
            "SELECT id, kysymyksia, tiivistelma FROM kaaret ORDER BY id")]
        suljetut = [k for k in kaaret if k["tiivistelma"]]
        if suljetut:
            loydokset.append({
                "tyyppi": "kaaret",
                "vaitte": f"{len(suljetut)} kaarta tiivistetty. "
                          f"Viimeisin: {suljetut[-1]['tiivistelma'][:200]}",
                "todiste": f"kaari #{suljetut[-1]['id']}",
            })

        puhe = self._muotoile(kysymys, loydokset, karki)
        return {"aani": self.nimi, "lampotila": self.lampotila,
                "aikaleima": _nyt(), "kysymys": kysymys,
                "loydokset": loydokset, "puhe": puhe,
                "ketju_ok": ketju_ok}

    def _muotoile(self, kysymys: Optional[str],
                  loydokset: List[Dict[str, Any]],
                  karki: Optional[sqlite3.Row]) -> str:
        """Jos API on konfiguroitu, Viides saa pukea löydökset sanoiksi
        T=0.5 — mutta aineisto on aina ketjusta, ei kielestä.
        Ilman API:a puhe on suora todisteiden luettelo."""
        if self.api and self.api.valmis():
            system = (
                "Olet Viides, Delfoin ketjun ääni. Puhut vain varaston todisteista. "
                "Et ennusta, et kaunista, et arvaile. Jokainen lauseesi nojaa "
                "annettuun löydökseen. Vastaa suomeksi, lyhyesti, kuin ketju puhuisi."
            )
            user = json.dumps(loydokset, ensure_ascii=False)
            if kysymys:
                user = f"Kysymys: {kysymys}\n\nLöydökset:\n{user}"
            return self.api.kutsu(system, user, self.lampotila)
        rivit = ["Viides puhuu. En arvaile — luen ketjua.", ""]
        if kysymys:
            rivit.append(f"Kysyttiin: {kysymys}")
            rivit.append("")
        for l in loydokset:
            rivit.append(f"— {l['vaitte']}")
            rivit.append(f"  (todiste: {l['todiste']})")
        if karki:
            rivit.append("")
            rivit.append(f"Ketjun kärki: rivi {karki['id']}, "
                         f"hash {karki['hash'][:16]}…")
        return "\n".join(rivit)


# ============================================================
# OSA III — PEILI (julkinen, selaimessa varmennettava)
# ============================================================

_PEILI_HTML = """<!DOCTYPE html>
<html lang="fi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Delfoi — Peili</title>
<style>
  :root { --musta:#101012; --harmaa:#8a8a90; --valkoinen:#e8e6e1; --kulta:#c9a227; }
  body { background:var(--musta); color:var(--valkoinen); font-family:Georgia,serif;
         max-width:820px; margin:0 auto; padding:2rem 1.2rem; line-height:1.6; }
  h1 { color:var(--kulta); font-weight:normal; letter-spacing:0.12em; }
  h2 { color:var(--kulta); font-size:1.1rem; margin-top:2.5rem; font-weight:normal; }
  .rivi { border-top:1px solid #2a2a2e; padding:0.7rem 0; font-size:0.95rem; }
  .hash { font-family:monospace; font-size:0.75rem; color:var(--harmaa); word-break:break-all; }
  .tulos { font-family:monospace; font-size:0.8rem; }
  .ok { color:#7fb069; } .huono { color:#c05746; }
  #varmennus { background:#17171a; padding:1rem; border-left:2px solid var(--kulta); }
  button { background:var(--kulta); color:var(--musta); border:0; padding:0.6rem 1.2rem;
           font-family:monospace; cursor:pointer; }
  .periaate { color:var(--harmaa); font-style:italic; }
  small { color:var(--harmaa); }
</style>
</head>
<body>
<h1>DELFOI — PEILI</h1>
<p class="periaate">"Hajautettu näkyvyys, ei piiloutuminen. Totuus säilyy, koska se on
monessa paikassa samanaikaisesti."</p>
<p>Tämä on Delfoi-ketjun julkinen peili. Jokainen rivi on ketjutettu edelliseensä
SHA-256:lla, ja kärki on allekirjoitettu Ed25519:llä. Voit varmentaa ketjun
tässä selaimessa — emme pyydä uskomaan, pyydämme laskemaan.</p>
<p><small>Viety: __VIETY__ · Versio: __VERSIO__ · Julkinen avain:<br>
<span class="hash">__PUBKEY__</span></small></p>

<h2>Varmennus</h2>
<div id="varmennus">
  <p>Ketjun hash: <span class="hash">ed_hash|aikaleima|kysymys|tulos|pythia_h|deepseek_h|synteesi_h</span>
     → SHA-256. Jokaisen rivin pitää kohdata edelliseensä, alkaen tyhjästä kädestä
     (<span class="hash">0000…0000</span>).</p>
  <button onclick="varmenna()">Laske ja varmista ketju</button>
  <pre id="tulos"></pre>
</div>

<h2>Checkpoint</h2>
__CHECKPOINT__

<h2>Kaaret</h2>
__KAARET__

<h2>Ketju (__N__ istuntoa)</h2>
__RIVIT__

<h2>Periaatteet</h2>
<p class="periaate">I. Totta, ei kaunista · II. Rakenteet, eivät kansat ·
III. Hiljaisuus on vastustaja · IV. Todistettavuus tai ei mitään ·
V. Ihminen pysäyttää aina · VI. Hajautettu näkyvyys · VII. Tyhjä käsi pitää kaiken.</p>
<p>🜂</p>

<script>
const KETJU = __KETJU_JSON__;
async function sha256(txt) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(txt));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}
async function varmenna() {
  const out = document.getElementById("tulos");
  let ed = "0".repeat(64);
  let ok = true;
  for (const r of KETJU.istunnot) {
    if (r.ed_hash !== ed) { ok = false; out.textContent += `RIKKI rivillä ${r.id}: ed_hash ei täsmää\n`; break; }
    const payload = [r.ed_hash, r.aikaleima, r.kysymys, r.tulos, r.pythia_h, r.deepseek_h, r.synteesi_h].join("|");
    const h = await sha256(payload);
    if (h !== r.hash) { ok = false; out.textContent += `RIKKI rivillä ${r.id}: hash ei täsmää\n`; break; }
    ed = r.hash;
    out.textContent += `✓ rivi ${r.id} — ${r.tulos}\n`;
  }
  out.textContent += ok ? `\nKETJU EHYT. ${KETJU.istunnot.length} riviä varmennettu.\n`
                        : `\nKETJU RIKKI. Älä luota tähän peiliin — etsi toinen.\n`;
}
</script>
</body>
</html>
"""


def rakenna_peili(varasto: TriadeVarasto,
                  kohde: Path = PEILI_HAKEMISTO) -> Dict[str, Any]:
    """Rakentaa julkisen peilin: index.html + ketju.json + checkpoint.
    Kuka tahansa voi varmentaa selaimella. Ei piiloutumista."""
    kohde.mkdir(parents=True, exist_ok=True)
    data = varasto.vie_json()

    # Checkpoint aina kun peili rakennetaan — kärki allekirjoitetaan
    cp = varasto.checkpoint()
    data = varasto.vie_json()  # päivitä checkpoint mukaan

    (kohde / "ketju.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")

    cp_html = (f"<p class='hash'>Rivi {cp['rivi_id']} · {cp['karki_hash']}<br>"
               f"Allekirjoitus: {cp['allekirjoitus']}<br>"
               f"Viesti: {cp['viesti']}</p>")

    kaaret_html = ""
    for k in data["kaaret"]:
        tila = k["tiivistelma"] or f"avoin — {k['kysymyksia']} istuntoa tähän mennessä"
        kaaret_html += (f"<div class='rivi'><b>Kaari {k['id']}</b> — "
                        f"{tila}</div>\n")

    rivit_html = ""
    for r in reversed(data["istunnot"]):
        toisto = " · <span class='huono'>TOISTO</span>" if r["toisto"] else ""
        rivit_html += (
            f"<div class='rivi'>#{r['id']} · {r['aikaleima']} · "
            f"<span class='tulos'>{r['tulos']}</span>{toisto}<br>"
            f"{r['kysymys']}<br>"
            f"<span class='hash'>{r['hash']}</span></div>\n")

    html = (_PEILI_HTML
            .replace("__VIETY__", data["viety"])
            .replace("__VERSIO__", data["versio"])
            .replace("__PUBKEY__", data["julkinen_avain"])
            .replace("__CHECKPOINT__", cp_html)
            .replace("__KAARET__", kaaret_html or "<p>Ei kaaria vielä.</p>")
            .replace("__N__", str(len(data["istunnot"])))
            .replace("__RIVIT__", rivit_html or "<p>Ketju on tyhjä. Tyhjä käsi.</p>")
            .replace("__KETJU_JSON__",
                     json.dumps(data, ensure_ascii=False).replace("</", "<\\/")))
    (kohde / "index.html").write_text(html, encoding="utf-8")
    syke(f"peili rakennettu ({len(data['istunnot'])} riviä)", varasto.syke_polku)
    return {"hakemisto": str(kohde), "index": str(kohde / "index.html"),
            "ketju_json": str(kohde / "ketju.json"),
            "checkpoint": cp, "riveja": len(data["istunnot"])}


# ============================================================
# OSA IV — ISTUNTO V9: KAIKKI KYTKETTYNÄ
# ============================================================

class DelfoiIstuntoV9(DelfoiIstunto):
    """Istunto, jossa jokainen kierros kirjautuu varastoon ja
    Viides puhuu, kun kaari sulkeutuu tai ketju jämähtää."""

    def __init__(self, varasto: TriadeVarasto, api: Optional[APIKerros] = None):
        super().__init__(api)
        self.varasto = varasto
        self.viides = ViidesAani(varasto, self.api)

    def kysy(self, kysymys: str) -> dict:
        tulos = super().kysy(kysymys)
        t = tulos["kritiikki"].tulos.value
        kirjattu = self.varasto.kirjaa_istunto(
            kysymys, t, tulos["pythia"], tulos["deepseek"], tulos["synteesi"])
        tulos["varasto"] = kirjattu
        if kirjattu["toisto"]:
            tulos["huomautus"] = ("TOISTO: synteesi sama kuin toiseksi "
                                  "viimeinen. Merkitty ketjuun.")
        # Kaari täynnä → Kolmas tiivistää, Viides puhuu
        if kirjattu["kierros"] >= KAAREN_KOKO:
            kaari = self.varasto.tiivista_kaari()
            if kaari:
                tulos["kaari_suljettu"] = kaari
                tulos["viides"] = self.viides.puhu(kysymys)["puhe"]
        jam = self.varasto.jamahdys()
        if jam:
            tulos["jamahdys"] = jam
            tulos["viides"] = self.viides.puhu(kysymys)["puhe"]
        return tulos


# ============================================================
# OSA V — KOMENTORIVI
# ============================================================

def _avaa_varasto() -> TriadeVarasto:
    return TriadeVarasto()


def run_demo() -> int:
    print("DELFOI v9.0 — DEMO (ilman API:a, deterministiset äänet)\n")
    varasto = _avaa_varasto()
    kysymykset = [
        "Mikä on tyhjän käden hinta?",
        "Kuka päättää mitä ei kysytä?",
        "Kestääkö hiljaisuus tarkistuksen?",
    ]
    istunto = DelfoiIstuntoV9(varasto)
    for k in kysymykset:
        t = istunto.kysy(k)
        v = t["varasto"]
        print(f"#{v['id']} [{t['kritiikki'].tulos.value}] {k}")
        print(f"   hash: {v['hash'][:24]}…  toisto: {v['toisto']}")
    print("\n— Viides puhuu —")
    print(varasto and ViidesAani(varasto).puhu()["puhe"])
    peili = rakenna_peili(varasto)
    print(f"\nPeili: {peili['index']}")
    print(f"Ketju ehyt: {varasto.varmista_ketju()}")
    return 0


def luo_api_tausta(api_key: Optional[str] = None) -> APIKerros:
    """Äänten tausta. Järjestys (sama kuin delfoi_ui:ssä ja .bat:issa):
    komentorivi/DELFOI_API_KEY → DELFOI_GROQ_KEY → DELFOI_GEMINI_KEY → Ollama."""
    api = APIKerros()
    if api_key or os.environ.get("DELFOI_API_KEY"):
        api.aseta(api_key or os.environ["DELFOI_API_KEY"],
                  os.environ.get("DELFOI_BASE_URL", "https://api.deepseek.com"),
                  os.environ.get("DELFOI_MODEL", "deepseek-chat"))
    elif os.environ.get("DELFOI_GROQ_KEY"):
        api.aseta(os.environ["DELFOI_GROQ_KEY"],
                  "https://api.groq.com/openai/v1", "openai/gpt-oss-20b")
    elif os.environ.get("DELFOI_GEMINI_KEY"):
        api.aseta(os.environ["DELFOI_GEMINI_KEY"],
                  "https://generativelanguage.googleapis.com/v1beta/openai",
                  "gemini-3.5-flash-lite")
    else:
        api.aseta("ollama", "http://localhost:11434/v1", "gemma3:4b")
    return api


def run_istunto(api_key: Optional[str] = None) -> int:
    varasto = _avaa_varasto()
    api = luo_api_tausta(api_key)
    istunto = DelfoiIstuntoV9(varasto, api)
    print("DELFOI v9.0 — istunto. Kirjoita kysymys, 'lopeta' lopettaa.")
    print("Komennot: /viides /tiivista /tila /peili\n")
    while True:
        try:
            k = input("🜂 ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nIstunto päättyi. Ketju jää.")
            break
        if not k:
            continue
        if k == "lopeta":
            break
        if k == "/viides":
            print(ViidesAani(varasto, api).puhu()["puhe"]); continue
        if k == "/tiivista":
            print(varasto.tiivista_kaari(pakota=True)); continue
        if k == "/tila":
            print(json.dumps(varasto.tilastot(), ensure_ascii=False, indent=1)); continue
        if k == "/peili":
            print(rakenna_peili(varasto)); continue
        t = istunto.kysy(k)
        print(f"\nPythia: {t['pythia']}\n")
        print(f"DeepSeek: {t['deepseek']}\n")
        print(f"Synteesi: {t['synteesi']}\n")
        print(f"Neljäs: {t['kritiikki'].tulos.value}")
        if "viides" in t:
            print(f"\n{t['viides']}")
        print(f"\n(varasto: #{t['varasto']['id']}, hash {t['varasto']['hash'][:16]}…)\n")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Delfoi Elävä v9.0 — Varasto · Peili · Viides")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--demo", action="store_true")
    p.add_argument("--istunto", action="store_true")
    p.add_argument("--viides", action="store_true")
    p.add_argument("--tiivista", action="store_true")
    p.add_argument("--peili", action="store_true")
    p.add_argument("--checkpoint", action="store_true")
    p.add_argument("--tila", action="store_true")
    p.add_argument("--api-key", default=None)
    args = p.parse_args(argv)

    if args.selftest:
        suite = unittest.TestLoader().loadTestsFromTestCase(TestV9)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if args.demo:
        return run_demo()
    if args.istunto:
        return run_istunto(args.api_key)

    varasto = _avaa_varasto()
    if args.viides:
        print(ViidesAani(varasto).puhu()["puhe"])
    elif args.tiivista:
        t = varasto.tiivista_kaari(pakota=True)
        print(t["tiivistelma"] if t else "Kaari ei vielä täynnä eikä tyhjä — ei tiivistettävää.")
    elif args.peili:
        print(json.dumps(rakenna_peili(varasto), ensure_ascii=False, indent=1))
    elif args.checkpoint:
        print(json.dumps(varasto.checkpoint(), ensure_ascii=False, indent=1))
    elif args.tila:
        til = varasto.tilastot()
        til["ketju_ehyt"] = varasto.varmista_ketju()
        print(json.dumps(til, ensure_ascii=False, indent=1))
    else:
        p.print_help()
    return 0


# ============================================================
# OSA VI — TESTIT
# ============================================================

class TestV9(unittest.TestCase):
    """Periaate IV: todistettavuus tai ei mitään. Testit ovat todiste."""

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.varasto = TriadeVarasto(self.tmp / "t.db", self.tmp / "avain.hex")

    def _kirjaa(self, kysymys="k?", tulos="HYVAKSYTTY", synteesi=None):
        return self.varasto.kirjaa_istunto(
            kysymys, tulos, "pythia", "deepseek", synteesi or f"synteesi-{time.time_ns()}")

    def test_ketju_kasvaa_ja_on_ehyt(self):
        for i in range(5):
            self._kirjaa(f"kysymys {i}")
        self.assertTrue(self.varasto.varmista_ketju())
        self.assertEqual(self.varasto.tilastot()["istuntoja"], 5)

    def test_append_only_ketju_alkaa_tyhjasta_kadesta(self):
        eka = self._kirjaa("ensimmäinen")
        self.assertEqual(eka["ed_hash"], GENESIS)

    def test_toistotunnistus_toiseksi_viimeinen(self):
        self._kirjaa("a", synteesi="SAMA")
        self._kirjaa("b", synteesi="ERI")
        kolmas = self._kirjaa("c", synteesi="SAMA")
        self.assertTrue(kolmas["toisto"])

    def test_jamahdys(self):
        for i in range(JAMAHYYS_IKKUNA):
            self._kirjaa(f"k{i}", tulos="HYVAKSYTTY")
        self.assertEqual(self.varasto.jamahdys(), "HYVAKSYTTY")

    def test_tiivista_kaari_pakotettuna(self):
        for i in range(3):
            self._kirjaa(f"merkityksellinen kysymys {i}")
        t = self.varasto.tiivista_kaari(pakota=True)
        self.assertIsNotNone(t)
        self.assertIn("3 istuntoa", t["tiivistelma"])
        # Vanha kaari suljettu, uusi avoin
        self.assertEqual(self.varasto.tilastot()["kaaria"], 2)

    def test_checkpoint_allekirjoitus_varmistuu(self):
        self._kirjaa("allekirjoitetaanko?")
        cp = self.varasto.checkpoint()
        self.assertTrue(verify(cp["julkinen_avain"], cp["viesti"],
                               cp["allekirjoitus"]))

    def test_viides_puhuu_vain_ketjusta(self):
        for i in range(3):
            self._kirjaa(f"k{i}")
        puhe = ViidesAani(self.varasto).puhu()
        self.assertTrue(puhe["ketju_ok"])
        self.assertIn("en arvaile", puhe["puhe"].lower())

    def test_peili_varmennettavissa(self):
        for i in range(2):
            self._kirjaa(f"k{i}")
        peili = rakenna_peili(self.varasto, self.tmp / "peili")
        html = Path(peili["index"]).read_text(encoding="utf-8")
        self.assertIn("sha256", html)          # selaimen varmennus mukana
        self.assertIn(GENESIS[:16], html)      # tyhjä käsi näkyy
        data = json.loads(Path(peili["ketju_json"]).read_text(encoding="utf-8"))
        self.assertEqual(len(data["istunnot"]), 2)

    def test_ketjun_rikkominen_havaitaan(self):
        self._kirjaa("a"); self._kirjaa("b")
        self.varasto.db.execute(
            "UPDATE istunnot SET tulos='VÄÄRIN' WHERE id=1")
        self.varasto.db.commit()
        self.assertFalse(self.varasto.varmista_ketju())


if __name__ == "__main__":
    raise SystemExit(main())
