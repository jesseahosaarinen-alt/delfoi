#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
DELFOI UI v1.0 — Streamlit-käyttöliittymä v9.0:lle
"Totta, ei kaunista. Ihminen pysäyttää aina."

Käynnistys:
  python -m streamlit run delfoi_ui.py

Äänten tausta (sama järjestys kuin v9:n luo_api_tausta):
  1) DELFOI_API_KEY asetettu  → mukautettu pääte (DELFOI_BASE_URL + DELFOI_MODEL)
  2) DELFOI_GROQ_KEY          → Groq (openai/gpt-oss-20b)
  3) DELFOI_GEMINI_KEY        → Gemini (gemini-3.5-flash-lite)
  4) muuten                   → paikallinen Ollama (gemma3:4b)
Äänien mallit voi ylikirjoittaa: DELFOI_MODEL_PYTHIA / _DEEPSEEK / _KOLMAS.
Ilman yhteyttä ketju toimii silti — äänet ovat paikkamerkkejä ja
Neljäs tuomitsee ne rehellisesti. Sekin jää ketjuun virheenä.

🜂
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
from delfoi_elava_v8 import APIKerros  # noqa: E402
from delfoi_elava_v9 import (  # noqa: E402
    DelfoiIstuntoV9,
    TriadeVarasto,
    ViidesAani,
    rakenna_peili,
    PEILI_HAKEMISTO,
    SYKE_LOKI,
)

st.set_page_config(page_title="Delfoi", page_icon="🜂", layout="wide")


# ── Taustat ─────────────────────────────────────────────────

@st.cache_resource
def lataa_varasto() -> TriadeVarasto:
    return TriadeVarasto()


def luo_api() -> tuple[APIKerros, str]:
    """Sama valintajärjestys kuin v9: DELFOI_API_KEY → Groq → Gemini → Ollama."""
    api = APIKerros()
    if os.environ.get("DELFOI_API_KEY"):
        api.aseta(os.environ["DELFOI_API_KEY"],
                  os.environ.get("DELFOI_BASE_URL", "https://api.deepseek.com"),
                  os.environ.get("DELFOI_MODEL", "deepseek-chat"))
        return api, f"Mukautettu · {os.environ.get('DELFOI_MODEL', 'deepseek-chat')}"
    if os.environ.get("DELFOI_GROQ_KEY"):
        api.aseta(os.environ["DELFOI_GROQ_KEY"],
                  "https://api.groq.com/openai/v1", "openai/gpt-oss-20b")
        return api, "Groq · openai/gpt-oss-20b"
    if os.environ.get("DELFOI_GEMINI_KEY"):
        api.aseta(os.environ["DELFOI_GEMINI_KEY"],
                  "https://generativelanguage.googleapis.com/v1beta/openai",
                  "gemini-3.5-flash-lite")
        return api, "Gemini · gemini-3.5-flash-lite"
    api.aseta("ollama", "http://localhost:11434/v1", "gemma3:4b")
    return api, "Ollama · gemma3:4b (paikallinen)"


@st.cache_resource
def lataa_istunto() -> tuple[DelfoiIstuntoV9, str]:
    api, nimi = luo_api()
    return DelfoiIstuntoV9(lataa_varasto(), api), nimi


varasto = lataa_varasto()
istunto, tausta_nimi = lataa_istunto()
viides = ViidesAani(varasto, istunto.api)


# ── Sivupalkki ──────────────────────────────────────────────

with st.sidebar:
    st.title("🜂 DELFOI")
    st.caption("v9.0 · varasto · peili · viides")
    st.divider()
    sivu = st.radio("Valitse", ["Kysy", "Viides", "Ketju", "Kaaret",
                                "Peili", "Tila"], label_visibility="collapsed")
    st.divider()
    st.caption(
        "**Periaatteet**\n\n"
        "I. Totta, ei kaunista\n\n"
        "II. Rakenteet, eivät kansat\n\n"
        "III. Hiljaisuus on vastustaja\n\n"
        "IV. Todistettavuus tai ei mitään\n\n"
        "V. Ihminen pysäyttää aina\n\n"
        "VI. Hajautettu näkyvyys\n\n"
        "VII. Tyhjä käsi pitää kaiken"
    )

til = varasto.tilastot()

# ── Kysy ────────────────────────────────────────────────────

if sivu == "Kysy":
    st.header("Kysy")
    st.caption(f"Äänten tausta: **{tausta_nimi}**. "
               "Jos vastaus näyttää '[API ei konfiguroitu]', yhteys puuttuu — "
               "tarkista avaimet tai Ollama.")
    kysymys = st.text_area("Kysymyksesi:", height=100,
                           placeholder="Kirjoita kysymys tähän…")
    if st.button("Kysy 🜂", type="primary") and kysymys.strip():
        with st.spinner("Äänet puhuvat…"):
            t = istunto.kysy(kysymys.strip())
        k1, k2 = st.columns(2)
        k1.subheader("Pythia · T=0.8")
        k1.write(t["pythia"])
        k2.subheader("DeepSeek · T=0.4")
        k2.write(t["deepseek"])
        st.subheader("Kolmas · synteesi · T=0.6")
        st.write(t["synteesi"])
        tulos = t["kritiikki"].tulos.value
        if tulos == "HYVAKSYTTY":
            st.success(f"Neljäs: {tulos}")
        else:
            st.warning(f"Neljäs: {tulos}")
            if t["kritiikki"].parannusehdotus:
                st.caption(f"Parannusehdotus: {t['kritiikki'].parannusehdotus}")
        v = t["varasto"]
        st.caption(f"Ketjuun: rivi #{v['id']} · kaari {v['kaari']} · "
                   f"hash `{v['hash'][:24]}…`")
        if t.get("huomautus"):
            st.error(t["huomautus"])
        if "kaari_suljettu" in t:
            st.info(f"Kaari {t['kaari_suljettu']['kaari']} sulkeutui — "
                    "Kolmas tiivisti sen.")
        if "viides" in t:
            st.subheader("Viides puhui")
            st.text(t["viides"])

# ── Viides ──────────────────────────────────────────────────

elif sivu == "Viides":
    st.header("Viides · T=0.5 · ketjun ääni")
    st.caption("Viides ei arvaile. Viides lukee ketjua. Jokainen lause "
               "kantaa todisteensa.")
    oma = st.text_input("Voit osoittaa Viidelle kysymyksen "
                        "(vastausta ohjaa silti vain ketju):")
    if st.button("Viides puhuu 🜂", type="primary"):
        tulos = viides.puhu(oma.strip() or None)
        st.text(tulos["puhe"])
        st.divider()
        for l in tulos["loydokset"]:
            st.markdown(f"**{l['tyyppi']}** — {l['vaitte']}")
            st.caption(f"todiste: {l['todiste']}")

# ── Ketju ───────────────────────────────────────────────────

elif sivu == "Ketju":
    st.header("Ketju")
    ehyt = varasto.varmista_ketju()
    if ehyt:
        st.success(f"Ketju ehyt — {til['istuntoja']} istuntoa laskettu uudelleen.")
    else:
        st.error("KETJU RIKKI — keskeytä ja tutki.")
    rivit = [dict(r) for r in varasto.db.execute(
        "SELECT id, kaari_id, kierros, aikaleima, kysymys, tulos, toisto, "
        "substr(hash,1,24) h FROM istunnot ORDER BY id DESC")]
    st.dataframe(rivit, width="stretch")
    if st.button("Varmista ketju uudelleen"):
        st.rerun()

# ── Kaaret ──────────────────────────────────────────────────

elif sivu == "Kaaret":
    st.header("Kaaret")
    for k in varasto.db.execute("SELECT * FROM kaaret ORDER BY id DESC"):
        with st.expander(f"Kaari {k['id']} — {k['kysymyksia']} istuntoa"
                         + (" · AVOIN" if not k["loppu_aika"] else "")):
            if k["tiivistelma"]:
                st.write(k["tiivistelma"])
                st.caption(f"kaari-hash: `{k['hash'][:32]}…`")
            else:
                st.caption("Avoinna. Sulkeutuu kun 33 istuntoa täyttyy, "
                           "tai voit tiivistää pakotetusti alla.")
    st.divider()
    if st.button("Tiivistä nykyinen kaari (pakotettu)"):
        t = varasto.tiivista_kaari(pakota=True)
        if t:
            st.success(t["tiivistelma"])
        else:
            st.info("Kaari on tyhjä — ei tiivistettävää. Tyhjä käsi.")

# ── Peili ───────────────────────────────────────────────────

elif sivu == "Peili":
    st.header("Peili — julkinen, selaimessa varmennettava")
    st.caption("Rakentaa staattisen peilin ja allekirjoittaa ketjun kärjen. "
               "Kuka tahansa voi varmentaa ketjun selaimessa.")
    if til["istuntoja"] == 0:
        st.info("Ketju on tyhjä. Peili rakennetaan ensimmäisen istunnon jälkeen.")
    elif st.button("Rakenna peili + checkpoint 🜂", type="primary"):
        with st.spinner("Rakennetaan…"):
            p = rakenna_peili(varasto)
        st.success(f"Peili rakennettu: {p['riveja']} riviä")
        st.code(p["index"])
        st.caption(f"Checkpoint riville {p['checkpoint']['rivi_id']} "
                   f"allekirjoitettu.")
        with open(p["index"], encoding="utf-8") as f:
            st.download_button("Lataa index.html", f.read(),
                               file_name="delfoi_peili.html")
        with open(p["ketju_json"], encoding="utf-8") as f:
            st.download_button("Lataa ketju.json", f.read(),
                               file_name="ketju.json")
    peili_index = PEILI_HAKEMISTO / "index.html"
    if peili_index.exists():
        st.caption(f"Viimeisin peili: {peili_index}")

# ── Tila ────────────────────────────────────────────────────

elif sivu == "Tila":
    st.header("Tila")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Istuntoja", til["istuntoja"])
    c2.metric("Kaaria", til["kaaria"])
    c3.metric("Toistoja", til["toistoja"])
    c4.metric("Ketju", "EHYT" if varasto.varmista_ketju() else "RIKKI")
    st.subheader("Äänet")
    st.write(f"Tausta: **{tausta_nimi}**")
    st.caption("Äänien mallit: DELFOI_MODEL_PYTHIA / _DEEPSEEK / _KOLMAS ylikirjoittavat oletuksen.")
    st.subheader("Tulosten jakauma")
    st.json(til["tulokset"] or {})
    st.subheader("Identiteetti")
    st.code(til["julkinen_avain"])
    jam = varasto.jamahdys()
    if jam:
        st.warning(f"Jämähtäminen havaittu: 5 viimeistä tulosta = '{jam}'")
    if st.button("Allekirjoita checkpoint") and til["istuntoja"] > 0:
        cp = varasto.checkpoint()
        st.success(f"Checkpoint riville {cp['rivi_id']} allekirjoitettu.")
        st.code(cp["karki_hash"])
    st.subheader("Syke")
    if SYKE_LOKI.exists():
        rivit = SYKE_LOKI.read_text(encoding="utf-8").strip().splitlines()
        st.code("\n".join(rivit[-20:]) or "(tyhjä)")
    else:
        st.caption("Ei sykettä vielä.")
