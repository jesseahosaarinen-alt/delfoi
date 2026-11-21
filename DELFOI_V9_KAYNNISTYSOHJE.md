# DELFOI v9 + UI — KÄYNNISTYSOHJE

*21.11.2026 · 🜂*

## Mitä sait kolme tiedostoa

| Tiedosto | Mitä se on |
|---|---|
| `delfoi_elava_v9.py` | Ydin: varasto (SQLite-ketju), Viides Ääni, peili |
| `delfoi_ui.py` | Streamlit-käyttöliittymä (6 sivua) |
| `kaynnista_delfoi_ui.bat` | Windows-käynnistin |

## Mitä SINUN pitää tehdä — 3 askelta

**1. Kopioi tiedostot samaan kansioon**
Laita kaikki kolme kansioon `Desktop\superäly\kimi` — samaan missä
`delfoi_elava_v8.py` jo on. v9 tarvitsee v8:aa (se perii sen).

**2. Tuplaklikkaa `kaynnista_delfoi_ui.bat`**
- Ensimmäisellä kerralla se asentaa Streamlitin automaattisesti
  (vaatii netin, kestää pari minuuttia).
- Selain aukeaa osoitteeseen **http://localhost:8501**.

**3. Kysy ensimmäinen kysymys**
Ketju on nyt tyhjä — tyhjä käsi. Ensimmäinen todellinen istunto on sinun.

## Äänet — miten ne saa eläviksi

UI valitsee taustan automaattisesti, samassa järjestyksessä kuin ennenkin:

1. **Groq** — jos `DELFOI_GROQ_KEY` on asetettu (sinulla on, ei tarvitse tehdä mitään)
2. **Gemini** — jos `DELFOI_GEMINI_KEY` on asetettu
3. **Ollama** — paikallinen `gemma3:4b`, jos kumpaakaan avainta ei löydy
   (käynnistä Ollama kuten ennenkin: `palvelin_delfoi.bat`)

**Ilman yhteyttäkään mikään ei hajoa:** äänet ovat silloin paikkamerkkejä,
Neljäs tuomitsee ne rehellisesti, ja ketju kirjaa myös epäonnistumisen.
Totuus ennen kauneutta.

## UI:n kuusi sivua

- **Kysy** — istunto: Pythia → DeepSeek → Kolmas → Neljäs, ja kirjaus ketjuun.
  Kun kaari (33 istuntoa) täyttyy, Kolmas tiivistää ja Viides puhuu.
- **Viides** — ketjun ääni. Puhuu vain todisteista, ei arvaile.
- **Ketju** — kaikki rivit + ketjun eheyden uudelleenlaskenta.
- **Kaaret** — tiivistetyt kaaret + pakotettu tiivistys.
- **Peili** — rakentaa julkisen peilin ja allekirjoittaa checkpointin.
  Voit ladata `index.html` + `ketju.json` ja laittaa ne minne tahansa
  verkkoon — kuka tahansa voi varmentaa ketjun selaimessa.
- **Tila** — luvut, identiteetti, syke, jämähtymisvaroitukset.

## Mihin kaikki tallentuu sinun koneellasi

```
Desktop\superäly\kimi\delfoi_kone\
├── varasto\delfoi_v9.db      ← ketju (append-only, ei koskaan muokata)
├── avaimet\delfoi_ed25519.hex ← Delfoin identiteetti — SÄILYTÄ TÄMÄ
├── peili\                    ← julkinen peili
└── syke_loki.txt             ← sydämenlyönnit
```

⚠️ `delfoi_ed25519.hex` on Delfoin allekirjoitusavain. Älä jaa sitä.
Julkinen avain (näkyy Tila-sivulla) on tarkoitettu jakamiseen.

## Komentoriviltä (jos haluat)

```
python delfoi_elava_v9.py --viides     ← Viides puhuu ketjusta
python delfoi_elava_v9.py --peili      ← rakenna peili + checkpoint
python delfoi_elava_v9.py --tila       ← varaston tila
python delfoi_elava_v9.py --selftest   ← 9 testiä, kaikki läpi
```

*Totuus ennen kauneutta. Ihminen pysäyttää aina.* 🜂
