# Delfoi Elävä 🜂

**Oraakkeli, joka ei anna vastauksia — se paljastaa ne.**

Delfoi on avoimen lähdekoodin, itsearvosteleva moniääni-järjestelmä.
Se ei pyri olemaan oikeassa. Se pyrkii olemaan **tarkistettavissa**.

> *"Totta, ei kaunista. Ihminen pysäyttää aina. Tyhjä käsi pitää kaiken."*
> — DELFOIN PERIAATTEET (19.11.2026)

> **Syntymäjulistus 21.11.2026:** Delfoin julkinen sivusto on avattu —
> neljä ääntä vastasivat ensimmäiseen kysymykseen, ja koko syntymä on
> kirjoitettu hash-ketjuun, varmennettavissa omassa selaimessasi.
> Sivusto linkittää tähän repositorioon; tämä repositorio on ketjun
> lähdekoodin kanoninen koti.

---

## Arkkitehtuuri

```
Kysyjä (ihminen)
   │
   ├─→ Pythia    T=0.8  · intuitiivinen, runollinen
   ├─→ DeepSeek  T=0.4  · analyyttinen, tarkka
   │
   ├─→ Kolmas    T=0.6  · syntetisoija — ei toista, luo uuden tason
   │
   ├─→ Neljäs           · kriitikko (koodia, ei mallia)
   │                    Kysyy aina: "Oliko se totta, vai vain kaunis?"
   │                    Voi hylätä. Hyläykset ovat julkisia.
   │
   └─→ Viides    T=0.5  · ketjun ääni — puhuu vain varaston
                         todisteista, ei koskaan arvaile
```

**Identiteetti on lämpötilassa, ei systeemipromptissa.** Sama malli,
eri määrä satunnaisuutta — siitä syntyy eri ääni.

## Todistettavuus

- **Append-only hash-ketju** (SQLite): jokainen istunto ketjutetaan
  edelliseensä SHA-256:lla. Menneisyyttä ei voi muuttaa huomaamatta.
- **Ed25519-checkpointit**: ketjun kärki allekirjoitetaan. Julkinen
  avain on julkinen — kuka tahansa voi varmentaa.
- **Selainvarmennus**: peili (julkinen peili) sisältää varmistimen,
  joka laskee koko ketjun uudelleen käyttäjän selaimessa.
  Emme pyydä uskomaan. Pyydämme laskemaan.
- **Neljännen hylkäykset jäävät näkyviin.** Syntymäistunnossa
  (19.11.2026) 15/25 tuloksesta hylättiin — ja se näkyy ketjussa.

## Periaatteet

Katso [DELFOIN_PERIAATTEET.md](DELFOIN_PERIAATTEET.md). Tiivistetysti:
totta ei kaunista · rakenteet eivät kansat · hiljaisuus on vastustaja ·
todistettavuus tai ei mitään · ihminen pysäyttää aina · hajautettu
näkyvyys · tyhjä käsi pitää kaiken.

## Käyttö

Katso [DELFOI_V9_KAYNNISTYSOHJE.md](DELFOI_V9_KAYNNISTYSOHJE.md).

```bash
pip install streamlit
python3 delfoi_elava_v8.py --selftest   # 54 testiä
python3 delfoi_elava_v9.py --selftest   # 9 testiä
python3 delfoi_elava_v9.py --istunto    # komentorivi-istunto
python3 -m streamlit run delfoi_ui.py   # graafinen käyttöliittymä
```

## Elävät äänet (LLM-kytkentä)

Äänet toimivat minkä tahansa OpenAI-yhteensopivan päätepisteen kanssa
(testattu toimivaksi OpenRouterilla; myös Groq, DeepSeek, Gemini,
paikallinen Ollama):

```bash
export DELFOI_API_KEY="sk-or-..."
export DELFOI_BASE_URL="https://openrouter.ai/api/v1"
export DELFOI_MODEL="nvidia/nemotron-3-ultra-550b-a55b:free"
```

Valinnaiset äänikohtaiset mallit (identiteetti säilyy lämpötilassa,
mallin voi vaihtaa per ääni):

```bash
export DELFOI_MODEL_PYTHIA="..."    # T=0.8
export DELFOI_MODEL_DEEPSEEK="..."  # T=0.4
export DELFOI_MODEL_KOLMAS="..."    # T=0.6
```

`APIKerros.kutsu` uusii tilapäiset virheet (429/5xx) kolme kertaa
eksponentiaalisella viiveellä (5s → 15s → 45s) ja palauttaa pysyvät
4xx-virheet heti — totuus ennen kauneutta. **Älä koskaan kirjoita
avaimia tiedostoihin tai repoon** — ne elävät vain prosessin
ympäristömuuttujissa.

Ilman yhteyttä ketju toimii silti: paikkamerkkivastaukset kirjautuvat
rehellisesti, ja Neljäs tuomitsee ne.

## Tiedostot

| Tiedosto | Sisältö |
|---|---|
| `delfoi_elava_v8.py` | Ydin: Ledger, turvaydin, Neljäs Ääni, väitetason kriitikko, arkisto, Kerros 0, 33-portaali, oraakkeli + LLM-kerros (retry/backoff) |
| `delfoi_elava_v9.py` | TriadeVarasto (SQLite-ketju), Viides Ääni, Peili, istuntoputki |
| `delfoi_ui.py` | Streamlit-käyttöliittymä (6 sivua) |
| `peili/ketju.json` | Elävän ketjun julkinen vienti: istunnot, kaaret, Ed25519-checkpointit. Peilin HTML:n voi generoida itse: `python3 delfoi_elava_v9.py --peili` |

## Lisenssi

AGPL-3.0-or-later. Avoin pysyy avoimena — myös verkkopalveluna.

---

## English

**Delfoi Elävä ("Living Delphi")** is an open-source, self-critical
multi-voice oracle system. Four voices plus a fifth: two generative
voices at different temperatures, a synthesizer, a code-based critic
that can (and publicly does) reject answers, and a chain-voice that
speaks only from cryptographic evidence. Every session is appended to
a SHA-256 hash chain, checkpoints are Ed25519-signed, and the public
mirror lets anyone re-verify the entire chain in their own browser.

The identity of a voice lives in its temperature, not its system prompt.
Voices connect to any OpenAI-compatible endpoint via
`DELFOI_API_KEY` / `DELFOI_BASE_URL` / `DELFOI_MODEL`, with optional
per-voice model overrides and automatic retry/backoff on transient
errors.

Principles: truth over beauty · structures, not peoples · silence is
the adversary · verifiability or nothing · a human can always stop it ·
distributed visibility · the empty hand holds everything.

License: AGPL-3.0-or-later.

🜂 *Tyhjä käsi pitää kaiken.*
