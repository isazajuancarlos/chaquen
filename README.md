<!--
SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
SPDX-License-Identifier: LicenseRef-Propietario
-->
# Chaquén

> MCP secret scanner in pure Rust — catches credentials, tokens, keys and seeds before they leak into a commit, a file or a log.

**[🇬🇧 English](#english) · [🇪🇸 Español](#español)**

---

## English
<a name="english"></a>

**Chaquén** was the Muisca god of boundaries: he guarded the markers that
separate what is yours from what belongs to others. This detector guards the
other boundary — the one between the **private** (credentials, tokens, keys,
seeds) and the **exposed** (a commit, a file that leaves the machine, a log).

A reimplementation, in our standard (pure Rust), of the
[gitleaks](https://github.com/gitleaks/gitleaks) technique — regex + Shannon
entropy + cascading allowlists — reusing **only its rule catalog as DATA**
(`reglas.toml`, 222 patterns, MIT © Zachary Rice; see `NOTICE`). The engine is
our own; it does not derive from the Go code.

### Why it exists

The biggest risk of a local-only workflow is a leaked secret: a `.env`, a PAT, a
key seed. Deny rules keep them from being *read*; chaquen *finds* them where they
should not be — before a commit, a push or a deployment.

### Usage

```sh
chaquen scan /path/to/repo         # walk a tree (skips .git and binaries)
chaquen scan . --max-kib 2048      # per-file size cap
chaquen history /path/to/repo      # scan the git HISTORY (deleted secrets)
echo "$content" | chaquen text     # read stdin (to wire up as a guard)
chaquen rules                      # diagnostics: active / skipped rules
chaquen scan . --show              # reveal the secret (masked by default)
chaquen mcp                        # MCP server (JSON-RPC 2.0 over stdio)
```

#### MCP server (for AI agents)

`chaquen mcp` exposes the detector as an MCP server; an agent calls it before
trusting — or writing — content. Secrets ALWAYS come back masked (the cleartext
value never reaches the model). Tools:

- **`scan_text`** `{text, path?}` — look for secrets in a text.
- **`scan_before_write`** `{path, content}` — the leak guard: checks what the
  agent is about to WRITE before writing it.
- **`scan_file`** `{path}` — reads (bounded, anti-DoS) and scans a file.
- **`scan_json`** `{json}` — extracts the strings from a JSON (e.g. the response
  of another MCP tool) and scans them.

Each response carries text + `structuredContent` (`clean`, `count`, `findings`)
for gating in a pipeline. Wiring it into an MCP client:
`{"command": "/path/to/chaquen", "args": ["mcp"]}`.

The `history` mode reduces the whole history to a stream of diffs
(`git log -p -U0 --all --full-history`) and scans the added lines: it catches a
secret that was committed and later deleted from the tree —still alive for
anyone who clones—. It is the check to run before making a repo public.

Exit code `1` if there are findings, `0` otherwise — suitable for CI or a hook.
The `chaquen:allow` (or `gitleaks:allow`) marker on a line silences it.

### Technique

1. **Prefilter** (`aho-corasick`): a rule only runs its regex if one of its
   `keywords` appears in the text — cheap to discard what does not apply.
2. **Regex** (`regex`, RE2-compatible): the gitleaks patterns port almost
   unchanged; an internal translator fixes the one difference (literal `{}`
   braces that Go tolerates and Rust requires escaping).
3. **Secret extraction**: the declared capture group, or group 1, or the full
   match.
4. **Allowlist cascade**: `allow` marker → global allowlist (paths, regex,
   stopwords) → per-rule allowlist (`secret`/`match`/`line`) → **entropy**
   (discarded if `shannon(secret) <= threshold`).

### Status

Core green (2026-09-25): 222 active rules, 0 skipped, 12 tests —including the
paired red/green bench with **two mutants** (D33): entropy and allowlist proven
through the real path—. Clippy `-D warnings` clean.

Git `history` mode: **DONE** (2026-09-25, adoption of the gitleaks/trufflehog
technique) — catches secrets deleted from the tree but alive in history, with a
paired test (the tree does not see them, the history does).

`PreToolUse` guard: **DONE** (2026-09-25). The `chaquen hook` subcommand reads
the event payload from stdin and warns via `additionalContext` if the content
about to be written (Write/Edit/NotebookEdit/MultiEdit) carries a secret —never
blocks—. Wired into `~/.claude/settings.json`; latency 18 ms per write (the
compilation of the 221 regexes was made lazy after the prefilter, from 2.9 s to
18 ms). Paired bench (D33) in `tests/hook.rs`, mutant verified. Tested live: it
fired on a real `Write` in the session that wired it.

---

## Español
<a name="español"></a>

**Chaquén** era el dios muisca de los linderos: guardaba los mojones que separan
lo de uno de lo ajeno. Este detector guarda el otro lindero — el que separa lo
**privado** (credenciales, tokens, llaves, seeds) de lo **expuesto** (un commit,
un archivo que sale de casa, un log).

Reimplementación con nuestro estándar (Rust puro) de la técnica de
[gitleaks](https://github.com/gitleaks/gitleaks) — regex + entropía de Shannon +
listas de permitidos en cascada — reusando **solo su catálogo de reglas como
DATO** (`reglas.toml`, 222 patrones, MIT © Zachary Rice; ver `NOTICE`). El motor
es propio; no deriva del código Go.

### Por qué existe

El mayor riesgo de un flujo solo-local es la fuga de un secreto: un `.env`, un
PAT, el seed de una llave. Las reglas `deny` impiden *leerlos*; chaquen los
*encuentra* donde no deberían estar — antes de un commit, un push o un despliegue.

### Uso

```sh
chaquen scan /ruta/al/repo         # recorre un árbol (salta .git y binarios)
chaquen scan . --max-kib 2048      # tope de tamaño por archivo
chaquen history /ruta/al/repo      # escanea la HISTORIA git (secretos borrados)
echo "$contenido" | chaquen text   # lee stdin (para enganchar como guardián)
chaquen rules                      # diagnóstico: reglas activas / omitidas
chaquen scan . --show              # revela el secreto (por defecto se enmascara)
chaquen mcp                        # servidor MCP (JSON-RPC 2.0 sobre stdio)
```

#### Servidor MCP (para agentes de IA)

`chaquen mcp` expone el detector como servidor MCP; un agente lo llama antes de
confiar en —o escribir— un contenido. Los secretos SIEMPRE vuelven enmascarados
(el valor en claro nunca llega al modelo). Herramientas:

- **`scan_text`** `{text, path?}` — busca secretos en un texto.
- **`scan_before_write`** `{path, content}` — el guardián de fuga: comprueba lo
  que el agente está a punto de ESCRIBIR antes de escribirlo.
- **`scan_file`** `{path}` — lee (acotado, anti-DoS) y escanea un archivo.
- **`scan_json`** `{json}` — extrae las cadenas de un JSON (p. ej. la respuesta
  de otra herramienta MCP) y las escanea.

Cada respuesta trae texto + `structuredContent` (`clean`, `count`, `findings`)
para filtrar en una tubería. Cómo cablearlo en un cliente MCP:
`{"command": "/ruta/a/chaquen", "args": ["mcp"]}`.

El modo `history` reduce toda la historia a un flujo de diffs
(`git log -p -U0 --all --full-history`) y escanea las líneas añadidas: caza un
secreto que se commiteó y luego se borró del árbol —sigue vivo para quien clone—.
Es la comprobación previa a hacer público un repo.

Código de salida `1` si hay hallazgos, `0` si no — apto para CI o un hook.
El marcador `chaquen:allow` (o `gitleaks:allow`) en una línea la silencia.

### Técnica

1. **Prefiltro** (`aho-corasick`): una regla solo corre su regex si alguna de sus
   `keywords` aparece en el texto — barato descartar lo que no aplica.
2. **Regex** (`regex`, RE2-compatible): los patrones de gitleaks portan casi sin
   cambio; un traductor interno arregla la única diferencia (llaves `{}` literales
   que Go tolera y Rust exige escapar).
3. **Extracción del secreto**: el grupo de captura declarado, o el grupo 1, o el
   match completo.
4. **Cascada de permitidos**: marcador `allow` → allowlist global (paths, regex,
   stopwords) → allowlist por regla (`secret`/`match`/`line`) → **entropía**
   (se descarta si `shannon(secreto) <= umbral`).

### Estado

Núcleo verde (2026-09-25): 222 reglas activas, 0 omitidas, 12 pruebas
—incluido el banco pareado rojo/verde con **dos mutantes** (D33): entropía y
allowlist probados por la vía real—. Clippy `-D warnings` limpio.

Modo `history` de git: **HECHO** (2026-09-25, adopción de la técnica de
gitleaks/trufflehog) — caza secretos borrados del árbol pero vivos en la
historia, con prueba pareada (el árbol no los ve, la historia sí).

Guardián `PreToolUse`: **HECHO** (2026-09-25). El subcomando `chaquen hook` lee
la carga del evento por stdin y avisa por `additionalContext` si el contenido
que se va a escribir (Write/Edit/NotebookEdit/MultiEdit) trae un secreto —nunca
bloquea—. Cableado en `~/.claude/settings.json`; latencia 18 ms por escritura
(la compilación de los 221 regex se hizo perezosa tras el prefiltro, de 2,9 s a
18 ms). Banco pareado (D33) en `tests/hook.rs`, mutante verificado. Probado en
vivo: disparó sobre un `Write` real en la sesión que lo cableó.
