// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: LicenseRef-Propietario
//! Recibos de revisión anclados al CONTENIDO (D31), no a `git` ni a `mtime`.
//!
//! Un veredicto («revisado», «limpio», «auditado») vale sobre un ARTEFACTO, no
//! sobre una rama (D31). `git diff` necesita un commit base; `git status` solo
//! ve lo que git ve; el `mtime` MIENTE bajo un restore de respaldo o una
//! sincronización en la nube —un restore con mtime viejo y contenido nuevo se
//! escapa a la revisión en silencio, que es el falso NEGATIVO, la dirección
//! peligrosa (D30)—. Hashear los bytes no tiene ese problema: el contenido
//! cambió ⇔ el hash cambió.
//!
//! Esto cubre lo que la D31 por SHA de git NO alcanza: artefactos SIN commitear
//! —el `.env` del VPS, un binario compilado, `vps-salud/estado.json`, un recibo
//! de despliegue—. Para esos, el ancla es el hash del contenido en el momento
//! en que se revisó.
//!
//! Idea destilada de `review-receipts.sh` de Claude Code Game Studios (estudio
//! 2026-11-10), reimplementada en Rust (D38) con SHA-256 nativo (sin dependencia
//! nueva: el protocolo solo-local hace arriesgado un `cargo add`).
//!
//! **Honestidad del negativo (D30).** El estado nunca colapsa «no cambió» con
//! «no se pudo mirar»: [`Estado::ReciboAusente`] (no hay línea base — no es
//! «limpio») y [`Estado::NoResuelto`] (un glob que el shell no expandió: toda
//! una clase de archivos se pidió y ninguno se examinó) son veredictos de
//! PRIMERA CLASE, no silencios.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

/// Marca de la primera línea del recibo y de la salida de `check`: positivo de
/// control (D30). Si un consumidor no la ve, el comando no corrió hasta el final
/// —«0 cambios» y «murió antes de comparar» dejan de ser indistinguibles—.
pub const SENTINEL: &str = "chaquen-receipt\tv1";

/// El estado de UN archivo frente a su línea base en el recibo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Estado {
    /// El hash actual coincide con el estampado: el veredicto previo sigue válido.
    SinCambio,
    /// El hash cambió desde la última estampa: el veredicto previo NO vale.
    Cambiado,
    /// Existe y nunca fue estampado: entra nuevo a la revisión.
    Nuevo,
    /// Fue estampado y el archivo ya NO existe: la última revisión lo leyó y hoy
    /// no está (no es «sin cambio» — la ausencia es un cambio).
    Desaparecido,
    /// Un patrón con metacaracteres glob (`*?[`) que el shell NO expandió y no
    /// existe como ruta literal: una clase entera pedida y nada examinado (D30).
    NoResuelto,
    /// La ruta trae un carácter de control (`\t`, `\n`, `\r`…): no se estampa ni
    /// se compara. Una línea del recibo es `PREFIJO\truta\thash`; un `\t`/`\n` en
    /// la ruta inyectaría o falsificaría estampas (un atacante que controle el
    /// nombre de un archivo fijaría una base falsa de OTRO y ocultaría su cambio).
    /// Se rechaza ruidosamente (D20): un nombre así no aparece en revisión legítima.
    RutaInvalida,
}

impl Estado {
    /// `true` si este estado INVALIDA un veredicto previo (algo que mirar de nuevo).
    #[must_use]
    pub fn invalida(&self) -> bool {
        matches!(
            self,
            Estado::Cambiado | Estado::Desaparecido | Estado::NoResuelto | Estado::RutaInvalida
        )
    }

    /// Etiqueta estable para la salida (la consume un script/CI).
    #[must_use]
    pub fn etiqueta(&self) -> &'static str {
        match self {
            Estado::SinCambio => "UNCHANGED",
            Estado::Cambiado => "CHANGED",
            Estado::Nuevo => "NEW",
            Estado::Desaparecido => "GONE",
            Estado::NoResuelto => "UNRESOLVED",
            Estado::RutaInvalida => "INVALID-PATH",
        }
    }
}

/// `true` si la ruta es segura para una línea del recibo: sin caracteres de
/// control, que son los que romperían el formato `PREFIJO\truta\thash`.
fn ruta_segura(ruta: &str) -> bool {
    !ruta.chars().any(char::is_control)
}

/// `true` si `h` es un SHA-256 bien formado: exactamente 64 hex en minúscula.
/// Al leer el recibo, descarta una línea inyectada o un campo desplazado por un
/// `\t` colado en una ruta (defensa en profundidad sobre `ruta_segura`).
fn hash_bien_formado(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// El resultado completo de un `check`, con su positivo de control.
#[derive(Debug, Clone)]
pub struct Reporte {
    /// `false` cuando el recibo no existía: NO EVALUADO, no «limpio» (D30).
    pub recibo_existia: bool,
    /// Un estado por ruta, orden estable (BTree) para una salida determinista.
    pub estados: BTreeMap<String, Estado>,
}

impl Reporte {
    /// `true` si hay algo que re-revisar (o si no había línea base).
    #[must_use]
    pub fn hay_que_revisar(&self) -> bool {
        !self.recibo_existia || self.estados.values().any(Estado::invalida)
    }

    /// Código de salida: `0` todo sin cambio; `1` algo invalidó el veredicto;
    /// `3` RECIBO AUSENTE (no evaluado — distinto de limpio).
    #[must_use]
    pub fn codigo(&self) -> u8 {
        if !self.recibo_existia {
            3
        } else if self.estados.values().any(Estado::invalida) {
            1
        } else {
            0
        }
    }

    /// Render con SENTINEL en la primera línea (positivo de control D30).
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = format!("{SENTINEL}\t{} compared\n", self.estados.len());
        if !self.recibo_existia {
            s.push_str("RECEIPT: NONE — no baseline existed; this is NOT a clean result (D30)\n");
        }
        for (ruta, estado) in &self.estados {
            let _ = writeln!(s, "{}\t{ruta}", estado.etiqueta());
        }
        s
    }
}

// ─────────────────────────── el recibo como archivo ──────────────────────────

/// Prefijo de cada línea de estampa en el recibo (append-only).
const PREFIJO: &str = "Reviewed-Content-Hash";

/// `true` si la ruta trae metacaracteres glob (el shell debió expandirla).
fn parece_glob(ruta: &str) -> bool {
    ruta.contains(['*', '?', '[', ']'])
}

/// Lee el recibo y devuelve el ÚLTIMO hash estampado por ruta (append-only: la
/// última línea gana, así una re-estampa actualiza la base sin reescribir).
fn leer_base(recibo: &str) -> BTreeMap<String, String> {
    let mut base = BTreeMap::new();
    for linea in recibo.lines() {
        // Formato: `Reviewed-Content-Hash\t<ruta>\t<hash>`
        let mut it = linea.splitn(3, '\t');
        if it.next() != Some(PREFIJO) {
            continue;
        }
        if let (Some(ruta), Some(hash)) = (it.next(), it.next()) {
            // Solo un hash bien formado entra: una línea inyectada por un `\n` en
            // un nombre de archivo, o un campo desplazado por un `\t`, deja aquí
            // algo que no es 64-hex y se descarta (defensa en profundidad).
            if hash_bien_formado(hash) && ruta_segura(ruta) {
                base.insert(ruta.to_string(), hash.to_string());
            }
        }
    }
    base
}

/// Estampa: hashea cada ruta existente y devuelve las líneas a APPENDear al
/// recibo. Una ruta ausente/no-resuelta no se estampa (no se inventa una base,
/// D20). `leer` lee los bytes de una ruta (inyectable para probar sin disco).
pub fn estampar_lineas<L>(rutas: &[String], mut leer: L) -> (String, Vec<(String, Estado)>)
where
    L: FnMut(&str) -> Option<Vec<u8>>,
{
    let mut salida = String::new();
    let mut avisos = Vec::new();
    for ruta in rutas {
        // Una ruta con un carácter de control NUNCA se estampa: inyectaría o
        // falsificaría líneas del recibo (integridad, no cosmética).
        if !ruta_segura(ruta) {
            avisos.push((ruta.clone(), Estado::RutaInvalida));
            continue;
        }
        match leer(ruta) {
            Some(bytes) => {
                let h = sha256_hex(&bytes);
                let _ = writeln!(salida, "{PREFIJO}\t{ruta}\t{h}");
            }
            None if parece_glob(ruta) => avisos.push((ruta.clone(), Estado::NoResuelto)),
            None => avisos.push((ruta.clone(), Estado::Desaparecido)),
        }
    }
    (salida, avisos)
}

/// Compara el estado actual de las rutas contra la base del recibo. Compara
/// TODAS las rutas que la base conoce (el recibo ES una lista: una ruta que la
/// última revisión leyó y el llamante olvidó pedir se compara igual) MÁS las
/// rutas nuevas pedidas. `leer` devuelve `None` si la ruta no existe.
pub fn verificar<L>(recibo_texto: Option<&str>, pedidas: &[String], mut leer: L) -> Reporte
where
    L: FnMut(&str) -> Option<Vec<u8>>,
{
    let recibo_existia = recibo_texto.is_some();
    let base = recibo_texto.map(leer_base).unwrap_or_default();

    // Universo: todo lo de la base + lo pedido (orden estable por BTree).
    let mut universo: BTreeMap<String, ()> = BTreeMap::new();
    for k in base.keys() {
        universo.insert(k.clone(), ());
    }
    for p in pedidas {
        universo.insert(p.clone(), ());
    }

    let mut estados = BTreeMap::new();
    for ruta in universo.keys() {
        // Una ruta pedida con carácter de control no se compara: no pudo haberse
        // estampado de forma segura (la base ya las filtró al leerse).
        if !ruta_segura(ruta) {
            estados.insert(ruta.clone(), Estado::RutaInvalida);
            continue;
        }
        let estampado = base.get(ruta);
        let estado = match leer(ruta) {
            Some(bytes) => {
                let actual = sha256_hex(&bytes);
                match estampado {
                    Some(prev) if *prev == actual => Estado::SinCambio,
                    Some(_) => Estado::Cambiado,
                    None => Estado::Nuevo,
                }
            }
            None => {
                if estampado.is_some() {
                    Estado::Desaparecido
                } else if parece_glob(ruta) {
                    Estado::NoResuelto
                } else {
                    // Pedida, nunca estampada y ausente: se reporta como GONE de
                    // su propia promesa (el llamante la nombró esperando que
                    // existiera). No se inventa un «limpio» (D20).
                    Estado::Desaparecido
                }
            }
        };
        estados.insert(ruta.clone(), estado);
    }

    Reporte { recibo_existia, estados }
}

// ───────────────────────────── SHA-256 nativo ────────────────────────────────
// Dominio público (FIPS 180-4). Sin dependencia: el protocolo solo-local hace
// de un `cargo add` una operación de red arriesgada, y el hash es ~80 líneas
// verificables contra los vectores NIST (ver pruebas). D38: Rust nativo.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 del mensaje, en hexadecimal minúsculo (64 caracteres).
#[must_use]
pub fn sha256_hex(msg: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Relleno: 0x80, ceros hasta 56 mod 64, y la longitud en bits (u64 BE).
    let bits = (msg.len() as u64).wrapping_mul(8);
    let mut datos = msg.to_vec();
    datos.push(0x80);
    while datos.len() % 64 != 56 {
        datos.push(0);
    }
    datos.extend_from_slice(&bits.to_be_bytes());

    // El relleno dejó `datos` en un múltiplo exacto de 64, así que el resto de
    // `as_chunks` es vacío y no se pierde ningún byte.
    for bloque in datos.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, palabra) in bloque.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*palabra);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = String::with_capacity(64);
    for palabra in h {
        let _ = write!(out, "{palabra:08x}");
    }
    out
}

/// Lee los bytes de una ruta del disco, o `None` si no existe/no se puede leer.
#[must_use]
pub fn leer_disco(ruta: &str) -> Option<Vec<u8>> {
    if parece_glob(ruta) {
        // Un glob que llega literal aquí es un glob que el shell NO expandió.
        return if Path::new(ruta).exists() {
            std::fs::read(ruta).ok()
        } else {
            None
        };
    }
    std::fs::read(ruta).ok()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // ── SHA-256 contra los vectores NIST (FIPS 180-4) — la AGUJA validada
    //    contra el artefacto, no contra el arnés (D33). ──
    #[test]
    fn sha256_vectores_nist() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // El vector de 56 bytes de arriba ya fuerza un segundo bloque de relleno
        // (56 + 1 + 8 > 64), así que el camino multi-bloque queda cubierto por
        // un valor NIST verificado, sin inventar ninguno (D33).
    }

    // Mutante D33: si el SHA fuera un hash trivial (p. ej. longitud), estos dos
    // mensajes del MISMO largo colisionarían. Deben diferir.
    #[test]
    fn sha256_discrimina_mismo_largo() {
        assert_ne!(sha256_hex(b"aaa"), sha256_hex(b"aab"));
    }

    fn mapa(pares: &[(&str, &[u8])]) -> std::collections::HashMap<String, Vec<u8>> {
        pares.iter().map(|(k, v)| (k.to_string(), v.to_vec())).collect()
    }

    // ── verificar(): pareja roja por estado ──

    #[test]
    fn sin_cambio_cuando_el_hash_coincide() {
        let disco = mapa(&[("a.txt", b"hola")]);
        let (recibo, _) = estampar_lineas(&["a.txt".into()], |r| disco.get(r).cloned());
        let rep = verificar(Some(&recibo), &["a.txt".into()], |r| disco.get(r).cloned());
        assert_eq!(rep.estados["a.txt"], Estado::SinCambio);
        assert_eq!(rep.codigo(), 0);
        assert!(!rep.hay_que_revisar());
    }

    #[test]
    fn cambiado_cuando_el_contenido_cambia_con_mtime_viejo() {
        // El caso que mtime NO ve: mismo nombre, contenido distinto (restore).
        let viejo = mapa(&[("a.txt", b"hola")]);
        let (recibo, _) = estampar_lineas(&["a.txt".into()], |r| viejo.get(r).cloned());
        let nuevo = mapa(&[("a.txt", b"HOLA cambiado")]);
        let rep = verificar(Some(&recibo), &["a.txt".into()], |r| nuevo.get(r).cloned());
        assert_eq!(rep.estados["a.txt"], Estado::Cambiado);
        assert_eq!(rep.codigo(), 1);
    }

    #[test]
    fn recibo_ausente_es_no_evaluado_no_limpio() {
        // D30: sin línea base NO es «limpio» — es código 3 y lo dice.
        let disco = mapa(&[("a.txt", b"hola")]);
        let rep = verificar(None, &["a.txt".into()], |r| disco.get(r).cloned());
        assert!(!rep.recibo_existia);
        assert_eq!(rep.codigo(), 3);
        assert!(rep.hay_que_revisar());
        assert!(rep.render().contains("RECEIPT: NONE"));
    }

    #[test]
    fn desaparecido_cuando_lo_estampado_ya_no_existe() {
        let antes = mapa(&[("a.txt", b"hola")]);
        let (recibo, _) = estampar_lineas(&["a.txt".into()], |r| antes.get(r).cloned());
        let vacio: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
        let rep = verificar(Some(&recibo), &[], |r| vacio.get(r).cloned());
        assert_eq!(rep.estados["a.txt"], Estado::Desaparecido);
        assert_eq!(rep.codigo(), 1);
    }

    #[test]
    fn no_resuelto_cuando_un_glob_no_expande() {
        // Un `*.rs` que llega literal = el shell no casó nada: clase entera
        // pedida y nada examinado (D30), NO «limpio».
        let vacio: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
        let rep = verificar(Some("otra cosa"), &["src/*.rs".into()], |r| vacio.get(r).cloned());
        assert_eq!(rep.estados["src/*.rs"], Estado::NoResuelto);
        assert!(rep.estados["src/*.rs"].invalida());
    }

    #[test]
    fn nuevo_cuando_existe_sin_estampa_previa() {
        let disco = mapa(&[("b.txt", b"nuevo")]);
        let rep = verificar(Some("recibo vacio sin lineas"), &["b.txt".into()], |r| disco.get(r).cloned());
        assert_eq!(rep.estados["b.txt"], Estado::Nuevo);
    }

    #[test]
    fn el_recibo_es_una_lista_compara_lo_que_el_llamante_olvido() {
        // Estampadas a.txt y b.txt; el check solo pide a.txt. b.txt debe
        // compararse igual (el recibo recuerda lo que la última revisión leyó).
        let disco = mapa(&[("a.txt", b"hola"), ("b.txt", b"mundo")]);
        let (recibo, _) = estampar_lineas(&["a.txt".into(), "b.txt".into()], |r| disco.get(r).cloned());
        let cambiado = mapa(&[("a.txt", b"hola"), ("b.txt", b"MUNDO!")]);
        let rep = verificar(Some(&recibo), &["a.txt".into()], |r| cambiado.get(r).cloned());
        assert_eq!(rep.estados["a.txt"], Estado::SinCambio);
        assert_eq!(rep.estados["b.txt"], Estado::Cambiado, "el recibo es una lista: b.txt se compara aunque no se pidió");
    }

    // ── Inyección de línea por nombre de archivo (hallazgo del security review
    //    2026-11-10). La pareja roja falla por la vía REAL: estampar/verificar. ──

    #[test]
    fn un_nombre_con_newline_no_inyecta_una_estampa_falsa() {
        // El ataque: un archivo cuyo nombre lleva un salto de línea y una estampa
        // forjada de OTRO archivo (/critico) con un hash viejo, para que un cambio
        // futuro de /critico se vea UNCHANGED.
        let hash_viejo = "0".repeat(64);
        let malicioso = format!("b.txt\n{PREFIJO}\t/critico\t{hash_viejo}");
        let disco = mapa(&[(malicioso.as_str(), b"x" as &[u8])]);
        let (recibo, avisos) = estampar_lineas(std::slice::from_ref(&malicioso), |r| disco.get(r).cloned());
        // No se estampó nada y se avisó RUTA INVÁLIDA (D20).
        assert!(recibo.is_empty(), "una ruta con \\n no debe producir ninguna línea");
        assert_eq!(avisos, vec![(malicioso, Estado::RutaInvalida)]);
        // Y /critico NO quedó con una base falsa: sin estampa, se evalúa como NEW/GONE.
        let critico = mapa(&[("/critico", b"contenido NUEVO" as &[u8])]);
        let rep = verificar(Some(&recibo), &["/critico".into()], |r| critico.get(r).cloned());
        assert_ne!(rep.estados["/critico"], Estado::SinCambio, "/critico jamás debió verse SinCambio");
    }

    #[test]
    fn leer_base_descarta_una_linea_inyectada_a_mano() {
        // Un recibo manipulado fuera de la herramienta: línea con hash no-hex y
        // una línea con un 4º campo. Ninguna debe entrar como base válida.
        let recibo = format!(
            "{PREFIJO}\t/a\tno-es-un-hash\n{PREFIJO}\t/b\t{}\textra\n{PREFIJO}\t/c\t{}\n",
            "a".repeat(64),
            "a".repeat(64)
        );
        let nuevo = mapa(&[("/a", b"z" as &[u8]), ("/b", b"z" as &[u8]), ("/c", b"z" as &[u8])]);
        let rep = verificar(Some(&recibo), &["/a".into(), "/b".into(), "/c".into()], |r| nuevo.get(r).cloned());
        // /a (hash inválido) y /b (campo extra ⇒ hash con tab, no 64-hex) no tienen
        // base ⇒ NEW, no SinCambio. /c es legítimo ⇒ tiene base y cambió.
        assert_eq!(rep.estados["/a"], Estado::Nuevo);
        assert_eq!(rep.estados["/b"], Estado::Nuevo);
        assert_eq!(rep.estados["/c"], Estado::Cambiado);
    }

    #[test]
    fn hash_bien_formado_discrimina() {
        assert!(hash_bien_formado(&"a".repeat(64)));
        assert!(!hash_bien_formado(&"A".repeat(64)), "mayúsculas no");
        assert!(!hash_bien_formado(&"a".repeat(63)), "63 no");
        assert!(!hash_bien_formado(&format!("{}\tx", "a".repeat(62))), "tab colado no");
    }

    #[test]
    fn el_render_lleva_el_sentinel_de_control() {
        let disco = mapa(&[("a.txt", b"x")]);
        let (recibo, _) = estampar_lineas(&["a.txt".into()], |r| disco.get(r).cloned());
        let rep = verificar(Some(&recibo), &["a.txt".into()], |r| disco.get(r).cloned());
        assert!(rep.render().starts_with(SENTINEL), "la 1ª línea debe ser el positivo de control");
        assert!(rep.render().contains("1 compared"));
    }
}
