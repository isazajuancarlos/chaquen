// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: LicenseRef-Propietario
//! El motor de detección: compila el catálogo y escanea texto.
//!
//! Cascada, en este orden (igual que gitleaks, pero nativo en Rust):
//!   prefiltro de keywords (Aho-Corasick) → regex → marcador `chaquen:allow`
//!   → extracción del secreto → entropía → listas de permitidos (global + regla).

use std::cell::OnceCell;

use aho_corasick::AhoCorasick;
use regex::{Regex, RegexBuilder};

use crate::entropia::shannon;
use crate::modelo::{Catalogo, Permitidos, Regla};

/// El catálogo por defecto, vendorizado en el binario (DATO, MIT © Zachary Rice).
pub const REGLAS_EMBEBIDAS: &str = include_str!("../reglas.toml");

/// Allowlists PROPIAS (NUESTRAS, MIT), aparte del catálogo vendorizado de
/// gitleaks (que dice «do not edit manually»). Se fusionan al arrancar.
pub const REGLAS_PROPIAS: &str = include_str!("../reglas-propias.toml");

/// Un secreto encontrado.
#[derive(Debug, Clone)]
pub struct Hallazgo {
    pub regla: String,
    pub descripcion: String,
    pub ruta: String,
    pub linea: usize,
    /// El secreto en claro (el llamante decide si lo enmascara al mostrar).
    pub secreto: String,
}

impl Hallazgo {
    /// El secreto enmascarado: primeros y últimos 3 caracteres, resto `*`.
    #[must_use]
    pub fn secreto_enmascarado(&self) -> String {
        enmascarar(&self.secreto)
    }
}

fn enmascarar(s: &str) -> String {
    let cs: Vec<char> = s.chars().collect();
    if cs.len() <= 8 {
        return "*".repeat(cs.len());
    }
    let ini: String = cs[..3].iter().collect();
    let fin: String = cs[cs.len() - 3..].iter().collect();
    format!("{ini}{}{fin}", "*".repeat(cs.len() - 6))
}

/// Una lista de permitidos ya compilada.
struct PermitidosComp {
    paths: Vec<Regex>,
    regexes: Vec<Regex>,
    objetivo: Objetivo,
    stopwords: Vec<String>,
}

#[derive(Clone, Copy)]
enum Objetivo {
    Secreto,
    Match,
    Linea,
}

struct ReglaComp {
    id: String,
    descripcion: String,
    /// El patrón SIN compilar. Compilar los 221 regex al arrancar costaba ~2,9 s
    /// (medido 2026-09-25): fatal para un hook que corre en cada escritura. Se
    /// compila PEREZOSAMENTE (abajo) y solo tras el prefiltro de keywords, así que
    /// el contenido sin secretos no compila ni un regex.
    regex_src: Option<String>,
    /// La regex ya compilada, memorizada al primer uso. `None` interno = la fuente
    /// no compiló (se audita a gritos en el comando `reglas`, D20).
    regex: OnceCell<Option<Regex>>,
    path: Option<Regex>,
    entropy: Option<f64>,
    secret_group: Option<usize>,
    keywords: Option<AhoCorasick>,
    permitidos: Vec<PermitidosComp>,
}

impl ReglaComp {
    /// Compila la regex la primera vez que se necesita y la memoriza. La
    /// traducción Go↔Rust vive en [`compila`]; aquí solo se difiere el costo.
    fn regex(&self) -> Option<&Regex> {
        self.regex
            .get_or_init(|| self.regex_src.as_ref().and_then(|p| compila(p).ok()))
            .as_ref()
    }

    /// ¿Esta regla llegó a tener patrón? (Sin compilarlo — para el reporte y para
    /// las reglas que solo casan por `path`.)
    fn tiene_patron(&self) -> bool {
        self.regex_src.is_some()
    }
}

/// El motor listo para escanear.
pub struct Motor {
    reglas: Vec<ReglaComp>,
    global: PermitidosComp,
    /// Reglas que NO compilaron (regex inválida para el motor de Rust). Se
    /// reportan a gritos (D20): un catálogo mermado en silencio miente sobre su
    /// cobertura.
    pub omitidas: Vec<(String, String)>,
}

fn construye(patron: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(patron)
        .size_limit(64 * 1024 * 1024)
        .dfa_size_limit(64 * 1024 * 1024)
        .build()
}

/// Compila un patrón, con un reintento que traduce la diferencia Go↔Rust: Go
/// (RE2/go-re2) acepta `{` y `}` LITERALES cuando no forman un cuantificador
/// válido; el crate `regex` de Rust los rechaza y exige `\{`/`\}`. Reescribe solo
/// las llaves que no son cuantificador y no están dentro de una clase `[...]`.
fn compila(patron: &str) -> Result<Regex, regex::Error> {
    match construye(patron) {
        Ok(re) => Ok(re),
        Err(e) => {
            if patron.is_ascii() {
                let traducido = go_a_rust(patron);
                if traducido != patron {
                    return construye(&traducido);
                }
            }
            Err(e)
        }
    }
}

/// Si `b` empieza en `{`, devuelve el largo de un cuantificador válido
/// (`{n}`, `{n,}`, `{n,m}`), o `None`.
fn largo_cuantificador(b: &[u8]) -> Option<usize> {
    let mut i = 1; // b[0] == '{'
    let inicio = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == inicio {
        return None; // Rust exige el mínimo: `{,m}` no vale.
    }
    if i < b.len() && b[i] == b',' {
        i += 1;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
    }
    if i < b.len() && b[i] == b'}' {
        Some(i + 1)
    } else {
        None
    }
}

fn go_a_rust(p: &str) -> String {
    let b = p.as_bytes();
    let n = b.len();
    // Paso 1: marca los bytes que pertenecen a un cuantificador válido (fuera de clase).
    let mut protegido = vec![false; n];
    let mut en_clase = false;
    let mut i = 0;
    while i < n {
        match b[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'[' if !en_clase => en_clase = true,
            b']' if en_clase => en_clase = false,
            b'{' if !en_clase => {
                if let Some(largo) = largo_cuantificador(&b[i..]) {
                    for k in &mut protegido[i..i + largo] {
                        *k = true;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    // Paso 2: escapa las llaves no protegidas y fuera de clase.
    let mut out = String::with_capacity(n + 8);
    en_clase = false;
    i = 0;
    while i < n {
        let c = b[i];
        if c == b'\\' {
            out.push('\\');
            if i + 1 < n {
                out.push(b[i + 1] as char);
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        match c {
            b'[' if !en_clase => en_clase = true,
            b']' if en_clase => en_clase = false,
            b'{' if !en_clase && !protegido[i] => {
                out.push_str("\\{");
                i += 1;
                continue;
            }
            b'}' if !en_clase && !protegido[i] => {
                out.push_str("\\}");
                i += 1;
                continue;
            }
            _ => {}
        }
        out.push(c as char);
        i += 1;
    }
    out
}

fn compila_lista(p: &Permitidos, omitidas: &mut Vec<(String, String)>, ctx: &str) -> PermitidosComp {
    let mut paths = Vec::new();
    for pr in &p.paths {
        match compila(pr) {
            Ok(r) => paths.push(r),
            Err(e) => omitidas.push((format!("{ctx} (allowlist path)"), e.to_string())),
        }
    }
    let mut regexes = Vec::new();
    for pr in &p.regexes {
        match compila(pr) {
            Ok(r) => regexes.push(r),
            Err(e) => omitidas.push((format!("{ctx} (allowlist regex)"), e.to_string())),
        }
    }
    let objetivo = match p.regex_target.as_deref() {
        Some("match") => Objetivo::Match,
        Some("line") => Objetivo::Linea,
        _ => Objetivo::Secreto,
    };
    PermitidosComp {
        paths,
        regexes,
        objetivo,
        stopwords: p.stopwords.iter().map(|s| s.to_lowercase()).collect(),
    }
}

impl Motor {
    /// Compila el catálogo embebido.
    ///
    /// # Errors
    /// Falla si el TOML embebido no parsea (no debería: es un artefacto fijo).
    pub fn embebido() -> anyhow::Result<Self> {
        let mut cat: Catalogo = toml::from_str(REGLAS_EMBEBIDAS)?;
        // Fusiona NUESTRAS allowlists (reglas.toml queda intacto, es vendored).
        let propias: Catalogo = toml::from_str(REGLAS_PROPIAS)?;
        cat.allowlists.extend(propias.allowlists);
        Ok(Self::desde_catalogo(&cat))
    }

    /// Compila un catálogo desde texto TOML.
    ///
    /// # Errors
    /// Falla si el TOML no parsea.
    pub fn desde_toml(texto: &str) -> anyhow::Result<Self> {
        let cat: Catalogo = toml::from_str(texto)?;
        Ok(Self::desde_catalogo(&cat))
    }

    fn desde_catalogo(cat: &Catalogo) -> Self {
        let mut omitidas = Vec::new();

        // Global: fusiona la forma singular y la plural.
        let mut global_src = cat.allowlist.clone().unwrap_or_default();
        for a in &cat.allowlists {
            global_src.paths.extend(a.paths.clone());
            global_src.regexes.extend(a.regexes.clone());
            global_src.stopwords.extend(a.stopwords.clone());
        }
        let global = compila_lista(&global_src, &mut omitidas, "global");

        let mut reglas = Vec::new();
        for r in &cat.rules {
            reglas.push(Self::compila_regla(r, &mut omitidas));
        }

        Self { reglas, global, omitidas }
    }

    fn compila_regla(r: &Regla, omitidas: &mut Vec<(String, String)>) -> ReglaComp {
        // La regex del CUERPO no se compila aquí (perezosa): se guarda la fuente y
        // la valida a gritos el comando `reglas` (D20), no cada escaneo. `omitidas`
        // sigue recogiendo las fallas de las allowlists, que sí se compilan aquí.
        let regex_src = r.regex.clone();
        let path = r.path.as_ref().and_then(|p| compila(p).ok());
        let keywords = if r.keywords.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&r.keywords)
                .ok()
        };
        let mut permitidos = Vec::new();
        if let Some(a) = &r.allowlist {
            permitidos.push(compila_lista(a, omitidas, &r.id));
        }
        for a in &r.allowlists {
            permitidos.push(compila_lista(a, omitidas, &r.id));
        }
        ReglaComp {
            id: r.id.clone(),
            descripcion: r.description.clone().unwrap_or_default(),
            regex_src,
            regex: OnceCell::new(),
            path,
            entropy: r.entropy,
            secret_group: r.secret_group,
            keywords,
            permitidos,
        }
    }

    /// Cuántas reglas quedaron activas (con patrón de contenido o de `path`).
    #[must_use]
    pub fn reglas_activas(&self) -> usize {
        self.reglas.iter().filter(|r| r.tiene_patron() || r.path.is_some()).count()
    }

    /// Fuerza la compilación de TODAS las reglas y devuelve las que no compilaron
    /// (fuente presente pero regex inválida). Es la auditoría D20 «a gritos»: el
    /// escaneo confía en el catálogo, y este método —que corre el comando
    /// `reglas` y una prueba— es el positivo de control de que no perdió reglas.
    #[must_use]
    pub fn reglas_rotas(&self) -> Vec<String> {
        self.reglas
            .iter()
            .filter(|r| r.tiene_patron() && r.regex().is_none())
            .map(|r| r.id.clone())
            .collect()
    }

    /// ¿La ruta está excluida por la lista global de paths?
    #[must_use]
    pub fn ruta_excluida(&self, ruta: &str) -> bool {
        self.global.paths.iter().any(|re| re.is_match(ruta))
    }

    /// Escanea el contenido de un archivo. `ruta` es solo para reportar y para
    /// las reglas basadas en `path`.
    #[must_use]
    pub fn escanear(&self, ruta: &str, contenido: &str) -> Vec<Hallazgo> {
        let mut hallazgos = Vec::new();
        if self.ruta_excluida(ruta) {
            return hallazgos;
        }
        for regla in &self.reglas {
            // Regla por ruta: casa contra el nombre del archivo, no el contenido.
            if let Some(pre) = &regla.path {
                if pre.is_match(ruta) && !regla.tiene_patron() {
                    hallazgos.push(Hallazgo {
                        regla: regla.id.clone(),
                        descripcion: regla.descripcion.clone(),
                        ruta: ruta.to_string(),
                        linea: 1,
                        secreto: format!("<file with sensitive path: {ruta}>"),
                    });
                    continue;
                }
            }
            // Sin patrón de contenido no hay nada más que hacer.
            if !regla.tiene_patron() {
                continue;
            }

            // Prefiltro (barato) ANTES de compilar: si la regla declara keywords,
            // al menos una debe aparecer. Así el contenido común no compila regex.
            if let Some(ac) = &regla.keywords {
                if !ac.is_match(contenido) {
                    continue;
                }
            }

            // Compilación perezosa: solo aquí, tras pasar el prefiltro.
            let Some(re) = regla.regex() else { continue };

            for m in re.captures_iter(contenido) {
                let todo = m.get(0).expect("el grupo 0 siempre existe");
                let secreto = self.extrae_secreto(regla, &m, todo.as_str());
                let inicio = todo.start();
                let linea_txt = linea_de(contenido, inicio);

                if linea_txt.contains("chaquen:allow") || linea_txt.contains("gitleaks:allow") {
                    continue;
                }
                if self.permitido(&self.global, &secreto, todo.as_str(), linea_txt) {
                    continue;
                }
                if regla.permitidos.iter().any(|p| self.permitido(p, &secreto, todo.as_str(), linea_txt)) {
                    continue;
                }
                if let Some(umbral) = regla.entropy {
                    if shannon(&secreto) <= umbral {
                        continue;
                    }
                }
                hallazgos.push(Hallazgo {
                    regla: regla.id.clone(),
                    descripcion: regla.descripcion.clone(),
                    ruta: ruta.to_string(),
                    linea: numero_de_linea(contenido, inicio),
                    secreto,
                });
            }
        }
        hallazgos
    }

    fn extrae_secreto(&self, regla: &ReglaComp, m: &regex::Captures, todo: &str) -> String {
        if let Some(g) = regla.secret_group {
            if let Some(mm) = m.get(g) {
                return mm.as_str().to_string();
            }
        }
        // Sin grupo declarado: el grupo 1 si existe, si no el match completo.
        if m.len() > 1 {
            if let Some(mm) = m.get(1) {
                return mm.as_str().to_string();
            }
        }
        todo.to_string()
    }

    fn permitido(&self, p: &PermitidosComp, secreto: &str, todo: &str, linea: &str) -> bool {
        let objetivo = match p.objetivo {
            Objetivo::Secreto => secreto,
            Objetivo::Match => todo,
            Objetivo::Linea => linea,
        };
        if p.regexes.iter().any(|re| re.is_match(objetivo)) {
            return true;
        }
        let sl = secreto.to_lowercase();
        p.stopwords.iter().any(|w| sl.contains(w.as_str()))
    }
}

/// La línea completa que contiene el byte `inicio`.
fn linea_de(contenido: &str, inicio: usize) -> &str {
    let ini = contenido[..inicio].rfind('\n').map_or(0, |i| i + 1);
    let fin = contenido[inicio..].find('\n').map_or(contenido.len(), |i| inicio + i);
    &contenido[ini..fin]
}

fn numero_de_linea(contenido: &str, inicio: usize) -> usize {
    contenido[..inicio].bytes().filter(|&b| b == b'\n').count() + 1
}

#[cfg(test)]
mod pruebas {
    use super::{enmascarar, Motor};

    #[test]
    fn el_catalogo_embebido_compila() {
        let m = Motor::embebido().expect("el catálogo embebido debe parsear");
        // Positivo de control: hay reglas activas de verdad, no una lista vacía
        // que pasaría todas las pruebas por no mirar nada (D30/D33).
        assert!(m.reglas_activas() > 180, "reglas activas: {}", m.reglas_activas());
    }

    #[test]
    fn enmascara_deja_puntas() {
        assert_eq!(enmascarar("AKIAIOSFODNN7EXAMPLE"), "AKI**************PLE");
        assert_eq!(enmascarar("corto"), "*****");
    }

    #[test]
    fn ninguna_regla_se_pierde_al_compilar_perezoso() {
        // D20: la compilación perezosa no debe ocultar una regla que no compila.
        // Fuerza las 221 fuentes y exige que TODAS compilen (lo que antes
        // garantizaba la compilación ávida al arrancar).
        let m = Motor::embebido().expect("catálogo embebido");
        let rotas = m.reglas_rotas();
        assert!(rotas.is_empty(), "reglas que no compilan: {rotas:?}");
    }
}
