// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: LicenseRef-Propietario
//! Modelo de datos del catálogo de reglas (`reglas.toml`).
//!
//! El formato es el de gitleaks (vendorizado como DATO, MIT © Zachary Rice; ver
//! NOTICE). Aquí solo se declara la forma; la lógica vive en [`crate::motor`].

use serde::Deserialize;

/// El catálogo completo: reglas + listas de permitidos globales.
#[derive(Debug, Deserialize)]
pub struct Catalogo {
    #[serde(default)]
    pub title: Option<String>,
    /// Lista de permitidos GLOBAL (`[allowlist]`, singular en el formato viejo).
    #[serde(default)]
    pub allowlist: Option<Permitidos>,
    /// Forma nueva plural (`[[allowlists]]`); se fusiona con la singular.
    #[serde(default)]
    pub allowlists: Vec<Permitidos>,
    #[serde(default)]
    pub rules: Vec<Regla>,
}

/// Una regla de detección.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Regla {
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
    /// El patrón. Puede faltar en reglas que solo casan por `path`.
    #[serde(default)]
    pub regex: Option<String>,
    /// Patrón sobre la RUTA del archivo (no sobre el contenido).
    #[serde(default)]
    pub path: Option<String>,
    /// Umbral de entropía: se descarta el hallazgo si `shannon(secreto) <= entropy`.
    #[serde(default)]
    pub entropy: Option<f64>,
    /// Grupo de captura que ES el secreto (1-indexado). Sin él: grupo 1 si existe,
    /// o el match completo.
    #[serde(default)]
    pub secret_group: Option<usize>,
    /// Palabras que deben aparecer para que valga la pena correr la regex (prefiltro).
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Listas de permitidos POR REGLA (`[[rules.allowlists]]`).
    #[serde(default)]
    pub allowlists: Vec<Permitidos>,
    /// Forma vieja singular por regla.
    #[serde(default)]
    pub allowlist: Option<Permitidos>,
}

/// Una lista de permitidos (global o por regla).
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Permitidos {
    #[serde(default)]
    pub description: Option<String>,
    /// Rutas (regex) que excluyen el archivo entero.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Regex que, si casan el objetivo, descartan el hallazgo.
    #[serde(default)]
    pub regexes: Vec<String>,
    /// Sobre qué texto se aplican las `regexes`: "secret" (defecto), "match" o "line".
    #[serde(default)]
    pub regex_target: Option<String>,
    /// Subcadenas que, si aparecen en el secreto, lo descartan.
    #[serde(default)]
    pub stopwords: Vec<String>,
}
