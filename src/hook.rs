// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: LicenseRef-Propietario
//! Adaptador de guardián `PreToolUse`.
//!
//! chaquen se engancha como hook INFORMATIVO sobre `Write`/`Edit`/`NotebookEdit`:
//! lee la carga JSON del evento, saca el CONTENIDO que se va a escribir y su
//! ruta, y si el motor huele un secreto emite un aviso por `additionalContext`
//! (el único canal medido que llega al modelo; ver CLAUDE.md 2026-08-05).
//!
//! **NUNCA bloquea.** Tapa el hueco que las reglas `deny` no cubren: esas
//! impiden LEER un secreto, no ESCRIBIRLO donde no debería estar (un `.env`
//! versionado, una credencial pegada en un fuente, un log). El listón de
//! «fallo real con fecha» de los guardianes que bloquean no aplica a un
//! informativo: un falso positivo aquí es una línea de contexto, no un comando
//! frenado.

use serde_json::Value;

use crate::{Hallazgo, Motor};

/// Saca `(ruta, contenido)` de una carga `PreToolUse` de las herramientas que
/// ESCRIBEN. Devuelve `None` si la herramienta no aporta contenido escribible
/// (otra herramienta, campo ausente, tipo inesperado) — el hook calla entonces.
pub fn contenido_escrito(raiz: &Value) -> Option<(String, String)> {
    let herramienta = raiz.get("tool_name")?.as_str()?;
    let ti = raiz.get("tool_input")?;
    let ruta = ti
        .get("file_path")
        .and_then(Value::as_str)
        .or_else(|| ti.get("notebook_path").and_then(Value::as_str))
        .unwrap_or("<escritura>")
        .to_string();
    let contenido: String = match herramienta {
        // Write reemplaza el archivo entero.
        "Write" => ti.get("content").and_then(Value::as_str)?.to_string(),
        // Edit escribe `new_string` (lo que ENTRA; `old_string` es lo que sale).
        "Edit" => ti.get("new_string").and_then(Value::as_str)?.to_string(),
        // NotebookEdit escribe el fuente nuevo de una celda.
        "NotebookEdit" => ti.get("new_source").and_then(Value::as_str)?.to_string(),
        // MultiEdit aplica varias ediciones: mira TODOS los `new_string`, o un
        // secreto colado en la segunda edición pasaría callado (D30).
        "MultiEdit" => {
            let edits = ti.get("edits").and_then(Value::as_array)?;
            let mut acc = String::new();
            for e in edits {
                if let Some(s) = e.get("new_string").and_then(Value::as_str) {
                    acc.push_str(s);
                    acc.push('\n');
                }
            }
            if acc.is_empty() {
                return None;
            }
            acc
        }
        _ => return None,
    };
    Some((ruta, contenido))
}

/// Evalúa una carga `PreToolUse`. `Some(aviso)` si el contenido a escribir trae
/// uno o más secretos; `None` si no hay nada que decir (incluida entrada rara:
/// es advisory, calla y deja pasar).
pub fn evaluar(motor: &Motor, entrada: &str) -> Option<String> {
    let raiz: Value = serde_json::from_str(entrada).ok()?;
    let (ruta, contenido) = contenido_escrito(&raiz)?;
    let hallazgos = motor.escanear(&ruta, &contenido);
    if hallazgos.is_empty() {
        return None;
    }
    Some(redactar_aviso(&ruta, &hallazgos))
}

/// El aviso que se entrega al modelo. Enmascara SIEMPRE el secreto (no se
/// revela en el contexto), nombra regla y línea, y ordena decirlo en la
/// respuesta (el `additionalContext` llega al contexto, no a la pantalla de
/// Juan — ver CLAUDE.md).
fn redactar_aviso(ruta: &str, hallazgos: &[Hallazgo]) -> String {
    let mut s = format!(
        "[⚠ chaquen: the write to «{ruta}» appears to contain {} secret(s) — \
         a real secret must NOT be left written in the tree (it stays in the commit, \
         leaves the machine, lingers in history). Confirm it is an example/placeholder \
         value and not a real credential; if it is real, do NOT write it. \
         Say so in your response:",
        hallazgos.len()
    );
    for h in hallazgos {
        s.push_str(&format!(
            "\n  - line {} [{}]: {}",
            h.linea,
            h.regla,
            h.secreto_enmascarado()
        ));
    }
    s.push(']');
    s
}
