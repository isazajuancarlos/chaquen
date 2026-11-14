// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: LicenseRef-Propietario
//! Banco pareado (D33) del guardián `PreToolUse` (`chaquen hook`). Cada sonda
//! con su pareja: la escritura que TIENE que avisar y la que TIENE que callar,
//! por el seam REAL (`chaquen::hook::evaluar`) — no por un arnés aparte, para
//! que el caso rojo falle por la misma vía que el hook en producción.
//!
//! El par discrimina por construcción: un mutante que siempre avisa rompe los
//! VERDES; uno que nunca avisa rompe los ROJOS. Ninguno pasa el banco entero.

use chaquen::hook::evaluar;
use chaquen::Motor;

/// Un PAT de GitHub realista (ghp_ + 36 alfanum): casa github-pat, entropía alta.
const PAT: &str = "ghp_wF3kZ9mQ2xB7nL5vC8rT1yH4jP6sD0aG2eU9";

fn motor() -> Motor {
    Motor::embebido().expect("catálogo embebido")
}

/// Carga `PreToolUse` mínima: herramienta + un campo de contenido en `tool_input`.
fn carga(tool: &str, campo: &str, ruta: &str, contenido: &str) -> String {
    serde_json::json!({
        "tool_name": tool,
        "tool_input": { "file_path": ruta, campo: contenido }
    })
    .to_string()
}

// ─────────────────────────── ROJOS (deben avisar) ───────────────────────────

#[test]
fn rojo_write_con_pat_en_content() {
    let c = carga("Write", "content", "/mnt/data/quipu/cfg.rs", &format!("let t = \"{PAT}\";"));
    let aviso = evaluar(&motor(), &c);
    assert!(aviso.is_some(), "Write con un PAT debía avisar");
}

#[test]
fn rojo_edit_con_pat_en_new_string() {
    // Edit escribe `new_string` (lo que ENTRA). Debe mirarse ese, no `old_string`.
    let c = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "/x/config.py",
            "old_string": "token = \"\"",
            "new_string": format!("token = \"{PAT}\"")
        }
    })
    .to_string();
    assert!(evaluar(&motor(), &c).is_some(), "Edit con PAT en new_string debía avisar");
}

#[test]
fn rojo_notebookedit_con_pat_en_new_source() {
    let c = serde_json::json!({
        "tool_name": "NotebookEdit",
        "tool_input": { "notebook_path": "/x/n.ipynb", "new_source": format!("k = '{PAT}'") }
    })
    .to_string();
    assert!(evaluar(&motor(), &c).is_some(), "NotebookEdit con PAT debía avisar");
}

#[test]
fn rojo_el_aviso_enmascara_el_secreto() {
    // Propiedad de seguridad: el secreto NUNCA viaja en claro al contexto.
    let c = carga("Write", "content", "/x/a.rs", &format!("\"{PAT}\""));
    let aviso = evaluar(&motor(), &c).expect("debía avisar");
    assert!(!aviso.contains(PAT), "el aviso filtró el secreto en claro: {aviso}");
    assert!(aviso.contains("ghp"), "el aviso debía mostrar el prefijo enmascarado");
}

#[test]
fn rojo_multiedit_con_pat_en_segunda_edicion() {
    // El secreto va en la SEGUNDA edición: si el hook solo mirara la primera,
    // pasaría callado (D30 — un punto ciego no se queja nunca).
    let c = serde_json::json!({
        "tool_name": "MultiEdit",
        "tool_input": {
            "file_path": "/x/s.rs",
            "edits": [
                { "old_string": "a", "new_string": "let a = 1;" },
                { "old_string": "b", "new_string": format!("let t = \"{PAT}\";") }
            ]
        }
    })
    .to_string();
    assert!(evaluar(&motor(), &c).is_some(), "MultiEdit con PAT en la 2ª edición debía avisar");
}

// ────────────────────────── VERDES (deben callar) ───────────────────────────

#[test]
fn verde_write_de_env_example_con_marcador() {
    // Un `.env.example` con placeholders no es un secreto (baja entropía / stopword).
    let c = carga("Write", "content", "/x/.env.example", "API_KEY=your-api-key-here\nSECRET=changeme\n");
    assert!(evaluar(&motor(), &c).is_none(), "un placeholder no debía avisar");
}

#[test]
fn verde_write_de_prosa_que_menciona_secretos() {
    // Prosa tipo CLAUDE.md: nombra secretos pero no contiene ningún VALOR.
    let c = carga(
        "Write",
        "content",
        "/x/CLAUDE.md",
        "nunca exponer el .env, el seed del OPRF ni las claves SSH privadas (id_ed25519)\n",
    );
    assert!(evaluar(&motor(), &c).is_none(), "la prosa sin valor secreto no debía avisar");
}

#[test]
fn verde_herramienta_que_no_escribe() {
    // Read no aporta contenido escribible: el hook no aplica.
    let c = serde_json::json!({ "tool_name": "Read", "tool_input": { "file_path": "/x" } }).to_string();
    assert!(evaluar(&motor(), &c).is_none(), "Read no debía disparar el hook");
}

#[test]
fn verde_json_malformado_calla() {
    // Advisory: ante entrada rara, calla y deja pasar (nunca revienta).
    assert!(evaluar(&motor(), "no soy json").is_none());
    assert!(evaluar(&motor(), "").is_none());
}

#[test]
fn verde_write_sin_campo_content() {
    let c = serde_json::json!({ "tool_name": "Write", "tool_input": { "file_path": "/x" } }).to_string();
    assert!(evaluar(&motor(), &c).is_none(), "sin content no hay nada que mirar");
}

#[test]
fn verde_edit_sin_secreto() {
    let c = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": { "file_path": "/x/main.rs", "new_string": "fn suma(a: i32, b: i32) -> i32 { a + b }" }
    })
    .to_string();
    assert!(evaluar(&motor(), &c).is_none(), "código normal no debía avisar");
}
