// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: LicenseRef-Propietario
//! Escaneo de la HISTORIA de git, no solo del árbol de trabajo.
//!
//! La idea (de gitleaks/trufflehog): un secreto que se commiteó y luego se borró
//! del árbol **sigue vivo en la historia** — y quien clone el repo lo obtiene. El
//! escaneo del árbol (`escanear`) no lo ve; este sí. Es la comprobación que toca
//! hacer ANTES de hacer público un repo.
//!
//! Técnica: `git log -p -U0 --all --full-history` reduce toda la historia a un
//! solo flujo de diffs (mucho más barato que un checkout por commit); se toman las
//! líneas AÑADIDAS (`+`) agrupadas por (commit, archivo) y se pasan al mismo motor
//! de detección. No hace falta más aparato que `git` y `std::process`.

use std::process::Command;

use crate::{Hallazgo, Motor};

/// Escanea la historia completa de un repositorio git.
///
/// # Errors
/// Falla si `git` no se puede ejecutar o `git log` devuelve un error (p. ej. la
/// ruta no es un repositorio).
pub fn escanear_historia(motor: &Motor, repo: &str) -> Result<Vec<Hallazgo>, String> {
    let salida = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "log", "-p", "-U0", "--all", "--full-history", "--no-color",
            "--format=commit %H",
        ])
        .output()
        .map_err(|e| format!("could not run git: {e}"))?;

    if !salida.status.success() {
        return Err(format!(
            "git log failed ({}): {}",
            salida.status,
            String::from_utf8_lossy(&salida.stderr).trim()
        ));
    }

    let texto = String::from_utf8_lossy(&salida.stdout);
    let mut hallazgos = Vec::new();
    let mut sha = String::new();
    let mut archivo = String::new();
    let mut bloque = String::new();

    for linea in texto.lines() {
        if let Some(resto) = linea.strip_prefix("commit ") {
            vaciar(motor, &sha, &archivo, &mut bloque, &mut hallazgos);
            sha = resto.trim().to_string();
        } else if let Some(p) = linea.strip_prefix("+++ b/") {
            vaciar(motor, &sha, &archivo, &mut bloque, &mut hallazgos);
            archivo = p.to_string();
        } else if linea.starts_with("+++") || linea.starts_with("---") {
            // Encabezados del diff (no son contenido añadido).
        } else if let Some(anadida) = linea.strip_prefix('+') {
            bloque.push_str(anadida);
            bloque.push('\n');
        }
    }
    vaciar(motor, &sha, &archivo, &mut bloque, &mut hallazgos);
    Ok(hallazgos)
}

/// Escanea el bloque de líneas añadidas acumulado y lo vacía. La `ruta` del
/// hallazgo lleva el commit corto + el archivo, para poder ubicarlo en la historia.
fn vaciar(motor: &Motor, sha: &str, archivo: &str, bloque: &mut String, out: &mut Vec<Hallazgo>) {
    if bloque.is_empty() {
        return;
    }
    // Se escanea con la ruta LIMPIA (`archivo`), no con «SHA archivo»: si no, las
    // allowlists por ruta (p. ej. saltar `vendor/`) no casan, porque el SHA
    // antepuesto rompe el ancla `^`/`/` del patrón. El SHA se añade DESPUÉS, solo
    // para poder ubicar el hallazgo en la historia.
    let corto = &sha[..sha.len().min(12)];
    let mut hs = motor.escanear(archivo, bloque);
    for h in &mut hs {
        h.ruta = if archivo.is_empty() {
            corto.to_string()
        } else {
            format!("{corto} {archivo}")
        };
    }
    out.extend(hs);
    bloque.clear();
}

#[cfg(test)]
mod pruebas {
    use super::escanear_historia;
    use crate::Motor;
    use std::process::Command;

    fn git(dir: &std::path::Path, args: &[&str]) {
        let ok = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .expect("git")
            .status
            .success();
        assert!(ok, "git {args:?} falló");
    }

    #[test]
    fn caza_un_secreto_borrado_del_arbol_pero_vivo_en_la_historia() {
        // D33 por la vía real: el escaneo del ÁRBOL no vería este secreto (se
        // borró); el de la HISTORIA sí. Esa es justo la discriminación que da valor
        // a este modo.
        let dir = std::env::temp_dir().join(format!("chaquen-hist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-q"]);

        // Commit 1: introduce un PAT de GitHub real (alta entropía, sin stopwords).
        let pat = "ghp_wF3kZ9mQ2xB7nL5vC8rT1yH4jP6sD0aG2eU9";
        std::fs::write(dir.join("config.js"), format!("const t = \"{pat}\";\n")).unwrap();
        git(&dir, &["add", "-A"]);
        git(&dir, &["commit", "-qm", "add config"]);

        // Commit 2: lo borra del árbol.
        std::fs::write(dir.join("config.js"), "const t = process.env.T;\n").unwrap();
        git(&dir, &["add", "-A"]);
        git(&dir, &["commit", "-qm", "quita el secreto"]);

        let motor = Motor::embebido().unwrap();

        // Control: el árbol ACTUAL ya no tiene el secreto.
        let arbol = motor.escanear("config.js", "const t = process.env.T;\n");
        assert!(arbol.is_empty(), "el árbol no debería tener el secreto: {arbol:?}");

        // La historia SÍ lo caza.
        let hist = escanear_historia(&motor, dir.to_str().unwrap()).unwrap();
        assert!(
            hist.iter().any(|h| h.secreto.contains("ghp_")),
            "la historia debía cazar el secreto borrado; hallazgos={hist:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn la_allowlist_por_ruta_aplica_en_la_historia() {
        // D33 por la vía real de `historia`: el MISMO secreto en `vendor/` (dep de
        // tercero, allowlisted) NO se reporta, pero en `src/` propio SÍ. Prueba que
        // el arreglo del SHA-antepuesto dejó funcionar el allowlist por ruta.
        let dir = std::env::temp_dir().join(format!("chaquen-hist-vendor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("vendor/axum/src")).unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        git(&dir, &["init", "-q"]);

        let pat = "ghp_wF3kZ9mQ2xB7nL5vC8rT1yH4jP6sD0aG2eU9";
        std::fs::write(dir.join("vendor/axum/src/lib.rs"), format!("const T:&str=\"{pat}\";\n")).unwrap();
        std::fs::write(dir.join("src/propio.rs"), format!("const T:&str=\"{pat}\";\n")).unwrap();
        git(&dir, &["add", "-A"]);
        git(&dir, &["commit", "-qm", "add"]);

        let motor = Motor::embebido().unwrap();
        let hist = escanear_historia(&motor, dir.to_str().unwrap()).unwrap();

        assert!(
            hist.iter().any(|h| h.ruta.contains("src/propio.rs")),
            "el secreto en src/ propio debía reportarse; hallazgos={hist:?}"
        );
        assert!(
            !hist.iter().any(|h| h.ruta.contains("vendor/")),
            "el secreto en vendor/ (allowlisted) NO debía reportarse; hallazgos={hist:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
