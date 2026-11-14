// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: LicenseRef-Propietario
//! CLI de chaquen: escanea un árbol o texto por stdin.

use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use walkdir::WalkDir;

use chaquen::Motor;

#[derive(Parser)]
#[command(name = "chaquen", about = "Secret scanner — guards the boundary between the private and the exposed.")]
struct Cli {
    #[command(subcommand)]
    orden: Orden,
    /// Show the secrets in the clear (masked by default).
    #[arg(long, global = true)]
    show: bool,
}

#[derive(Subcommand)]
enum Orden {
    /// Scan a file or directory (recursive).
    Scan {
        /// Root path.
        path: String,
        /// Maximum file size to read, in KiB (larger files are skipped).
        #[arg(long, default_value_t = 10240)]
        max_kib: u64,
    },
    /// Read text from stdin and report findings (to wire up as a guard).
    Text {
        /// Path label for the report.
        #[arg(long, default_value = "<stdin>")]
        path: String,
    },
    /// Scan the entire git HISTORY (catches secrets deleted from the tree but
    /// alive in past commits). Run before making a repo public.
    History {
        /// Path to the git repository.
        path: String,
    },
    /// `PreToolUse` guard: read the event's JSON payload from stdin and, if the
    /// content about to be written contains a secret, warn via
    /// `additionalContext`. NEVER blocks (always exits 0).
    Hook,
    /// Diagnostics: how many rules loaded and which ones were skipped.
    Rules,
    /// MCP server (JSON-RPC 2.0 over stdio): exposes scan_text, scan_before_write,
    /// scan_file and scan_json so an agent can detect secrets (always masked).
    Mcp,
    /// Content-hash review receipts (D31 without commits): anchor a verdict to
    /// an artifact's bytes so a backup/cloud-sync restore cannot silently escape
    /// re-review. UNCHANGED/CHANGED/NEW/GONE/UNRESOLVED, and RECEIPT:NONE as a
    /// first-class "not assessed" (never a false clean).
    Receipt {
        #[command(subcommand)]
        accion: AccionRecibo,
    },
}

#[derive(Subcommand)]
enum AccionRecibo {
    /// Stamp the current content hash of each path into the receipt (append-only).
    Hash {
        /// Receipt file (created/appended).
        #[arg(long)]
        receipt: String,
        /// Paths to stamp (a shell-expanded glob is fine).
        rutas: Vec<String>,
    },
    /// Compare each path against the receipt. Exit 0 all unchanged, 1 something
    /// invalidated the verdict, 3 no baseline (NOT assessed — not clean).
    Check {
        /// Receipt file to read as the baseline.
        #[arg(long)]
        receipt: String,
        /// Paths to check (the receipt's own list is always compared too).
        rutas: Vec<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let motor = match Motor::embebido() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("chaquen: could not load the catalog: {e}");
            return ExitCode::from(2);
        }
    };

    // A gritos si el catálogo perdió reglas al compilar (D20).
    if !motor.omitidas.is_empty() {
        eprintln!(
            "chaquen: WARNING — {} catalog pattern(s) did not compile in the Rust engine and were skipped:",
            motor.omitidas.len()
        );
        for (id, err) in &motor.omitidas {
            eprintln!("  - {id}: {err}");
        }
    }

    match cli.orden {
        Orden::Mcp => {
            eprintln!("chaquen {} — MCP stdio ready", env!("CARGO_PKG_VERSION"));
            chaquen::mcp::servir(&motor);
            ExitCode::SUCCESS
        }
        Orden::Rules => {
            println!("active rules: {}", motor.reglas_activas());
            println!("allowlist patterns skipped: {}", motor.omitidas.len());
            // Auditoría D20: fuerza la compilación de TODAS las reglas (que el
            // escaneo hace perezosa) y grita si alguna fuente no compila.
            let rotas = motor.reglas_rotas();
            println!("rules with a regex that does not compile: {}", rotas.len());
            for id in &rotas {
                eprintln!("  - {id}");
            }
            if rotas.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Orden::History { path } => match chaquen::escanear_historia(&motor, &path) {
            Ok(hs) => reportar(&hs, cli.show),
            Err(e) => {
                eprintln!("chaquen: {e}");
                ExitCode::from(2)
            }
        },
        Orden::Hook => {
            let mut buf = String::new();
            // Ante cualquier problema de lectura: calla y deja pasar (advisory).
            if std::io::stdin().read_to_string(&mut buf).is_err() {
                return ExitCode::SUCCESS;
            }
            if let Some(mut aviso) = chaquen::hook::evaluar(&motor, &buf) {
                if let Some(nota) = binario_desactualizado() {
                    aviso = format!("{nota}\n{aviso}");
                }
                let salida = serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "additionalContext": aviso
                    }
                });
                println!("{salida}");
            }
            // NUNCA bloquea: un informativo sale 0 aunque encuentre algo.
            ExitCode::SUCCESS
        }
        Orden::Text { path } => {
            let mut buf = String::new();
            if std::io::stdin().read_to_string(&mut buf).is_err() {
                eprintln!("chaquen: stdin is not valid UTF-8 text");
                return ExitCode::from(2);
            }
            let hs = motor.escanear(&path, &buf);
            reportar(&hs, cli.show)
        }
        Orden::Scan { path, max_kib } => {
            let mut total = Vec::new();
            let tope = max_kib * 1024;
            // Positivo de control (D30): un «0 hallazgos» solo vale si el escaneo
            // recorrió algo. Sin este denominador, `scan <ruta-mal-escrita>` da el
            // mismo «no findings» tranquilizador que un árbol real y limpio.
            let mut archivos = 0u64;
            let mut bytes = 0u64;
            for entrada in WalkDir::new(&path).into_iter().filter_map(Result::ok) {
                if !entrada.file_type().is_file() {
                    continue;
                }
                let p = entrada.path();
                if salta_ruta(p) {
                    continue;
                }
                let Ok(meta) = entrada.metadata() else { continue };
                if meta.len() > tope {
                    continue;
                }
                // Solo texto UTF-8; los binarios se saltan (leer como bytes y validar).
                let Ok(datos) = std::fs::read(p) else { continue };
                let Ok(texto) = String::from_utf8(datos) else { continue };
                archivos += 1;
                bytes += texto.len() as u64;
                let ruta_str = p.to_string_lossy();
                total.extend(motor.escanear(&ruta_str, &texto));
            }
            // El denominador va a stderr SIEMPRE (no ensucia la lista de stdout).
            eprintln!(
                "chaquen: scanned {archivos} text file(s), {bytes} byte(s), with {} active rule(s).",
                motor.reglas_activas()
            );
            if archivos == 0 {
                // NO EVALUADO, no «limpio»: el camino que hallaría un secreto no
                // se recorrió (ruta vacía, inexistente o toda saltada). Código 3,
                // distinto del 0 de un árbol real sin hallazgos (D30).
                eprintln!(
                    "chaquen: NOT ASSESSED — 0 files were scanned under «{path}»; this is NOT a clean result."
                );
                return ExitCode::from(3);
            }
            reportar(&total, cli.show)
        }
        Orden::Receipt { accion } => ejecutar_recibo(accion),
    }
}

/// `chaquen receipt hash|check`: recibos de revisión por hash de contenido (D31).
fn ejecutar_recibo(accion: AccionRecibo) -> ExitCode {
    use chaquen::recibo;
    match accion {
        AccionRecibo::Hash { receipt, rutas } => {
            if rutas.is_empty() {
                eprintln!("chaquen receipt hash: no paths given.");
                return ExitCode::from(2);
            }
            let (lineas, avisos) = recibo::estampar_lineas(&rutas, recibo::leer_disco);
            // Append-only: añade al recibo sin borrar la historia previa (D22).
            use std::io::Write as _;
            let abrir = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&receipt);
            match abrir {
                Ok(mut f) => {
                    if let Err(e) = f.write_all(lineas.as_bytes()) {
                        eprintln!("chaquen receipt hash: could not write {receipt}: {e}");
                        return ExitCode::from(2);
                    }
                }
                Err(e) => {
                    eprintln!("chaquen receipt hash: could not open {receipt}: {e}");
                    return ExitCode::from(2);
                }
            }
            let estampadas = lineas.lines().count();
            eprintln!("{}\t{estampadas} stamped", recibo::SENTINEL);
            // D20: nombra lo que NO se pudo estampar en vez de callarlo.
            for (ruta, estado) in &avisos {
                eprintln!("chaquen receipt hash: {} {ruta} — not stamped", estado.etiqueta());
            }
            ExitCode::SUCCESS
        }
        AccionRecibo::Check { receipt, rutas } => {
            let texto = std::fs::read_to_string(&receipt).ok();
            let reporte = recibo::verificar(texto.as_deref(), &rutas, recibo::leer_disco);
            print!("{}", reporte.render());
            ExitCode::from(reporte.codigo())
        }
    }
}

/// Salta el árbol `.git` interno (los objetos son binarios comprimidos; la
/// historia se escanea con otra técnica, no aquí).
fn salta_ruta(p: &Path) -> bool {
    p.components().any(|c| c.as_os_str() == ".git")
}

/// D38: un binario viejo junto a una fuente nueva se ve idéntico a un guardián
/// al día. Si algún `.rs` de `src/` es más reciente que este ejecutable, lo
/// dice DENTRO del propio aviso del hook en vez de callarlo.
fn binario_desactualizado() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let exe_mtime = exe.metadata().ok()?.modified().ok()?;
    // exe = <crate>/target/release/chaquen  →  <crate>/src
    let src = exe.parent()?.parent()?.parent()?.join("src");
    let mut mas_nuevo = std::time::SystemTime::UNIX_EPOCH;
    visitar_rs(&src, &mut mas_nuevo);
    if mas_nuevo > exe_mtime {
        Some("[⚠ chaquen: the source is newer than the binary — rebuild me with `cargo build --release`]".to_string())
    } else {
        None
    }
}

fn visitar_rs(dir: &Path, mas_nuevo: &mut std::time::SystemTime) {
    let Ok(entradas) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entradas.flatten() {
        let ruta = e.path();
        if ruta.is_dir() {
            visitar_rs(&ruta, mas_nuevo);
        } else if ruta.extension().is_some_and(|x| x == "rs") {
            if let Ok(m) = e.metadata().and_then(|md| md.modified()) {
                if m > *mas_nuevo {
                    *mas_nuevo = m;
                }
            }
        }
    }
}

fn reportar(hs: &[chaquen::Hallazgo], mostrar: bool) -> ExitCode {
    if hs.is_empty() {
        eprintln!("chaquen: no findings.");
        return ExitCode::SUCCESS;
    }
    for h in hs {
        let secreto = if mostrar { h.secreto.clone() } else { h.secreto_enmascarado() };
        println!("{}:{}  [{}]  {}", h.ruta, h.linea, h.regla, secreto);
    }
    eprintln!("chaquen: {} finding(s).", hs.len());
    // Código != 0 para que un guardián/CI lo vea rojo.
    ExitCode::from(1)
}
