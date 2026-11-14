// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: LicenseRef-Propietario
//! Transporte MCP para chaquen: JSON-RPC 2.0 por stdio (un mensaje JSON por línea).
//!
//! Convierte el detector de secretos en un servidor MCP que un agente llama antes
//! de confiar en —o escribir— contenido. El foso frente a los escáneres de git
//! genéricos: el ángulo **agente/pre-escritura** (`scan_before_write`) y que
//! **SIEMPRE enmascara** — el secreto en claro NUNCA sale al contexto del modelo.
//!
//! Reusa `Motor` (D9). Métodos: initialize, tools/list, tools/call, ping.
//! Tools: scan_text, scan_before_write, scan_file, scan_json.

use crate::motor::{Hallazgo, Motor};
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};

const VERSIONES: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
/// Tope de lectura de `scan_file`: sin esto un archivo enorme tumba el servicio (DoS).
const LIMITE_ARCHIVO: u64 = 8 * 1024 * 1024;

fn ok(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn error_tool(texto: String) -> Value {
    json!({"content": [{"type": "text", "text": texto}], "isError": true})
}

/// Junta recursivamente los VALORES string de un JSON (no las claves).
fn extraer_texto(v: &Value, acc: &mut String) {
    match v {
        Value::String(s) => {
            acc.push_str(s);
            acc.push('\n');
        }
        Value::Array(a) => a.iter().for_each(|x| extraer_texto(x, acc)),
        Value::Object(o) => o.values().for_each(|x| extraer_texto(x, acc)),
        _ => {}
    }
}

/// Texto legible. SIEMPRE enmascara el secreto.
fn resumen(hs: &[Hallazgo]) -> String {
    if hs.is_empty() {
        return "✅ No secrets detected.".to_string();
    }
    let lista = hs
        .iter()
        .map(|h| {
            format!(
                "  - [{}] line {}: {} ({})",
                h.regla,
                h.linea,
                h.secreto_enmascarado(),
                h.descripcion
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "⚠️ {} SECRET(S) detected (masked):\n{lista}\n\
         Do NOT write, commit or expose this content. If it already leaked, ROTATE the credential.",
        hs.len()
    )
}

/// Salida ESTRUCTURADA. Nunca incluye el secreto en claro (solo enmascarado).
fn estructurado(hs: &[Hallazgo]) -> Value {
    let items: Vec<Value> = hs
        .iter()
        .map(|h| {
            json!({
                "rule": h.regla,
                "description": h.descripcion,
                "line": h.linea,
                "severity": "high",
                "masked": h.secreto_enmascarado(),
            })
        })
        .collect();
    json!({
        "clean": hs.is_empty(),
        "count": hs.len(),
        "highestSeverity": if hs.is_empty() { Value::Null } else { json!("high") },
        "findings": items,
    })
}

fn resultado_scan(hs: &[Hallazgo]) -> Value {
    json!({
        "content": [{"type": "text", "text": resumen(hs)}],
        "structuredContent": estructurado(hs),
        "isError": false
    })
}

fn leer_acotado(ruta: &str) -> io::Result<String> {
    let f = std::fs::File::open(ruta)?;
    let mut s = String::new();
    f.take(LIMITE_ARCHIVO).read_to_string(&mut s)?;
    Ok(s)
}

fn lista_tools() -> Value {
    json!({
        "tools": [
            {
                "name": "scan_text",
                "description": "Scan a text for secrets (credentials, tokens, keys) with 220+ rules. Returns findings ALWAYS masked, with text and structuredContent (clean, count, findings).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Text to inspect."},
                        "path": {"type": "string", "description": "Optional path (some rules depend on the file name, e.g. .env)."}
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "scan_before_write",
                "description": "Leak guard for agents: inspects the content an agent is about to WRITE to a path, before writing it. If it carries a secret, it reports it (masked) so it is NOT written/committed. Ideal as a step before any write.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Destination path of the write."},
                        "content": {"type": "string", "description": "Content about to be written."}
                    },
                    "required": ["path", "content"]
                }
            },
            {
                "name": "scan_file",
                "description": "Reads a local file (bounded, DoS-proof read) and scans it for secrets.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path of the file to inspect."}
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "scan_json",
                "description": "Scans an arbitrary JSON value (e.g. the raw response of another MCP tool): extracts all of its strings and looks for secrets in them.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "json": {"description": "JSON value to inspect."}
                    },
                    "required": ["json"]
                }
            }
        ]
    })
}

fn ejecutar_tool(params: &Value, motor: &Motor) -> Value {
    let nombre = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(Value::Null);
    match nombre {
        "scan_text" => match args.get("text").and_then(Value::as_str) {
            Some(texto) => {
                let ruta = args.get("path").and_then(Value::as_str).unwrap_or("input.txt");
                resultado_scan(&motor.escanear(ruta, texto))
            }
            None => error_tool("Missing required argument 'text' (string).".to_string()),
        },
        "scan_before_write" => {
            let path = args.get("path").and_then(Value::as_str);
            let content = args.get("content").and_then(Value::as_str);
            match (path, content) {
                (Some(p), Some(c)) => resultado_scan(&motor.escanear(p, c)),
                _ => error_tool("Missing 'path' and/or 'content' (strings).".to_string()),
            }
        }
        "scan_file" => match args.get("path").and_then(Value::as_str) {
            Some(ruta) => match leer_acotado(ruta) {
                Ok(contenido) => resultado_scan(&motor.escanear(ruta, &contenido)),
                Err(e) => error_tool(format!("Could not read '{ruta}': {e}")),
            },
            None => error_tool("Missing required argument 'path' (string).".to_string()),
        },
        "scan_json" => match args.get("json") {
            Some(v) if !v.is_null() => {
                let mut acc = String::new();
                extraer_texto(v, &mut acc);
                resultado_scan(&motor.escanear("input.json", &acc))
            }
            _ => error_tool("Missing required argument 'json'.".to_string()),
        },
        otro => error_tool(format!("Unknown tool: '{otro}'.")),
    }
}

fn negociar_version(pedida: Option<&str>) -> &'static str {
    match pedida {
        Some(p) => VERSIONES.iter().copied().find(|v| *v == p).unwrap_or(VERSIONES[0]),
        None => VERSIONES[0],
    }
}

/// Procesa un mensaje JSON-RPC parseado. `Some` si es petición; `None` si es notificación.
pub fn manejar(req: &Value, motor: &Motor) -> Option<Value> {
    let metodo = req.get("method").and_then(Value::as_str);
    let id = req.get("id")?;
    let metodo = match metodo {
        Some(m) => m,
        None => return Some(error(id, -32600, "Invalid request: missing 'method'")),
    };
    let resp = match metodo {
        "initialize" => {
            let pedida = req
                .get("params")
                .and_then(|p| p.get("protocolVersion"))
                .and_then(Value::as_str);
            ok(
                id,
                json!({
                    "protocolVersion": negociar_version(pedida),
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "chaquen", "version": env!("CARGO_PKG_VERSION")}
                }),
            )
        }
        "tools/list" => ok(id, lista_tools()),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            ok(id, ejecutar_tool(&params, motor))
        }
        "ping" => ok(id, json!({})),
        otro => error(id, -32601, &format!("Unsupported method: {otro}")),
    };
    Some(resp)
}

/// Bucle stdio del servidor MCP. stdout SOLO lleva JSON-RPC (los logs van a stderr).
pub fn servir(motor: &Motor) {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut salida = stdout.lock();
    for linea in stdin.lock().lines() {
        let linea = match linea {
            Ok(l) => l,
            Err(_) => break,
        };
        if linea.trim().is_empty() {
            continue;
        }
        let respuesta: Option<Value> = match serde_json::from_str::<Value>(&linea) {
            Ok(req) => manejar(&req, motor),
            Err(e) => Some(json!({
                "jsonrpc": "2.0", "id": Value::Null,
                "error": {"code": -32700, "message": format!("Invalid JSON: {e}")}
            })),
        };
        if let Some(resp) = respuesta {
            if writeln!(salida, "{resp}").is_err() || salida.flush().is_err() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn motor() -> Motor {
        Motor::embebido().expect("catálogo embebido")
    }

    fn call(nombre: &str, args: Value) -> Value {
        let req = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":nombre,"arguments":args}});
        manejar(&req, &motor()).unwrap()
    }

    // Aguja fiable (la misma que usan las pruebas de chaquen): un PAT de GitHub.
    const SECRETO: &str = "ghp_wF3kZ9mQ2xB7nL5vC8rT1yH4jP6sD0aG2eU9";

    #[test]
    fn initialize_serverinfo() {
        let r = manejar(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}), &motor()).unwrap();
        assert_eq!(r["result"]["serverInfo"]["name"], "chaquen");
        assert_eq!(r["result"]["protocolVersion"], "2025-03-26");
    }

    #[test]
    fn tools_list_tiene_scan_before_write() {
        let r = manejar(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}), &motor()).unwrap();
        let nombres: Vec<&str> = r["result"]["tools"].as_array().unwrap()
            .iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(nombres.contains(&"scan_text"));
        assert!(nombres.contains(&"scan_before_write"));
        assert!(nombres.contains(&"scan_file"));
        assert!(nombres.contains(&"scan_json"));
    }

    // D33: ROJO — un secreto se detecta y sale ENMASCARADO (nunca en claro).
    #[test]
    fn scan_text_detecta_y_enmascara() {
        let r = call("scan_text", json!({"text": SECRETO}));
        assert_eq!(r["result"]["structuredContent"]["clean"], false);
        assert_eq!(r["result"]["structuredContent"]["highestSeverity"], "high");
        let txt = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(txt.contains('*'), "el secreto debe salir enmascarado: {txt}");
        // el enmascarado no debe reproducir el cuerpo del secreto (solo 3+3 extremos)
        assert!(!txt.contains("wF3kZ9mQ"), "no debe filtrar el secreto en claro");
    }

    // VERDE — texto limpio no dispara.
    #[test]
    fn scan_text_limpio() {
        let r = call("scan_text", json!({"text": "esto es una nota normal sin credenciales"}));
        assert_eq!(r["result"]["structuredContent"]["clean"], true);
    }

    // El foso: scan_before_write caza el secreto antes de escribir.
    #[test]
    fn scan_before_write_atrapa_el_secreto() {
        let r = call("scan_before_write", json!({"path": "config.pem", "content": SECRETO}));
        assert_eq!(r["result"]["structuredContent"]["clean"], false);
    }

    #[test]
    fn scan_before_write_sin_args_es_error() {
        let r = call("scan_before_write", json!({"path": "x"}));
        assert_eq!(r["result"]["isError"], true);
    }

    #[test]
    fn scan_file_inexistente_es_error() {
        let r = call("scan_file", json!({"path": "/no/existe/zzz.txt"}));
        assert_eq!(r["result"]["isError"], true);
    }

    #[test]
    fn metodo_desconocido_error_32601() {
        let r = manejar(&json!({"jsonrpc":"2.0","id":9,"method":"foo/bar"}), &motor()).unwrap();
        assert_eq!(r["error"]["code"], -32601);
    }

    #[test]
    fn notificacion_no_responde() {
        assert!(manejar(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}), &motor()).is_none());
    }
}
