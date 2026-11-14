// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: LicenseRef-Propietario
//! E2E del transporte MCP: arranca el BINARIO real (`chaquen mcp`) y le habla
//! JSON-RPC 2.0 por stdio, como lo haría un agente (D28). Los tests de
//! `src/mcp.rs` ejercen el dispatcher `manejar()` de estructura a estructura;
//! eso mide el códec, no el producto. Aquí se cruza la frontera del proceso:
//! stdin real → bucle `servir()` → stdout real.
//!
//! Dos invariantes que SOLO esta capa puede comprobar:
//!   1. stdout lleva EXCLUSIVAMENTE JSON-RPC (los logs van a stderr); si se
//!      contaminara, un cliente MCP no podría parsear el stream.
//!   2. el secreto en claro NUNCA sale por stdout — es la promesa del producto.
//!      El control discrimina (D33/D30): exige a la vez que SÍ se detectó
//!      (clean=false, el camino se recorrió) y que NO se filtró el cuerpo.

use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

/// PAT de GitHub realista — el MISMO fixture que usa el resto del banco. No es
/// un secreto real; es la aguja validada contra el artefacto (D33).
const PAT: &str = "ghp_wF3kZ9mQ2xB7nL5vC8rT1yH4jP6sD0aG2eU9";
/// El cuerpo del PAT (sin los 3+3 extremos que el enmascarado conserva): esta
/// subcadena NO debe aparecer jamás en stdout.
const CUERPO_PAT: &str = "kZ9mQ2xB7nL5vC8rT1yH4jP6sD0a";

/// Arranca `chaquen mcp`, le entrega las líneas por stdin, cierra stdin (EOF ⇒
/// el servidor termina su bucle) y devuelve (stdout, stderr) completos.
fn correr_mcp(lineas: &[&str]) -> (String, String) {
    let mut hijo = Command::new(env!("CARGO_BIN_EXE_chaquen"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("arrancar el binario chaquen mcp");
    {
        let mut si = hijo.stdin.take().expect("stdin del hijo");
        for l in lineas {
            writeln!(si, "{l}").expect("escribir en stdin del hijo");
        }
    } // stdin se cae aquí → EOF → `servir()` sale del bucle
    let salida = hijo.wait_with_output().expect("esperar a chaquen mcp");
    (
        String::from_utf8_lossy(&salida.stdout).into_owned(),
        String::from_utf8_lossy(&salida.stderr).into_owned(),
    )
}

/// Las líneas no vacías de stdout, parseadas como JSON (una respuesta por línea).
fn respuestas(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).unwrap_or_else(|e| panic!("stdout no es JSON-RPC por línea: {e}\nlínea: {l}")))
        .collect()
}

/// Control POSITIVO (D30): el ciclo real initialize → tools/list → tools/call
/// por stdio produce 3 respuestas JSON-RPC correlacionadas por id.
#[test]
fn ciclo_initialize_list_call_por_stdio() {
    let (out, _err) = correr_mcp(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        &format!(r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"scan_text","arguments":{{"text":"token = {PAT}"}}}}}}"#),
    ]);
    let r = respuestas(&out);
    assert_eq!(r.len(), 3, "3 peticiones con id ⇒ 3 respuestas; stdout:\n{out}");
    assert_eq!(r[0]["id"], 1);
    assert_eq!(r[0]["result"]["serverInfo"]["name"], "chaquen");
    assert_eq!(r[0]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(r[1]["id"], 2);
    let ofrece_sbw = r[1]["result"]["tools"].as_array().unwrap()
        .iter().any(|t| t["name"].as_str() == Some("scan_before_write"));
    assert!(ofrece_sbw, "tools/list debe ofrecer scan_before_write");
    assert_eq!(r[2]["id"], 3);
    assert_eq!(r[2]["result"]["structuredContent"]["clean"], false, "debía detectar el PAT");
}

/// stdout lleva SOLO JSON-RPC; el banner de arranque va a stderr, no a stdout.
#[test]
fn stdout_no_se_contamina_con_logs() {
    let (out, err) = correr_mcp(&[r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#]);
    // toda línea no vacía de stdout parsea como JSON-RPC 2.0
    for v in respuestas(&out) {
        assert_eq!(v["jsonrpc"], "2.0", "línea de stdout sin marco JSON-RPC");
    }
    assert!(!out.contains("MCP stdio ready"), "el log no debe salir por stdout");
    assert!(err.contains("MCP stdio ready"), "el banner debe ir a stderr; stderr:\n{err}");
}

/// LA INVARIANTE DEL PRODUCTO (D33): un secreto a punto de escribirse se
/// reporta (clean=false) PERO su cuerpo en claro NUNCA aparece en stdout.
/// Rojo si el enmascarado se rompe; discrimina porque exige además que el
/// camino se recorrió (si no detectara, clean sería true y el assert cae).
#[test]
fn el_secreto_en_claro_nunca_sale_por_stdout() {
    let (out, _err) = correr_mcp(&[
        &format!(r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"scan_before_write","arguments":{{"path":"config.pem","content":"{PAT}"}}}}}}"#),
    ]);
    let r = respuestas(&out);
    assert_eq!(r[0]["result"]["structuredContent"]["clean"], false, "el camino de detección debía recorrerse");
    assert!(!out.contains(CUERPO_PAT), "FUGA: el cuerpo del secreto salió en claro por stdout:\n{out}");
    assert!(!out.contains(PAT), "FUGA: el secreto completo salió en claro por stdout");
}

/// JSON inválido por el stream ⇒ error de parseo -32700, sin tumbar el servidor.
#[test]
fn json_invalido_por_stdio_da_32700() {
    let (out, _err) = correr_mcp(&["{ esto no es json", r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#]);
    let r = respuestas(&out);
    assert_eq!(r[0]["error"]["code"], -32700, "JSON malo ⇒ -32700");
    // y el servidor sigue vivo: la siguiente petición válida responde
    assert_eq!(r[1]["id"], 7, "el servidor debe seguir atendiendo tras un JSON malo");
}
