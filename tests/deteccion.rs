// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: LicenseRef-Propietario
//! Banco pareado (D33): cada sonda con su pareja — lo que TIENE que ver y lo que
//! TIENE que no ver — y el mutante que prueba que la salvaguarda discrimina por
//! la vía real (no por el arnés).

use chaquen::Motor;

// ---------- Integración contra el catálogo embebido (222 reglas) ----------

#[test]
fn rojo_detecta_github_pat() {
    let m = Motor::embebido().unwrap();
    // 'ghp_' + 36 alfanum: casa github-pat, entropía alta.
    let pat = "ghp_wF3kZ9mQ2xB7nL5vC8rT1yH4jP6sD0aG2eU9";
    let contenido = format!("const token = \"{pat}\";\n");
    let hs = m.escanear("config.js", &contenido);
    assert!(
        hs.iter().any(|h| h.secreto.contains("ghp_")),
        "debía detectar el PAT de GitHub; hallazgos={hs:?}"
    );
}

#[test]
fn rojo_detecta_aws_access_key() {
    let m = Motor::embebido().unwrap();
    let clave = "AKIAZ3XK7QW6RT2LMNP4"; // AKIA + 16 en [A-Z2-7], entropía alta
    let contenido = format!("aws_access_key_id = {clave}\n");
    let hs = m.escanear("credenciales.ini", &contenido);
    assert!(
        hs.iter().any(|h| h.secreto.contains("AKIA")),
        "debía detectar la llave AWS; hallazgos={hs:?}"
    );
}

#[test]
fn verde_ignora_referencia_a_variable() {
    let m = Motor::embebido().unwrap();
    // Una referencia a variable de entorno NO es un secreto.
    let contenido = "password = \"${DB_PASSWORD}\"\nAPI_KEY=$API_KEY\n";
    let hs = m.escanear("app.conf", contenido);
    assert!(hs.is_empty(), "no debía marcar referencias a variables; hallazgos={hs:?}");
}

#[test]
fn verde_ignora_codigo_ordinario() {
    let m = Motor::embebido().unwrap();
    // Control anti-sobredisparo: texto normal, cero secretos.
    let contenido = "fn suma(a: i32, b: i32) -> i32 {\n    a + b\n}\n";
    let hs = m.escanear("lib.rs", contenido);
    assert!(hs.is_empty(), "no debía marcar código ordinario; hallazgos={hs:?}");
}

#[test]
fn el_marcador_allow_silencia() {
    let m = Motor::embebido().unwrap();
    let pat = "ghp_wF3kZ9mQ2xB7nL5vC8rT1yH4jP6sD0aG2eU9";
    let contenido = format!("token = \"{pat}\" // chaquen:allow\n");
    let hs = m.escanear("config.js", &contenido);
    assert!(hs.is_empty(), "el marcador chaquen:allow debía silenciar; hallazgos={hs:?}");
}

// ---------- Discriminación con mutante (D33) ----------

const MINI_CON_ENTROPIA: &str = r#"
title = "mini"
[[rules]]
id = "clave-generica"
regex = '''token\s*=\s*"([a-z0-9]{16,})"'''
entropy = 3.5
keywords = ["token"]
"#;

// El MUTANTE: la MISMA regla sin la puerta de entropía.
const MINI_SIN_ENTROPIA: &str = r#"
title = "mini"
[[rules]]
id = "clave-generica"
regex = '''token\s*=\s*"([a-z0-9]{16,})"'''
keywords = ["token"]
"#;

#[test]
fn la_entropia_discrimina_por_la_via_real() {
    let bajo = "token = \"aaaaaaaaaaaaaaaa\"\n"; // 16 'a', entropía 0
    let alto = "token = \"a8f3k2p9x7q1w6z4\"\n"; // entropía alta

    let con = Motor::desde_toml(MINI_CON_ENTROPIA).unwrap();
    let sin = Motor::desde_toml(MINI_SIN_ENTROPIA).unwrap();

    // Con la puerta: el alto dispara, el bajo NO.
    assert_eq!(con.escanear("f", alto).len(), 1, "el secreto de alta entropía debe dispararse");
    assert_eq!(con.escanear("f", bajo).len(), 0, "el placeholder repetitivo debe suprimirse");

    // MUTANTE: quitando la entropía, el bajo SÍ dispara. Prueba que es la
    // entropía —y no el arnés— la que suprimía el placeholder.
    assert_eq!(sin.escanear("f", bajo).len(), 1, "sin la puerta de entropía, el placeholder se cuela");
}

const MINI_CON_ALLOW: &str = r#"
title = "mini"
[[rules]]
id = "r"
regex = '''secret\s*=\s*"([A-Za-z0-9]{8,})"'''
keywords = ["secret"]
[[rules.allowlists]]
regexes = ['''(?i)example''']
"#;

const MINI_SIN_ALLOW: &str = r#"
title = "mini"
[[rules]]
id = "r"
regex = '''secret\s*=\s*"([A-Za-z0-9]{8,})"'''
keywords = ["secret"]
"#;

#[test]
fn el_allowlist_discrimina_por_la_via_real() {
    let placeholder = "secret = \"exampleKEY123\"\n";

    let con = Motor::desde_toml(MINI_CON_ALLOW).unwrap();
    let sin = Motor::desde_toml(MINI_SIN_ALLOW).unwrap();

    assert_eq!(con.escanear("f", placeholder).len(), 0, "el allowlist debe suprimir 'example*'");
    // MUTANTE: sin el allowlist, el mismo texto dispara.
    assert_eq!(sin.escanear("f", placeholder).len(), 1, "sin allowlist el placeholder se cuela");
}

#[test]
fn allowlist_propia_salta_vendor_pero_no_src() {
    // D33 pareado: el MISMO secreto (PAT) se silencia bajo `vendor/` (dep de
    // tercero) pero AVISA bajo `src/`. Prueba que la allowlist propia discrimina
    // por RUTA, no que cegó al motor.
    let m = Motor::embebido().unwrap();
    let pat = "const T: &str = \"ghp_wF3kZ9mQ2xB7nL5vC8rT1yH4jP6sD0aG2eU9\";\n";
    assert_eq!(
        m.escanear("proyecto/vendor/x25519-dalek/src/lib.rs", pat).len(),
        0,
        "un secreto en vendor/ (dep de tercero) no debe reportarse"
    );
    assert!(
        !m.escanear("proyecto/src/lib.rs", pat).is_empty(),
        "el MISMO secreto en src/ propio SÍ debe reportarse"
    );
}
