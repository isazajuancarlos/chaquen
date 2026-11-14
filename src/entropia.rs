// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: LicenseRef-Propietario
//! Entropía de Shannon sobre un secreto candidato.
//!
//! Se calcula sobre los BYTES del texto (igual que gitleaks, que la mide sobre
//! el grupo capturado, no sobre el archivo entero): `-Σ p·log2(p)`.

/// Entropía de Shannon en bits/byte. Cadena vacía → 0.0.
#[must_use]
pub fn shannon(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let bytes = s.as_bytes();
    let mut conteo = [0u32; 256];
    for &b in bytes {
        conteo[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut h = 0.0;
    for &c in &conteo {
        if c == 0 {
            continue;
        }
        let p = f64::from(c) / n;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod pruebas {
    use super::shannon;

    #[test]
    fn vacio_es_cero() {
        assert_eq!(shannon(""), 0.0);
    }

    #[test]
    fn un_solo_simbolo_es_cero() {
        // Sin sorpresa: entropía nula.
        assert_eq!(shannon("aaaaaaaa"), 0.0);
    }

    #[test]
    fn aleatorio_supera_a_repetitivo() {
        // Positivo de control: un secreto real tiene MÁS entropía que un
        // placeholder repetitivo. Si esto se invierte, la métrica está rota.
        let repetitivo = shannon("aaaaaaaaaaaaaaaa");
        let aleatorio = shannon("wJalrXUtnFEMI7K9");
        assert!(aleatorio > repetitivo);
        assert!(aleatorio > 3.0, "entropía de un secreto real: {aleatorio}");
    }
}
