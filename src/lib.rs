// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: LicenseRef-Propietario
//! **chaquen** — detector de secretos en Rust.
//!
//! Chaquén, dios muisca de los linderos: un detector de fugas guarda el lindero
//! entre lo privado y lo expuesto. Reimplementación con nuestro estándar (Rust,
//! D38) de la técnica de gitleaks (regex + entropía + listas de permitidos en
//! cascada), reusando solo su catálogo de reglas como DATO (MIT, ver NOTICE).

pub mod entropia;
pub mod historia;
pub mod hook;
pub mod mcp;
pub mod modelo;
pub mod motor;
pub mod recibo;

pub use historia::escanear_historia;
pub use motor::{Hallazgo, Motor};
