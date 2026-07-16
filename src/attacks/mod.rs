//! Attack executors: the transport (HTTP) and domain-specific helpers
//! (filesystem, database) used by the `.klr` interpreter to carry out and
//! evaluate attacks.

pub mod database;
pub mod filesystem;
pub mod http;
