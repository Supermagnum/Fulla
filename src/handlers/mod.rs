pub mod confirm;
pub mod revoke;
pub mod submit;
pub mod web;

pub fn normalize_base_url(raw: &str) -> String {
    raw.trim().trim_end_matches('/').to_string()
}
