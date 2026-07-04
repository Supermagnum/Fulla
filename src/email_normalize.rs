//! Mailbox identity normalization for duplicate pending detection (case + confusables).

use confusables::Confusable;

/// Normalize an email for identity comparison (pending guard, anti-homoglyph).
///
/// ASCII characters are lowercased only. Non-ASCII code points are mapped through
/// Unicode confusable replacement (UTS #39 data) so Cyrillic `е` (U+0435) becomes Latin `e`
/// without rewriting ASCII letters such as `m` (which whole-string skeleton would map to `rn`).
pub fn normalize_email_identity(raw: &str) -> String {
    raw.trim()
        .to_lowercase()
        .chars()
        .map(normalize_char)
        .collect()
}

fn normalize_char(c: char) -> String {
    if c.is_ascii() {
        return c.to_string();
    }
    c.to_string().replace_confusable()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_folds_without_ascii_skeleton_side_effects() {
        assert_eq!(
            normalize_email_identity("User@Example.COM"),
            "user@example.com"
        );
    }

    #[test]
    fn cyrillic_homoglyph_local_part() {
        let latin = "user-abc@example.com";
        let homoglyph = format!("us\u{0435}r-abc@example.com");
        assert_eq!(normalize_email_identity(&homoglyph), latin);
    }

    #[test]
    fn cyrillic_homoglyph_domain() {
        let latin = "user@example.com";
        let homoglyph = format!("user@ex\u{0430}mple.com");
        assert_eq!(normalize_email_identity(&homoglyph), latin);
    }
}
