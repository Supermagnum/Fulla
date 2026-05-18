//! Minijinja wrappers (loads template files once at startup).

use std::path::Path;

use anyhow::{Context, Result};
use minijinja::Environment;
use serde::Serialize;

pub struct WebTemplates {
    env: Environment<'static>,
}

impl WebTemplates {
    pub fn load_from_dir(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        let pairs: &[(&str, &str)] = &[
            ("base", "base.html"),
            ("index", "index.html"),
            ("submit", "submit.html"),
            ("revoke", "revoke.html"),
            ("key_detail", "key_detail.html"),
            ("key_list", "key_list.html"),
            ("confirm", "confirm.html"),
            ("rejected", "rejected.html"),
            ("submit_pending", "submit_pending.html"),
            ("submit_accepted", "submit_accepted.html"),
            ("email_new_key", "email/new_key_notification.txt"),
        ];

        let mut env = Environment::new();
        for (logical, rel) in pairs {
            let path = dir.join(rel);
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("reading template `{}`", path.display()))?;
            env.add_template_owned((*logical).to_string(), raw)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        Ok(Self { env })
    }

    pub fn render<S: Serialize>(&self, logical: &str, ctx: S) -> Result<String> {
        let t = self
            .env
            .get_template(logical)
            .map_err(|e| anyhow::anyhow!("missing template `{}`: {}", logical, e))?;
        Ok(t.render(ctx)?)
    }
}
