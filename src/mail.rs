//! Outbound SMTP (lettre).

use anyhow::{Context, Result};
use lettre::message::{Mailbox, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::AsyncTransport;
use lettre::{AsyncSmtpTransport, Message, Tokio1Executor};

use crate::config::Config;

enum MailerInner {
    Smtp {
        mx: Mailbox,
        relay: Box<AsyncSmtpTransport<Tokio1Executor>>,
    },
    #[cfg(test)]
    Noop,
}

pub struct Mailer {
    inner: MailerInner,
}

impl Mailer {
    pub fn new(config: &Config) -> Result<Self> {
        let from: Mailbox = config
            .keyserver_smtp_from
            .parse()
            .context("KEYSERVER_SMTP_FROM is not a valid mailbox")?;

        let relay: Box<AsyncSmtpTransport<Tokio1Executor>> = if config.keyserver_smtp_tls {
            let creds = Credentials::new(
                config.keyserver_smtp_user.clone(),
                config.keyserver_smtp_password.clone(),
            );
            let relay_builder = AsyncSmtpTransport::<Tokio1Executor>::relay(
                &config.keyserver_smtp_host,
            )
            .with_context(|| {
                format!(
                    "Invalid SMTP relay host `{}`",
                    config.keyserver_smtp_host
                )
            })?;
            Box::new(
                relay_builder
                    .credentials(creds)
                    .port(config.keyserver_smtp_port)
                    .build(),
            )
        } else {
            Box::new(
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(
                    config.keyserver_smtp_host.clone(),
                )
                .port(config.keyserver_smtp_port)
                .build(),
            )
        };

        Ok(Mailer {
            inner: MailerInner::Smtp { mx: from, relay },
        })
    }

    #[cfg(test)]
    pub(crate) fn noop_for_tests() -> Self {
        Mailer {
            inner: MailerInner::Noop,
        }
    }

    pub async fn send_plain(&self, to: &str, subject: &str, body: &str) -> Result<()> {
        match &self.inner {
            MailerInner::Smtp { mx, relay } => {
                let to_mb: Mailbox = to
                    .parse()
                    .with_context(|| format!("Recipient `{to}` is not a valid mailbox"))?;

                let email = Message::builder()
                    .from(mx.clone())
                    .to(to_mb)
                    .subject(subject)
                    .singlepart(SinglePart::plain(body.to_string()))?;

                relay
                    .send(email)
                    .await
                    .map(|_| ())
                    .map_err(|e| anyhow::anyhow!("SMTP send failed: {e}"))
            }
            #[cfg(test)]
            MailerInner::Noop => {
                let _ = (to, subject, body);
                Ok(())
            }
        }
    }
}
