use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

pub fn init(filter: &str, json: bool) -> anyhow::Result<()> {
    let registry = tracing_subscriber::registry().with(EnvFilter::try_new(filter)?);
    if json {
        registry
            .with(tracing_subscriber::fmt::layer().json())
            .try_init()?;
    } else {
        registry.with(tracing_subscriber::fmt::layer()).try_init()?;
    }
    Ok(())
}
