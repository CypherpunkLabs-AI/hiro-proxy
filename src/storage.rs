use std::{collections::HashMap, time::Duration};

use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
    presigning::PresigningConfig,
};
use secrecy::ExposeSecret;

use crate::config::R2Config;

#[derive(Clone)]
pub struct R2Storage {
    client: Client,
    bucket: String,
    presign_ttl: Duration,
}

pub struct PresignedRequest {
    pub url: String,
    pub headers: HashMap<String, String>,
}

impl R2Storage {
    pub fn new(config: &R2Config) -> Self {
        let credentials = Credentials::new(
            config.access_key_id.expose_secret(),
            config.secret_access_key.expose_secret(),
            None,
            None,
            "r2-static-credentials",
        );
        let sdk_config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("auto"))
            .endpoint_url(config.endpoint.as_str().trim_end_matches('/'))
            .credentials_provider(credentials)
            .force_path_style(true)
            .build();
        Self {
            client: Client::from_conf(sdk_config),
            bucket: config.bucket.clone(),
            presign_ttl: Duration::from_secs(config.presign_ttl_seconds),
        }
    }

    pub async fn presign_upload(
        &self,
        key: &str,
        content_length: i64,
    ) -> anyhow::Result<PresignedRequest> {
        let request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type("application/octet-stream")
            .content_length(content_length)
            .presigned(PresigningConfig::expires_in(self.presign_ttl)?)
            .await?;
        Ok(PresignedRequest {
            url: request.uri().to_owned(),
            headers: request
                .headers()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
        })
    }

    pub async fn delete_object(&self, key: &str) -> anyhow::Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;
        Ok(())
    }

    pub async fn object_size(&self, key: &str) -> anyhow::Result<i64> {
        Ok(self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?
            .content_length()
            .unwrap_or_default())
    }

    pub async fn presign_download(&self, key: &str) -> anyhow::Result<PresignedRequest> {
        let request = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(PresigningConfig::expires_in(self.presign_ttl)?)
            .await?;
        Ok(PresignedRequest {
            url: request.uri().to_owned(),
            headers: request
                .headers()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
        })
    }
}
