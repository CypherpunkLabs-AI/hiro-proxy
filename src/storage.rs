use std::{collections::HashMap, time::Duration};

use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
    presigning::PresigningConfig,
    types::{CompletedMultipartUpload, CompletedPart},
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

    pub async fn create_multipart(&self, key: &str) -> anyhow::Result<String> {
        let output = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .content_type("application/octet-stream")
            .send()
            .await?;
        output
            .upload_id()
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("R2 did not return a multipart upload ID"))
    }

    pub async fn presign_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
    ) -> anyhow::Result<PresignedRequest> {
        let request = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
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

    pub async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: Vec<(i32, String)>,
    ) -> anyhow::Result<()> {
        let completed_parts = parts
            .into_iter()
            .map(|(part_number, e_tag)| {
                CompletedPart::builder()
                    .part_number(part_number)
                    .e_tag(e_tag)
                    .build()
            })
            .collect::<Vec<_>>();
        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(completed_parts))
                    .build(),
            )
            .send()
            .await?;
        Ok(())
    }

    pub async fn abort_multipart(&self, key: &str, upload_id: &str) -> anyhow::Result<()> {
        self.client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await?;
        Ok(())
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
