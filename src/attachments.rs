use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use xmsg::client::AttachmentRef;

pub(crate) const MAX_FILES: usize = 8;
pub(crate) const READ_DEFAULT: usize = 8192;
pub(crate) const READ_MAX: usize = 32768;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReadArguments {
    pub(crate) message_id: String,
    pub(crate) index: usize,
    pub(crate) offset: Option<usize>,
    pub(crate) limit: Option<usize>,
}

impl ReadArguments {
    pub(crate) fn validate(&self) -> bool {
        !self.message_id.is_empty()
            && self.message_id.len() <= 4096
            && self.index < MAX_FILES
            && (1..=READ_MAX).contains(&self.limit.unwrap_or(READ_DEFAULT))
    }
}

fn owned(
    store: &crate::grants::Store,
    context: &crate::auth::VerifiedContext,
    bus: &str,
    mailbox: &str,
    args: &ReadArguments,
) -> Result<Option<AttachmentRef>, crate::outbound::Error> {
    crate::reads::owned_attachment(
        store,
        context.identity(),
        bus,
        mailbox,
        &args.message_id,
        args.index,
    )
    .map_err(|error| match error {
        crate::reads::Error::Arguments => crate::outbound::Error::Configuration,
        crate::reads::Error::Authority(error) => error.into(),
        crate::reads::Error::Database(error) => error.into(),
        crate::reads::Error::Encoding(error) => error.into(),
    })
}

async fn checked_owned(
    file: std::path::PathBuf,
    context: crate::auth::VerifiedContext,
    bus: String,
    mailbox: String,
    args: ReadArguments,
) -> Result<Option<AttachmentRef>, crate::outbound::Error> {
    tokio::task::spawn_blocking(move || {
        let store = crate::grants::Store::open_for_dispatch(&file)?;
        if !crate::attachment_store::ready(&store.connection)? {
            return Err(crate::outbound::Error::MigrationRequired);
        }
        let reference = owned(&store, &context, &bus, &mailbox, &args)?;
        crate::outbound::require_current(&context, &store)?;
        Ok(reference)
    })
    .await
    .map_err(|_| crate::outbound::Error::Worker)?
}

pub(crate) async fn read(
    store: crate::grants::Store,
    context: &crate::auth::VerifiedContext,
    endpoint: &crate::outbound::Endpoint,
    bus: &str,
    mailbox: &str,
    args: ReadArguments,
) -> Result<serde_json::Value, crate::outbound::Error> {
    use crate::outbound::Error;
    use serde_json::json;
    if !args.validate() {
        return Err(Error::Configuration);
    }
    let file = store.file.clone();
    drop(store);
    tracing::info!(target: "gateway_dispatch", operation = "xmsg_read_attachment", "dispatch");
    let reference = checked_owned(
        file.clone(),
        context.clone(),
        bus.to_owned(),
        mailbox.to_owned(),
        args.clone(),
    )
    .await?;
    let Some(reference) = reference else {
        return Ok(json!({"state":"not_found","untrusted":true}));
    };
    let offset = args.offset.unwrap_or(0);
    if offset > reference.size {
        return Err(Error::Configuration);
    }
    let limit = args
        .limit
        .unwrap_or(READ_DEFAULT)
        .min(endpoint.frame_budget().saturating_sub(1024) / 6);
    if limit == 0 {
        return Err(Error::Configuration);
    }
    let response = endpoint
        .read_attachment(&args.message_id, args.index, offset, Some(limit))
        .await;
    let current = checked_owned(
        file,
        context.clone(),
        bus.to_owned(),
        mailbox.to_owned(),
        args.clone(),
    )
    .await?;
    if current.as_ref() != Some(&reference) {
        return Err(Error::Denied);
    }
    let response = match response {
        Ok(xmsg::client::AttachmentRead::Ready(value)) => value,
        Ok(xmsg::client::AttachmentRead::Pending) => {
            return Ok(
                json!({"state":"pending","message_id":args.message_id,"index":args.index,"untrusted":true}),
            );
        }
        Err(xmsg::client::ClientError::Refused { code })
            if matches!(
                code.as_str(),
                "gone" | "not_found" | "unavailable" | "integrity" | "rate_limited"
            ) =>
        {
            return Ok(
                json!({"state":code,"message_id":args.message_id,"index":args.index,"untrusted":true}),
            );
        }
        Err(error) => return Err(error.into()),
    };
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Range {
        status: String,
        attachment: AttachmentRef,
        offset: usize,
        length: usize,
        next: Option<usize>,
        encoding: String,
        data: String,
    }
    let range: Range = serde_json::from_value(response)
        .map_err(|_| Error::Transport(xmsg::client::ClientError::Protocol))?;
    let length = match range.encoding.as_str() {
        "utf-8" => range.data.len(),
        "base64" => STANDARD
            .decode(&range.data)
            .map_err(|_| Error::Transport(xmsg::client::ClientError::Protocol))?
            .len(),
        _ => return Err(Error::Transport(xmsg::client::ClientError::Protocol)),
    };
    let end = offset.checked_add(length).ok_or(Error::Configuration)?;
    if range.status != "ok"
        || range.attachment != reference
        || range.offset != offset
        || range.length != length
        || length > limit
        || end > reference.size
        || match range.next {
            Some(next) => next != end || next >= reference.size,
            None => end != reference.size,
        }
    {
        return Err(Error::Transport(xmsg::client::ClientError::Protocol));
    }
    Ok(
        json!({"state":"found","message_id":args.message_id,"index":args.index,
        "attachment":reference,"offset":offset,"length":length,"next_offset":range.next,
        "encoding":range.encoding,"data":range.data,"untrusted":true}),
    )
}

#[derive(Clone)]
pub struct Input {
    name: String,
    media_type: String,
    data: Vec<u8>,
}

impl std::fmt::Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentInput")
            .field("size", &self.data.len())
            .finish_non_exhaustive()
    }
}

fn optional_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}

impl<'de> Deserialize<'de> for Input {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            name: String,
            #[serde(default, deserialize_with = "optional_string")]
            media_type: Option<String>,
            #[serde(default, deserialize_with = "optional_string")]
            text: Option<String>,
            #[serde(default, deserialize_with = "optional_string")]
            base64: Option<String>,
        }
        let wire = Wire::deserialize(d)?;
        let default_media_type = if wire.text.is_some() {
            "text/plain; charset=utf-8"
        } else {
            "application/octet-stream"
        };
        let data = match (wire.text, wire.base64) {
            (Some(text), None) => text.into_bytes(),
            (None, Some(data)) => STANDARD
                .decode(data)
                .map_err(|_| serde::de::Error::custom("invalid attachment base64"))?,
            _ => {
                return Err(serde::de::Error::custom(
                    "attachment requires text xor base64",
                ))
            }
        };
        let name = normalize_name(&wire.name)
            .ok_or_else(|| serde::de::Error::custom("invalid attachment name"))?;
        let media_type = wire.media_type.unwrap_or_else(|| default_media_type.into());
        if !valid_media_type(&media_type) {
            return Err(serde::de::Error::custom("invalid attachment media_type"));
        }
        Ok(Self {
            name,
            media_type,
            data,
        })
    }
}

pub(crate) fn deserialize_inputs<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Input>, D::Error> {
    let inputs = Vec::<Input>::deserialize(d)?;
    if inputs.len() > MAX_FILES {
        return Err(serde::de::Error::custom(
            "at most eight attachments are allowed",
        ));
    }
    Ok(inputs)
}

pub(crate) struct Prepared {
    pub(crate) reference: AttachmentRef,
    pub(crate) data: Vec<u8>,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedAttachment")
            .field("size", &self.data.len())
            .finish_non_exhaustive()
    }
}

pub(crate) fn prepare(
    inputs: &[Input],
    cap: usize,
) -> Result<Vec<Prepared>, crate::outbound::Error> {
    if inputs.len() > MAX_FILES {
        return Err(crate::outbound::Error::Configuration);
    }
    inputs
        .iter()
        .map(|input| {
            if input.data.len() > cap {
                return Err(crate::outbound::Error::Oversized);
            }
            Ok(Prepared {
                reference: AttachmentRef {
                    name: input.name.clone(),
                    size: input.data.len(),
                    media_type: input.media_type.clone(),
                    sha256: format!("{:x}", Sha256::digest(&input.data)),
                },
                data: input.data.clone(),
            })
        })
        .collect()
}

pub(crate) fn validate_refs(refs: &[AttachmentRef]) -> bool {
    refs.len() <= MAX_FILES
        && refs.iter().all(|r| {
            normalize_name(&r.name).as_ref() == Some(&r.name)
                && valid_media_type(&r.media_type)
                && i64::try_from(r.size).is_ok()
                && r.sha256.len() == 64
                && r.sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

fn normalize_name(name: &str) -> Option<String> {
    let mut out = String::new();
    let mut space = false;
    for c in name.chars() {
        if matches!(c, '"' | '<' | '>' | '/') || c.is_control() {
            continue;
        }
        let c = if c.is_ascii() { c } else { '_' };
        if c.is_whitespace() {
            if out.is_empty() || space {
                continue;
            }
            space = true;
            out.push(' ');
        } else {
            space = false;
            out.push(c);
        }
        if out.len() == 128 {
            break;
        }
    }
    let out = out.trim_end().to_string();
    (!out.is_empty()).then_some(out)
}

fn valid_media_type(value: &str) -> bool {
    if value == "text/plain; charset=utf-8" {
        return true;
    }
    let token = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    };
    value.len() <= 64
        && value
            .split_once('/')
            .is_some_and(|(a, b)| token(a) && token(b))
}

#[cfg(test)]
mod media_type_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn inline_text_defaults_to_utf8_plain_text() {
        let input: Input =
            serde_json::from_value(json!({"name":"note.txt","text":"héllo"})).unwrap();
        let prepared = prepare(&[input], 1024).unwrap();
        assert_eq!(
            prepared[0].reference.media_type,
            "text/plain; charset=utf-8"
        );
        assert!(validate_refs(std::slice::from_ref(&prepared[0].reference)));
    }

    #[test]
    fn binary_input_does_not_infer_text_media_type() {
        for name in ["note.txt", "binary.bin"] {
            let input: Input = serde_json::from_value(json!({
                "name":name,"base64":STANDARD.encode("valid UTF-8 text")
            }))
            .unwrap();
            let prepared = prepare(&[input], 1024).unwrap();
            assert_eq!(prepared[0].reference.media_type, "application/octet-stream");
        }
    }

    #[test]
    fn explicit_media_types_are_preserved() {
        for media_type in [
            "application/json",
            "text/markdown",
            "text/plain; charset=utf-8",
        ] {
            for field in ["text", "base64"] {
                let mut value = json!({"name":"note.txt","media_type":media_type});
                value[field] = if field == "text" {
                    json!("hello")
                } else {
                    json!(STANDARD.encode("hello"))
                };
                let input: Input = serde_json::from_value(value).unwrap();
                let prepared = prepare(&[input], 1024).unwrap();
                assert_eq!(prepared[0].reference.media_type, media_type);
                assert!(validate_refs(std::slice::from_ref(&prepared[0].reference)));
            }
        }
    }

    #[test]
    fn media_type_parameters_remain_restricted() {
        for media_type in [
            "text/plain; charset=latin1",
            "text/plain; charset=UTF-8",
            "text/plain;charset=utf-8",
            "text/plain; charset=utf-8; extra=value",
            "text/plain; other=value",
            "text/plain\r\nInjected: value",
        ] {
            let input = json!({"name":"note.txt","text":"hello","media_type":media_type});
            assert!(
                serde_json::from_value::<Input>(input).is_err(),
                "{media_type:?}"
            );
            let reference = AttachmentRef {
                name: "note.txt".into(),
                size: 5,
                media_type: media_type.into(),
                sha256: format!("{:x}", Sha256::digest(b"hello")),
            };
            assert!(!validate_refs(&[reference]), "{media_type:?}");
        }
    }
}
