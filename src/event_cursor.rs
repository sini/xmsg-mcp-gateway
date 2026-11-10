use crate::event_store::EventKey;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

pub(crate) fn encode(
    key: &EventKey,
    owner: &str,
    sequence: i64,
) -> Result<String, crate::event_store::Error> {
    let aad = format!("events/cursor/v1/{owner}");
    Ok(URL_SAFE_NO_PAD.encode(key.seal(&aad, &sequence.to_be_bytes())?))
}

pub(crate) fn decode(
    key: &EventKey,
    owner: &str,
    cursor: &str,
) -> Result<i64, crate::event_store::Error> {
    if cursor.len() > 256 {
        return Err(crate::event_store::Error::Key);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| crate::event_store::Error::Key)?;
    let raw = key.open(&format!("events/cursor/v1/{owner}"), &bytes)?;
    let sequence = i64::from_be_bytes(raw.try_into().map_err(|_| crate::event_store::Error::Key)?);
    if sequence < 0 {
        return Err(crate::event_store::Error::Key);
    }
    Ok(sequence)
}
