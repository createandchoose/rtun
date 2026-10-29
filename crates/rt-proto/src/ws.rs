use crate::errors::WsFrameError;

pub const MAX_WS_DATAGRAMS: usize = 32;
pub const MAX_DATAGRAM_LEN: usize = u16::MAX as usize;

pub fn encode_batch<'a, I>(datagrams: I) -> Result<Vec<u8>, WsFrameError>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut output = Vec::new();
    let mut count = 0usize;
    for datagram in datagrams {
        if count >= MAX_WS_DATAGRAMS {
            return Err(WsFrameError::TooManyDatagrams);
        }
        if datagram.is_empty() || datagram.len() > MAX_DATAGRAM_LEN {
            return Err(WsFrameError::BadLength);
        }
        output.extend_from_slice(&(datagram.len() as u16).to_be_bytes());
        output.extend_from_slice(datagram);
        count += 1;
    }
    if count == 0 {
        return Err(WsFrameError::BadLength);
    }
    Ok(output)
}

pub fn decode_batch(frame: &[u8]) -> Result<Vec<&[u8]>, WsFrameError> {
    let mut datagrams = Vec::new();
    let mut cursor = 0usize;
    while cursor < frame.len() {
        if datagrams.len() >= MAX_WS_DATAGRAMS {
            return Err(WsFrameError::TooManyDatagrams);
        }
        if cursor + 2 > frame.len() {
            return Err(WsFrameError::Truncated);
        }
        let len = u16::from_be_bytes([frame[cursor], frame[cursor + 1]]) as usize;
        cursor += 2;
        if len == 0 {
            return Err(WsFrameError::BadLength);
        }
        if cursor + len > frame.len() {
            return Err(WsFrameError::Truncated);
        }
        datagrams.push(&frame[cursor..cursor + len]);
        cursor += len;
    }
    if datagrams.is_empty() {
        return Err(WsFrameError::BadLength);
    }
    Ok(datagrams)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_roundtrip() {
        let a = vec![1u8; 32];
        let b = vec![2u8; 128];
        let c = vec![3u8; 148];
        let frame = encode_batch([a.as_slice(), b.as_slice(), c.as_slice()]).unwrap();
        let decoded = decode_batch(&frame).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], a);
        assert_eq!(decoded[1], b);
        assert_eq!(decoded[2], c);
    }

    #[test]
    fn rejects_too_many_datagrams() {
        let packet = [0u8; 4];
        let result = encode_batch(std::iter::repeat_n(packet.as_slice(), 33));
        assert_eq!(result.unwrap_err(), WsFrameError::TooManyDatagrams);
    }

    #[test]
    fn rejects_empty_and_truncated() {
        assert_eq!(
            encode_batch(std::iter::empty()).unwrap_err(),
            WsFrameError::BadLength
        );
        assert_eq!(
            encode_batch([&[][..]]).unwrap_err(),
            WsFrameError::BadLength
        );
        assert_eq!(
            decode_batch(&[0x00, 0x20, 0x01]).unwrap_err(),
            WsFrameError::Truncated
        );
        assert_eq!(
            decode_batch(&[0x00, 0x00]).unwrap_err(),
            WsFrameError::BadLength
        );
    }

    #[test]
    fn rejects_trailing_half_header() {
        let mut frame = encode_batch([&[1u8; 8][..]]).unwrap();
        frame.push(0);
        assert_eq!(decode_batch(&frame).unwrap_err(), WsFrameError::Truncated);
    }

    #[test]
    fn large_datagram_roundtrip() {
        let packet = vec![7u8; 65535];
        let frame = encode_batch([packet.as_slice()]).unwrap();
        let decoded = decode_batch(&frame).unwrap();
        assert_eq!(decoded[0].len(), 65535);
    }
}
