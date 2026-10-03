//! Lossless metadata removal for JPEG and PNG. Image data is copied byte-for-byte;
//! only the metadata containers are dropped, so there is no re-encoding.

/// Removes EXIF (incl. GPS), XMP and IPTC metadata from a JPEG.
/// Keeps JFIF (APP0), ICC colour profiles (APP2) and Adobe (APP14) segments.
pub fn strip_jpeg(data: &[u8]) -> Result<Vec<u8>, String> {
    if !data.starts_with(&[0xFF, 0xD8]) {
        return Err("Not a JPEG file".into());
    }
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..2]);
    let mut pos = 2;

    loop {
        if pos >= data.len() {
            return Err("Truncated JPEG: no image data found".into());
        }
        if data[pos] != 0xFF {
            return Err(format!("Corrupt JPEG: expected marker at byte {}", pos));
        }
        // Skip fill bytes between markers
        let mut marker_pos = pos;
        while marker_pos + 1 < data.len() && data[marker_pos + 1] == 0xFF {
            marker_pos += 1;
        }
        let marker = *data.get(marker_pos + 1).ok_or("Truncated JPEG marker")?;

        match marker {
            // Start of scan: everything after this is entropy-coded image data
            0xDA => {
                out.extend_from_slice(&data[marker_pos..]);
                return Ok(out);
            }
            // Markers without a length field
            0x01 | 0xD0..=0xD7 => {
                out.extend_from_slice(&data[marker_pos..marker_pos + 2]);
                pos = marker_pos + 2;
            }
            _ => {
                let len_bytes = data
                    .get(marker_pos + 2..marker_pos + 4)
                    .ok_or("Truncated JPEG segment header")?;
                let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
                let end = marker_pos + 2 + len;
                if len < 2 || end > data.len() {
                    return Err("Corrupt JPEG segment length".into());
                }
                // APP1 = EXIF/XMP, APP13 = Photoshop/IPTC, COM = free-text comment
                let drop = matches!(marker, 0xE1 | 0xED | 0xFE);
                if !drop {
                    out.extend_from_slice(&data[marker_pos..end]);
                }
                pos = end;
            }
        }
    }
}

/// Removes EXIF, text (which may hold XMP/GPS) and timestamp chunks from a PNG.
pub fn strip_png(data: &[u8]) -> Result<Vec<u8>, String> {
    const SIG: &[u8] = b"\x89PNG\r\n\x1a\n";
    if !data.starts_with(SIG) {
        return Err("Not a PNG file".into());
    }
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(SIG);
    let mut pos = SIG.len();

    while pos < data.len() {
        let header = data.get(pos..pos + 8).ok_or("Truncated PNG chunk header")?;
        let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let chunk_type = &header[4..8];
        // length + type + data + CRC
        let end = pos
            .checked_add(12)
            .and_then(|p| p.checked_add(len))
            .filter(|&e| e <= data.len())
            .ok_or("Corrupt PNG chunk length")?;

        let drop = matches!(chunk_type, b"eXIf" | b"tEXt" | b"zTXt" | b"iTXt" | b"tIME");
        if !drop {
            out.extend_from_slice(&data[pos..end]);
        }
        pos = end;
        if chunk_type == b"IEND" {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(marker: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0xFF, marker];
        v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn jpeg_drops_exif_keeps_image_data() {
        let mut jpg = vec![0xFF, 0xD8];
        jpg.extend(segment(0xE0, b"JFIF\0\x01\x01"));
        jpg.extend(segment(0xE1, b"Exif\0\0GPSLatitude..."));
        jpg.extend(segment(0xE2, b"ICC_PROFILE\0"));
        jpg.extend(segment(0xDB, &[0u8; 5]));
        let scan = [0xFF, 0xDA, 0x00, 0x02, 0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD9];
        jpg.extend_from_slice(&scan);

        let out = strip_jpeg(&jpg).unwrap();
        assert!(!out.windows(4).any(|w| w == b"Exif"));
        assert!(out.windows(4).any(|w| w == b"JFIF"));
        assert!(out.windows(11).any(|w| w == b"ICC_PROFILE"));
        assert!(out.ends_with(&scan));
    }

    #[test]
    fn jpeg_rejects_truncated_input() {
        assert!(strip_jpeg(&[0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x40]).is_err());
        assert!(strip_jpeg(b"not a jpeg").is_err());
    }

    #[test]
    fn png_drops_metadata_chunks() {
        fn chunk(t: &[u8; 4], d: &[u8]) -> Vec<u8> {
            let mut v = (d.len() as u32).to_be_bytes().to_vec();
            v.extend_from_slice(t);
            v.extend_from_slice(d);
            v.extend_from_slice(&[0, 0, 0, 0]);
            v
        }
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend(chunk(b"IHDR", &[0; 13]));
        png.extend(chunk(b"eXIf", b"GPS"));
        png.extend(chunk(b"iTXt", b"XML:com.adobe.xmp"));
        png.extend(chunk(b"IDAT", b"pixels"));
        png.extend(chunk(b"IEND", b""));

        let out = strip_png(&png).unwrap();
        assert!(!out.windows(4).any(|w| w == b"eXIf" || w == b"iTXt"));
        assert!(out.windows(6).any(|w| w == b"pixels"));
        assert!(out.windows(4).any(|w| w == b"IEND"));
    }
}
