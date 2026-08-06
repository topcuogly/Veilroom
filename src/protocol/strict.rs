//! Strict CBOR decoding (section 30).
//!
//! Strictness is enforced inline while a schema decodes a payload through
//! [`StrictDecoder`]; every byte of the payload must be consumed by a schema
//! decoder, so the whole payload is always validated. Enforced rules:
//!
//! - Nesting depth limited by `Limits::max_cbor_nesting_depth`.
//! - Map and array sizes limited by `Limits::max_cbor_map_entries` and
//!   `Limits::max_cbor_array_entries`.
//! - Indefinite-length structures are rejected.
//! - Duplicate map keys are rejected.
//! - Text and byte strings are length-limited.
//! - Type mismatches, tags, and malformed input are rejected.
//! - Trailing data after the message value is rejected.

use minicbor::Decoder;

use crate::limits::Limits;

/// Errors produced by strict CBOR decoding.
#[derive(Debug, thiserror::Error)]
pub enum StrictError {
    /// The underlying CBOR decoder rejected the input.
    #[error("invalid CBOR: {0}")]
    Cbor(#[from] minicbor::decode::Error),

    /// An indefinite-length map or array is not allowed in V1.
    #[error("indefinite-length CBOR structures are not allowed")]
    IndefiniteNotAllowed,

    /// The payload nests collections deeper than the configured limit.
    #[error("CBOR nesting exceeds the limit of {limit} levels")]
    NestingTooDeep {
        /// The configured maximum nesting depth.
        limit: usize,
    },

    /// A map declares more entries than the configured limit.
    #[error("CBOR map declares {declared} entries, maximum is {limit}")]
    MapTooLarge {
        /// The number of entries declared by the map header.
        declared: u64,
        /// The configured maximum number of map entries.
        limit: usize,
    },

    /// An array declares more elements than the configured limit.
    #[error("CBOR array declares {declared} elements, maximum is {limit}")]
    ArrayTooLarge {
        /// The number of elements declared by the array header.
        declared: u64,
        /// The configured maximum number of array elements.
        limit: usize,
    },

    /// A map contains the same key twice.
    #[error("duplicate CBOR map key {key}")]
    DuplicateMapKey {
        /// The duplicated key.
        key: u64,
    },

    /// A text string exceeds the configured length limit.
    #[error("CBOR text is {length} bytes, maximum is {limit}")]
    TextTooLong {
        /// The length of the text string in bytes.
        length: usize,
        /// The configured maximum text length in bytes.
        limit: usize,
    },

    /// A byte string exceeds the configured length limit.
    #[error("CBOR byte string is {length} bytes, maximum is {limit}")]
    BytesTooLong {
        /// The length of the byte string in bytes.
        length: usize,
        /// The configured maximum byte-string length in bytes.
        limit: usize,
    },

    /// Bytes remain after the message value has been decoded.
    #[error("trailing data after the message value")]
    TrailingData,
}

/// Strict, schema-driven CBOR decoder.
///
/// Wraps a [`minicbor::Decoder`] and adds the V1 strictness rules. Schema
/// decoders read values through this type and through the entry iterators
/// returned by [`StrictDecoder::map_entries`] and
/// [`StrictDecoder::array_entries`].
pub struct StrictDecoder<'a> {
    inner: Decoder<'a>,
    depth: usize,
    limits: &'a Limits,
}

impl<'a> StrictDecoder<'a> {
    /// Creates a strict decoder over `input`, bound to `limits`.
    pub fn new(input: &'a [u8], limits: &'a Limits) -> Self {
        Self {
            inner: Decoder::new(input),
            depth: 0,
            limits,
        }
    }

    /// Decodes an unsigned 8-bit integer.
    pub fn u8(&mut self) -> Result<u8, StrictError> {
        Ok(self.inner.u8()?)
    }

    /// Decodes an unsigned 16-bit integer.
    pub fn u16(&mut self) -> Result<u16, StrictError> {
        Ok(self.inner.u16()?)
    }

    /// Decodes an unsigned 32-bit integer.
    pub fn u32(&mut self) -> Result<u32, StrictError> {
        Ok(self.inner.u32()?)
    }

    /// Decodes an unsigned 64-bit integer.
    pub fn u64(&mut self) -> Result<u64, StrictError> {
        Ok(self.inner.u64()?)
    }

    /// Decodes a definite-length text string.
    ///
    /// Indefinite-length text is rejected by the underlying decoder.
    pub fn str(&mut self) -> Result<&'a str, StrictError> {
        let text = self.inner.str()?;
        if text.len() > self.limits.max_cbor_text_bytes() {
            return Err(StrictError::TextTooLong {
                length: text.len(),
                limit: self.limits.max_cbor_text_bytes(),
            });
        }
        Ok(text)
    }

    /// Decodes a definite-length byte string.
    ///
    /// Indefinite-length byte strings are rejected by the underlying decoder.
    pub fn bytes(&mut self) -> Result<&'a [u8], StrictError> {
        let bytes = self.inner.bytes()?;
        if bytes.len() > self.limits.max_cbor_bytes_len() {
            return Err(StrictError::BytesTooLong {
                length: bytes.len(),
                limit: self.limits.max_cbor_bytes_len(),
            });
        }
        Ok(bytes)
    }

    /// Decodes a boolean.
    pub fn bool(&mut self) -> Result<bool, StrictError> {
        Ok(self.inner.bool()?)
    }

    /// Decodes a null value.
    pub fn null(&mut self) -> Result<(), StrictError> {
        Ok(self.inner.null()?)
    }

    /// Decodes a definite-length map, calling `entries` for every key/value
    /// pair.
    ///
    /// `entries` receives this decoder to read the value of each entry and
    /// must reject keys it does not know. Enforces the nesting depth, map
    /// size, and indefinite-length rules.
    pub fn map_entries<E, F>(&mut self, mut entries: F) -> Result<(), E>
    where
        E: From<StrictError>,
        F: FnMut(&mut Self, u64) -> Result<(), E>,
    {
        let declared = self.inner.map().map_err(StrictError::from)?;
        let declared = declared.ok_or(StrictError::IndefiniteNotAllowed)?;
        self.enter_container(
            declared,
            self.limits.max_cbor_map_entries(),
            ContainerKind::Map,
        )?;
        let result = self.read_map_entries(declared, &mut entries);
        self.depth -= 1;
        result
    }

    /// Decodes a definite-length array, calling `elements` for every element.
    ///
    /// `elements` receives this decoder to read each element. Enforces the
    /// nesting depth, array size, and indefinite-length rules.
    pub fn array_entries<E, F>(&mut self, mut elements: F) -> Result<(), E>
    where
        E: From<StrictError>,
        F: FnMut(&mut Self) -> Result<(), E>,
    {
        let declared = self.inner.array().map_err(StrictError::from)?;
        let declared = declared.ok_or(StrictError::IndefiniteNotAllowed)?;
        self.enter_container(
            declared,
            self.limits.max_cbor_array_entries(),
            ContainerKind::Array,
        )?;
        let result = self.read_array_entries(declared, &mut elements);
        self.depth -= 1;
        result
    }

    /// Verifies that the whole input was consumed.
    ///
    /// Must be called once the message value has been decoded; any remaining
    /// bytes are rejected as trailing data.
    pub fn finish(&self) -> Result<(), StrictError> {
        if self.inner.position() == self.inner.input().len() {
            Ok(())
        } else {
            Err(StrictError::TrailingData)
        }
    }

    fn enter_container(
        &mut self,
        declared: u64,
        limit: usize,
        kind: ContainerKind,
    ) -> Result<(), StrictError> {
        if self.depth >= self.limits.max_cbor_nesting_depth() {
            return Err(StrictError::NestingTooDeep {
                limit: self.limits.max_cbor_nesting_depth(),
            });
        }
        if declared > limit as u64 {
            return Err(match kind {
                ContainerKind::Map => StrictError::MapTooLarge { declared, limit },
                ContainerKind::Array => StrictError::ArrayTooLarge { declared, limit },
            });
        }
        self.depth += 1;
        Ok(())
    }

    fn read_map_entries<E, F>(&mut self, declared: u64, entries: &mut F) -> Result<(), E>
    where
        E: From<StrictError>,
        F: FnMut(&mut Self, u64) -> Result<(), E>,
    {
        let mut seen: Vec<u64> = Vec::new();
        for _ in 0..declared {
            let key = self.u64()?;
            if seen.contains(&key) {
                return Err(StrictError::DuplicateMapKey { key }.into());
            }
            seen.push(key);
            entries(self, key)?;
        }
        Ok(())
    }

    fn read_array_entries<E, F>(&mut self, declared: u64, elements: &mut F) -> Result<(), E>
    where
        E: From<StrictError>,
        F: FnMut(&mut Self) -> Result<(), E>,
    {
        for _ in 0..declared {
            elements(self)?;
        }
        Ok(())
    }
}

/// The kind of container being entered, for size-limit error reporting.
enum ContainerKind {
    /// A CBOR map.
    Map,
    /// A CBOR array.
    Array,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode<T>(
        input: &[u8],
        f: impl FnOnce(&mut StrictDecoder<'_>) -> Result<T, StrictError>,
    ) -> Result<T, StrictError> {
        let limits = Limits::default();
        let mut decoder = StrictDecoder::new(input, &limits);
        let value = f(&mut decoder)?;
        decoder.finish()?;
        Ok(value)
    }

    #[test]
    fn scalars_decode() {
        assert_eq!(decode(&[0x05], |d| d.u8()).unwrap(), 5);
        assert_eq!(decode(&[0x19, 0x01, 0x00], |d| d.u16()).unwrap(), 256);
        assert_eq!(
            decode(&[0x1a, 0x00, 0x01, 0x00, 0x00], |d| d.u32()).unwrap(),
            65536
        );
        assert_eq!(
            decode(&[0x1b, 0, 0, 0, 0, 0, 0, 0, 0x7f], |d| d.u64()).unwrap(),
            127
        );
        assert!(!decode(&[0xf4], |d| d.bool()).unwrap());
        decode(&[0xf6], |d| d.null()).unwrap();
        assert_eq!(
            decode(&[0x61, b'e'], |d| d.str().map(str::to_owned)).unwrap(),
            "e"
        );
        assert_eq!(
            decode(&[0x43, b'a', b'b', b'c'], |d| d.bytes().map(<[u8]>::to_vec)).unwrap(),
            b"abc".to_vec()
        );
    }

    #[test]
    fn type_mismatch_is_rejected() {
        assert!(matches!(
            decode(&[0x61, b'a'], |d| d.u8()),
            Err(StrictError::Cbor(_))
        ));
        assert!(matches!(
            decode(&[0x05], |d| d.str().map(str::to_owned)),
            Err(StrictError::Cbor(_))
        ));
        assert!(matches!(
            decode(&[0x05], |d| d.bool()),
            Err(StrictError::Cbor(_))
        ));
    }

    #[test]
    fn integer_range_is_enforced() {
        // 0x18 0xFF is the u8 value 255; 0x18 0x80 is 128; u8() must reject 256.
        assert!(matches!(
            decode(&[0x19, 0x01, 0x00], |d| d.u8()),
            Err(StrictError::Cbor(_))
        ));
    }

    #[test]
    fn tags_are_rejected() {
        // Tag 1 followed by an integer.
        assert!(matches!(
            decode(&[0xc1, 0x05], |d| d.u8()),
            Err(StrictError::Cbor(_))
        ));
    }

    #[test]
    fn indefinite_structures_are_rejected() {
        // Indefinite map 0xBF ... 0xFF.
        assert!(matches!(
            decode(&[0xbf, 0x01, 0x02, 0xff], |d| d.map_entries(|_, _| Ok(()))),
            Err(StrictError::IndefiniteNotAllowed)
        ));
        // Indefinite array 0x9F 0xFF.
        assert!(matches!(
            decode(&[0x9f, 0xff], |d| d.array_entries(|_| Ok(()))),
            Err(StrictError::IndefiniteNotAllowed)
        ));
        // Indefinite text and byte strings are rejected by the decoder.
        assert!(matches!(
            decode(&[0x7f, 0xff], |d| d.str().map(str::to_owned)),
            Err(StrictError::Cbor(_))
        ));
        assert!(matches!(
            decode(&[0x5f, 0xff], |d| d.bytes().map(<[u8]>::to_vec)),
            Err(StrictError::Cbor(_))
        ));
    }

    #[test]
    fn map_size_limit_is_enforced() {
        // Map with 65 declared entries: 0xB8 0x41.
        assert!(matches!(
            decode(&[0xb8, 0x41], |d| d.map_entries(|_, _| Ok(()))),
            Err(StrictError::MapTooLarge {
                declared: 65,
                limit: 64
            })
        ));
        // Map with exactly 64 entries is allowed (content missing is a Cbor error).
        assert!(matches!(
            decode(&[0xb8, 0x40], |d| d.map_entries(|_, _| Ok(()))),
            Err(StrictError::Cbor(_))
        ));
    }

    #[test]
    fn array_size_limit_is_enforced() {
        // Array with 257 declared elements: 0x99 0x01 0x01.
        assert!(matches!(
            decode(&[0x99, 0x01, 0x01], |d| d.array_entries(|_| Ok(()))),
            Err(StrictError::ArrayTooLarge {
                declared: 257,
                limit: 256
            })
        ));
    }

    #[test]
    fn nesting_limit_is_enforced() {
        // Seven maps with entries plus the innermost empty map make eight
        // nested collections, which is allowed; one more is not.
        decode(&build_nested_maps(7), decode_nested).unwrap();
        assert!(matches!(
            decode(&build_nested_maps(8), decode_nested).unwrap_err(),
            StrictError::NestingTooDeep { limit: 8 }
        ));
    }

    fn build_nested_maps(depth: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..depth {
            out.extend_from_slice(&[0xa1, 0x01]);
        }
        out.push(0xa0);
        out
    }

    fn decode_nested(decoder: &mut StrictDecoder<'_>) -> Result<(), StrictError> {
        decoder.map_entries(|decoder, key| {
            assert_eq!(key, 1);
            decode_nested(decoder)
        })
    }

    #[test]
    fn duplicate_map_keys_are_rejected() {
        // map { 1: 2, 1: 3 }
        assert!(matches!(
            decode(&[0xa2, 0x01, 0x02, 0x01, 0x03], |d| d.map_entries(
                |d, key| {
                    assert_eq!(key, 1);
                    d.u8().map(|_| ())
                }
            )),
            Err(StrictError::DuplicateMapKey { key: 1 })
        ));
    }

    #[test]
    fn negative_and_complex_map_keys_are_rejected() {
        // map { -1: 2 } and map { [1]: 2 }.
        assert!(matches!(
            decode(&[0xa1, 0x20, 0x02], |d| d.map_entries(|_, _| Ok(()))),
            Err(StrictError::Cbor(_))
        ));
        assert!(matches!(
            decode(&[0xa1, 0x81, 0x01, 0x02], |d| d.map_entries(|_, _| Ok(()))),
            Err(StrictError::Cbor(_))
        ));
    }

    #[test]
    fn text_and_bytes_length_limits_are_enforced() {
        // 0x79 0x10 0x01 = text of 4097 bytes; fill with 'a'.
        let mut long_text = vec![0x79, 0x10, 0x01];
        long_text.extend(std::iter::repeat_n(b'a', 4097));
        assert!(matches!(
            decode(&long_text, |d| d.str().map(str::to_owned)).unwrap_err(),
            StrictError::TextTooLong {
                length: 4097,
                limit: 4096
            }
        ));

        // 0x59 0x10 0x01 = byte string of 4097 bytes.
        let mut long_bytes = vec![0x59, 0x10, 0x01];
        long_bytes.extend(std::iter::repeat_n(0u8, 4097));
        assert!(matches!(
            decode(&long_bytes, |d| d.bytes().map(<[u8]>::to_vec)).unwrap_err(),
            StrictError::BytesTooLong {
                length: 4097,
                limit: 4096
            }
        ));
    }

    #[test]
    fn trailing_data_is_rejected() {
        // Valid empty map followed by one extra byte.
        assert!(matches!(
            decode(&[0xa0, 0x00], |d| d.map_entries(|_, _| Ok(()))),
            Err(StrictError::TrailingData)
        ));
    }
}
