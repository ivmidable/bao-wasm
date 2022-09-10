use std::io::prelude::*;
use wasm_bindgen::prelude::*;
use std::io::Cursor;
use std::convert::TryInto;
use bao::{decode, encode, Hash};


#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    data: Vec<u8>,
    hash: Hash,
    outboard: Option<Vec<u8>>,
    slice_start: Option<u64>,
    slice_length: Option<u64>,
}

#[wasm_bindgen]
impl Encoded {
    #[wasm_bindgen(constructor)]
    pub fn new(data: Vec<u8>, hash: &[u8], outboard: Option<Vec<u8>>, slice_start: Option<u64>, slice_length: Option<u64>) -> Encoded {
        let hash_array:[u8;32] = hash.try_into().unwrap();
        Encoded {
            data,
            hash: Hash::from(hash_array),
            outboard,
            slice_start,
            slice_length,
        }
    }

    pub fn get_data(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn get_hash(&self) -> String {
        self.hash.to_hex().to_string()
    }

    pub fn is_outboard(&self) -> bool {
        self.outboard.is_some()
    }

    pub fn get_slice_start(&self) -> Option<u64> {
        self.slice_start
    }

    pub fn get_slice_length(&self) -> Option<u64> {
        self.slice_length
    }
}

#[wasm_bindgen]
pub fn encode(outboard: bool, input: &[u8]) -> Encoded {
    if outboard == false {
        let res = encode::encode(input);
        Encoded {
            data: res.0,
            hash: res.1,
            outboard: None,
            slice_start: None,
            slice_length: None,
        }
    } else {
        let res = encode::outboard(input);
        Encoded {
            data: input.to_vec(),
            hash: res.1,
            outboard: Some(res.0),
            slice_start: None,
            slice_length: None,
        }
    }
}

#[wasm_bindgen]
pub fn decode(encoded: Encoded) -> Vec<u8> {
    match encoded.outboard {
        None => decode::decode(encoded.data.as_slice(), &encoded.hash).unwrap(),
        Some(outboard) => {
            let mut outboard_output = Vec::new();
            let mut decoder =
                decode::Decoder::new_outboard(encoded.data.as_slice(), &*outboard, &encoded.hash);
            decoder.read_to_end(&mut outboard_output).unwrap();
            outboard_output
        }
    }
}

#[wasm_bindgen]
pub fn slice(encoded: Encoded) -> Encoded {
    let mut slice = Vec::new();
    let mut extractor;
    match encoded.outboard {
        None => {
            extractor = bao::encode::SliceExtractor::new(
                Cursor::new(&encoded.data), 
                encoded.slice_start.unwrap(), 
                encoded.slice_length.unwrap()
            );
        },
        Some(ref outboard) => {
            extractor = encode::SliceExtractor::new_outboard(
                Cursor::new(&encoded.data),
                Cursor::new(outboard),
                encoded.slice_start.unwrap(),
                encoded.slice_length.unwrap(),
            );
            
        }   
    }
    extractor.read_to_end(&mut slice).unwrap();
    Encoded { data:slice, hash:encoded.hash, outboard:None, slice_start:Some(encoded.slice_start.unwrap()), slice_length:Some(encoded.slice_length.unwrap()) }
}

#[wasm_bindgen]
pub fn decode_slice(encoded: Encoded) -> Vec<u8> {
    let mut decoded = Vec::new();
    let mut decoder = bao::decode::SliceDecoder::new(
        &*encoded.data,
        &encoded.hash,
        encoded.slice_start.unwrap(),
        encoded.slice_length.unwrap(),
    );
    decoder.read_to_end(&mut decoded).unwrap();
    decoded
}

#[cfg(test)]
mod test_wrapped {
    #[test]
    fn test_encode() {
        let input = b"some input";
        let encoded = super::encode(false, input);
        assert_eq!(
            encoded.data,
            vec![10, 0, 0, 0, 0, 0, 0, 0, 115, 111, 109, 101, 32, 105, 110, 112, 117, 116]
        );
    }

    #[test]
    fn test_encode_outboard() {
        let input = b"some input";
        let encoded = super::encode(true, input);
        assert_eq!(encoded.outboard.unwrap(), vec![10, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_decode() {
        let input = b"some input";
        let encoded = super::encode(false, input);
        let decoded_at_once = super::decode(encoded);
        assert_eq!(decoded_at_once, input);
    }

    #[test]
    fn test_decode_outboard() {
        let input = b"some input";
        let encoded = super::encode(true, input);
        let decoded_at_once = super::decode(encoded);
        assert_eq!(decoded_at_once, input);
    }

    #[test]
    fn test_extract_slice() {
        let input:[u8; 2000] = [23; 2000];
        let mut encoded = super::encode(false, &input[..]);
        encoded.slice_start = Some(0);
        encoded.slice_length = Some(1024);
        let slice = super::slice(encoded);
        assert_eq!(slice.data.len(), 1096);
    }

    #[test]
    fn test_decode_slice() {
        let input:[u8; 2000] = [23; 2000];
        let mut encoded = super::encode(true, &input[..]);
        encoded.slice_start = Some(0);
        encoded.slice_length = Some(100);
        let slice = super::slice(encoded);
        let decoded = super::decode_slice(slice);
        assert_eq!(decoded.len(), 100);
        assert_eq!(decoded, input[..100])
    }
}
