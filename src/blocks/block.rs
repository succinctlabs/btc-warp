use nakamoto::chain::BlockHeader;

#[derive(Copy, Clone, Debug)]
pub struct Header(BlockHeader);

impl Header {
    pub fn from_vec_blockheader(block_headers: Vec<BlockHeader>) -> Vec<Header> {
        block_headers.into_iter().map(|h| Header(h)).collect()
    }

    pub fn to_hex(&self) -> String {
        let slice: Vec<u8> = Header::into(*self);
        hex::encode(&slice[..])
    }

    pub fn to_hex_vec(headers: Vec<Header>) -> Vec<String> {
        headers.into_iter().map(|h| h.to_hex()).collect()
    }
}

impl Into<Vec<u8>> for Header {
    fn into(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.0.version.to_le_bytes());
        bytes.extend_from_slice(self.0.prev_blockhash.as_ref());
        bytes.extend_from_slice(self.0.merkle_root.as_ref());
        bytes.extend_from_slice(&self.0.time.to_le_bytes());
        bytes.extend_from_slice(&self.0.bits.to_le_bytes());
        bytes.extend_from_slice(&self.0.nonce.to_le_bytes());
        bytes
    }
}

impl From<BlockHeader> for Header {
    fn from(block_header: BlockHeader) -> Self {
        Header(block_header)
    }
}
