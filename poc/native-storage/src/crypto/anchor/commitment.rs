//! 对原生库完整逻辑内容做有界承诺；每个调用都借用显式事务。
use rusqlite::{types::ValueRef, Transaction};
use sha2::{Digest, Sha256};

use crate::{
    crypto::schema,
    model::{Error, Result},
};

const TOTAL_LIMIT: usize = 64 * 1024 * 1024;
const ROW_LIMIT: usize = 4 * 1024 * 1024;
const TABLES: [(&str, &str, &str); 7] = [
    ("crypto_meta", "singleton", "singleton,format,service,account,device,revision,identity_json,conversation,provider,provider_hash,encryptions,processed_cursor,decryptions,download_cursor"),
    ("crypto_pending", "singleton", "singleton,request_id,operation,input_hash,base_revision,base_provider_hash"),
    ("crypto_results", "request_id", "request_id,input_hash,kind,outcome_json"),
    ("crypto_outbox", "attempt_id", "attempt_id,message_id,request_id,input_hash,envelope_json"),
    ("crypto_inbox", "message_key", "message_key,first_sequence,message_id,sender_account,sender_device,envelope_hash,ciphertext_hash,text_hash,envelope_json,plaintext_json"),
    ("crypto_receipts", "sequence", "sequence,message_key,request_id,input_hash"),
    ("crypto_downloads", "sequence", "sequence,envelope_hash,ciphertext_hash,envelope_json"),
];

struct Commitment {
    hash: Sha256,
    bytes: usize,
}
impl Commitment {
    fn add(&mut self, tag: u8, value: &[u8]) -> Result<usize> {
        let size = value.len().checked_add(9).ok_or_else(limit)?;
        if size > ROW_LIMIT {
            return Err(limit());
        }
        self.bytes = self.bytes.checked_add(size).ok_or_else(limit)?;
        if self.bytes > TOTAL_LIMIT {
            return Err(limit());
        }
        self.hash.update([tag]);
        self.hash.update((value.len() as u64).to_be_bytes());
        self.hash.update(value);
        Ok(size)
    }
}
fn limit() -> Error {
    Error::new("anchor_commitment_limit", true)
}

pub(crate) fn head(tx: &Transaction<'_>, omit_pending: bool) -> Result<String> {
    schema::validate(tx)?;
    let mut state = Commitment {
        hash: Sha256::new(),
        bytes: 0,
    };
    state.add(b'D', b"Rocket-IM/native-anchor/logical-head/v1")?;
    state.add(b'V', &schema::version(tx)?.to_be_bytes())?;
    // 精确 schema 由 validate 验证；控制表单独签名，不进入承诺以避免自引用。
    let mut schema_query = tx.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE tbl_name!='anchor_control' ORDER BY type,name LIMIT 17").map_err(Error::database)?;
    let mut rows = schema_query.query([]).map_err(Error::database)?;
    let mut schema_count = 0_u64;
    while let Some(row) = rows.next().map_err(Error::database)? {
        schema_count += 1;
        state.add(b'S', b"")?;
        for index in 0..4 {
            add_value(&mut state, row.get_ref(index).map_err(Error::database)?)?;
        }
    }
    state.add(b's', &schema_count.to_be_bytes())?;
    for (table, order, selected) in TABLES {
        state.add(b'T', table.as_bytes())?;
        // 名称和顺序只来自上面的固定表，绝不插入调用方输入。
        let mut query = tx
            .prepare(&format!(
                "SELECT {selected} FROM {table} ORDER BY {order} LIMIT 129"
            ))
            .map_err(Error::database)?;
        let columns = query.column_count();
        for column in query.column_names() {
            state.add(b'C', column.as_bytes())?;
        }
        if table == "crypto_pending" && omit_pending {
            state.add(b't', &0_u64.to_be_bytes())?;
            continue;
        }
        let mut rows = query.query([]).map_err(Error::database)?;
        let mut count = 0_u64;
        while let Some(row) = rows.next().map_err(Error::database)? {
            count += 1;
            if count > 128 {
                return Err(limit());
            }
            let mut size = state.add(b'R', b"")?;
            for index in 0..columns {
                size += add_value(&mut state, row.get_ref(index).map_err(Error::database)?)?;
                if size > ROW_LIMIT {
                    return Err(limit());
                }
            }
        }
        state.add(b't', &count.to_be_bytes())?;
    }
    Ok(format!("{:x}", state.hash.finalize()))
}
fn add_value(state: &mut Commitment, value: ValueRef<'_>) -> Result<usize> {
    match value {
        ValueRef::Null => state.add(b'N', &[]),
        ValueRef::Integer(value) => state.add(b'I', &value.to_be_bytes()),
        ValueRef::Real(value) => state.add(b'F', &value.to_bits().to_be_bytes()),
        ValueRef::Text(value) => state.add(b'T', value),
        ValueRef::Blob(value) => state.add(b'B', value),
    }
}
