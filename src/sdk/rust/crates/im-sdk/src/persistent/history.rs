//! 只投影已提交消息；不持久化分页会话，不改变旧库格式或密码状态。
use super::{
    data::{Data, StoredMessage},
    types::*,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryDirection {
    Forward,
    Backward,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryQuery {
    /// 1..=64；JSON 编码预算可能使非末页短于此值。
    pub page_size: u32,
    pub direction: HistoryDirection,
    /// None 开始新范围；后续原样传回，保持方向和页大小。
    pub cursor: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryItem {
    /// 从 1 开始的本地持久化追加位置，十进制字符串；不是服务器序号或时间。
    pub local_position: String,
    pub message: Message,
    /// 仅已提交的 Service 永久拒绝具有此值；原本地请求结果仍可精确查询。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection: Option<super::network::SendRejection>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryPage {
    pub items: Vec<HistoryItem>,
    /// 首次读取时固定的包含式上界，空库为 "0"。
    pub upper_bound: String,
    pub direction: HistoryDirection,
    pub page_size: u32,
    pub next_cursor: Option<String>,
    pub done: bool,
}

// 单条最大正文的 JSON 转义可放大六倍；预留 IPC 帧及游标空间。
const PAGE_BYTES: usize = 512 * 1024;

pub(super) fn page(data: Data, space: &str, query: HistoryQuery) -> Result<HistoryPage> {
    let messages = data.history_messages()?;
    if !(1..=64).contains(&query.page_size) {
        return Err(Error::new("history_page_size_invalid"));
    }
    let (upper, mut consumed) = if let Some(cursor) = &query.cursor {
        if cursor.len() > 128 {
            return Err(Error::new("history_cursor_invalid"));
        }
        let parts: Vec<_> = cursor.split(':').collect();
        if parts.len() != 4
            || parts[0] != "h1"
            || parts[3].len() != 64
            || !parts[3]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::new("history_cursor_invalid"));
        }
        let parse = |s: &str| {
            number(s)
                .ok()
                .and_then(|n| usize::try_from(n).ok())
                .ok_or_else(|| Error::new("history_cursor_invalid"))
        };
        let upper = parse(parts[1])?;
        let consumed = parse(parts[2])?;
        if upper > messages.len() || consumed == 0 || consumed >= upper {
            return Err(Error::new("history_cursor_mismatch"));
        }
        if &token(&data, &messages, space, &query, upper, consumed)? != cursor {
            return Err(Error::new("history_cursor_mismatch"));
        }
        (upper, consumed)
    } else {
        (messages.len(), 0)
    };
    let mut items = Vec::new();
    let mut bytes = 0;
    while consumed < upper && items.len() < query.page_size as usize {
        let index = match query.direction {
            HistoryDirection::Forward => consumed,
            HistoryDirection::Backward => upper - consumed - 1,
        };
        let item = HistoryItem {
            local_position: (index + 1).to_string(),
            message: messages[index].message.clone(),
            rejection: data.requests.values().find_map(|r| {
                if matches!(&r.result, RequestState::Complete {outcome} if matches!(&outcome.value, Value::Sent {envelope} if envelope == &messages[index].envelope)) {
                    r.rejection.clone()
                } else { None }
            }),
        };
        let length = encode(&item)?.len();
        if bytes + length > PAGE_BYTES {
            break;
        }
        bytes += length;
        items.push(item);
        consumed += 1;
    }
    let done = consumed == upper;
    let next_cursor = if done {
        None
    } else {
        Some(token(&data, &messages, space, &query, upper, consumed)?)
    };
    Ok(HistoryPage {
        items,
        upper_bound: upper.to_string(),
        direction: query.direction,
        page_size: query.page_size,
        next_cursor,
        done,
    })
}

fn token(
    data: &Data,
    messages: &[StoredMessage],
    space: &str,
    query: &HistoryQuery,
    upper: usize,
    consumed: usize,
) -> Result<String> {
    // 绑定完整查询前缀，拒绝截短/分叉的快照；追加消息与恢复转换不改变原范围。
    // 这是查询定位符而非授权令牌；权限始终由每个作业及交付边界检查。
    let prefix = hash(&encode(&messages[..upper])?);
    let binding = hash(&encode(&(
        "Rocket-IM/SDK/history/v1",
        space,
        &data.state.scope,
        &data.state.identity,
        query.direction,
        query.page_size,
        upper,
        consumed,
        prefix,
    ))?);
    Ok(format!("h1:{upper}:{consumed}:{binding}"))
}
