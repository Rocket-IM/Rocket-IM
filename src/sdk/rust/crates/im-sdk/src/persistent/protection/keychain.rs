//! 专用文件钥匙串适配：句柄从明确路径取得，绝不查询或锁定默认钥匙串。
//! 仅当前程序可读取新建项目；不接收钥匙串密码，不启用交互。
//! 文件钥匙串 API 已废弃，适用于本 macOS 隔离实验，不等于生产访问控制。
use super::super::types::{Error, Result};
use std::path::Path;

#[cfg(target_os = "macos")]
#[path = "keychain_ffi.rs"]
mod ffi;

#[cfg(target_os = "macos")]
mod platform {
    use super::{ffi, Error, Path, Result};
    use std::{ffi::CString, fs, path::Component, ptr};

    const MAX_SECRET: usize = 1024 * 1024;

    // 句柄从 Create/Open 成功返回，始终非空，且每份持有引用只释放一次。
    struct OwnedRef(ffi::KeychainRef);
    impl Drop for OwnedRef {
        fn drop(&mut self) {
            // SAFETY: 系统返回的 retained CF 对象由此包装独占释放。
            unsafe { ffi::CFRelease(self.0) };
        }
    }

    fn check(status: i32, stage: &str) -> Result<()> {
        match status {
            0 => Ok(()),
            -25291 => Err(Error::paused("keychain_unavailable")),
            -25293 => Err(Error::paused("keychain_auth_failed")),
            -25294 => Err(Error::paused("keychain_missing")),
            -25295 => Err(Error::paused("keychain_invalid")),
            -25299 => Err(Error::paused("keychain_item_exists")),
            -25300 => Err(Error::paused("keychain_item_missing")),
            -25308 => Err(Error::paused("keychain_interaction_denied")),
            // 保留平台失败码，但不记录路径、账号、密码或秘密内容。
            other => Err(Error::paused(&format!(
                "keychain_{stage}_os_status_{other}"
            ))),
        }
    }

    fn no_ui() -> Result<()> {
        // SAFETY: Boolean 的 C ABI 为 UInt8。此设置只禁用本进程的可选 UI。
        check(
            unsafe { ffi::SecKeychainSetUserInteractionAllowed(0) },
            "disable_ui",
        )
    }

    fn path_name(path: &Path) -> Result<CString> {
        let text = path
            .to_str()
            .filter(|text| text.len() <= 4096 && text.ends_with(".keychain-db"))
            .ok_or_else(|| Error::paused("keychain_path_invalid"))?;
        if !path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(Error::paused("keychain_path_invalid"));
        }
        CString::new(text).map_err(|_| Error::paused("keychain_path_invalid"))
    }

    fn item_names(service: &str, account: &str) -> Result<()> {
        if [service, account]
            .iter()
            .any(|text| text.is_empty() || text.len() > 4096 || text.contains('\0'))
        {
            return Err(Error::paused("keychain_item_invalid"));
        }
        Ok(())
    }

    fn unlocked(keychain: &OwnedRef) -> Result<()> {
        let mut status = 0;
        // SAFETY: 非空持有句柄有效，输出指向本栈上的 UInt32。
        check(
            unsafe { ffi::SecKeychainGetStatus(keychain.0, &mut status) },
            "get_status",
        )?;
        if status & 1 == 0 {
            return Err(Error::paused("keychain_locked"));
        }
        Ok(())
    }

    fn open(path: &Path, require_unlocked: bool) -> Result<OwnedRef> {
        let name = path_name(path)?;
        // Open 可以为不存在的路径返回句柄，因此先验证实际文件，再询问状态。
        let metadata = fs::symlink_metadata(path).map_err(|_| Error::paused("keychain_missing"))?;
        if !metadata.file_type().is_file() || metadata.len() == 0 {
            return Err(Error::paused("keychain_invalid"));
        }
        no_ui()?;
        let mut raw = ptr::null();
        // SAFETY: 路径是存活的 C 字符串；输出指针有效，不传默认钥匙串。
        check(
            unsafe { ffi::SecKeychainOpen(name.as_ptr(), &mut raw) },
            "open",
        )?;
        if raw.is_null() {
            return Err(Error::paused("keychain_invalid"));
        }
        let keychain = OwnedRef(raw);
        if require_unlocked {
            unlocked(&keychain)?;
        }
        Ok(keychain)
    }

    pub(crate) fn add(path: &Path, service: &str, account: &str, secret: &[u8]) -> Result<()> {
        item_names(service, account)?;
        if secret.is_empty() || secret.len() > MAX_SECRET {
            return Err(Error::paused("keychain_secret_invalid"));
        }
        let keychain = open(path, true)?;
        let access = trusted_access()?;
        let mut attributes = [
            ffi::Attribute {
                tag: u32::from_be_bytes(*b"svce"),
                length: service.len() as u32,
                data: service.as_ptr().cast_mut().cast(),
            },
            ffi::Attribute {
                tag: u32::from_be_bytes(*b"acct"),
                length: account.len() as u32,
                data: account.as_ptr().cast_mut().cast(),
            },
        ];
        let mut list = ffi::AttributeList {
            count: 2,
            attributes: attributes.as_mut_ptr(),
        };
        // SAFETY: SDK 将 attributes/secret 作为输入复制；所有内存和 ACL 对象存活至返回。
        // ACL 在创建项时共同提供，避免先创建只授权当前二进制的项再修改权限。
        check(
            unsafe {
                ffi::SecKeychainItemCreateFromContent(
                    u32::from_be_bytes(*b"genp"),
                    &mut list,
                    secret.len() as u32,
                    secret.as_ptr().cast(),
                    keychain.0,
                    access.reference.0,
                    ptr::null_mut(),
                )
            },
            "add",
        )
    }

    pub(crate) fn read(path: &Path, service: &str, account: &str) -> Result<Vec<u8>> {
        item_names(service, account)?;
        let keychain = open(path, true)?;
        let mut size = 0;
        let mut data = ptr::null_mut();
        // SAFETY: 明确限定单个钥匙串，输入与两个输出变量均存活且长度有界。
        check(
            unsafe {
                ffi::SecKeychainFindGenericPassword(
                    keychain.0,
                    service.len() as u32,
                    service.as_ptr().cast(),
                    account.len() as u32,
                    account.as_ptr().cast(),
                    &mut size,
                    &mut data,
                    ptr::null_mut(),
                )
            },
            "read",
        )?;
        let result = if data.is_null() || size == 0 || size as usize > MAX_SECRET {
            Err(Error::paused("keychain_secret_invalid"))
        } else {
            // SAFETY: Find 成功分配的 size 字节到 FreeContent 前有效，只复制一次。
            Ok(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), size as usize) }.to_vec())
        };
        if !data.is_null() {
            // SAFETY: 系统分配的内容只能由配对 API 释放，且这里恰好调用一次。
            check(
                unsafe { ffi::SecKeychainItemFreeContent(ptr::null_mut(), data) },
                "free_content",
            )?;
        }
        result
    }

    pub(crate) fn replace(path: &Path, service: &str, account: &str, secret: &[u8]) -> Result<()> {
        item_names(service, account)?;
        let keychain = open(path, true)?;
        let mut item = ptr::null();
        // SAFETY: 明确钥匙串及项目，输出引用由 OwnedRef 独占释放。
        check(
            unsafe {
                ffi::SecKeychainFindGenericPassword(
                    keychain.0,
                    service.len() as u32,
                    service.as_ptr().cast(),
                    account.len() as u32,
                    account.as_ptr().cast(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut item,
                )
            },
            "find_item",
        )?;
        let item = owned(item)?;
        // SAFETY: 保留既有 ACL，仅同步替换当前明确项目的内容；秘密不进入属性或日志。
        check(
            unsafe {
                ffi::SecKeychainItemModifyAttributesAndData(
                    item.0,
                    ptr::null(),
                    secret.len() as u32,
                    secret.as_ptr().cast(),
                )
            },
            "replace",
        )
    }

    struct Access {
        reference: OwnedRef,
        // CFArray 的元素未使用 retain 回调，因此显式保持全部对象到创建完成。
        _keep_alive: Vec<OwnedRef>,
    }
    fn trusted_access() -> Result<Access> {
        let current = std::env::current_exe()
            .and_then(fs::canonicalize)
            .map_err(|_| Error::paused("keychain_trusted_binary_invalid"))?;
        let paths = vec![current];
        #[cfg(feature = "persistent-test-hooks")]
        let paths = {
            let mut paths = paths;
            if let Ok(input) = std::env::var("ROCKET_IM_TEST_TRUSTED_APPLICATIONS") {
                let extras: Vec<std::path::PathBuf> = serde_json::from_str(&input)
                    .map_err(|_| Error::paused("test_trust_invalid"))?;
                if extras.len() > 2 {
                    return Err(Error::paused("test_trust_invalid"));
                }
                for path in extras {
                    paths.push(
                        fs::canonicalize(path).map_err(|_| Error::paused("test_trust_invalid"))?,
                    );
                }
            }
            paths
        };
        let mut keep_alive = Vec::new();
        for current in paths {
            let name = CString::new(
                current
                    .to_str()
                    .ok_or_else(|| Error::paused("keychain_trusted_binary_invalid"))?,
            )
            .map_err(|_| Error::paused("keychain_trusted_binary_invalid"))?;
            let mut application = ptr::null();
            // SAFETY: 当前实际运行程序路径；系统据路径建立代码身份约束。
            check(
                unsafe {
                    ffi::SecTrustedApplicationCreateFromPath(name.as_ptr(), &mut application)
                },
                "trusted_application",
            )?;
            keep_alive.push(owned(application)?);
        }
        let pointers: Vec<_> = keep_alive.iter().map(|value| value.0).collect();
        // SAFETY: 借用的对象由 keep_alive 保持，数组只在同步创建 ACL 时使用。
        let array = owned(unsafe {
            ffi::CFArrayCreate(
                ptr::null(),
                pointers.as_ptr(),
                pointers.len() as isize,
                ptr::null(),
            )
        })?;
        // SAFETY: 编译期 NUL 结尾字符串；0x08000100 为 kCFStringEncodingUTF8。
        let description = owned(unsafe {
            ffi::CFStringCreateWithCString(
                ptr::null(),
                c"Rocket-IM SDK local database key".as_ptr(),
                0x08000100,
            )
        })?;
        let mut access = ptr::null();
        // SAFETY: 非空数组仅含当前指定可信应用；不使用 NULL/空列表表达全允许。
        check(
            unsafe { ffi::SecAccessCreate(description.0, array.0, &mut access) },
            "create_access",
        )?;
        keep_alive.push(array);
        keep_alive.push(description);
        Ok(Access {
            reference: owned(access)?,
            _keep_alive: keep_alive,
        })
    }
    fn owned(raw: ffi::KeychainRef) -> Result<OwnedRef> {
        if raw.is_null() {
            Err(Error::paused("keychain_object_invalid"))
        } else {
            Ok(OwnedRef(raw))
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::{Error, Path, Result};
    pub(crate) fn add(_: &Path, _: &str, _: &str, _: &[u8]) -> Result<()> {
        Err(Error::paused("keychain_platform_unavailable"))
    }
    pub(crate) fn read(_: &Path, _: &str, _: &str) -> Result<Vec<u8>> {
        Err(Error::paused("keychain_platform_unavailable"))
    }
    pub(crate) fn replace(_: &Path, _: &str, _: &str, _: &[u8]) -> Result<()> {
        Err(Error::paused("keychain_platform_unavailable"))
    }
}
pub(super) use platform::{add, read, replace};
