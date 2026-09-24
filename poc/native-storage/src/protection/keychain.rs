//! 专用文件钥匙串适配：句柄从明确路径取得，绝不查询或锁定默认钥匙串。
//! 密码、秘密仅接收内存字节；调用方负责管道输入和使用后的内存清理。
//! 文件钥匙串 API 已废弃，适用于本 macOS 隔离实验，不等于生产访问控制。
use crate::model::{Error, Result};
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
            -25291 => Err(Error::new("keychain_unavailable", true)),
            -25293 => Err(Error::new("keychain_auth_failed", true)),
            -25294 => Err(Error::new("keychain_missing", true)),
            -25295 => Err(Error::new("keychain_invalid", true)),
            -25299 => Err(Error::new("keychain_item_exists", true)),
            -25300 => Err(Error::new("keychain_item_missing", true)),
            -25308 => Err(Error::new("keychain_interaction_denied", true)),
            // 保留平台失败码，但不记录路径、账号、密码或秘密内容。
            other => Err(Error::new(
                &format!("keychain_{stage}_os_status_{other}"),
                true,
            )),
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
            .ok_or_else(|| Error::new("keychain_path_invalid", true))?;
        if !path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(Error::new("keychain_path_invalid", true));
        }
        CString::new(text).map_err(|_| Error::new("keychain_path_invalid", true))
    }

    fn password_size(password: &[u8]) -> Result<u32> {
        // 本装置使用随机 ASCII 密码，避免系统 canonical UTF-8 要求的歧义。
        if password.is_empty()
            || password.len() > 4096
            || !password.is_ascii()
            || password.contains(&0)
        {
            return Err(Error::new("keychain_password_invalid", true));
        }
        Ok(password.len() as u32)
    }

    fn item_names(service: &str, account: &str) -> Result<()> {
        if [service, account]
            .iter()
            .any(|text| text.is_empty() || text.len() > 4096 || text.contains('\0'))
        {
            return Err(Error::new("keychain_item_invalid", true));
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
            return Err(Error::new("keychain_locked", true));
        }
        Ok(())
    }

    fn open(path: &Path, require_unlocked: bool) -> Result<OwnedRef> {
        let name = path_name(path)?;
        // Open 可以为不存在的路径返回句柄，因此先验证实际文件，再询问状态。
        let metadata =
            fs::symlink_metadata(path).map_err(|_| Error::new("keychain_missing", true))?;
        if !metadata.file_type().is_file() || metadata.len() == 0 {
            return Err(Error::new("keychain_invalid", true));
        }
        no_ui()?;
        let mut raw = ptr::null();
        // SAFETY: 路径是存活的 C 字符串；输出指针有效，不传默认钥匙串。
        check(
            unsafe { ffi::SecKeychainOpen(name.as_ptr(), &mut raw) },
            "open",
        )?;
        if raw.is_null() {
            return Err(Error::new("keychain_invalid", true));
        }
        let keychain = OwnedRef(raw);
        if require_unlocked {
            unlocked(&keychain)?;
        }
        Ok(keychain)
    }

    pub(in crate::protection) fn create(path: &Path, password: &[u8]) -> Result<()> {
        let name = path_name(path)?;
        let size = password_size(password)?;
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(Error::new("keychain_exists", true)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::new("keychain_path_invalid", true)),
        }
        no_ui()?;
        let mut raw = ptr::null();
        // SAFETY: 所有输入在调用期间存活；禁用提示，系统复制密码后返回。
        // Create 可能由系统登记这个新实验钥匙串，本模块不设置搜索列表。
        check(
            unsafe {
                ffi::SecKeychainCreate(
                    name.as_ptr(),
                    size,
                    password.as_ptr().cast(),
                    0,
                    ptr::null(),
                    &mut raw,
                )
            },
            "create",
        )?;
        if raw.is_null() {
            return Err(Error::new("keychain_invalid", true));
        }
        unlocked(&OwnedRef(raw))
    }

    pub(in crate::protection) fn unlock(path: &Path, password: &[u8]) -> Result<()> {
        let size = password_size(password)?;
        let keychain = open(path, false)?;
        // SAFETY: 明确句柄与存活密码，usePassword=true，不能启用交互解锁。
        check(
            unsafe { ffi::SecKeychainUnlock(keychain.0, size, password.as_ptr().cast(), 1) },
            "unlock",
        )?;
        unlocked(&keychain)
    }

    pub(in crate::protection) fn lock(path: &Path) -> Result<()> {
        let keychain = open(path, false)?;
        // SAFETY: 只锁这个明确且非空的句柄，不使用 LockAll 或默认钥匙串。
        check(unsafe { ffi::SecKeychainLock(keychain.0) }, "lock")
    }

    pub(in crate::protection) fn add(
        path: &Path,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<()> {
        item_names(service, account)?;
        if secret.is_empty() || secret.len() > MAX_SECRET {
            return Err(Error::new("keychain_secret_invalid", true));
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

    pub(in crate::protection) fn read(
        path: &Path,
        service: &str,
        account: &str,
    ) -> Result<Vec<u8>> {
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
            Err(Error::new("keychain_secret_invalid", true))
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

    pub(in crate::protection) fn remove(path: &Path, service: &str, account: &str) -> Result<()> {
        item_names(service, account)?;
        let keychain = open(path, true)?;
        let mut item = ptr::null();
        // SAFETY: 只查明确实验项的 retained 引用，不读取秘密内容。
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
        if item.is_null() {
            return Err(Error::new("keychain_item_missing", true));
        }
        let item = OwnedRef(item);
        // SAFETY: item 为上述明确匹配项，删除之后 retained 引用仍由包装释放。
        check(unsafe { ffi::SecKeychainItemDelete(item.0) }, "delete_item")
    }

    struct Access {
        reference: OwnedRef,
        // CFArray 的元素未使用 retain 回调，因此显式保持全部对象到创建完成。
        _keep_alive: Vec<OwnedRef>,
    }
    fn trusted_access() -> Result<Access> {
        const BINARIES: [&str; 4] = [
            "native_crypto",
            "native_anchored",
            "native_rebuild",
            "native_protection",
        ];
        let current = std::env::current_exe()
            .and_then(fs::canonicalize)
            .map_err(|_| Error::new("keychain_trusted_binary_invalid", true))?;
        if !current
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| BINARIES.contains(&name))
        {
            return Err(Error::new("keychain_trusted_binary_invalid", true));
        }
        let directory = current
            .parent()
            .filter(|directory| directory.file_name().is_some_and(|name| name == "release"))
            .ok_or_else(|| Error::new("keychain_trusted_binary_invalid", true))?;
        let mut keep_alive = Vec::new();
        for binary in BINARIES {
            let path = directory.join(binary);
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| Error::new("keychain_trusted_binary_missing", true))?;
            if !metadata.file_type().is_file() || metadata.len() == 0 {
                return Err(Error::new("keychain_trusted_binary_invalid", true));
            }
            let name = CString::new(
                path.to_str()
                    .ok_or_else(|| Error::new("keychain_trusted_binary_invalid", true))?,
            )
            .map_err(|_| Error::new("keychain_trusted_binary_invalid", true))?;
            let mut application = ptr::null();
            // SAFETY: 四个明确存在的实验二进制路径；系统据路径建立代码身份约束。
            check(
                unsafe {
                    ffi::SecTrustedApplicationCreateFromPath(name.as_ptr(), &mut application)
                },
                "trusted_application",
            )?;
            keep_alive.push(owned(application)?);
        }
        let pointers: Vec<_> = keep_alive.iter().map(|value| value.0).collect();
        // SAFETY: 借用的四个对象由 keep_alive 保持，数组只在同步创建 ACL 时使用。
        let array =
            owned(unsafe { ffi::CFArrayCreate(ptr::null(), pointers.as_ptr(), 4, ptr::null()) })?;
        // SAFETY: 编译期 NUL 结尾字符串；0x08000100 为 kCFStringEncodingUTF8。
        let description = owned(unsafe {
            ffi::CFStringCreateWithCString(
                ptr::null(),
                c"Rocket-IM isolated native protection".as_ptr(),
                0x08000100,
            )
        })?;
        let mut access = ptr::null();
        // SAFETY: 非空数组仅含四个指定可信应用；不使用 NULL/空列表表达全允许。
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
            Err(Error::new("keychain_object_invalid", true))
        } else {
            Ok(OwnedRef(raw))
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::{Error, Path, Result};
    pub(in crate::protection) fn create(_: &Path, _: &[u8]) -> Result<()> {
        unavailable()
    }
    pub(in crate::protection) fn unlock(_: &Path, _: &[u8]) -> Result<()> {
        unavailable()
    }
    pub(in crate::protection) fn lock(_: &Path) -> Result<()> {
        unavailable()
    }
    pub(in crate::protection) fn add(_: &Path, _: &str, _: &str, _: &[u8]) -> Result<()> {
        unavailable()
    }
    pub(in crate::protection) fn read(_: &Path, _: &str, _: &str) -> Result<Vec<u8>> {
        unavailable()
    }
    pub(in crate::protection) fn remove(_: &Path, _: &str, _: &str) -> Result<()> {
        unavailable()
    }
    fn unavailable<T>() -> Result<T> {
        Err(Error::new("keychain_platform_unavailable", true))
    }
}

pub(super) use platform::{add, create, lock, read, remove, unlock};
