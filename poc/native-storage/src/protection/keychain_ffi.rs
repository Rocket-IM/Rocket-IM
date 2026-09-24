//! macOS 26.1 SDK 的文件钥匙串 ABI；只声明本隔离实验实际使用的系统入口。
use std::ffi::{c_char, c_void};

pub(super) type KeychainRef = *const c_void;
pub(super) type ItemRef = *const c_void;

#[repr(C)]
pub(super) struct Attribute {
    pub tag: u32,
    pub length: u32,
    pub data: *mut c_void,
}
#[repr(C)]
pub(super) struct AttributeList {
    pub count: u32,
    pub attributes: *mut Attribute,
}

#[link(name = "Security", kind = "framework")]
extern "C" {
    pub(super) fn SecKeychainCreate(
        path: *const c_char,
        password_len: u32,
        password: *const c_void,
        prompt_user: u8,
        initial_access: *const c_void,
        keychain: *mut KeychainRef,
    ) -> i32;
    pub(super) fn SecKeychainOpen(path: *const c_char, keychain: *mut KeychainRef) -> i32;
    pub(super) fn SecKeychainGetStatus(keychain: KeychainRef, status: *mut u32) -> i32;
    pub(super) fn SecKeychainSetUserInteractionAllowed(allowed: u8) -> i32;
    pub(super) fn SecKeychainUnlock(
        keychain: KeychainRef,
        password_len: u32,
        password: *const c_void,
        use_password: u8,
    ) -> i32;
    pub(super) fn SecKeychainLock(keychain: KeychainRef) -> i32;
    pub(super) fn SecKeychainItemCreateFromContent(
        class: u32,
        attributes: *mut AttributeList,
        length: u32,
        data: *const c_void,
        keychain: KeychainRef,
        access: *const c_void,
        item: *mut ItemRef,
    ) -> i32;
    pub(super) fn SecTrustedApplicationCreateFromPath(
        path: *const c_char,
        app: *mut *const c_void,
    ) -> i32;
    pub(super) fn SecAccessCreate(
        description: *const c_void,
        trusted_apps: *const c_void,
        access: *mut *const c_void,
    ) -> i32;
    pub(super) fn SecKeychainFindGenericPassword(
        keychain: KeychainRef,
        service_len: u32,
        service: *const c_char,
        account_len: u32,
        account: *const c_char,
        password_len: *mut u32,
        password: *mut *mut c_void,
        item: *mut ItemRef,
    ) -> i32;
    pub(super) fn SecKeychainItemFreeContent(attributes: *mut c_void, data: *mut c_void) -> i32;
    pub(super) fn SecKeychainItemDelete(item: ItemRef) -> i32;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    pub(super) fn CFRelease(value: *const c_void);
    pub(super) fn CFStringCreateWithCString(
        allocator: *const c_void,
        value: *const c_char,
        encoding: u32,
    ) -> *const c_void;
    pub(super) fn CFArrayCreate(
        allocator: *const c_void,
        values: *const *const c_void,
        count: isize,
        callbacks: *const c_void,
    ) -> *const c_void;
}
