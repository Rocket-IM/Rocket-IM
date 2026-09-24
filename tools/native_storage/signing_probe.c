/* 仅供本轮合成钥匙串签名验收：真实读秘密但绝不输出内容，只读公开 ACL。
 * 接口依据 macOS SDK 的 SecKeychainItem/SecAccess/SecACL/SecTrustedApplication.h。
 * 文件钥匙串 API 已弃用；此探针不代表正式 SDK 或生产安全保障。 */
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* 本文件有意验证旧文件钥匙串 ACL，弃用提示不扩散到其他源文件。 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static const char service[] = "org.rocket-im.native-protected.v1";
enum { MAX_ENTRIES = 64, MAX_PUBLIC_BYTES = 65536, MAX_ITEM = 256 };

static void release(CFTypeRef value) {
    if (value != NULL) CFRelease(value);
}

static bool suffix(const char *text, const char *end) {
    size_t length = strlen(text), tail = strlen(end);
    return length >= tail && strcmp(text + length - tail, end) == 0;
}

static bool valid_input(const char *path, const char *item) {
    size_t length = strlen(item);
    if (path[0] != '/' || strlen(path) >= PATH_MAX ||
        length <= 4 || length > MAX_ITEM || strncmp(item, "lab-", 4) != 0 ||
        suffix(item, ".trust")) return false;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)item[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) return false;
    }
    const char *name = strrchr(path, '/');
    if (name == NULL || strncmp(name + 1, "lab-", 4) != 0 ||
        !suffix(name + 1, ".keychain-db")) return false;
    struct stat metadata;
    char canonical[PATH_MAX];
    return lstat(path, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
           metadata.st_size > 0 && realpath(path, canonical) != NULL &&
           strcmp(path, canonical) == 0;
}

/* 逐 UTF-16 单元转义，包含控制字符和代理对；不依赖系统描述文本作 JSON。 */
static void json_string(CFStringRef value) {
    if (value == NULL || CFGetTypeID(value) != CFStringGetTypeID()) {
        fputs("null", stdout);
        return;
    }
    CFIndex length = CFStringGetLength(value);
    if (length > MAX_PUBLIC_BYTES) {
        fputs("null", stdout);
        return;
    }
    putchar('"');
    for (CFIndex i = 0; i < length; ++i) {
        UniChar c = CFStringGetCharacterAtIndex(value, i);
        if (c == '"' || c == '\\') printf("\\%c", (char)c);
        else if (c >= 0x20 && c <= 0x7e) putchar((int)c);
        else printf("\\u%04x", (unsigned)c);
    }
    putchar('"');
}

static void public_data(SecTrustedApplicationRef application) {
    CFDataRef data = NULL;
    OSStatus status = SecTrustedApplicationCopyData(application, &data);
    CFIndex length = data == NULL ? 0 : CFDataGetLength(data);
    bool bounded = length >= 0 && length <= MAX_PUBLIC_BYTES;
    printf("{\"status\":%d,\"data_format\":\"opaque_public\",\"bounded\":%s,\"data_hex\":",
           (int)status, bounded ? "true" : "false");
    if (status == errSecSuccess && data != NULL && bounded) {
        const UInt8 *bytes = CFDataGetBytePtr(data);
        putchar('"');
        for (CFIndex i = 0; i < length; ++i) printf("%02x", bytes[i]);
        putchar('"');
    } else fputs("null", stdout);
    putchar('}');
    release(data);
}

static void acl_entry(SecACLRef acl) {
    CFArrayRef applications = NULL;
    CFStringRef description = NULL;
    SecKeychainPromptSelector prompt = 0;
    OSStatus status = SecACLCopyContents(acl, &applications, &description, &prompt);
    CFArrayRef authorizations = SecACLCopyAuthorizations(acl);
    bool partition = false;
    CFIndex count = authorizations == NULL ? 0 : CFArrayGetCount(authorizations);
    printf("{\"contents_status\":%d,\"prompt_selector\":%u,\"authorizations_available\":%s,",
           (int)status, (unsigned)prompt, authorizations == NULL ? "false" : "true");
    printf("\"authorizations_bounded\":%s,\"authorizations\":[", count <= MAX_ENTRIES ? "true" : "false");
    for (CFIndex i = 0; i < count && i < MAX_ENTRIES; ++i) {
        CFTypeRef value = CFArrayGetValueAtIndex(authorizations, i);
        if (i != 0) putchar(',');
        json_string((CFStringRef)value);
        if (value != NULL && CFEqual(value, kSecACLAuthorizationPartitionID)) partition = true;
    }
    printf("],\"is_partition_acl\":%s,\"description_bounded\":%s,\"description\":",
           partition ? "true" : "false",
           description == NULL || CFStringGetLength(description) <= MAX_PUBLIC_BYTES ? "true" : "false");
    json_string(description);
    printf(",\"applications_present\":%s,\"applications\":[", applications == NULL ? "false" : "true");
    count = applications == NULL ? 0 : CFArrayGetCount(applications);
    for (CFIndex i = 0; i < count && i < MAX_ENTRIES; ++i) {
        if (i != 0) putchar(',');
        CFTypeRef value = CFArrayGetValueAtIndex(applications, i);
        if (value != NULL && CFGetTypeID(value) == SecTrustedApplicationGetTypeID())
            public_data((SecTrustedApplicationRef)value);
        else fputs("{\"invalid_type\":true}", stdout);
    }
    printf("],\"applications_bounded\":%s}", count <= MAX_ENTRIES ? "true" : "false");
    release(authorizations);
    release(description);
    release(applications);
}

/* 此 lookup 不索要秘密；公开 ACL 的成功不能代替上面独立的秘密读取结果。 */
static void item_acl(SecKeychainRef keychain, const char *item) {
    SecKeychainItemRef reference = NULL;
    SecAccessRef access = NULL;
    CFArrayRef list = NULL;
    OSStatus lookup = SecKeychainFindGenericPassword(keychain, (UInt32)(sizeof(service) - 1),
        service, (UInt32)strlen(item), item, NULL, NULL, &reference);
    printf(",\"lookup_status\":%d,\"access_status\":", (int)lookup);
    if (lookup != errSecSuccess || reference == NULL) {
        fputs("null,\"acl_list_status\":null,\"acls\":[]", stdout);
        release(reference);
        return;
    }
    OSStatus copied = SecKeychainItemCopyAccess(reference, &access);
    printf("%d,\"acl_list_status\":", (int)copied);
    if (copied != errSecSuccess || access == NULL) {
        fputs("null,\"acls\":[]", stdout);
        release(access);
        release(reference);
        return;
    }
    OSStatus listed = SecAccessCopyACLList(access, &list);
    printf("%d,\"acls\":[", (int)listed);
    CFIndex count = list == NULL ? 0 : CFArrayGetCount(list);
    for (CFIndex i = 0; listed == errSecSuccess && i < count && i < MAX_ENTRIES; ++i) {
        if (i != 0) putchar(',');
        CFTypeRef value = CFArrayGetValueAtIndex(list, i);
        if (value != NULL && CFGetTypeID(value) == SecACLGetTypeID()) acl_entry((SecACLRef)value);
        else fputs("{\"invalid_type\":true}", stdout);
    }
    printf("],\"acls_bounded\":%s", count <= MAX_ENTRIES ? "true" : "false");
    release(list);
    release(access);
    release(reference);
}

static void item_probe(SecKeychainRef keychain, const char *kind, const char *item) {
    UInt32 length = 0;
    void *secret = NULL;
    OSStatus status = SecKeychainFindGenericPassword(keychain, (UInt32)(sizeof(service) - 1),
        service, (UInt32)strlen(item), item, &length, &secret, NULL);
    bool got_secret = status == errSecSuccess && secret != NULL && length != 0;
    OSStatus freed = errSecSuccess;
    if (secret != NULL) {
        /* volatile 写入不得被优化掉；清零后立即使用配对系统 API 释放。 */
        volatile unsigned char *bytes = secret;
        for (UInt32 i = 0; i < length; ++i) bytes[i] = 0;
        freed = SecKeychainItemFreeContent(NULL, secret);
    }
    printf("{\"kind\":\"%s\",\"read_status\":%d,\"got_secret\":%s,\"free_status\":%d",
           kind, (int)status, got_secret ? "true" : "false", (int)freed);
    item_acl(keychain, item);
    putchar('}');
}

static int startup_failure(const char *stage, OSStatus status) {
    printf("{\"pid\":%ld,\"started\":false,\"completed\":false,\"startup_stage\":\"%s\","
           "\"startup_status\":%d,\"items\":[]}\n", (long)getpid(), stage, (int)status);
    return 2;
}

int main(int argc, char **argv) {
    if (argc != 3 || !valid_input(argv[1], argv[2])) return startup_failure("input", errSecParam);
    OSStatus status = SecKeychainSetUserInteractionAllowed(false);
    if (status != errSecSuccess) return startup_failure("disable_ui", status);
    SecKeychainRef keychain = NULL;
    status = SecKeychainOpen(argv[1], &keychain);
    if (status != errSecSuccess || keychain == NULL) {
        release(keychain);
        return startup_failure("open", status == errSecSuccess ? errSecInvalidKeychain : status);
    }
    char trust[MAX_ITEM + sizeof(".trust")];
    snprintf(trust, sizeof(trust), "%s.trust", argv[2]);
    printf("{\"pid\":%ld,\"started\":true,\"completed\":true,\"startup_status\":0,\"items\":[",
           (long)getpid());
    item_probe(keychain, "key", argv[2]);
    putchar(',');
    item_probe(keychain, "trust", trust);
    fputs("]}\n", stdout);
    release(keychain);
    /* 0 表示两次读取和 ACL 探测已执行；访问是否拒绝必须由调用方检查字段。 */
    return ferror(stdout) ? 3 : 0;
}
#pragma clang diagnostic pop
