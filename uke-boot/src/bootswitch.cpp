// SPDX-License-Identifier: MIT
// Fixed-slot-A boot-image switcher for Uke. Only /dev/disk/by-partlabel/boot_a
// is ever written; GPT, UFS boot LUN, boot_b, linux and userdata are untouched.
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <openssl/evp.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;
using Bytes = std::vector<unsigned char>;

static constexpr uint64_t capacity = 100663296;
static constexpr const char *store_root = "/var/lib/uke/switch";

static void need(bool ok, const std::string &why) {
    if (!ok) throw std::runtime_error(why);
}
static std::string digest(const Bytes &data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> out{};
    unsigned length = 0;
    need(EVP_Digest(data.data(), data.size(), out.data(), &length, EVP_sha256(), nullptr) == 1 && length == 32,
         "SHA-256 failed");
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (unsigned i = 0; i < length; ++i) result += digits[out[i] >> 4], result += digits[out[i] & 15];
    return result;
}
static Bytes read_file(const fs::path &path) {
    std::ifstream input(path, std::ios::binary);
    need(bool(input), "Cannot open " + path.string());
    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    need(size == static_cast<std::streamoff>(capacity), "Boot image must be exactly 96 MiB: " + path.string());
    input.seekg(0);
    Bytes data(static_cast<size_t>(size));
    input.read(reinterpret_cast<char *>(data.data()), data.size());
    need(input.gcount() == static_cast<std::streamsize>(data.size()), "Short boot image read: " + path.string());
    return data;
}
static void write_file(const fs::path &path, const Bytes &data) {
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    need(!ec, "Cannot create store directory");
    const auto temporary = path.string() + ".new";
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        need(bool(output), "Cannot create " + temporary);
        output.write(reinterpret_cast<const char *>(data.data()), data.size());
        output.flush();
        need(bool(output), "Cannot write " + temporary);
    }
    fs::rename(temporary, path, ec);
    need(!ec, "Cannot publish " + path.string());
}
static void backup_file(const fs::path &path, const Bytes &data) {
    if (fs::exists(path)) {
        const auto old = path.string() + ".old";
        std::error_code ec;
        fs::remove(old, ec);
        fs::rename(path, old, ec);
        need(!ec, "Cannot rotate old backup");
    }
    write_file(path, data);
}
static std::string resolved_partition(const char *label) {
    const auto path = std::string("/dev/disk/by-partlabel/") + label;
    char target[PATH_MAX];
    need(realpath(path.c_str(), target) != nullptr,
         std::string("Cannot resolve ") + path + ": " + std::strerror(errno));
    return target;
}
static Bytes read_partition(const char *label) {
    const auto path = resolved_partition(label);
    const int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    need(fd >= 0, std::string("Cannot open ") + path + ": " + std::strerror(errno));
    struct stat st{};
    uint64_t bytes = 0;
    need(!fstat(fd, &st) && S_ISBLK(st.st_mode) && !ioctl(fd, BLKGETSIZE64, &bytes),
         std::string("Cannot inspect ") + path);
    need(bytes == capacity, std::string(path) + " is not exactly 96 MiB");
    Bytes data(capacity);
    size_t done = 0;
    while (done < data.size()) {
        const auto n = pread(fd, data.data() + done, data.size() - done, static_cast<off_t>(done));
        if (n < 0 && errno == EINTR) continue;
        need(n > 0, std::string("Short read from ") + path);
        done += static_cast<size_t>(n);
    }
    close(fd);
    return data;
}
static void write_partition(const char *label, const Bytes &data) {
    const auto path = resolved_partition(label);
    const int fd = open(path.c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    need(fd >= 0, std::string("Cannot open ") + path + ": " + std::strerror(errno));
    struct stat st{};
    uint64_t bytes = 0;
    need(!fstat(fd, &st) && S_ISBLK(st.st_mode) && !ioctl(fd, BLKGETSIZE64, &bytes) && bytes == capacity,
         std::string(path) + " identity/capacity changed");
    size_t done = 0;
    while (done < data.size()) {
        const auto n = pwrite(fd, data.data() + done, data.size() - done, static_cast<off_t>(done));
        if (n < 0 && errno == EINTR) continue;
        need(n > 0, std::string("Short write to ") + path);
        done += static_cast<size_t>(n);
    }
    need(!fsync(fd), std::string("fsync failed for ") + path);
    close(fd);
    need(read_partition(label) == data, std::string("Full readback differs for ") + path);
}
static std::string boot_cmdline(const Bytes &image) {
    need(image.size() == capacity && !memcmp(image.data(), "ANDROID!", 8), "Not an Android boot image");
    const auto version = *reinterpret_cast<const uint32_t *>(image.data() + 40);
    if (version >= 3) {
        const char *begin = reinterpret_cast<const char *>(image.data() + 44);
        const auto end = std::find(begin, begin + 1536, '\0');
        return std::string(begin, end);
    }
    const char *begin = reinterpret_cast<const char *>(image.data() + 64);
    const auto end = std::find(begin, begin + 512, '\0');
    return std::string(begin, end);
}
static bool is_linux(const Bytes &image) {
    return boot_cmdline(image).find("senemos.root=linux") != std::string::npos;
}
static fs::path store_path(const std::string &kind) {
    need(kind == "android" || kind == "linux", "Unknown image set");
    return fs::path(store_root) / kind / "boot.img";
}
static void show_status() {
    const auto boota = read_partition("boot_a");
    const auto bootb = read_partition("boot_b");
    const auto ah = digest(boota), bh = digest(bootb);
    std::cout << "fixed active slot: a\n";
    std::cout << "boot_a: " << (is_linux(boota) ? "linux" : "android") << " sha256=" << ah << '\n';
    std::cout << "boot_b: " << (is_linux(bootb) ? "linux" : "android") << " sha256=" << bh << '\n';
    for (const auto &kind : {"android", "linux"}) {
        const auto path = store_path(kind);
        if (!fs::is_regular_file(path)) {
            std::cout << "store/" << kind << ": missing\n";
            continue;
        }
        const auto image = read_file(path);
        std::cout << "store/" << kind << ": sha256=" << digest(image)
                  << " matches_boot_a=" << (digest(image) == ah)
                  << " matches_boot_b=" << (digest(image) == bh) << '\n';
    }
}
static void import_set(const std::string &kind, const fs::path &source) {
    const auto image = read_file(source);
    const bool linux = is_linux(image);
    need(kind == "linux" ? linux : !linux,
         kind == "linux" ? "Linux store requires senemos.root=linux" : "Android store must not carry senemos.root=linux");
    write_file(store_path(kind), image);
    std::cout << "stored " << kind << " boot image: " << digest(image) << '\n';
}
static void to_set(const std::string &kind) {
    const auto target = read_file(store_path(kind));
    const bool linux = is_linux(target);
    need(kind == "linux" ? linux : !linux, "Store image does not match its set type");
    const auto current = read_partition("boot_a");
    if (current == target) {
        std::cout << "boot_a already holds store/" << kind << "; no write\n";
        return;
    }
    backup_file(fs::path(store_root) / "boot-a.previous.img", current);
    try {
        write_partition("boot_a", target);
    } catch (...) {
        try {
            write_partition("boot_a", current);
        } catch (...) {
            throw std::runtime_error("boot_a update and rollback failed; use Fastboot/recovery");
        }
        throw;
    }
    std::cout << "boot_a now holds store/" << kind << " sha256=" << digest(target) << "; reboot to apply\n";
}
int main(int argc, char **argv) {
    try {
        need(geteuid() == 0, "Root privileges are required");
        if (argc == 2 && std::string(argv[1]) == "status") {
            show_status();
            return 0;
        }
        if (argc >= 2 && (std::string(argv[1]) == "to-android" || std::string(argv[1]) == "to-linux")) {
            need(argc == 2, "to-* takes no arguments");
            to_set(std::string(argv[1]).substr(3));
            return 0;
        }
        if (argc >= 2 && (std::string(argv[1]) == "import-android" || std::string(argv[1]) == "import-linux")) {
            const auto kind = std::string(argv[1]).substr(7);
            fs::path source;
            if (argc == 2) {
                source = kind == "android" ? fs::path("/dev/disk/by-partlabel/boot_a")
                                           : fs::path("/dev/disk/by-partlabel/boot_b");
            } else if (argc == 3) {
                source = argv[2];
            } else if (argc == 4 && std::string(argv[2]) == "--from") {
                source = argv[3];
            } else {
                need(false, "Usage: import-android|import-linux [--from FILE]");
            }
            if (source.string().starts_with("/dev/")) {
                const auto image = read_partition(source.filename().c_str());
                const auto temporary = fs::path("/tmp") / ("uke-import-" + kind + ".img");
                write_file(temporary, image);
                import_set(kind, temporary);
                fs::remove(temporary);
            } else {
                import_set(kind, source);
            }
            return 0;
        }
        std::cerr << "Usage: uke-boot-switch status | to-android | to-linux | import-android [--from FILE] | import-linux [--from FILE]\n";
        return 2;
    } catch (const std::exception &error) {
        std::cerr << "uke-boot-switch: " << error.what() << '\n';
        return 1;
    }
}
