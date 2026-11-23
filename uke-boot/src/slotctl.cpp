// SPDX-License-Identifier: MIT
// Uke QTI slot-status and set-active utility. This is a small command-line
// frontend to the validated slot::Disk implementation in slot-control.hpp; it
// never writes boot images, root filesystems or arbitrary GPT bytes.
#include "boot-common.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/file.h>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <memory>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;
using Bytes = std::vector<unsigned char>;

struct Fd {
    int value;
    explicit Fd(int fd) : value(fd) { if (fd < 0) throw std::runtime_error(std::strerror(errno)); }
    ~Fd() { if (value >= 0) close(value); }
    Fd(const Fd &) = delete;
    Fd &operator=(const Fd &) = delete;
    Fd(Fd &&other) noexcept : value(other.value) { other.value = -1; }
    Fd &operator=(Fd &&other) noexcept {
        if (this != &other) { if (value >= 0) close(value); value = other.value; other.value = -1; }
        return *this;
    }
};

static void need(bool ok, const std::string &why) {
    if (!ok) throw std::runtime_error(why);
}

static bool token(const std::string &s) {
    return !s.empty() && s.size() < 128 && s.front() != '.' &&
        s.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-") == std::string::npos;
}

static Bytes file(const fs::path &path) {
    std::ifstream input(path, std::ios::binary);
    need(bool(input), "Cannot open " + path.string());
    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    need(size >= 0 && size <= 64 * 1024 * 1024, "Unsupported metadata file size");
    input.seekg(0);
    Bytes data(static_cast<size_t>(size));
    input.read(reinterpret_cast<char *>(data.data()), data.size());
    need(input.gcount() == static_cast<std::streamsize>(data.size()), "Short metadata read");
    return data;
}

static void save_new(const fs::path &path, const Bytes &data) {
    need(path.is_absolute() && path.lexically_normal() == path, "Unsafe backup path");
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    need(!ec, "Cannot create slot backup directory");
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    need(bool(output), "Cannot create " + path.string());
    output.write(reinterpret_cast<const char *>(data.data()), data.size());
    need(bool(output), "Cannot write " + path.string());
}

static uint32_t le32(const Bytes &bytes, size_t i) {
    return uint32_t(bytes.at(i)) | uint32_t(bytes.at(i + 1)) << 8 |
           uint32_t(bytes.at(i + 2)) << 16 | uint32_t(bytes.at(i + 3)) << 24;
}
static uint64_t le64(const Bytes &bytes, size_t i) {
    return uint64_t(le32(bytes, i)) | uint64_t(le32(bytes, i + 4)) << 32;
}

#include "slot-control.hpp"

static std::string ufs_controller(const fs::path &path) {
    const auto real = fs::canonical(path).string();
    const std::string suffix = "/1d84000.ufshc/";
    const auto controller = real.find(suffix);
    need(controller != std::string::npos &&
         real.find("/block/", controller + suffix.size()) != std::string::npos &&
         real.find("/virtual/") == std::string::npos,
         "Only the measured Uke physical UFS controller is supported");
    return real.substr(0, controller + suffix.size() - 1);
}

static std::pair<std::string, dev_t> partition(const std::string &label,
                                               const fs::path &sys = "/sys/class/block") {
    std::pair<std::string, dev_t> result;
    for (const auto &entry : fs::directory_iterator(sys)) {
        if (!fs::exists(entry.path() / "partition")) continue;
        std::istringstream input(read_text(entry.path() / "uevent"));
        std::string row, name;
        while (std::getline(input, row))
            if (row.rfind("PARTNAME=", 0) == 0) name = row.substr(9);
        if (name != label) continue;
        need(result.first.empty(), "Duplicate physical " + label + " partition");
        const auto number = read_text(entry.path() / "dev");
        unsigned major = 0, minor = 0;
        char tail = 0;
        need(sscanf(number.c_str(), "%u:%u %c", &major, &minor, &tail) == 2 &&
             token(entry.path().filename()), "Invalid partition identity");
        (void)ufs_controller(entry.path());
        result = {entry.path().filename(), makedev(major, minor)};
    }
    need(!result.first.empty(), "Physical " + label + " partition unavailable");
    return result;
}

static bool lock_metadata_fd(int fd) {
    for (unsigned attempt = 0;; ++attempt) {
        if (!flock(fd, LOCK_EX | LOCK_NB)) return true;
        if ((errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR) || attempt == 50) return false;
        if (!attempt) std::cerr << "UFS slot metadata is busy; waiting up to five seconds\n";
        usleep(100000);
    }
}

struct SlotMetadata {
    std::string name;
    Fd fd;
    std::unique_ptr<slot::Disk> gpt;
    SlotMetadata(const std::string &name, dev_t expected, bool allow_backup_crc)
        : name(name), fd(open(("/dev/" + name).c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)) {
        struct stat st{};
        uint64_t bytes = 0;
        unsigned sector = 0;
        need(!fstat(fd.value, &st) && S_ISBLK(st.st_mode) && st.st_rdev == expected &&
             !ioctl(fd.value, BLKGETSIZE64, &bytes) && !ioctl(fd.value, BLKSSZGET, &sector),
             "Physical UFS GPT descriptor identity/capacity unavailable");
        need(lock_metadata_fd(fd.value), std::string("Cannot lock GPT descriptor: ") + std::strerror(errno));
        gpt = std::make_unique<slot::Disk>(fd.value, bytes, sector, allow_backup_crc);
    }
};

static std::vector<std::unique_ptr<SlotMetadata>> metadata(const std::string &controller,
                                                          bool allow_backup_crc = false) {
    std::map<std::string, fs::path> labels;
    for (const auto &entry : fs::directory_iterator("/sys/class/block")) {
        if (!fs::exists(entry.path() / "partition")) continue;
        const auto physical = fs::canonical(entry.path());
        if (physical.string().rfind(controller + "/", 0) != 0) continue;
        std::istringstream rows(read_text(entry.path() / "uevent"));
        std::string row;
        while (std::getline(rows, row))
            if (row.rfind("PARTNAME=", 0) == 0)
                need(labels.emplace(row.substr(9), physical).second, "Duplicate physical partition label");
    }
    std::set<fs::path> disks;
    for (const auto &[name, path] : labels) {
        if (!name.ends_with("_a")) continue;
        const auto other = labels.find(name.substr(0, name.size() - 1) + "b");
        if (other != labels.end() && path.parent_path() == other->second.parent_path())
            disks.insert(path.parent_path());
    }
    std::vector<std::unique_ptr<SlotMetadata>> result;
    for (const auto &path : disks) {
        const auto name = path.filename().string();
        unsigned major = 0, minor = 0;
        char tail = 0;
        need(token(name) && sscanf(read_text(path / "dev").c_str(), "%u:%u %c", &major, &minor, &tail) == 2,
             "Invalid UFS disk identity");
        result.push_back(std::make_unique<SlotMetadata>(name, makedev(major, minor), allow_backup_crc));
    }
    need(!result.empty() && result.size() <= 8, "UFS slot metadata unavailable");
    return result;
}

static Fd ufs_bsg(const std::string &controller) {
    std::string name, identity;
    for (const auto &entry : fs::directory_iterator("/sys/class/bsg")) {
        if (!entry.path().filename().string().starts_with("ufs-bsg")) continue;
        if (fs::canonical(entry.path()).string().rfind(controller + "/", 0) != 0) continue;
        need(name.empty() && token(entry.path().filename()), "Ambiguous UFS BSG endpoint");
        name = entry.path().filename();
        identity = read_text(entry.path() / "dev");
    }
    unsigned major = 0, minor = 0;
    char extra = 0;
    need(!name.empty() && sscanf(identity.c_str(), "%u:%u %c", &major, &minor, &extra) == 2,
         "UFS BSG endpoint unavailable");
    Fd fd(open(("/dev/bsg/" + name).c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
    struct stat st{};
    need(!fstat(fd.value, &st) && S_ISCHR(st.st_mode) && st.st_rdev == makedev(major, minor),
         "UFS BSG identity changed");
    return fd;
}

static std::pair<slot::Disk *, std::string> boot_table(const std::vector<std::unique_ptr<SlotMetadata>> &disks) {
    slot::Disk *result = nullptr;
    std::string name;
    for (const auto &disk : disks) {
        if (disk->gpt->parts.contains("boot_a") && disk->gpt->parts.contains("boot_b")) {
            need(!result, "Boot GPT is ambiguous");
            result = disk->gpt.get();
            name = disk->name;
        }
    }
    need(result, "Boot slot GPT unavailable");
    return {result, name};
}

static std::string current_root_controller() {
    try {
        const auto root = partition("linux");
        return ufs_controller(fs::path("/sys/class/block") / root.first);
    } catch (const std::exception &) {
        const auto root = partition("userdata");
        return ufs_controller(fs::path("/sys/class/block") / root.first);
    }
}

static unsigned current_slot(const Fd &bsg) {
    const auto command = read_text("/proc/cmdline");
    if (command.find("androidboot.slot_suffix=") == std::string::npos) {
        const auto lun = slot::boot_lun(bsg.value);
        need(lun == 1 || lun == 2, "Invalid UFS boot LUN");
        return lun - 1;
    }
    return slot::current(command);
}

static void print_flags(const char *name, uint64_t attrs) {
    std::cout << name << ": active=" << bool(attrs & slot::active)
              << " successful=" << bool(attrs & slot::successful)
              << " unbootable=" << bool(attrs & slot::unbootable)
              << " priority=" << ((attrs >> 48) & 3)
              << " retries=" << ((attrs >> 51) & 7) << '\n';
}

static int status() {
    const auto controller = current_root_controller();
    const auto disks = metadata(controller);
    const auto [table, disk_name] = boot_table(disks);
    auto bsg = ufs_bsg(controller);
    const auto boot_lun = slot::boot_lun(bsg.value);
    const auto current = current_slot(bsg);
    std::cout << "current slot: " << (current ? "b" : "a") << '\n';
    print_flags("boot_a", table->parts.at("boot_a").attrs);
    print_flags("boot_b", table->parts.at("boot_b").attrs);
    std::cout << "boot GPT disk: " << disk_name << '\n';
    std::cout << "UFS boot LUN: " << boot_lun << " (slot " << (boot_lun == 1 ? 'a' : 'b') << ")\n";
    std::cout << "linux/userdata roots are not modified by this tool\n";
    return 0;
}

static int switch_slot(const std::string &target_name, bool dry_run) {
    need(target_name == "a" || target_name == "b", "Target must be a or b");
    const auto controller = current_root_controller();
    const auto disks = metadata(controller);
    const auto [table, disk_name] = boot_table(disks);
    (void)disk_name;
    auto bsg = ufs_bsg(controller);
    const auto current = current_slot(bsg);
    const unsigned target = target_name == "a" ? 0 : 1;
    need(target == 1 - current, "Target must be the inactive slot");
    need(!(table->parts.at(target ? "boot_b" : "boot_a").attrs & slot::unbootable),
         "Target slot is marked unbootable");
    need(slot::boot_lun(bsg.value) == current + 1, "UFS boot LUN differs from the running slot");
    print_flags("boot_a", table->parts.at("boot_a").attrs);
    print_flags("boot_b", table->parts.at("boot_b").attrs);

    const fs::path state = "/var/lib/senemos/slot";
    std::error_code ec;
    fs::create_directories(state, ec);
    need(!ec, "Cannot create slot backup directory");

    std::vector<slot::Disk *> changed;
    for (auto &disk : disks) {
        if (disk->gpt->prepare(current, target)) changed.push_back(disk->gpt.get());
    }
    need(!changed.empty(), "No consistent QTI slot metadata found");
    if (dry_run) {
        std::cout << "dry-run: would switch " << (current ? "b" : "a") << " -> " << target_name
                  << " and set UFS boot LUN " << target + 1 << "; no bytes written\n";
        return 0;
    }
    for (auto *disk : changed) {
        // The backup is written before any metadata mutation.
        disk->backup(state / ("gpt-" + std::to_string(getpid()) + "-" + std::to_string(current) + "-" + std::to_string(target) + ".bin"));
    }
    try {
        for (auto *disk : changed) disk->commit();
        (void)slot::boot_lun(bsg.value, target + 1);
    } catch (...) {
        try {
            for (auto *disk : changed) disk->restore();
            (void)slot::boot_lun(bsg.value, current + 1);
        } catch (...) {
            throw std::runtime_error("Slot switch and restoration failed; retain backups and use recovery");
        }
        throw;
    }
    std::cout << "slot " << target_name << " selected; reboot to apply\n";
    return 0;
}

static int accept_slot() {
    const auto controller = current_root_controller();
    const auto disks = metadata(controller);
    const auto [table, disk_name] = boot_table(disks);
    (void)disk_name;
    auto bsg = ufs_bsg(controller);
    const auto current = current_slot(bsg);
    const fs::path state = "/var/lib/senemos/slot";
    std::error_code ec;
    fs::create_directories(state, ec);
    need(!ec, "Cannot create slot backup directory");
    table->backup(state / ("gpt-accept-" + std::to_string(getpid()) + ".bin"));
    table->success(current);
    table->commit();
    std::cout << "slot " << (current ? "b" : "a") << " marked successful\n";
    return 0;
}

int main(int argc, char **argv) {
    try {
        need(geteuid() == 0, "Root privileges are required");
        if (argc == 2 && std::string(argv[1]) == "status") return status();
        if ((argc == 3 || (argc == 4 && std::string(argv[3]) == "--dry-run")) && std::string(argv[1]) == "switch") return switch_slot(argv[2], argc == 4);
        if (argc == 2 && std::string(argv[1]) == "accept") return accept_slot();
        std::cerr << "Usage: uke-slotctl status | switch a|b [--dry-run] | accept\n";
        return 2;
    } catch (const std::exception &error) {
        std::cerr << "uke-slotctl: " << error.what() << '\n';
        return 1;
    }
}
