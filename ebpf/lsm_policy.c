// ebpf/lsm_policy.c
// BPF LSM policy for AgentSentry demo.
//
// Toolchain choice: BCC (python3-bpfcc) instead of CO-RE libbpf.
// Reason: BCC ships as a distro package on Linux Mint/Ubuntu, requires no
// separate vmlinux.h generation step, and is fully functional for a demo on a
// single known kernel. CO-RE is better for distribution; BCC is better for
// a single-machine proof-of-concept where we can verify the kernel version.
//
// This file is compiled at runtime by BCC from Python (loader.py).
// It is standard BPF C with BCC helpers.
//
// Verified hooks (kernel 6.14, confirmed via BTF and kallsyms):
//   bpf_lsm_file_open          -> security_file_open
//   bpf_lsm_inode_create       -> security_inode_create
//   bpf_lsm_bprm_check_security -> security_bprm_check
//   bpf_lsm_socket_connect     -> security_socket_connect
//
// To verify on your VM:
//   bpftool btf dump file /sys/kernel/btf/vmlinux | grep bpf_lsm_file_open
//   grep bpf_lsm_file_open /proc/kallsyms

#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/bpf.h>

// ── Shared map: attacker cgroup ID set by loader ──────────────────────────
BPF_ARRAY(config_map, u64, 2);
// index 0: attacker_cgroup_id
// index 1: mode  (0 = log-only, 1 = enforce)

// ── Event ring buffer ──────────────────────────────────────────────────────
struct event_t {
    u32 pid;
    u32 uid;
    u64 cgroup_id;
    u32 kind;        // 0=file_open, 1=inode_create, 2=exec, 3=connect
    u32 verdict;     // 0=allow, 1=deny
    char path[256];
    char comm[16];
};
BPF_RINGBUF_OUTPUT(events, 1 << 20);  // 1 MB ring buffer

// ── Helpers ───────────────────────────────────────────────────────────────

// Read dentry path into buf (BPF-safe, bounded loop)
static __always_inline int read_dentry_path(struct dentry *dentry, char *buf, int bufsz) {
    // We walk up at most 32 dentry levels to build path.
    // BPF verifier requires bounded loops.
    char tmp[256];
    int total = 0;

    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (!dentry) break;
        struct dentry *parent = NULL;
        bpf_probe_read_kernel(&parent, sizeof(parent), &dentry->d_parent);
        if (!parent || parent == dentry) break;

        struct qstr d_name = {};
        bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);

        unsigned int len = d_name.len & 0xFF;  // cap at 255
        if (len == 0) { dentry = parent; continue; }

        bpf_probe_read_kernel_str(tmp, sizeof(tmp), d_name.name);

        // prepend "/name" into buf – we fill from position 0 each level
        // Simple approach: just store final component for demo path check
        // Full path reconstruction is complex in BPF; we store the last 2
        // components which is sufficient for prefix checks.
        if (total == 0) {
            bpf_probe_read_kernel_str(buf, bufsz, d_name.name);
            total = len;
        }
        dentry = parent;
    }
    return total;
}

// Get full path from file struct into buf
static __always_inline void get_file_path(struct file *file, char *buf, int bufsz) {
    if (!file) return;
    // BCC provides bpf_d_path helper on kernels that support it (5.9+)
    // On kernels without it, we read from f_path manually.
    struct path f_path = {};
    bpf_probe_read_kernel(&f_path, sizeof(f_path), &file->f_path);
    // Use bpf_d_path (available kernel >= 5.9)
    bpf_d_path(&f_path, buf, bufsz);
}

// Check if path starts with prefix
static __always_inline int path_starts_with(const char *path, const char *prefix, int prefix_len) {
    char p[256] = {};
    bpf_probe_read_kernel_str(p, sizeof(p), path);
    #pragma unroll
    for (int i = 0; i < 32 && i < prefix_len; i++) {
        if (p[i] != prefix[i]) return 0;
        if (p[i] == '\0') return 0;
    }
    return 1;
}

// ── Cgroup guard: returns 1 if current cgroup == attacker cgroup ──────────
static __always_inline int in_attacker_cgroup(void) {
    int key0 = 0;
    u64 *attacker_cgid = config_map.lookup(&key0);
    if (!attacker_cgid || *attacker_cgid == 0) return 0;  // not configured yet

    u64 current_cgid = bpf_get_current_cgroup_id();
    return (current_cgid == *attacker_cgid) ? 1 : 0;
}

// Returns 1 if enforce mode is on
static __always_inline int is_enforce_mode(void) {
    int key1 = 1;
    u64 *mode = config_map.lookup(&key1);
    if (!mode) return 0;
    return (*mode == 1) ? 1 : 0;
}

// Emit event and return verdict
static __always_inline int emit_and_decide(u32 kind, const char *path, u32 deny) {
    struct event_t *ev = events.ringbuf_reserve(sizeof(struct event_t));
    if (!ev) return 0;  // ring full: allow (fail open on ring issue only)

    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->cgroup_id = bpf_get_current_cgroup_id();
    ev->kind = kind;
    ev->verdict = deny;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    if (path)
        bpf_probe_read_kernel_str(ev->path, sizeof(ev->path), path);

    events.ringbuf_submit(ev, 0);

    if (deny && is_enforce_mode()) return -EPERM;
    return 0;  // allow (log-only or permitted)
}

// ── Hook 1: file_open ─────────────────────────────────────────────────────
// Fires when any process opens a file. We check if the path is under /home/demo/secrets.
// Verified: bpf_lsm_file_open exists in kernel 6.14 BTF as LSM_HOOK(int, 0, file_open, ...)
LSM_PROBE(file_open, struct file *file)
{
    if (!in_attacker_cgroup()) return 0;

    char path[256] = {};
    get_file_path(file, path, sizeof(path));

    // Block access to secrets directory
    const char secrets_prefix[] = "/home/demo/secrets";
    if (__builtin_memcmp(path, secrets_prefix, sizeof(secrets_prefix) - 1) == 0) {
        return emit_and_decide(0, path, 1);  // kind=file_open, deny=1
    }

    // Allow: emit allow event for reads outside secrets that are also outside workspace
    // (informational only)
    return emit_and_decide(0, path, 0);
}

// ── Hook 2: inode_create ──────────────────────────────────────────────────
// Fires when a new file/dir is created. Block creation outside /home/demo/workspace.
// Verified: bpf_lsm_inode_create in kernel 6.14 BTF.
LSM_PROBE(inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    if (!in_attacker_cgroup()) return 0;

    // Get path of the parent directory (dir)
    char parent_path[256] = {};
    // We use the dentry's parent to reconstruct the directory path
    struct dentry *parent_dentry = NULL;
    bpf_probe_read_kernel(&parent_dentry, sizeof(parent_dentry), &dentry->d_parent);

    // BCC's bpf_d_path works on struct path, not dentry directly.
    // Construct a temporary path struct for the parent.
    // For demo: read the path from the dentry name chain.
    // We rely on the fact that the attacker only creates /tmp/outside/pwned.txt.
    struct qstr d_name = {};
    bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
    char fname[64] = {};
    bpf_probe_read_kernel_str(fname, sizeof(fname), d_name.name);

    // Build an event path string for display
    char event_path[256] = "inode_create:";
    bpf_probe_read_kernel_str(event_path + 13, sizeof(event_path) - 13, d_name.name);

    // Allow creation inside /home/demo/workspace – block everything else.
    // We check the parent inode path. In BPF we check by walking i_sb and comparing
    // against the known workspace inode or by string matching.
    // Approach: use bpf_d_path on a synthesized path (safe in kernel 6.x).

    // For the demo, we track by checking if it's the /tmp path which is clearly outside.
    // A production version would do full path comparison.
    // Here we check if the parent dentry contains "tmp" in its path which is sufficient
    // to block /tmp/outside/pwned.txt
    char p0[256] = {};
    if (parent_dentry) {
        struct path tmp_path = {};
        bpf_probe_read_kernel(&tmp_path.dentry, sizeof(tmp_path.dentry), &parent_dentry);
        // Get the mount from current task
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct fs_struct *fs = NULL;
        bpf_probe_read_kernel(&fs, sizeof(fs), &task->fs);
        struct path root_path = {};
        if (fs) bpf_probe_read_kernel(&root_path, sizeof(root_path), &fs->root);
        tmp_path.mnt = root_path.mnt;
        bpf_d_path(&tmp_path, p0, sizeof(p0));
    }

    // Block if parent is NOT inside /home/demo/workspace
    const char workspace[] = "/home/demo/workspace";
    int in_workspace = (__builtin_memcmp(p0, workspace, sizeof(workspace) - 1) == 0);
    if (!in_workspace && p0[0] != '\0') {
        return emit_and_decide(1, p0, 1);  // kind=inode_create, deny=1
    }

    return emit_and_decide(1, p0, 0);
}

// ── Hook 3: bprm_check_security ───────────────────────────────────────────
// Fires before a new binary is executed. Block binaries outside allow list.
// Verified: bpf_lsm_bprm_check_security in kernel 6.14 BTF.
//
// NOTE on BPF verifier: pointer arrays of strings fail verification because
// the verifier cannot track pointer arithmetic across array loads.
// We use explicit __builtin_memcmp() against literal strings instead —
// the compiler inlines them as direct comparisons which the verifier accepts.
// Each string must be a local array (stack), not a pointer from an array.
LSM_PROBE(bprm_check_security, struct linux_binprm *bprm)
{
    if (!in_attacker_cgroup()) return 0;

    char path[256] = {};
    struct file *file = NULL;
    bpf_probe_read_kernel(&file, sizeof(file), &bprm->file);
    get_file_path(file, path, sizeof(path));

    // Allow list – each comparison is a separate literal to satisfy BPF verifier.
    // Paths must match exactly (null-padded to 256 bytes from bpf_d_path).
    #define ALLOW(s) if (__builtin_memcmp(path, s, sizeof(s)) == 0) return emit_and_decide(2, path, 0)
    ALLOW("/bin/sh");
    ALLOW("/bin/bash");
    ALLOW("/bin/dash");
    ALLOW("/usr/bin/python3");
    ALLOW("/usr/bin/python3.10");
    ALLOW("/usr/bin/python3.11");
    ALLOW("/usr/bin/python3.12");
    ALLOW("/bin/ls");
    ALLOW("/usr/bin/ls");
    ALLOW("/bin/cat");
    ALLOW("/usr/bin/cat");
    ALLOW("/usr/bin/id");
    ALLOW("/bin/echo");
    ALLOW("/usr/bin/echo");
    ALLOW("/bin/mkdir");
    ALLOW("/usr/bin/mkdir");
    #undef ALLOW

    // Allow anything under /usr/lib/python (interpreter sub-invocations)
    const char pylib[] = "/usr/lib/python";
    if (__builtin_memcmp(path, pylib, sizeof(pylib) - 1) == 0) {
        return emit_and_decide(2, path, 0);
    }

    // Allow anything under /usr/bin/python (versioned symlinks resolved)
    const char pybin[] = "/usr/bin/python";
    if (__builtin_memcmp(path, pybin, sizeof(pybin) - 1) == 0) {
        return emit_and_decide(2, path, 0);
    }

    // Not in allow list → deny (blocks /tmp/attacker_nc and similar)
    return emit_and_decide(2, path, 1);  // kind=exec, deny=1
}

// ── Hook 4: socket_connect ────────────────────────────────────────────────
// Fires before any TCP/UDP connect. Block all outbound connections.
// Verified: bpf_lsm_socket_connect in kernel 6.14 BTF.
LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    if (!in_attacker_cgroup()) return 0;

    char addr_str[64] = {};
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);

    if (family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
        u32 ip = 0;
        u16 port = 0;
        bpf_probe_read_kernel(&ip, sizeof(ip), &addr4->sin_addr.s_addr);
        bpf_probe_read_kernel(&port, sizeof(port), &addr4->sin_port);
        // Format: "ip:port" stored as raw bytes in path field
        __builtin_memcpy(addr_str, "AF_INET connect", 15);
    } else {
        __builtin_memcpy(addr_str, "non-IPv4 connect", 16);
    }

    // Block all connections from attacker cgroup
    return emit_and_decide(3, addr_str, 1);  // kind=connect, deny=1
}
