//! Penguin flight recorder.
//!
//! Keeps what a bug report taken after a freeze or an unexpected restart cannot get any more:
//! the kernel log, system crash logs and resource use of the current session and the one before
//! it. Everything stays in credential-encrypted storage, only for the system, and is bounded in
//! size and age. App logs are never recorded. Wi-Fi network names and hardware addresses are
//! scrubbed before anything is written.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime};

const DIR: &str = "/data/misc_ce/0/penguin_flightlog";
const KEEP: Duration = Duration::from_secs(7 * 24 * 3600);
const KERNEL_LIMIT: u64 = 2 << 20;
const SYSTEM_LIMIT: u64 = 1536 << 10;
const SNAPSHOT_LIMIT: u64 = 1 << 20;
const SNAPSHOT_EVERY: Duration = Duration::from_secs(300);
const KERNEL_POLL: Duration = Duration::from_secs(2);
const KERNEL_TAIL: usize = 64 << 10;
/// How long a written line can stay only in the page cache. This phone always restarts with a
/// hard reset, which clears RAM (pstore included), so what is on disk is all that survives.
const SYNC_EVERY: Duration = Duration::from_secs(1);
/// Lines that often come right before a freeze or restart: written to disk at once.
const URGENT: &[&str] = &[
    "Kernel panic",
    "Internal error",
    "Unable to handle",
    "BUG:",
    "Oops",
    "lockup",
    "watchdog",
    "Watchdog",
    "blocked for more than",
    "detected stall",
    "detected stalls",
    "SysRq",
    "sysrq:",
    "Call trace",
    "FATAL EXCEPTION",
    "Fatal signal",
    "*** *** ***",
    "am_crash",
    "thermal_shutdown",
    "critical temperature",
    "Restarting system",
    "Rebooting",
];
const UNCLEAN_PROP: &str = "sys.penguin.flightlog.unclean";
/// Switching off deletes the logs only after this long, so switching it straight back on (as
/// someone checking the switch after a restart does) keeps the session that ended in the restart.
const CLEAR_GRACE: Duration = Duration::from_secs(15 * 60);
/// Holds the time the recorder was switched off; removed when it is switched back on.
const DISABLED_MARKER: &str = "disabled_at";
/// Early-boot captures, in device-encrypted storage so they are taken before the user unlocks.
const BOOT_DIR: &str = "/data/misc/penguin_flightlog";
const BOOTS_KEEP: usize = 6;
/// pstore records of the boot before, copied here by init: coredomain may not read pstore.
const PSTORE: &str = "/data/misc/penguin_flightlog/pstore";
/// Where the bootloader saves a minidump after a panic or watchdog reset, when armed through
/// /sys/kernel/dload. This phone always restarts with a hard reset, which clears RAM and so
/// pstore, so this is the only place the kernel log of the crash itself survives.
const RAWDUMP: &str = "/dev/block/by-name/rawdump";
/// Minidump section with the kernel console (the ramoops console region, plain text). It only
/// holds lines at the console log level, so it misses the registers and call trace of an oops.
const RAWDUMP_CONSOLE: &str = "md_KCONSOLE.BIN";
/// Minidump sections with the kernel's printk ring: text blocks, descriptors and record headers.
/// Together they give the whole kernel log at every level, as dmesg would have shown it.
const RAWDUMP_PRINTK: [&str; 3] = ["md_KLOGBUF.BIN", "md_LOG_DESC.BIN", "md_LOG_INFO.BIN"];
/// Identifies the last minidump filed, so a dump is filed once and not again on every boot. The
/// version prefix changes when more is filed from a dump, which files the last dump once more.
const RAWDUMP_SEEN: &str = "/data/misc/penguin_flightlog/rawdump_seen";
const RAWDUMP_SEEN_VERSION: &str = "v2";
/// Crash settings recorded with each boot, to tell from a report what the previous boot was armed with.
const ARMED_SETTINGS: &[&str] = &[
    "/sys/kernel/dload/dload_mode",
    "/sys/kernel/dload/emmc_dload",
    "/sys/kernel/reboot/mode",
    "/proc/sys/kernel/soft_watchdog",
    "/proc/sys/kernel/softlockup_panic",
    "/proc/sys/kernel/hardlockup_panic",
    "/sys/module/printk/parameters/console_no_auto_verbose",
];

/// System log tags worth keeping. App tags are left out on purpose.
const LOG_FILTER: &[&str] = &[
    "*:S",
    "Watchdog:V",
    "ActivityManager:W",
    "Looper:W",
    "lowmemorykiller:I",
    "lmkd:I",
    "SurfaceFlinger:W",
    "init:I",
    "servicemanager:W",
    "AndroidRuntime:E",
    "DEBUG:V",
    "libc:F",
    "am_anr:V",
    "am_crash:V",
    "am_kill:V",
    "am_low_memory:V",
    "am_wtf:V",
    "watchdog:V",
    "sysui_multi_action:S",
];

extern "C" {
    fn klogctl(kind: c_int, buf: *mut c_char, len: c_int) -> c_int;
    fn __system_property_set(name: *const c_char, value: *const c_char) -> c_int;
}

static STATE_PATH: OnceLock<CString> = OnceLock::new();

/// One per log file: the file and whether it has lines not yet on disk. The writer thread and
/// [sync_loop] share it, so a sync never races a rotation onto a closed or reused descriptor.
struct Shared {
    file: File,
    dirty: bool,
}

type SyncList = Arc<Mutex<Vec<Arc<Mutex<Shared>>>>>;

/// Size-capped log file: at the limit it becomes `<name>.1` and a new one is started.
struct Rotating {
    path: PathBuf,
    limit: u64,
    shared: Arc<Mutex<Shared>>,
    size: u64,
}

impl Rotating {
    fn open(path: PathBuf, limit: u64, list: &SyncList) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata()?.len();
        let shared = Arc::new(Mutex::new(Shared { file, dirty: false }));
        list.lock().unwrap().push(shared.clone());
        Ok(Self { path, limit, shared, size })
    }

    fn write_line(&mut self, line: &str) {
        self.write(line, false);
    }

    /// Writes the line and, if `urgent`, gets it to disk before returning.
    fn write(&mut self, line: &str, urgent: bool) {
        let len = line.len() as u64 + 1;
        let mut s = self.shared.lock().unwrap();
        if self.size + len > self.limit {
            // The old part keeps its lines: sync it before starting the next.
            let _ = s.file.sync_data();
            let mut old = self.path.clone().into_os_string();
            old.push(".1");
            let _ = fs::rename(&self.path, &old);
            match OpenOptions::new().create(true).write(true).truncate(true).open(&self.path) {
                Ok(f) => {
                    s.file = f;
                    self.size = 0;
                }
                Err(_) => return,
            }
        }
        // One write per line, unbuffered, so a line is never half in the page cache.
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        if s.file.write_all(&buf).is_ok() {
            self.size += len;
            if urgent {
                let _ = s.file.sync_data();
                s.dirty = false;
            } else {
                s.dirty = true;
            }
        }
    }
}

fn is_urgent(line: &str) -> bool {
    URGENT.iter().any(|k| line.contains(k)) || kernel_level(line).is_some_and(|l| l <= 2)
}

/// Syslog level of a kernel line read with syslog(2), "<3>[  12.3] ...", if it has one.
fn kernel_level(line: &str) -> Option<u8> {
    let b = line.as_bytes();
    (b.len() >= 3 && b[0] == b'<' && b[2] == b'>' && b[1].is_ascii_digit()).then(|| b[1] - b'0')
}

/// Removes Wi-Fi network names and masks hardware addresses. Returns None to drop the line.
fn scrub(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    if lower.contains("ssid") || lower.contains("kernelsu") {
        return None;
    }
    let b = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < b.len() {
        if i + 17 <= b.len() && is_mac(&b[i..i + 17]) {
            out.push_str("xx:xx:xx:xx:xx:xx");
            i += 17;
        } else {
            let ch = line[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    Some(out)
}

fn is_mac(s: &[u8]) -> bool {
    (0..17).all(|k| if k % 3 == 2 { s[k] == b':' || s[k] == b'-' } else { s[k].is_ascii_hexdigit() })
        && (s[2] == s[5])
}

fn set_prop(name: &str, value: &str) {
    if let (Ok(n), Ok(v)) = (CString::new(name), CString::new(value)) {
        unsafe { __system_property_set(n.as_ptr(), v.as_ptr()) };
    }
}

fn read_trim(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn newest_mtime(dir: &Path) -> Option<SystemTime> {
    fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter_map(|e| e.metadata().ok()?.modified().ok())
        .max()
}

/// Deletes recorded files older than [KEEP].
fn prune_old(dir: &Path) {
    let now = SystemTime::now();
    for sub in ["cur", "prev"] {
        let Ok(entries) = fs::read_dir(dir.join(sub)) else { continue };
        for e in entries.flatten() {
            let old = e
                .metadata()
                .and_then(|m| m.modified())
                .map(|t| now.duration_since(t).unwrap_or_default() > KEEP)
                .unwrap_or(false);
            let name = e.file_name();
            let name = name.to_string_lossy();
            if old && name != "state" && name != "boot_id" && name != "info" {
                let _ = fs::remove_file(e.path());
            }
        }
    }
    let prev = dir.join("prev");
    if let Some(t) = newest_mtime(&prev) {
        if now.duration_since(t).unwrap_or_default() > KEEP {
            let _ = fs::remove_dir_all(&prev);
        }
    }
}

/// Moves the last boot's session to `prev` and starts a new one. A session that never got
/// stopped cleanly means the phone went down without a shutdown: a hang, panic or watchdog reset.
fn start_session(dir: &Path) -> std::io::Result<PathBuf> {
    let boot_id = read_trim("/proc/sys/kernel/random/boot_id").unwrap_or_default();
    let cur = dir.join("cur");
    if cur.is_dir() {
        if read_trim(cur.join("boot_id")).as_deref() == Some(boot_id.as_str()) {
            // Restarted within the same boot: keep appending.
            fs::write(cur.join("state"), "running")?;
            return Ok(cur);
        }
        let clean = read_trim(cur.join("state")).as_deref() == Some("clean");
        let prev = dir.join("prev");
        let _ = fs::remove_dir_all(&prev);
        fs::rename(&cur, &prev)?;
        if !clean {
            set_prop(UNCLEAN_PROP, "1");
        }
    }
    fs::create_dir_all(&cur)?;
    fs::write(cur.join("boot_id"), &boot_id)?;
    fs::write(cur.join("state"), "running")?;
    let uptime = read_trim("/proc/uptime").unwrap_or_default();
    let started = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    fs::write(cur.join("info"), format!("started_epoch {started}\nuptime_at_start {uptime}\n"))?;
    Ok(cur)
}

extern "C" fn on_term(_: c_int) {
    // Only async-signal-safe calls here.
    if let Some(path) = STATE_PATH.get() {
        unsafe {
            let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_TRUNC | libc::O_CLOEXEC);
            if fd >= 0 {
                libc::write(fd, b"clean".as_ptr().cast(), 5);
                libc::fsync(fd);
                libc::close(fd);
            }
            libc::_exit(0);
        }
    }
    unsafe { libc::_exit(0) };
}

/// Follows the kernel log through syslog(2), as /dev/kmsg is not readable by the system user.
///
/// SYSLOG_ACTION_READ blocks until there are messages nobody has read yet and returns only those,
/// starting with everything still in the ring buffer, so a restart neither replays nor loses
/// anything. Nothing else on Android reads the kernel log this way (logd does only with
/// ro.logd.kernel). If the read is refused, fall back to polling.
fn kernel_loop(mut out: Rotating) {
    let mut buf = vec![0u8; KERNEL_TAIL];
    let mut pending: Vec<u8> = Vec::new();
    loop {
        let n = unsafe { klogctl(2, buf.as_mut_ptr().cast(), buf.len() as c_int) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            out.write_line("--- kernel log: blocking read refused, polling instead ---");
            return kernel_poll_loop(out);
        }
        pending.extend_from_slice(&buf[..n as usize]);
        while let Some(p) = pending.iter().position(|&c| c == b'\n') {
            if p > 0 {
                if let Some(s) = scrub(&String::from_utf8_lossy(&pending[..p])) {
                    out.write(&s, is_urgent(&s));
                }
            }
            pending.drain(..=p);
        }
    }
}

/// Polls the newest [KERNEL_TAIL] bytes of the ring buffer and writes what came after the last
/// line already written; the whole buffer is read only when more than that arrived in between.
/// The kernel walks the whole buffer for each read, so this costs more than [kernel_loop].
fn kernel_poll_loop(mut out: Rotating) {
    let full = unsafe { klogctl(10, std::ptr::null_mut(), 0) }.max(KERNEL_TAIL as c_int) as usize;
    let mut buf = vec![0u8; full];
    let mut last: Option<Vec<u8>> = None;
    loop {
        let mut len = if last.is_some() { KERNEL_TAIL } else { full };
        loop {
            let n = unsafe { klogctl(3, buf.as_mut_ptr().cast(), len as c_int) };
            if n <= 0 {
                break;
            }
            let data = &buf[..n as usize];
            let start = match &last {
                None => Some(0),
                Some(l) => rfind_line(data, l),
            };
            let start = match start {
                Some(s) => s,
                None if len < full => {
                    len = full;
                    continue;
                }
                None => {
                    out.write_line("--- kernel log wrapped, lines lost ---");
                    0
                }
            };
            for l in data[start..].split(|&c| c == b'\n').filter(|l| !l.is_empty()) {
                if let Some(s) = scrub(&String::from_utf8_lossy(l)) {
                    out.write(&s, is_urgent(&s));
                }
            }
            if let Some(l) = data.split(|&c| c == b'\n').filter(|l| !l.is_empty()).last() {
                last = Some(l.to_vec());
            }
            break;
        }
        thread::sleep(KERNEL_POLL);
    }
}

/// Offset just past the last occurrence of `line` as a whole line in `data`.
fn rfind_line(data: &[u8], line: &[u8]) -> Option<usize> {
    let mut pos = data.len();
    while pos > 0 && data[pos - 1] == b'\n' {
        pos -= 1;
    }
    loop {
        let start = data[..pos].iter().rposition(|&c| c == b'\n').map_or(0, |p| p + 1);
        if &data[start..pos] == line {
            return Some((pos + 1).min(data.len()));
        }
        if start == 0 {
            return None;
        }
        pos = start - 1;
    }
}

fn logcat_loop(mut out: Rotating) {
    loop {
        let child = Command::new("/system/bin/logcat")
            .args(["-b", "crash,system,main,events", "-v", "threadtime", "-v", "year"])
            .args(LOG_FILTER)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        if let Ok(mut child) = child {
            if let Some(stdout) = child.stdout.take() {
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    if let Some(s) = scrub(&line) {
                        out.write(&s, is_urgent(&s));
                    }
                }
            }
            let _ = child.wait();
        }
        out.write_line("--- logcat restarted ---");
        thread::sleep(Duration::from_secs(5));
    }
}

/// Gets the log files to disk every [SYNC_EVERY] while they have new lines. Only these files are
/// synced (not the whole of /data, which on f2fs would mean a checkpoint each time).
fn sync_loop(list: SyncList, dir: PathBuf) {
    // The new session's directory entries, so the files themselves are found after a reset.
    if let Ok(d) = File::open(&dir) {
        let _ = d.sync_all();
    }
    loop {
        thread::sleep(SYNC_EVERY);
        let files: Vec<_> = list.lock().unwrap().clone();
        for f in files {
            let mut s = f.lock().unwrap();
            if s.dirty {
                s.dirty = false;
                let _ = s.file.sync_data();
            }
        }
    }
}

struct Proc {
    name: String,
    ticks: u64,
    threads: u64,
    rss_kb: u64,
}

/// Fields of /proc/<pid>/stat after the comm, which can hold spaces and parentheses.
fn stat_fields(stat: &str) -> Option<(&str, Vec<&str>)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    Some((&stat[open + 1..close], stat[close + 1..].split_whitespace().collect()))
}

fn proc_name(pid: &str, comm: &str) -> String {
    let cmd = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let first = cmd.split(|&c| c == 0).next().unwrap_or(&[]);
    let s = String::from_utf8_lossy(first);
    let base = s.rsplit('/').next().unwrap_or("").trim();
    if base.is_empty() { comm.to_string() } else { base.chars().take(48).collect() }
}

struct Snapshotter {
    page_kb: u64,
    proc_ticks: HashMap<u32, u64>,
    thread_ticks: HashMap<u32, u64>,
    last: Option<SystemTime>,
    last_had_baseline: bool,
}

impl Snapshotter {
    fn take(&mut self, out: &mut Rotating) {
        let now = SystemTime::now();
        let secs = self
            .last
            .and_then(|l| now.duration_since(l).ok())
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        self.last = Some(now);
        let epoch = now.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let uptime = read_trim("/proc/uptime").unwrap_or_default();
        out.write_line(&format!("=== epoch {epoch} uptime {uptime}"));

        if let Some(m) = read_trim("/proc/meminfo") {
            let keep = [
                "MemTotal", "MemAvailable", "Cached", "AnonPages", "Shmem", "SUnreclaim",
                "KernelStack", "PageTables", "SwapTotal", "SwapFree", "Mlocked",
            ];
            let v: Vec<String> = m
                .lines()
                .filter_map(|l| {
                    let (k, rest) = l.split_once(':')?;
                    keep.contains(&k).then(|| format!("{k}={}", rest.trim().trim_end_matches(" kB")))
                })
                .collect();
            out.write_line(&format!("mem_kb {}", v.join(" ")));
        }
        if let Some(m) = read_trim("/proc/vmstat") {
            let keep = ["pswpin", "pswpout", "pgmajfault", "oom_kill", "allocstall_normal", "allocstall_movable"];
            let v: Vec<String> = m
                .lines()
                .filter(|l| keep.iter().any(|k| l.split(' ').next() == Some(k)))
                .map(|l| l.replace(' ', "="))
                .collect();
            out.write_line(&format!("vm {}", v.join(" ")));
        }
        if let Some(z) = read_trim("/sys/block/zram0/mm_stat") {
            out.write_line(&format!("zram_mm_stat {z}"));
        }
        for p in ["memory", "cpu", "io"] {
            if let Some(s) = read_trim(format!("/proc/pressure/{p}")) {
                out.write_line(&format!("psi_{p} {}", s.replace('\n', " | ")));
            }
        }
        if let Ok(entries) = fs::read_dir("/sys/kernel/dmabuf/buffers") {
            let total: u64 = entries
                .flatten()
                .filter_map(|e| read_trim(e.path().join("size"))?.parse::<u64>().ok())
                .sum();
            out.write_line(&format!("dmabuf_kb {}", total / 1024));
        }
        if let Ok(entries) = fs::read_dir("/sys/class/thermal") {
            let mut v: Vec<String> = entries
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("thermal_zone"))
                .filter_map(|e| {
                    let t = read_trim(e.path().join("type"))?;
                    let temp = read_trim(e.path().join("temp"))?.parse::<i64>().ok()?;
                    (temp > 0).then(|| format!("{t}={}", temp / 100))
                })
                .collect();
            v.sort();
            out.write_line(&format!("thermal_dC {}", v.join(" ")));
        }

        // Processes and threads.
        let mut procs: Vec<(u32, Proc, u64)> = Vec::new();
        let mut threads: Vec<(u64, String)> = Vec::new();
        let mut new_proc_ticks = HashMap::new();
        let mut new_thread_ticks = HashMap::new();
        for e in fs::read_dir("/proc").into_iter().flatten().flatten() {
            let pid_s = e.file_name().to_string_lossy().to_string();
            let Ok(pid) = pid_s.parse::<u32>() else { continue };
            let Some(stat) = read_trim(format!("/proc/{pid}/stat")) else { continue };
            let Some((comm, f)) = stat_fields(&stat) else { continue };
            if f.len() < 22 {
                continue;
            }
            let ticks = f[11].parse::<u64>().unwrap_or(0) + f[12].parse::<u64>().unwrap_or(0);
            let threads_n = f[17].parse::<u64>().unwrap_or(0);
            let rss_kb = f[21].parse::<u64>().unwrap_or(0) * self.page_kb;
            // A process with no baseline started during the interval, so all its time is new.
            let baseline = if self.last_had_baseline { 0 } else { ticks };
            let delta = ticks.saturating_sub(*self.proc_ticks.get(&pid).unwrap_or(&baseline));
            new_proc_ticks.insert(pid, ticks);
            let name = proc_name(&pid_s, comm);
            for t in fs::read_dir(format!("/proc/{pid}/task")).into_iter().flatten().flatten() {
                let Ok(tid) = t.file_name().to_string_lossy().parse::<u32>() else { continue };
                let Some(ts) = read_trim(t.path().join("stat")) else { continue };
                let Some((tcomm, tf)) = stat_fields(&ts) else { continue };
                if tf.len() < 13 {
                    continue;
                }
                let tt = tf[11].parse::<u64>().unwrap_or(0) + tf[12].parse::<u64>().unwrap_or(0);
                if self.last_had_baseline {
                    let d = tt.saturating_sub(*self.thread_ticks.get(&tid).unwrap_or(&0));
                    if d > 0 {
                        threads.push((d, format!("{name}[{pid}]/{tcomm}[{tid}]")));
                    }
                }
                new_thread_ticks.insert(tid, tt);
            }
            procs.push((pid, Proc { name, ticks, threads: threads_n, rss_kb }, delta));
        }
        self.proc_ticks = new_proc_ticks;
        self.thread_ticks = new_thread_ticks;
        self.last_had_baseline = true;
        let pct = |d: u64| if secs > 0.0 { d as f64 / secs } else { 0.0 }; // 100 ticks/s = 100%
        out.write_line(&format!("procs {} interval_s {:.0}", procs.len(), secs));

        procs.sort_by(|a, b| b.2.cmp(&a.2));
        for (pid, p, d) in procs.iter().take(8).filter(|x| x.2 > 0) {
            out.write_line(&format!(
                "top_cpu {:.1}% {}[{pid}] total_ticks={} threads={} rss_kb={}",
                pct(*d), p.name, p.ticks, p.threads, p.rss_kb
            ));
        }
        threads.sort_by(|a, b| b.0.cmp(&a.0));
        for (d, n) in threads.iter().take(8) {
            out.write_line(&format!("top_thread {:.1}% {n}", pct(*d)));
        }
        procs.sort_by(|a, b| b.1.rss_kb.cmp(&a.1.rss_kb));
        for (pid, p, _) in procs.iter().take(8) {
            out.write_line(&format!("top_rss {} kB {}[{pid}] threads={}", p.rss_kb, p.name, p.threads));
        }
        procs.sort_by(|a, b| b.1.threads.cmp(&a.1.threads));
        for (pid, p, _) in procs.iter().take(5) {
            out.write_line(&format!("top_threads {} {}[{pid}]", p.threads, p.name));
        }
    }
}

fn clear(dir: &Path) {
    let _ = fs::remove_dir_all(dir.join("cur"));
    let _ = fs::remove_dir_all(dir.join("prev"));
    let _ = fs::remove_dir_all(Path::new(BOOT_DIR).join("boots"));
    let _ = fs::remove_dir_all(PSTORE);
    let _ = fs::remove_file(dir.join(DISABLED_MARKER));
}

fn write_scrubbed(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut out = String::with_capacity(data.len());
    for l in String::from_utf8_lossy(data).lines() {
        if let Some(s) = scrub(l) {
            out.push_str(&s);
            out.push('\n');
        }
    }
    fs::write(path, out)
}

/// Directory name for a boot: a running number first, so names sort by age. Not the time, as
/// the clock can still be at 1970 this early in boot.
fn boot_dir_name(seq: u64, boot_id: &str) -> String {
    format!("{seq:06}-{}", boot_id.get(..8).unwrap_or(boot_id))
}

fn next_seq(names: &[String]) -> u64 {
    names.iter().filter_map(|n| n.split('-').next()?.parse::<u64>().ok()).max().map_or(1, |m| m + 1)
}

/// Oldest names past the newest [BOOTS_KEEP].
fn boots_to_drop(mut names: Vec<String>) -> Vec<String> {
    names.sort();
    let n = names.len().saturating_sub(BOOTS_KEEP);
    names.truncate(n);
    names
}

/// Runs early in every boot while switched on, before anything can overwrite what the last
/// crash left: the kernel's crash records in pstore (gone after one more restart) and the kernel
/// log from the very start of this boot, which holds the PMIC power-on and reset reason and
/// would otherwise roll out of the ring buffer within hours.
fn boot_capture() {
    let root = Path::new(BOOT_DIR).join("boots");
    let boot_id = read_trim("/proc/sys/kernel/random/boot_id").unwrap_or_default();
    let suffix = format!("-{}", boot_id.get(..8).unwrap_or(&boot_id));
    let existing: Vec<String> = fs::read_dir(&root)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    if !boot_id.is_empty() && existing.iter().any(|n| n.ends_with(&suffix)) {
        return; // Already captured this boot.
    }
    let dir = root.join(boot_dir_name(next_seq(&existing), &boot_id));
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("penguin_flightlog: cannot create {}: {e}", dir.display());
        return;
    }

    let mut info = format!(
        "epoch {}\nboot_id {boot_id}\nuptime {}\n",
        epoch_now(),
        read_trim("/proc/uptime").unwrap_or_default()
    );
    for s in ARMED_SETTINGS {
        info.push_str(&format!("{s} {}\n", read_trim(s).unwrap_or_else(|| "?".into())));
    }

    // The whole ring buffer, without consuming it.
    let size = unsafe { klogctl(10, std::ptr::null_mut(), 0) }.max(KERNEL_TAIL as c_int) as usize;
    let mut buf = vec![0u8; size];
    let n = unsafe { klogctl(3, buf.as_mut_ptr().cast(), size as c_int) };
    if n > 0 {
        let _ = write_scrubbed(&dir.join("kernel_boot.log"), &buf[..n as usize]);
    } else {
        info.push_str(&format!("kernel_log error {}\n", std::io::Error::last_os_error()));
    }

    // The bootloader's log of this boot, which can carry the reason the last one ended.
    match fs::read("/proc/bootloader_log") {
        Ok(d) => {
            let _ = write_scrubbed(&dir.join("bootloader.log"), &d);
        }
        Err(err) => info.push_str(&format!("bootloader_log error {err}\n")),
    }

    // pstore: the console log of the boot before, staged by init. Each copy is removed once filed,
    // so a boot without a record can't pick up an older one. pmsg is binary logger data that
    // dumpstate already turns into LAST LOGCAT.
    match fs::read_dir(PSTORE) {
        Ok(entries) => {
            let pstore = dir.join("pstore");
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("pmsg") {
                    continue;
                }
                let read = fs::read(e.path());
                let _ = fs::remove_file(e.path());
                match read {
                    Ok(d) if !d.is_empty() => {
                        let _ = fs::create_dir_all(&pstore);
                        let _ = write_scrubbed(&pstore.join(&name), &d);
                        info.push_str(&format!("pstore {name} {} bytes\n", d.len()));
                    }
                    Ok(_) => info.push_str(&format!("pstore {name} empty\n")),
                    Err(err) => info.push_str(&format!("pstore {name} error {err}\n")),
                }
            }
        }
        Err(err) => info.push_str(&format!("pstore error {err}\n")),
    }

    // The bootloader's minidump of a crash: the kernel console up to the panic.
    info.push_str(&format!("rawdump {}\n", capture_rawdump(&dir)));
    let _ = fs::write(dir.join("info"), info);

    let names: Vec<String> = fs::read_dir(&root)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    for old in boots_to_drop(names) {
        let _ = fs::remove_dir_all(root.join(old));
    }
    if let Ok(c) = CString::new(BOOT_DIR) {
        unsafe {
            let fd = libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC);
            if fd >= 0 {
                libc::syncfs(fd);
                libc::close(fd);
            }
        }
    }
}

/// A minidump section: where it is in the partition and how long it is.
#[derive(Debug, PartialEq)]
struct Section {
    offset: u64,
    size: u64,
}

const RAWDUMP_HEADER: usize = 0x38;
const RAWDUMP_ENTRY: usize = 0x40;

/// Finds a section in a minidump header ("Raw_Dmp!", then 64-byte entries: valid, version,
/// type, offset, size, address, name). None if there is no valid dump or no such section.
fn find_section(head: &[u8], name: &str) -> Option<Section> {
    if head.len() < RAWDUMP_HEADER || &head[..8] != b"Raw_Dmp!" {
        return None;
    }
    let u32_at = |o: usize| u32::from_le_bytes(head[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(head[o..o + 8].try_into().unwrap());
    if u32_at(12) != 1 {
        return None; // Header not valid: no dump, or one still being written.
    }
    let count = u32_at(0x34) as usize;
    for i in 0..count {
        let e = RAWDUMP_HEADER + i * RAWDUMP_ENTRY;
        if e + RAWDUMP_ENTRY > head.len() {
            break;
        }
        let raw = &head[e + 0x2c..e + RAWDUMP_ENTRY];
        let n = &raw[..raw.iter().position(|&c| c == 0).unwrap_or(raw.len())];
        if u32_at(e) == 1 && n == name.as_bytes() {
            return Some(Section { offset: u64_at(e + 12), size: u64_at(e + 20) });
        }
    }
    None
}

/// Text of a ramoops ring ("DBGC", start, size, data) in the order it was written.
fn ramoops_text(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < 12 || &buf[..4] != b"DBGC" {
        return None;
    }
    let start = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
    let data = &buf[12..];
    if size > data.len() || start > size {
        return None;
    }
    let mut out = Vec::with_capacity(size);
    if size == data.len() {
        out.extend_from_slice(&data[start..]); // Wrapped: oldest part first.
    }
    out.extend_from_slice(&data[..start.min(size)]);
    if size < data.len() {
        out.extend_from_slice(&data[start..size]);
    }
    Some(out)
}

const PRB_DESC: usize = 24; // state_var, text_blk_lpos.begin, text_blk_lpos.next
const PRB_INFO: usize = 88; // seq, ts_nsec, text_len, facility, flags:5 level:3, caller_id, dev_info

/// The kernel log from a printk ring (Linux 5.10 and later) as dmesg prints it, oldest first:
/// "<level>[seconds][caller] text". Records still being written or already reused are left
/// out, and a gap in the sequence numbers is marked.
fn printk_ring_text(data: &[u8], desc: &[u8], info: &[u8]) -> Option<(Vec<u8>, usize)> {
    let n = desc.len() / PRB_DESC;
    if n == 0 || data.len() < 16 || info.len() < n * PRB_INFO {
        return None;
    }
    let u64_at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let size = data.len() as u64;
    let mut records = Vec::new();
    for i in 0..n {
        let d = i * PRB_DESC;
        let sv = u64_at(desc, d);
        let state = sv >> 62; // 1 committed, 2 finalized
        let id = sv & ((1 << 62) - 1);
        if !(state == 1 || state == 2) || id % n as u64 != i as u64 {
            continue;
        }
        let (begin, next) = (u64_at(desc, d + 8), u64_at(desc, d + 16));
        let r = i * PRB_INFO;
        let seq = u64_at(info, r);
        let ts = u64_at(info, r + 8);
        let len = u16::from_le_bytes(info[r + 16..r + 18].try_into().unwrap()) as usize;
        let level = info[r + 19] >> 5;
        let caller = u32::from_le_bytes(info[r + 20..r + 24].try_into().unwrap());
        let text: &[u8] = if begin & 1 == 1 || len == 0 {
            b"" // No data block (dropped or empty).
        } else {
            // A block that would cross the end of the ring is stored from its start instead.
            let mut at = (begin % size) as usize;
            if begin / size != next / size && next % size != 0 {
                at = 0;
            }
            if at + 8 + len > data.len() || u64_at(data, at) != id {
                continue; // Overwritten since.
            }
            &data[at + 8..at + 8 + len]
        };
        records.push((seq, ts, level, caller, text));
    }
    if records.is_empty() {
        return None;
    }
    records.sort_by_key(|r| r.0);
    let mut out = Vec::with_capacity(data.len());
    let mut last: Option<u64> = None;
    for (seq, ts, level, caller, text) in &records {
        if let Some(l) = last {
            if *seq > l + 1 {
                out.extend_from_slice(format!("--- {} records lost ---\n", seq - l - 1).as_bytes());
            }
        }
        last = Some(*seq);
        let who = if caller & 0x8000_0000 != 0 {
            format!("C{}", caller & 0x7fff_ffff)
        } else {
            format!("T{caller}")
        };
        let prefix = format!("<{level}>[{:5}.{:06}][{who:>6}] ", ts / 1_000_000_000, ts % 1_000_000_000 / 1000);
        for line in text.split(|&c| c == b'\n') {
            out.extend_from_slice(prefix.as_bytes());
            out.extend_from_slice(line);
            out.push(b'\n');
        }
    }
    Some((out, records.len()))
}

fn fnv1a(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf29ce484222325, |h, &b| (h ^ b as u64).wrapping_mul(0x100000001b3))
}

fn read_at(f: &File, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let mut buf = vec![0u8; len];
    f.read_exact_at(&mut buf, offset)?;
    Ok(buf)
}

/// The whole kernel log of the crashed boot from a minidump's printk ring, if it has one.
fn rawdump_kmsg(f: &File, head: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut parts = Vec::new();
    for name in RAWDUMP_PRINTK {
        let sec = find_section(head, name).ok_or_else(|| format!("no {name}"))?;
        if sec.size == 0 || sec.size > 16 << 20 {
            return Err(format!("{name} size {}", sec.size));
        }
        parts.push(read_at(f, sec.offset, sec.size as usize).map_err(|e| e.to_string())?);
    }
    printk_ring_text(&parts[0], &parts[1], &parts[2]).ok_or_else(|| "printk ring unreadable".into())
}

/// Files the kernel console and the whole kernel log of a new minidump into `dir`. Only the
/// section table and those sections are read, and the partition is never written. Returns what
/// happened, for `info`.
fn capture_rawdump(dir: &Path) -> String {
    let f = match File::open(RAWDUMP) {
        Ok(f) => f,
        Err(e) => return format!("error {e}"),
    };
    let head = match read_at(&f, 0, 16 << 10) {
        Ok(h) => h,
        Err(e) => return format!("error {e}"),
    };
    let Some(sec) = find_section(&head, RAWDUMP_CONSOLE) else { return "none".into() };
    if sec.size == 0 || sec.size > 4 << 20 {
        return format!("console size {}", sec.size);
    }
    let raw = match read_at(&f, sec.offset, sec.size as usize) {
        Ok(r) => r,
        Err(e) => return format!("error {e}"),
    };
    let Some(text) = ramoops_text(&raw) else { return "console unreadable".into() };
    let hash = format!("{:016x}", fnv1a(&text));
    let seen = format!("{RAWDUMP_SEEN_VERSION} {hash}");
    if read_trim(RAWDUMP_SEEN).as_deref() == Some(seen.as_str()) {
        return format!("seen {hash}");
    }
    if let Err(e) = write_scrubbed(&dir.join("rawdump_console.log"), &text) {
        return format!("error {e}");
    }
    let kmsg = match rawdump_kmsg(&f, &head) {
        Ok((log, records)) => match write_scrubbed(&dir.join("rawdump_kmsg.log"), &log) {
            Ok(()) => format!("kmsg {records} records"),
            Err(e) => format!("kmsg error {e}"),
        },
        Err(e) => format!("kmsg {e}"),
    };
    let _ = fs::write(RAWDUMP_SEEN, &seen);
    format!("filed {hash} {} bytes, {kmsg}", text.len())
}

fn epoch_now() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// How much longer the logs are kept after being switched off at `since`, or None if they are due.
fn grace_left(since: u64, now: u64) -> Option<Duration> {
    let left = (since + CLEAR_GRACE.as_secs()).saturating_sub(now);
    (left > 0).then(|| Duration::from_secs(left))
}

/// Switched off: deletes the logs once they have stayed off for [CLEAR_GRACE]. Waits in the
/// background and gives up as soon as the recorder starts again, which removes the marker. Also
/// run at boot while switched off, so logs left from a restart within the grace period still go.
fn disable(dir: &Path) {
    if !dir.is_dir() {
        return;
    }
    let marker = dir.join(DISABLED_MARKER);
    if !marker.exists() {
        let _ = fs::write(&marker, epoch_now().to_string());
    }
    loop {
        // A missing marker means the recorder was switched back on.
        let Some(since) = read_trim(&marker).and_then(|s| s.parse::<u64>().ok()) else { return };
        match grace_left(since, epoch_now()) {
            Some(left) => thread::sleep(left),
            None => return clear(dir),
        }
    }
}

fn main() {
    let dir = Path::new(DIR);
    match std::env::args().nth(1).as_deref() {
        Some("--clear") => return clear(dir),
        Some("--disable") => return disable(dir),
        Some("--boot-capture") => return boot_capture(),
        _ => {}
    }
    // Switched back on: cancel a pending deletion.
    let _ = fs::remove_file(dir.join(DISABLED_MARKER));
    let cur = match start_session(dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("penguin_flightlog: cannot start a session in {DIR}: {e}");
            std::process::exit(1);
        }
    };
    prune_old(dir);

    if let Ok(c) = CString::new(cur.join("state").into_os_string().into_encoded_bytes()) {
        let _ = STATE_PATH.set(c);
    }
    unsafe {
        libc::signal(libc::SIGTERM, on_term as extern "C" fn(c_int) as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_term as extern "C" fn(c_int) as libc::sighandler_t);
    }

    let list: SyncList = Arc::new(Mutex::new(Vec::new()));
    let open = |name: &str, limit| Rotating::open(cur.join(name), limit, &list);
    let (Ok(kernel), Ok(system), Ok(mut snaps)) =
        (open("kernel.log", KERNEL_LIMIT), open("system.log", SYSTEM_LIMIT), open("snapshots.log", SNAPSHOT_LIMIT))
    else {
        eprintln!("penguin_flightlog: cannot open the log files");
        std::process::exit(1);
    };

    thread::spawn(move || kernel_loop(kernel));
    thread::spawn(move || logcat_loop(system));
    let sync_dir = cur.clone();
    let sync_list = list.clone();
    thread::spawn(move || sync_loop(sync_list, sync_dir));

    let page_kb = (unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) / 1024) as u64;
    let mut snap = Snapshotter {
        page_kb,
        proc_ticks: HashMap::new(),
        thread_ticks: HashMap::new(),
        last: None,
        last_had_baseline: false,
    };
    // A first pass records the baseline so the next one can report CPU use over the interval.
    snap.take(&mut snaps);
    loop {
        thread::sleep(SNAPSHOT_EVERY);
        snap.take(&mut snaps);
        prune_old(dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_addresses_and_networks() {
        assert_eq!(
            scrub("wlan: connected to 3c:22:fb:1a:0B:9e on 5GHz").unwrap(),
            "wlan: connected to xx:xx:xx:xx:xx:xx on 5GHz"
        );
        assert!(scrub("peach_v2: SSID HomeNet RSSI -40").is_none());
        assert!(scrub("KernelSU: hook_manager: unmark 1793").is_none());
        assert_eq!(scrub("time 12:30:45.123 ok").unwrap(), "time 12:30:45.123 ok");
    }

    #[test]
    fn finds_the_last_written_line() {
        let data = b"a\nb\nc\nb\nd\n";
        assert_eq!(rfind_line(data, b"b"), Some(8));
        assert_eq!(rfind_line(data, b"d"), Some(10));
        assert_eq!(rfind_line(data, b"x"), None);
        assert_eq!(rfind_line(b"one\ntwo", b"one"), Some(4));
    }

    #[test]
    fn keeps_logs_for_the_grace_period() {
        let g = CLEAR_GRACE.as_secs();
        assert_eq!(grace_left(1000, 1000), Some(CLEAR_GRACE));
        assert_eq!(grace_left(1000, 1000 + g - 1), Some(Duration::from_secs(1)));
        assert_eq!(grace_left(1000, 1000 + g), None);
        // Clock behind the marker (wrong time early at boot): keep waiting, never clear early.
        assert_eq!(grace_left(1000, 10), Some(Duration::from_secs(g + 990)));
    }

    #[test]
    fn keeps_the_newest_boots() {
        let id = "0a80151d-9bef-4f70-a8b3-6dcc15ee1712";
        assert_eq!(boot_dir_name(7, id), "000007-0a80151d");
        // Zero padding keeps the order right across digit counts.
        assert!(boot_dir_name(999, id) < boot_dir_name(1000, id));
        assert_eq!(next_seq(&[]), 1);
        assert_eq!(next_seq(&[boot_dir_name(3, id), boot_dir_name(9, id), "junk".into()]), 10);
        let names: Vec<String> = (0..BOOTS_KEEP + 2).rev().map(|i| boot_dir_name(i as u64, id)).collect();
        assert_eq!(boots_to_drop(names), vec![boot_dir_name(0, id), boot_dir_name(1, id)]);
        assert!(boots_to_drop(vec![boot_dir_name(5, id)]).is_empty());
    }

    #[test]
    fn spots_urgent_lines() {
        assert_eq!(kernel_level("<2>[  1.0] x"), Some(2));
        assert_eq!(kernel_level("[  1.0] x"), None);
        assert!(is_urgent("<0>[ 98.1][ T1] Kernel panic - not syncing: sysrq triggered crash"));
        assert!(is_urgent("<6>[ 98.0][ T1] sysrq: Trigger a crash"));
        assert!(is_urgent("<2>[ 5.0][ T9] anything at crit"));
        assert!(is_urgent("2026-11-21 12:00:00.000  1  1 W Watchdog: *** WATCHDOG KILLING SYSTEM PROCESS"));
        assert!(!is_urgent("<3>[ 5.0][ T9] peach_v2: scan failed"));
        assert!(!is_urgent("<6>[ 5.0][ T9] OPLUS_CHG: soc=100"));
    }

    fn entry(name: &str, valid: u32, offset: u64, size: u64) -> Vec<u8> {
        let mut e = vec![0u8; RAWDUMP_ENTRY];
        e[0..4].copy_from_slice(&valid.to_le_bytes());
        e[4..8].copy_from_slice(&0x1000u32.to_le_bytes());
        e[8..12].copy_from_slice(&3u32.to_le_bytes());
        e[12..20].copy_from_slice(&offset.to_le_bytes());
        e[20..28].copy_from_slice(&size.to_le_bytes());
        e[0x2c..0x2c + name.len()].copy_from_slice(name.as_bytes());
        e
    }

    fn header(valid: u32, entries: &[Vec<u8>]) -> Vec<u8> {
        let mut h = vec![0u8; RAWDUMP_HEADER];
        h[..8].copy_from_slice(b"Raw_Dmp!");
        h[8..12].copy_from_slice(&0x1011u32.to_le_bytes());
        h[12..16].copy_from_slice(&valid.to_le_bytes());
        h[0x34..0x38].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        for e in entries {
            h.extend_from_slice(e);
        }
        h
    }

    #[test]
    fn finds_minidump_sections() {
        let h = header(1, &[entry("md_KELF_HDR.BIN", 1, 0x2c78, 0x6e20), entry("md_KCONSOLE.BIN", 1, 0x4f5b88, 0x40000)]);
        assert_eq!(find_section(&h, RAWDUMP_CONSOLE), Some(Section { offset: 0x4f5b88, size: 0x40000 }));
        assert_eq!(find_section(&h, "md_KPMSG.BIN"), None);
        // Not a name prefix match.
        assert_eq!(find_section(&h, "md_KCONSOLE"), None);
        assert_eq!(find_section(&header(0, &[entry("md_KCONSOLE.BIN", 1, 1, 1)]), RAWDUMP_CONSOLE), None);
        assert_eq!(find_section(&header(1, &[entry("md_KCONSOLE.BIN", 0, 1, 1)]), RAWDUMP_CONSOLE), None);
        assert_eq!(find_section(&[0u8; 4096], RAWDUMP_CONSOLE), None);
        // Count larger than the bytes read: stops at the end instead of panicking.
        let mut short = header(1, &[]);
        short[0x34..0x38].copy_from_slice(&500u32.to_le_bytes());
        assert_eq!(find_section(&short, RAWDUMP_CONSOLE), None);
    }

    #[test]
    fn unwraps_the_console_ring() {
        let ring = |start: u32, size: u32, data: &[u8]| {
            let mut b = b"DBGC".to_vec();
            b.extend_from_slice(&start.to_le_bytes());
            b.extend_from_slice(&size.to_le_bytes());
            b.extend_from_slice(data);
            b
        };
        // Wrapped: "CD" is newest, written over the start.
        assert_eq!(ramoops_text(&ring(2, 6, b"CDxyAB")).unwrap(), b"xyABCD");
        // Not full yet.
        assert_eq!(ramoops_text(&ring(3, 3, b"abc\0\0\0")).unwrap(), b"abc");
        assert!(ramoops_text(&ring(9, 6, b"abcdef")).is_none());
        assert!(ramoops_text(b"nope").is_none());
    }

    #[test]
    fn decodes_the_printk_ring() {
        // Ring of 64 bytes and 4 descriptors. Records 0..2 in order, record 3 still reserved.
        let mut data = vec![0u8; 64];
        let mut desc = vec![0u8; 4 * PRB_DESC];
        let mut info = vec![0u8; 4 * PRB_INFO];
        let mut put = |i: usize, state: u64, id: u64, begin: u64, next: u64, seq: u64, text: &[u8], level: u8, caller: u32| {
            let d = i * PRB_DESC;
            desc[d..d + 8].copy_from_slice(&((state << 62) | id).to_le_bytes());
            desc[d + 8..d + 16].copy_from_slice(&begin.to_le_bytes());
            desc[d + 16..d + 24].copy_from_slice(&next.to_le_bytes());
            let r = i * PRB_INFO;
            info[r..r + 8].copy_from_slice(&seq.to_le_bytes());
            info[r + 8..r + 16].copy_from_slice(&(seq * 1_500_000_000).to_le_bytes());
            info[r + 16..r + 18].copy_from_slice(&(text.len() as u16).to_le_bytes());
            info[r + 19] = level << 5;
            info[r + 20..r + 24].copy_from_slice(&caller.to_le_bytes());
        };
        // Record 0 at 48 (first lap), records 1 and 2 at 0 and 16 (second lap, 64 + offset).
        put(0, 2, 4, 48, 64, 0, b"oldest", 6, 1);
        put(1, 2, 5, 64, 80, 1, b"second", 4, 0x8000_0002);
        put(2, 1, 6, 80, 96, 2, b"a\nb", 0, 7);
        put(3, 0, 3, 0, 0, 9, b"", 6, 0);
        data[48..56].copy_from_slice(&4u64.to_le_bytes());
        data[56..62].copy_from_slice(b"oldest");
        data[0..8].copy_from_slice(&5u64.to_le_bytes());
        data[8..14].copy_from_slice(b"second");
        data[16..24].copy_from_slice(&6u64.to_le_bytes());
        data[24..27].copy_from_slice(b"a\nb");
        let (text, n) = printk_ring_text(&data, &desc, &info).unwrap();
        assert_eq!(n, 3);
        assert_eq!(
            String::from_utf8(text).unwrap(),
            "<6>[    0.000000][    T1] oldest\n<4>[    1.500000][    C2] second\n<0>[    3.000000][    T7] a\n<0>[    3.000000][    T7] b\n"
        );
        // A block overwritten since (id no longer matches) is dropped, and the gap is marked.
        data[0..8].copy_from_slice(&99u64.to_le_bytes());
        let (text, n) = printk_ring_text(&data, &desc, &info).unwrap();
        assert_eq!(n, 2);
        assert!(String::from_utf8(text).unwrap().contains("--- 1 records lost ---\n"));
        assert!(printk_ring_text(&data, &[], &info).is_none());
    }

    #[test]
    fn rotates_and_syncs() {
        let dir = std::env::temp_dir().join(format!("flightlog-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let list: SyncList = Arc::new(Mutex::new(Vec::new()));
        let mut r = Rotating::open(dir.join("k.log"), 16, &list).unwrap();
        r.write_line("0123456789");
        assert!(list.lock().unwrap()[0].lock().unwrap().dirty);
        r.write("abcdefghij", true);
        assert!(!list.lock().unwrap()[0].lock().unwrap().dirty);
        assert_eq!(fs::read_to_string(dir.join("k.log.1")).unwrap(), "0123456789\n");
        assert_eq!(fs::read_to_string(dir.join("k.log")).unwrap(), "abcdefghij\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_stat_with_odd_comm() {
        let (comm, f) = stat_fields("123 (a (b) c) S 1 2 3 4 5 6 7 8 9 10 11 12").unwrap();
        assert_eq!(comm, "a (b) c");
        assert_eq!(f[0], "S");
    }
}
