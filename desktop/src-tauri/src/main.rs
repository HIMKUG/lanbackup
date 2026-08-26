#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // 探针：每次启动清空诊断文件（均为追加模式，全程时间线不互相覆盖）。
    // 文件在 %TEMP%——不写盘符根目录（高频根目录写入是杀软 HIPS 的典型触发特征）。
    // 探针文件清理（PROBE_ENABLED 门控，见 lib.rs）：关闭时零文件系统开销
    if backup_desktop_lib::PROBE_ENABLED {
        let tmp = std::env::temp_dir();
        let _ = std::fs::remove_file(tmp.join("tauri_debug_log.txt"));
        let _ = std::fs::remove_file(tmp.join("wd_alive.txt"));
        let _ = std::fs::remove_file(tmp.join("proc_alive.txt"));
    }

    backup_desktop_lib::run()
}
