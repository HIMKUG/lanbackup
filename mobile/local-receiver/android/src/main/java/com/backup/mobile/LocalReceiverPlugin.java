package com.backup.mobile;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.net.wifi.WifiManager;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.util.Log;

import androidx.activity.result.ActivityResult;
import androidx.documentfile.provider.DocumentFile;

import com.backup.mobile.receiver.LanBackupCore;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.ActivityCallback;
import com.getcapacitor.annotation.CapacitorPlugin;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.BufferedInputStream;
import java.net.DatagramPacket;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.RejectedExecutionHandler;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 手机端接收服务（Capacitor 原生插件）
 *
 * 用 {@link ServerSocket} 实现 LocalSend v2 协议接收端，文件写入 SAF 备份目录。
 * 桌面端（LsHttpClientV2）通过该服务把文件推送到手机（电脑 → 手机方向）。
 *
 * 协议端点（与 shared-core transfer.ts 发送端对应）：
 * - POST /api/localsend/v2/register      → 设备信息
 * - GET  /api/localsend/v2/info          → 设备信息
 * - POST /api/localsend/v2/prepare-upload → 协商会话（接受全部文件）
 * - POST /api/localsend/v2/upload        → 接收文件内容并写入 SAF
 * - POST /api/localsend/v2/cancel        → 取消（忽略）
 *
 * 冲突策略与 shared-core conflict.ts 一致：同名且大小不同 → 重命名 `原名_MMDDhhmmss.扩展名`，永不覆盖。
 */
@CapacitorPlugin(
        name = "LocalReceiver",
        // 必须注册 pickDirectory 的 requestCode：Capacitor 的活动结果路由
        // （Bridge.getPluginWithRequestCode）只匹配注解里声明的 requestCodes，
        // 未声明时文件选择器返回后结果永远不会回到插件。
        requestCodes = {LocalReceiverPlugin.REQ_PICK_DIRECTORY})
public class LocalReceiverPlugin extends Plugin {

    /** logcat 标签：adb logcat -s LocalReceiver 可过滤 */
    private static final String TAG = "LocalReceiver";

    /** LocalSend v2 multicast 组播组与端口（与 localsend core 常量一致） */
    private static final String MULTICAST_GROUP = "224.0.0.167";
    private static final int MULTICAST_PORT = 53317;
    /** 广播周期（毫秒）：LocalSend 设备持续广播，扫描方被动监听即可发现 */
    private static final long ANNOUNCE_INTERVAL_MS = 2000;

    // ================================================================
    // v4.4 三层合并架构：私有缓存目录
    // ================================================================
    /** 私有缓存目录（应用私有，不对用户可见） */
    private static final String PRIVATE_CACHE_DIR = "session_chunks";
    /** 合并临时文件（合并中） */
    private static final String PART_TMP_DIR = "part_tmp";
    /** 合并就绪文件（已验证，等待提交） */
    private static final String PART_READY_DIR = "part_ready";

    private ServerSocket serverSocket;
    private ExecutorService executor;
    /** 每连接处理线程池：大文件上传不再阻塞 accept 循环（单连接不再卡死其他设备的请求） */
    private ExecutorService clientPool;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private volatile String rootUri;
    private volatile String selfCode;

    /** 组播广播线程：接收服务运行期间周期广播本机信息，让电脑端能扫描到手机 */
    private ExecutorService announcerExecutor;
    private volatile boolean announcerRunning = false;

    /** 常驻配对服务（53318）：配对/问候/解除/目录同步/信息探测，不依赖接收服务 */
    private ServerSocket pairingServerSocket;
    private ExecutorService pairingExecutor;
    /** 每连接处理线程池：配对确认弹窗阻塞 45s 不再卡死其他配对请求（/info /manifest） */
    private ExecutorService pairingClientPool;
    private final AtomicBoolean pairingRunning = new AtomicBoolean(false);

    /** 扫描结果中的单个设备 */
    private static class ScannedDevice {
        final String alias;
        final String fingerprint;
        final String ip;
        final int port;
        /** 最近一次被发现的时刻（epoch ms）：getScanResults 按它剪枝，停止广播/下线的设备自动消失 */
        final long lastSeen;

        ScannedDevice(String alias, String fingerprint, String ip, int port, long lastSeen) {
            this.alias = alias;
            this.fingerprint = fingerprint;
            this.ip = ip;
            this.port = port;
            this.lastSeen = lastSeen;
        }
    }

    /** 主动扫描局域网：组播监听 + /24 子网 HTTP 探测 */
    private final List<ScannedDevice> scanResults = Collections.synchronizedList(new ArrayList<>());
    private ExecutorService scanExecutor;
    private volatile boolean scanning = false;
    private WifiManager.MulticastLock multicastLock;
    /** Rust 核心侧组播锁守卫句柄（M22）：0 = 未持有。仅当核心 .so 打包进 APK 时非零 */
    private long coreGuardHandle;
    private MulticastSocket scanMulticastSocket;

    /** 对方通过 /sync-dir 同步过来的目录映射（direction → 目录名） */
    private final Map<String, String> syncedDirs = new HashMap<>();

    /**
     * 双端配对记录：对方验证本机连接码通过后，记录对方信任信息
     * （deviceId → {name, ip, port, fingerprint:对方码}）。与本地 pairings 合并，
     * 消除"一端有已配对、另一端没有"的信息差；解除配对方可 /unpair 双向删除。
     */
    private final Map<String, JSONObject> pairedPeers = new HashMap<>();

    /** 待前端确认的接收会话（prepare-upload 阻塞等待用户同意/拒绝） */
    private final Map<String, CompletableFuture<Boolean>> pendingApprovals = new HashMap<>();
    /** 待前端确认的配对请求（/verify 配对验证阻塞等待被动方同意/拒绝） */
    private final Map<String, CompletableFuture<Boolean>> pendingPairings = new HashMap<>();
    /** 会话总字节（接收进度用）：prepare-upload 时按文件 size 求和 */
    private final Map<String, Long> sessionTotalBytes = new HashMap<>();

    // ---------------------------------------------------------------- 设备身份（设备名 + 公开 deviceId）

    /** 简单键值持久化（SharedPreferences） */
    private String prefString(String key, String def) {
        return getContext().getSharedPreferences("lanbackup", Context.MODE_PRIVATE)
                .getString(key, def);
    }

    private void prefPut(String key, String val) {
        getContext().getSharedPreferences("lanbackup", Context.MODE_PRIVATE)
                .edit().putString(key, val).apply();
    }

    private static final String PAIRED_PEERS_KEY = "paired_peers";

    /** 发送方是否已配对（按 IP 匹配 pairedPeers；用于接收确认超时自动接受策略） */
    private boolean isTrustedPeer(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        synchronized (pairedPeers) {
            for (JSONObject p : pairedPeers.values()) {
                if (ip.equals(p.optString("ip"))) return true;
            }
        }
        return false;
    }

    /** 配对信任表落盘（SharedPreferences，JSON 数组；每次增删后调用） */
    private void persistPairedPeers() {
        try {
            JSONArray arr = new JSONArray();
            synchronized (pairedPeers) {
                for (Map.Entry<String, JSONObject> e : pairedPeers.entrySet()) {
                    try {
                        JSONObject p = new JSONObject();
                        p.put("deviceId", e.getKey());
                        p.put("name", e.getValue().optString("name"));
                        p.put("ip", e.getValue().optString("ip"));
                        p.put("port", e.getValue().optInt("port", 53317));
                        p.put("fingerprint", e.getValue().optString("fingerprint"));
                        p.put("at", e.getValue().optLong("at", 0));
                        arr.put(p);
                    } catch (Exception ignored) {
                    }
                }
            }
            prefPut(PAIRED_PEERS_KEY, arr.toString());
        } catch (Exception ignored) {
        }
    }

    /** 从本地存储恢复配对信任表（进程重启后配对关系不丢） */
    private void loadPairedPeers() {
        try {
            String raw = prefString(PAIRED_PEERS_KEY, "");
            if (raw.isEmpty()) return;
            JSONArray arr = new JSONArray(raw);
            synchronized (pairedPeers) {
                pairedPeers.clear();
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject p = arr.optJSONObject(i);
                    if (p == null) continue;
                    String deviceId = p.optString("deviceId", "");
                    if (deviceId.isEmpty() || deviceId.equals(deviceId())) continue;
                    JSONObject peer = new JSONObject();
                    peer.put("name", p.optString("name", "未知设备"));
                    peer.put("ip", p.optString("ip", ""));
                    peer.put("port", p.optInt("port", 53317));
                    peer.put("fingerprint", p.optString("fingerprint", ""));
                    peer.put("at", p.optLong("at", System.currentTimeMillis()));
                    pairedPeers.put(deviceId, peer);
                }
            }
            Log.i(TAG, "已从本地恢复配对记录: " + pairedPeers.size() + " 台");
        } catch (Exception ignored) {
        }
    }

    /**
     * 公开 deviceId（安装后固定）：广播/注册响应中作为 fingerprint 使用。
     * 与连接码（selfCode）分离——连接码只在 /verify 端点本地比对，绝不广播。
     */
    private String deviceId() {
        String id = prefString("device_id", "");
        if (id.isEmpty()) {
            id = UUID.randomUUID().toString();
            prefPut("device_id", id);
        }
        return id;
    }

    /** 设备名（默认机型，如“小米 17”），可在设置中修改 */
    private String deviceName() {
        String n = prefString("device_name", "");
        if (n.isEmpty()) {
            n = android.os.Build.MODEL;
            prefPut("device_name", n);
        }
        return n;
    }

    /** 会话中的单个文件（对齐 LocalSend core `SessionFileV2`：token + 文件名元数据） */
    private static class SessionFile {
        final String token;
        final String fileName;
        final String fileType;
        // scheduler v1 扩展字段
        final String merkleRoot;
        final String[] pieceHashes;
        final long chunkSize;

        SessionFile(String token, String fileName, String fileType, String merkleRoot, String[] pieceHashes, long chunkSize) {
            this.token = token;
            this.fileName = fileName;
            this.fileType = fileType == null ? "" : fileType;
            this.merkleRoot = merkleRoot;
            this.pieceHashes = pieceHashes;
            this.chunkSize = chunkSize;
        }
    }

    /** sessionId -> (fileId -> SessionFile) */
    private final Map<String, Map<String, SessionFile>> sessions = new HashMap<>();
    /** 会话累计：总字节 / 开始时间 / 文件总数（接收历史按会话聚合） */
    private final Map<String, Long> sessionBytes = new HashMap<>();
    private final Map<String, Long> sessionStart = new HashMap<>();
    private final Map<String, Integer> sessionCount = new HashMap<>();

    @PluginMethod
    public void start(PluginCall call) {
        Log.i(TAG, "start: 请求启动接收服务器");
        if (running.get()) {
            // 已在运行 → 先停止旧实例再以新目录重启（切换接收目录后必须生效，
            // 否则文件会继续写入旧目录）
            Log.i(TAG, "start: 已在运行，先停止旧实例再重启（可能切换了接收目录）");
            stopMulticastAnnouncer();
            running.set(false);
            if (serverSocket != null) {
                try {
                    serverSocket.close();
                } catch (IOException ignored) {
                }
            }
            if (executor != null) {
                executor.shutdownNow();
            }
            synchronized (sessions) {
                sessions.clear();
                sessionBytes.clear();
                sessionStart.clear();
                sessionCount.clear();
            }
        }
        Integer port = call.getInt("port", 53317);
        String root = call.getString("rootUri");
        String code = call.getString("selfCode", "");
        if (root == null || root.isEmpty()) {
            Log.e(TAG, "start: 缺少接收目录 URI");
            call.reject("缺少接收目录 URI");
            return;
        }
        this.rootUri = root;
        this.selfCode = code;
        Log.i(TAG, "start: port=" + port + " root=" + root + " selfCode(前2后2)=" + mask(code));
        try {
            serverSocket = new ServerSocket(port);
            running.set(true);
            executor = Executors.newSingleThreadExecutor();
            clientPool = new ThreadPoolExecutor(
                Runtime.getRuntime().availableProcessors() * 2,
                Runtime.getRuntime().availableProcessors() * 2,
                0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(100),
                new ThreadPoolExecutor.CallerRunsPolicy());
            executor.submit(this::acceptLoop);
            // 周期广播本机信息（LocalSend v2 multicast），让同网段电脑端能发现手机
            startMulticastAnnouncer(serverSocket.getLocalPort(), code);
            JSObject res = new JSObject();
            res.put("ok", true);
            res.put("port", serverSocket.getLocalPort());
            Log.i(TAG, "start: 服务器已启动，实际端口=" + serverSocket.getLocalPort());
            call.resolve(res);
        } catch (IOException e) {
            Log.e(TAG, "start: 启动失败", e);
            call.reject("启动接收服务器失败: " + e.getMessage());
        }
    }

    @PluginMethod
    public void stop(PluginCall call) {
        Log.i(TAG, "stop: 停止接收服务器");
        stopMulticastAnnouncer();
        running.set(false);
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException ignored) {
            }
        }
        if (executor != null) {
            executor.shutdownNow();
        }
        if (clientPool != null) {
            clientPool.shutdownNow();
        }
        synchronized (sessions) {
            sessions.clear();
            sessionBytes.clear();
            sessionStart.clear();
            sessionCount.clear();
        }
        call.resolve();
    }

    @PluginMethod
    public void isRunning(PluginCall call) {
        call.resolve(new JSObject().put("running", running.get()));
    }

    // ---------------------------------------------------------------- 配对：设备信息 / 验证 / 目录同步

    /** 本机设备信息：设备名、机型、公开 deviceId */
    @PluginMethod
    public void getDeviceInfo(PluginCall call) {
        JSObject res = new JSObject();
        res.put("name", deviceName());
        res.put("model", android.os.Build.MODEL);
        res.put("deviceId", deviceId());
        call.resolve(res);
    }

    /** 修改本机设备名（持久化，参与广播） */
    @PluginMethod
    public void setDeviceName(PluginCall call) {
        String name = call.getString("name", "");
        if (name.trim().isEmpty()) {
            call.reject("设备名不能为空");
            return;
        }
        prefPut("device_name", name.trim());
        Log.i(TAG, "setDeviceName: " + deviceName());
        call.resolve();
    }

    /** 探测目标设备（GET /info）：用于在线状态与配对时读取对方公开信息 */
    @PluginMethod
    public void pingDevice(PluginCall call) {
        final String ip = call.getString("ip");
        final int port = call.getInt("port", 53317);
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                URL url = new URL("http://" + ip + ":" + port + "/api/localsend/v2/info");
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(3000);
                conn.setReadTimeout(3000);
                int resp = conn.getResponseCode();
                if (resp != 200) {
                    call.reject("设备无响应 HTTP " + resp);
                    return;
                }
                JSONObject o = new JSONObject(
                        new String(readAllBytes(conn.getInputStream()), StandardCharsets.UTF_8));
                call.resolve(new JSObject()
                        .put("alias", o.optString("alias"))
                        .put("fingerprint", o.optString("fingerprint"))
                        .put("port", o.optInt("port", port)));
            } catch (Exception e) {
                call.reject("无法连接设备: " + e.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }
        }).start();
    }

    /**
     * 向目标设备提交连接码验证 / 连接问候（POST /verify）。
     * - code 非空：配对（连接码在目标本地比对，不泄露目标连接码）；
     * - code 空：连接问候（校验本机 deviceId 是否在目标信任列表）。
     * 同时携带本机 deviceId/name/myCode，目标验证通过后记录双端配对。
     * 桌面端 verify 服务监听在 接收端口+1（53318）。
     */
    @PluginMethod
    public void verifyDevice(PluginCall call) {
        final String ip = call.getString("ip");
        final int port = call.getInt("port", 53317);
        final String code = call.getString("code", "");
        final String deviceId = call.getString("deviceId", "");
        final String name = call.getString("name", "");
        final String myCode = call.getString("myCode", "");
        final int myPort = call.getInt("myPort", 0);
        final boolean probe = call.getBoolean("probe", false);
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                JSONObject payload = new JSONObject();
                payload.put("code", code);
                if (!deviceId.isEmpty()) payload.put("deviceId", deviceId);
                if (!name.isEmpty()) payload.put("name", name);
                if (!myCode.isEmpty()) payload.put("myCode", myCode);
                if (myPort > 0) payload.put("port", myPort);
                // 状态探测（probe=true）：对方不应触发"已连接"事件。
                // 漏传会导致手机端轮询被对方误认为连接问候 → 连接状态不对称（电脑已连接、手机在线）
                if (probe) payload.put("probe", true);
                byte[] body = payload.toString().getBytes(StandardCharsets.UTF_8);
                URL url = new URL("http://" + ip + ":" + (port + 1) + "/api/localsend/v2/verify");
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(3000);
                conn.setReadTimeout(3000);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Content-Length", String.valueOf(body.length));
                conn.getOutputStream().write(body);
                int resp = conn.getResponseCode();
                JSONObject o = new JSONObject(
                        new String(readAllBytes(conn.getInputStream()), StandardCharsets.UTF_8));
                boolean ok = resp == 200 && o.optBoolean("ok", false);
                String reason = o.optString("reason", "");
                Log.i(TAG, "verifyDevice: 目标 " + ip + " " + (code.isEmpty() ? "问候" : "验证") + (ok ? "通过" : "未通过" + (reason.isEmpty() ? "" : " (" + reason + ")")));
                JSObject res = new JSObject().put("ok", ok);
                if (!reason.isEmpty()) res.put("reason", reason);
                call.resolve(res);
            } catch (Exception e) {
                call.reject("验证失败: " + e.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }
        }).start();
    }

    /** 本机连接码（prefs 优先；未刷新过返回空，由前端用设备号默认算法兜底） */
    @PluginMethod
    public void getSelfCode(PluginCall call) {
        call.resolve(new JSObject().put("code", effectiveSelfCode()));
    }

    /**
     * 有效本机码：刷新过的 prefs 码 → 接收服务传入的码 → 设备号派生默认码。
     * 关键：接收服务未启动时 selfCode 字段为空，若没有默认码兜底，
     * 电脑端输入本机码验证会永远失败（本机无法比对）。默认码算法与
     * shared-core identity.ts 完全一致，保证显示码 == 验证码。
     */
    private String effectiveSelfCode() {
        String pref = prefString("self_code", "");
        if (!pref.isEmpty()) {
            return pref;
        }
        if (selfCode != null && !selfCode.isEmpty()) {
            return selfCode;
        }
        String derived = defaultSelfCode();
        prefPut("self_code", derived);
        return derived;
    }

    /** 与 shared-core identity.ts 一致的默认码：FNV-1a 32 + xorshift，UTF-8 字节 */
    private String defaultSelfCode() {
        final String ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
        final String input = deviceId() + "|localsend-backup|v1";
        int hash = 0x811c9dc5;
        for (byte b : input.getBytes(StandardCharsets.UTF_8)) {
            hash ^= (b & 0xff);
            hash = hash * 0x01000193; // int 溢出即 32 位乘法，与 Math.imul 一致
        }
        int seed = hash;
        StringBuilder code = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            seed ^= seed << 13;
            seed ^= seed >>> 17;
            seed ^= seed << 5;
            code.append(ALPHABET.charAt(Integer.remainderUnsigned(seed, ALPHABET.length())));
        }
        return code.toString();
    }

    /** 刷新本机连接码：生成随机码并持久化，旧码立即失效（对方需重新配对） */
    @PluginMethod
    public void refreshCode(PluginCall call) {
        String code = randomCode();
        prefPut("self_code", code);
        Log.i(TAG, "refreshCode: 本机连接码已刷新");
        call.resolve(new JSObject().put("code", code));
    }

    /** 随机 8 位连接码（LCG 伪随机，字符集与默认算法一致） */
    private String randomCode() {
        final String ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
        long seed = System.nanoTime() ^ (System.currentTimeMillis() * 2654435761L);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            seed = seed * 6364136223846793005L + 1442695040888963407L;
            sb.append(ALPHABET.charAt((int) ((seed >>> 33) % ALPHABET.length())));
        }
        return sb.toString();
    }

    /** 本机被验证方记录的对端信任列表（双端配对同步） */
    @PluginMethod
    public void getPairedPeers(PluginCall call) {
        JSONArray arr = new JSONArray();
        synchronized (pairedPeers) {
            for (Map.Entry<String, JSONObject> e : pairedPeers.entrySet()) {
                try {
                    JSONObject p = e.getValue();
                    JSONObject out = new JSONObject();
                    out.put("deviceId", e.getKey());
                    out.put("name", p.optString("name"));
                    out.put("ip", p.optString("ip"));
                    out.put("port", p.optInt("port", 53317));
                    out.put("fingerprint", p.optString("fingerprint"));
                    out.put("at", p.optLong("at", 0));
                    arr.put(out);
                } catch (Exception ignored) {
                }
            }
        }
        call.resolve(new JSObject().put("peers", arr));
    }

    /**
     * 本端主动确认配对：把配对记录写入原生 pairedPeers。
     * 关键：本端作为"验证方"配对成功时，对端问候本机查的就是这个 map；
     * 不写入会导致对端问候本机时返回"未信任"，被误判为解除配对。
     * 前端在配对成功/启动/合并后批量调用，进程重启后自动回填（自愈）。
     */
    @PluginMethod
    public void confirmPaired(PluginCall call) {
        String deviceId = call.getString("deviceId", "");
        if (deviceId.isEmpty() || deviceId.equals(deviceId())) {
            call.resolve();
            return;
        }
        try {
            JSONObject peer = new JSONObject();
            peer.put("name", call.getString("name", "未知设备"));
            peer.put("ip", call.getString("ip", ""));
            peer.put("port", call.getInt("port", 53317));
            peer.put("fingerprint", call.getString("fingerprint", ""));
            peer.put("at", System.currentTimeMillis());
            synchronized (pairedPeers) {
                pairedPeers.put(deviceId, peer);
            }
            persistPairedPeers();
            Log.i(TAG, "本端确认配对: deviceId=" + mask(deviceId) + " name=" + peer.optString("name"));
        } catch (Exception ignored) {
        }
        call.resolve();
    }

    /**
     * 全量同步配对记录到原生 pairedPeers（清空后重建）。
     * 只增不删会导致已解除配对的残留记录继续被信任，造成状态横跳。
     */
    @PluginMethod
    public void setPairedPeers(PluginCall call) {
        JSONArray arr = call.getArray("peers");
        synchronized (pairedPeers) {
            pairedPeers.clear();
            if (arr != null) {
                for (int i = 0; i < arr.length(); i++) {
                    try {
                        JSONObject p = arr.getJSONObject(i);
                        String deviceId = p.optString("deviceId", "");
                        if (deviceId.isEmpty() || deviceId.equals(deviceId())) continue;
                        JSONObject peer = new JSONObject();
                        peer.put("name", p.optString("name", "未知设备"));
                        peer.put("ip", p.optString("ip", ""));
                        peer.put("port", p.optInt("port", 53317));
                        peer.put("fingerprint", p.optString("fingerprint", ""));
                        peer.put("at", System.currentTimeMillis());
                        pairedPeers.put(deviceId, peer);
                    } catch (Exception ignored) {
                    }
                }
            }
        }
        persistPairedPeers();
        call.resolve();
    }

    /** 通知对方解除配对（POST /unpair，目标端口+1） */
    @PluginMethod
    public void sendUnpair(PluginCall call) {
        final String ip = call.getString("ip");
        final int port = call.getInt("port", 53317);
        final String deviceId = call.getString("deviceId", "");
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                JSONObject payload = new JSONObject();
                payload.put("deviceId", deviceId);
                byte[] body = payload.toString().getBytes(StandardCharsets.UTF_8);
                URL url = new URL("http://" + ip + ":" + (port + 1) + "/api/localsend/v2/unpair");
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(3000);
                conn.setReadTimeout(3000);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Content-Length", String.valueOf(body.length));
                conn.getOutputStream().write(body);
                int resp = conn.getResponseCode();
                call.resolve(new JSObject().put("ok", resp == 200));
            } catch (Exception e) {
                call.reject("解除配对通知失败: " + e.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }
        }).start();
    }

    /** 通知对方断开连接（POST /api/backup/v1/disconnect，目标端口+1；仅清除已连接状态） */
    @PluginMethod
    public void sendDisconnect(PluginCall call) {
        final String ip = call.getString("ip");
        final int port = call.getInt("port", 53317);
        final String deviceId = call.getString("deviceId", "");
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                JSONObject payload = new JSONObject();
                payload.put("deviceId", deviceId);
                byte[] body = payload.toString().getBytes(StandardCharsets.UTF_8);
                URL url = new URL("http://" + ip + ":" + (port + 1) + "/api/backup/v1/disconnect");
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(3000);
                conn.setReadTimeout(3000);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Content-Length", String.valueOf(body.length));
                conn.getOutputStream().write(body);
                int resp = conn.getResponseCode();
                call.resolve(new JSObject().put("ok", resp == 200));
            } catch (Exception e) {
                call.reject("断开连接通知失败: " + e.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }
        }).start();
    }

    /** 镜像模式：通知目标设备把多余文件移动到其 <接收目录>/delete/ 下（假删除） */
    @PluginMethod
    public void moveToDelete(PluginCall call) {
        final String ip = call.getString("ip");
        final int port = call.getInt("port", 53317);
        final JSONArray files = call.getArray("files");
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                JSONObject payload = new JSONObject();
                payload.put("files", files);
                byte[] body = payload.toString().getBytes(StandardCharsets.UTF_8);
                URL url = new URL("http://" + ip + ":" + (port + 1) + "/api/backup/v1/move-to-delete");
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Content-Length", String.valueOf(body.length));
                conn.getOutputStream().write(body);
                int resp = conn.getResponseCode();
                call.resolve(new JSObject().put("ok", resp == 200));
            } catch (Exception e) {
                call.reject("移动多余文件失败: " + e.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }
        }).start();
    }

    /** 断点续传：查询目标设备大文件已收分片索引（GET 配对服务 chunk-status） */
    @PluginMethod
    public void getChunkStatus(PluginCall call) {
        final String ip = call.getString("ip");
        final int port = call.getInt("port", 53317);
        final String encodedPath = call.getString("encodedPath", "");
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                URL url = new URL("http://" + ip + ":" + (port + 1) + "/api/backup/v1/chunk-status?encodedPath="
                        + java.net.URLEncoder.encode(encodedPath, "UTF-8"));
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                int resp = conn.getResponseCode();
                if (resp == 200) {
                    try (java.io.InputStream in = conn.getInputStream()) {
                        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
                        byte[] buf = new byte[4096];
                        int n;
                        while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
                        JSONObject o = new JSONObject(bos.toString("UTF-8"));
                        JSONArray chunks = o.optJSONArray("receivedChunks");
                        call.resolve(new JSObject().put("receivedChunks", chunks != null ? chunks : new JSONArray()));
                    }
                } else {
                    call.resolve(new JSObject().put("receivedChunks", new JSONArray()));
                }
            } catch (Exception e) {
                call.resolve(new JSObject().put("receivedChunks", new JSONArray()));
            } finally {
                if (conn != null) conn.disconnect();
            }
        }).start();
    }

    // ---------------------------------------------------------------- 常驻配对服务（53318）

    /**
     * 插件加载时启动常驻配对服务（端口 = 接收端口+1，53318）：
     * 处理 /info /verify /unpair /sync-dir，与桌面端配对服务对称。
     * 关键：配对/问候/解除不依赖接收服务是否运行，两端任何时刻都能互相验证，
     * 保证在线状态检测（连接问候）与配对始终可用。
     */
    @Override
    public void load() {
        super.load();
        loadPairedPeers();
        // 配对服务常驻：已配对设备穿透隐藏连接（白名单校验），未配对设备无法连接；
        // 隐藏时接收服务器关闭，子网扫描探测不到本机（/register 无响应）
        startPairingServer();
    }

    private void startPairingServer() {
        // P1 修复：改用 compareAndSet 消除检查-执行竞态（两个线程同时调用时只有一个能成功设置）
        if (!pairingRunning.compareAndSet(false, true)) return; // 已在运行（重启接收服务时）
        try {
            pairingServerSocket = new ServerSocket(MULTICAST_PORT + 1);
            pairingExecutor = Executors.newSingleThreadExecutor();
            pairingClientPool = Executors.newCachedThreadPool();
            pairingExecutor.submit(this::pairingAcceptLoop);
            Log.i(TAG, "配对服务已启动: 端口 " + (MULTICAST_PORT + 1));
        } catch (IOException e) {
            Log.w(TAG, "配对服务端口 " + (MULTICAST_PORT + 1) + " 绑定失败（可能已被占用）", e);
        }
    }

    /** 停止配对服务（隐藏模式）：关闭监听 → accept 循环退出 */
    private void stopPairingServer() {
        pairingRunning.set(false);
        if (pairingServerSocket != null) {
            try {
                pairingServerSocket.close();
            } catch (IOException ignored) {
            }
            pairingServerSocket = null;
        }
        if (pairingExecutor != null) {
            pairingExecutor.shutdownNow();
            pairingExecutor = null;
        }
        if (pairingClientPool != null) {
            pairingClientPool.shutdownNow();
            pairingClientPool = null;
        }
        Log.i(TAG, "配对服务已停止（隐藏模式）");
    }

    private void pairingAcceptLoop() {
        while (pairingRunning.get()) {
            try {
                Socket client = pairingServerSocket.accept();
                // 每连接独立线程：配对确认弹窗最长阻塞 45s，不能卡住 /info /manifest /chunk-status
                if (pairingClientPool != null) {
                    pairingClientPool.submit(() -> handlePairingClient(client));
                } else {
                    handlePairingClient(client);
                }
            } catch (IOException e) {
                if (!pairingRunning.get()) break;
            }
        }
        Log.i(TAG, "常驻配对服务已停止");
    }

    /** 处理单条配对服务连接（仅配对相关路由） */
    private void handlePairingClient(Socket client) {
        try (Socket ignored = client) {
            client.setSoTimeout(15000);
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();

            String requestLine = readLine(in);
            if (requestLine == null) return;
            String[] parts = requestLine.split(" ");
            if (parts.length < 2) return;
            String path = parts[1];
            int q = path.indexOf('?');
            if (q >= 0) path = path.substring(0, q);

            int contentLength = 0;
            String line;
            while ((line = readLine(in)) != null && !line.isEmpty()) {
                String lower = line.toLowerCase(Locale.ROOT);
                if (lower.startsWith("content-length:")) {
                    try {
                        contentLength = Integer.parseInt(line.substring(line.indexOf(':') + 1).trim());
                    } catch (NumberFormatException nfe) {
                        Log.w(TAG, "handlePairingClient: 非法 Content-Length，按 0 处理");
                    }
                }
            }
            String clientIp = client.getInetAddress() == null
                    ? "" : client.getInetAddress().getHostAddress();

            switch (path) {
                case "/api/localsend/v2/info":
                    respondJson(out, 200, deviceInfo());
                    break;
                case "/api/localsend/v2/verify": {
                    String body = readBody(in, contentLength);
                    respondJson(out, 200, verifyCode(body, clientIp));
                    break;
                }
                case "/api/localsend/v2/unpair": {
                    String body = readBody(in, contentLength);
                    handleUnpair(body);
                    respondJson(out, 200, "{\"ok\":true}");
                    break;
                }
                case "/api/backup/v1/disconnect": {
                    String body = readBody(in, contentLength);
                    handleDisconnect(body);
                    respondJson(out, 200, "{\"ok\":true}");
                    break;
                }
                case "/api/backup/v1/move-to-delete": {
                    // 镜像模式：把对端多余文件移动到 <接收目录>/delete/ 下（假删除，保持目录一致）
                    String body = readBody(in, contentLength);
                    int moved = moveToDelete(body);
                    respondJson(out, 200, "{\"ok\":true,\"moved\":" + moved + "}");
                    break;
                }
                case "/api/localsend/v2/sync-dir": {
                    String body = readBody(in, contentLength);
                    handleSyncDir(body);
                    respondJson(out, 200, "{\"ok\":true}");
                    break;
                }
                case "/api/localsend/v2/file-receipt": {
                    // 接收方回执：本机发送的文件已在对方成功写入
                    String body = readBody(in, contentLength);
                    try {
                        JSONObject o = new JSONObject(body);
                        String fileName = o.optString("fileName", "");
                        if (!fileName.isEmpty()) {
                            Log.i(TAG, "收到文件回执: " + fileName);
                            try {
                                notifyListeners("file-receipt", new JSObject().put("fileName", fileName));
                            } catch (Exception ignored2) {
                            }
                        }
                    } catch (Exception ignored2) {
                    }
                    respondJson(out, 200, "{\"ok\":true}");
                    break;
                }
                case "/api/backup/v1/manifest": {
                    // B 端清单：当前接收目录的文件快照（三路对比增量备份的第三路）
                    respondJson(out, 200, buildManifestJson());
                    break;
                }
                case "/api/backup/v1/chunk-status": {
                    // 断点续传查询：返回大文件已收分片索引（encodedPath 参数为 pct 编码的正式相对路径）
                    JSONObject res = new JSONObject();
                    JSONArray chunks = new JSONArray();
                    String file = "";
                    String raw = parts.length > 1 ? parts[1] : "";
                    int qi = raw.indexOf('?');
                    if (qi >= 0) {
                        for (String kv : raw.substring(qi + 1).split("&")) {
                            if (kv.startsWith("encodedPath=")) file = kv.substring(12);
                        }
                    }
                    if (!file.isEmpty()) {
                        DocumentFile root = DocumentFile.fromTreeUri(getContext(), Uri.parse(rootUri));
                        DocumentFile chunkRoot = root.findFile(".chunks");
                        if (chunkRoot != null && chunkRoot.isDirectory()) {
                            DocumentFile fileDir = chunkRoot.findFile(file);
                            if (fileDir != null && fileDir.isDirectory()) {
                                for (DocumentFile pf : fileDir.listFiles()) {
                                    try {
                                        Integer.parseInt(pf.getName());
                                        chunks.put(pf.getName());
                                    } catch (NumberFormatException nfe) {
                                    }
                                }
                            }
                        }
                    }
                    res.put("receivedChunks", chunks);
                    res.put("nextChunk", chunks.length());
                    res.put("fileComplete", false);
                    respondJson(out, 200, res.toString());
                    break;
                }
                default:
                    Log.w(TAG, "配对服务: 未知路径 404 " + path);
                    respondJson(out, 404, "{\"error\":\"not found\"}");
            }
        } catch (Exception e) {
            Log.w(TAG, "handlePairingClient: 处理异常", e);
        }
    }

    /** 通知目标设备本机选择的备份目录名（POST /sync-dir，目标端口+1） */
    @PluginMethod
    public void sendSyncDir(PluginCall call) {
        final String ip = call.getString("ip");
        final int port = call.getInt("port", 53317);
        final String direction = call.getString("direction", "");
        final String name = call.getString("name", "");
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                JSONObject payload = new JSONObject();
                payload.put("direction", direction);
                payload.put("name", name);
                byte[] body = payload.toString().getBytes(StandardCharsets.UTF_8);
                URL url = new URL("http://" + ip + ":" + (port + 1) + "/api/localsend/v2/sync-dir");
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(3000);
                conn.setReadTimeout(3000);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Content-Length", String.valueOf(body.length));
                conn.getOutputStream().write(body);
                int resp = conn.getResponseCode();
                call.resolve(new JSObject().put("ok", resp == 200));
            } catch (Exception e) {
                call.reject("同步目录失败: " + e.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }
        }).start();
    }

    /** 读取对方通过 /sync-dir 同步过来的目录名 */
    @PluginMethod
    public void getSyncedDir(PluginCall call) {
        String direction = call.getString("direction", "");
        JSObject res = new JSObject();
        synchronized (syncedDirs) {
            String name = syncedDirs.get(direction);
            if (name != null) {
                res.put("name", name);
                res.put("at", System.currentTimeMillis());
            } else {
                res.put("name", JSONObject.NULL);
                res.put("at", JSONObject.NULL);
            }
        }
        call.resolve(res);
    }

    /** 当前接收目录的清单快照（B 端清单：三路对比增量备份的第三路） */
    private String buildManifestJson() {
        try {
            JSONObject out = new JSONObject();
            out.put("generatedAt", System.currentTimeMillis() / 1000);
            out.put("deviceCode", deviceId());
            out.put("version", 1);
            JSONObject files = new JSONObject();
            if (rootUri != null && !rootUri.isEmpty()) {
                DocumentFile dir = DocumentFile.fromTreeUri(getContext(), Uri.parse(rootUri));
                if (dir != null && dir.isDirectory()) {
                    collectManifestFiles(dir, "", files);
                }
            }
            out.put("files", files);
            return out.toString();
        } catch (Exception e) {
            Log.e(TAG, "buildManifestJson 失败", e);
            return "{\"generatedAt\":0,\"deviceCode\":\"\",\"files\":{},\"version\":1}";
        }
    }

    /** 递归收集目录清单：{relPath: {size, mtime}}（mtime 单位毫秒，与 shared-core 一致） */
    private void collectManifestFiles(DocumentFile dir, String prefix, JSONObject files) {
        for (DocumentFile f : dir.listFiles()) {
            if (f.getName() == null) continue;
            // 跳过内部文件/目录（分片、解密临时、聚合批次），避免污染三路对比
            String n = f.getName();
            if (n.equals(".chunks") || n.startsWith("__batch__") || n.startsWith("__chunked__") || n.endsWith(".dec_tmp")) continue;
            String rel = prefix.isEmpty() ? n : prefix + "/" + n;
            if (f.isDirectory()) {
                collectManifestFiles(f, rel, files);
            } else if (f.isFile()) {
                try {
                    JSONObject info = new JSONObject();
                    info.put("size", f.length());
                    info.put("mtime", f.lastModified());
                    files.put(rel, info);
                } catch (Exception ignored) {
                }
            }
        }
    }

    // ---------------------------------------------------------------- 组播广播（设备发现）

    /**
     * 启动周期组播广播：接收服务运行期间，每 2 秒向 LocalSend v2 组播组
     * （224.0.0.167:53317）广播本机信息。电脑端（localsend multicast 监听）
     * 被动收到广播后即可在「扫描局域网设备」中列出本机。
     *
     * 报文格式与 localsend core `MulticastMessageV2` 一致（camelCase）。
     */
    private void startMulticastAnnouncer(int serverPort, String code) {
        if (code == null || code.isEmpty()) {
            Log.w(TAG, "multicastAnnouncer: 无本机连接码，跳过广播（电脑端将无法发现本机）");
            return;
        }
        announcerRunning = true;
        announcerExecutor = Executors.newSingleThreadExecutor();
        final byte[] payload = buildAnnounceJson(serverPort, code).getBytes(StandardCharsets.UTF_8);
        announcerExecutor.submit(() -> {
            Log.i(TAG, "multicastAnnouncer: 开始广播 port=" + serverPort + " 间隔=" + ANNOUNCE_INTERVAL_MS + "ms");
            while (announcerRunning) {
                try {
                    List<NetworkInterface> ifaces = multicastInterfaces();
                    for (NetworkInterface ni : ifaces) {
                        for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                            InetAddress addr = ia.getAddress();
                            if (!(addr instanceof Inet4Address)) {
                                continue;
                            }
                            try (MulticastSocket socket = new MulticastSocket()) {
                                socket.setReuseAddress(true);
                                socket.setNetworkInterface(ni);
                                DatagramPacket packet = new DatagramPacket(
                                        payload, payload.length,
                                        InetAddress.getByName(MULTICAST_GROUP), MULTICAST_PORT);
                                socket.send(packet);
                                Log.d(TAG, "multicastAnnouncer: 已广播 -> " + ni.getName() + " " + addr.getHostAddress());
                            } catch (Exception e) {
                                Log.w(TAG, "multicastAnnouncer: 接口发送失败 " + ni.getName(), e);
                            }
                        }
                    }
                    Thread.sleep(ANNOUNCE_INTERVAL_MS);
                } catch (InterruptedException ie) {
                    break;
                } catch (Exception e) {
                    Log.e(TAG, "multicastAnnouncer: 异常", e);
                    try {
                        Thread.sleep(ANNOUNCE_INTERVAL_MS);
                    } catch (InterruptedException ignored) {
                        break;
                    }
                }
            }
            Log.i(TAG, "multicastAnnouncer: 已停止");
        });
    }

    /** 停止组播广播 */
    private void stopMulticastAnnouncer() {
        announcerRunning = false;
        if (announcerExecutor != null) {
            announcerExecutor.shutdownNow();
            announcerExecutor = null;
        }
    }

    /** 可用的组播网络接口（启用、支持组播、非回环） */
    private List<NetworkInterface> multicastInterfaces() throws SocketException {
        List<NetworkInterface> result = new ArrayList<>();
        Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
        while (ifaces.hasMoreElements()) {
            NetworkInterface ni = ifaces.nextElement();
            if (ni.isUp() && ni.supportsMulticast() && !ni.isLoopback()) {
                result.add(ni);
            }
        }
        return result;
    }

    /** 构造 LocalSend v2 MulticastMessageV2 广播报文（camelCase）。
     *  alias=设备名、fingerprint=公开 deviceId —— 连接码不参与广播。 */
    private String buildAnnounceJson(int serverPort, String code) {
        try {
            JSONObject msg = new JSONObject();
            msg.put("alias", deviceName());
            msg.put("version", "2.2");
            msg.put("deviceModel", android.os.Build.MODEL);
            msg.put("deviceType", "mobile");
            msg.put("fingerprint", deviceId());
            msg.put("port", serverPort);
            msg.put("protocol", "http");
            msg.put("download", false);
            return msg.toString();
        } catch (Exception e) {
            Log.e(TAG, "buildAnnounceJson: 构造失败", e);
            return "{}";
        }
    }

    // ---------------------------------------------------------------- 主动扫描局域网（发现电脑）

    /**
     * 启动扫描：①加入组播组监听电脑的 announce 广播；②对每个网段做 /24 子网
     * HTTP register 探测（网段不支持组播时兜底）。结果按 fingerprint 去重，
     * 前端通过 {@link #getScanResults()} 轮询获取。
     */
    @PluginMethod
    public void startScan(PluginCall call) {
        // 防止重复调用泄漏旧线程池：已在扫描时显式清理再重启
        if (scanning) {
            // 清理旧的扫描资源和线程池（但不重置 scanning 标志，因为 stopScan 会把它关掉）
            stopMulticastAnnouncer();
            scanning = false;
            if (scanMulticastSocket != null) {
                scanMulticastSocket.close();
                scanMulticastSocket = null;
            }
            if (scanExecutor != null) {
                scanExecutor.shutdownNow();
                scanExecutor = null;
            }
            if (multicastLock != null && multicastLock.isHeld()) {
                multicastLock.release();
            }
            multicastLock = null;
            releaseCoreGuard();
            Log.i(TAG, "startScan: 检测到重复调用，已清理旧扫描资源");
            // fall-through 继续初始化新扫描
        }
        final int port = call.getInt("port", MULTICAST_PORT);
        final String code = call.getString("selfCode", "");
        // announce=true 配对模式（广播自己）；false 仅监听/探测（启动自动连接用，不暴露自己）
        final boolean announce = call.getBoolean("announce", false);
        scanning = true;
        scanResults.clear();
        scanExecutor = Executors.newFixedThreadPool(50);
        scanExecutor.submit(() -> listenMulticast(code));
        scanExecutor.submit(() -> subnetScan(port, code));
        if (announce) {
            startMulticastAnnouncer(port, code);
        }
        Log.i(TAG, "startScan: 开始扫描局域网 port=" + port + " announce=" + announce);
        call.resolve();
    }

    /** 停止扫描 */
    @PluginMethod
    public void stopScan(PluginCall call) {
        stopMulticastAnnouncer();
        scanning = false;
        if (scanMulticastSocket != null) {
            scanMulticastSocket.close();
            scanMulticastSocket = null;
        }
        if (scanExecutor != null) {
            scanExecutor.shutdownNow();
            scanExecutor = null;
        }
        if (multicastLock != null && multicastLock.isHeld()) {
            multicastLock.release();
        }
        multicastLock = null;
        releaseCoreGuard();
        Log.i(TAG, "stopScan: 已停止扫描");
        call.resolve();
    }

    /** 获取扫描结果：[{alias, fingerprint, ip, port}]（8 秒未再发现的设备自动剪枝） */
    @PluginMethod
    public void getScanResults(PluginCall call) {
        JSONArray arr = new JSONArray();
        long now = System.currentTimeMillis();
        synchronized (scanResults) {
            // 剪枝：停止广播/下线的设备在下一轮轮询中自动消失，发现表实时可用
            scanResults.removeIf(d -> now - d.lastSeen > 8000);
            for (ScannedDevice d : scanResults) {
                try {
                    arr.put(new JSONObject()
                            .put("alias", d.alias)
                            .put("fingerprint", d.fingerprint)
                            .put("ip", d.ip)
                            .put("port", d.port));
                } catch (Exception ignored) {
                }
            }
        }
        call.resolve(new JSObject().put("devices", arr));
    }

    /** 释放 Rust 侧组播锁守卫句柄（幂等）。仅释放 Rust 句柄；真实锁由 Android 进程退出时回收 */
    private void releaseCoreGuard() {
        if (coreGuardHandle != 0) {
            if (LanBackupCore.isAvailable()) {
                LanBackupCore.releaseMulticastGuard(coreGuardHandle);
            }
            coreGuardHandle = 0;
        }
    }

    /** 组播监听线程：加入 224.0.0.167:53317，收到 announce 后解析上报 */
    private void listenMulticast(String code) {
        WifiManager wm = (WifiManager) getContext().getApplicationContext()
                .getSystemService(Context.WIFI_SERVICE);
        if (wm != null) {
            // M22：核心 .so 已打包时，把 WifiManager 交给 Rust 侧守卫（进程级单例，
            // 供核心 PresenceSocket 绑定时持锁）；本线程自己的组播套接字仍走内置锁——
            // 核心当前不在应用内运行，守卫不会主动 acquire，Java 锁才是收包路径的实际持锁者
            if (LanBackupCore.isAvailable() && coreGuardHandle == 0) {
                coreGuardHandle = LanBackupCore.createMulticastGuard(wm, "lanbackup-scan");
            }
            multicastLock = wm.createMulticastLock("lanbackup-scan");
            multicastLock.setReferenceCounted(false);
            multicastLock.acquire();
        }
        try (MulticastSocket ms = new MulticastSocket()) {
            ms.setReuseAddress(true);
            ms.bind(new InetSocketAddress(MULTICAST_PORT));
            ms.setTimeToLive(1);
            ms.setSoTimeout(1500);
            ms.joinGroup(InetAddress.getByName(MULTICAST_GROUP));
            scanMulticastSocket = ms;
            Log.i(TAG, "listenMulticast: 已加入组播组 " + MULTICAST_GROUP + ":" + MULTICAST_PORT);
            byte[] buf = new byte[2048];
            while (scanning) {
                DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                try {
                    ms.receive(pkt);
                } catch (SocketTimeoutException ste) {
                    continue; // 定时醒来检查 scanning 标志
                } catch (IOException e) {
                    if (scanning) continue;
                    break;
                }
                String json = new String(pkt.getData(), pkt.getOffset(), pkt.getLength(),
                        StandardCharsets.UTF_8);
                addScannedFromAnnounce(json, pkt.getAddress().getHostAddress(), code);
            }
        } catch (Exception e) {
            Log.e(TAG, "listenMulticast: 组播监听结束", e);
        } finally {
            if (multicastLock != null && multicastLock.isHeld()) {
                multicastLock.release();
            }
            multicastLock = null;
            releaseCoreGuard();
        }
        Log.i(TAG, "listenMulticast: 退出");
    }

    /** 解析组播 announce 报文（MulticastMessageV2）并入结果列表（按 fingerprint 去重） */
    private void addScannedFromAnnounce(String json, String ip, String selfCode) {
        try {
            JSONObject o = new JSONObject(json);
            String fp = o.optString("fingerprint", "");
            if (fp.isEmpty() || fp.equals(selfCode)) {
                return;
            }
            String alias = o.optString("alias", ip);
            int devPort = o.optInt("port", MULTICAST_PORT);
            synchronized (scanResults) {
                for (ScannedDevice d : scanResults) {
                    if (d.fingerprint.equals(fp)) return;
                }
                scanResults.add(new ScannedDevice(alias, fp, ip, devPort, System.currentTimeMillis()));
            }
            Log.i(TAG, "扫描到设备(组播) alias=" + alias + " ip=" + ip + " port=" + devPort);
        } catch (Exception ignored) {
        }
    }

    /** 对每个 IPv4 网段做 /24 子网探测：逐主机 POST /api/localsend/v2/register */
    private void subnetScan(int port, String selfCode) {
        int myPort = serverSocket != null ? serverSocket.getLocalPort() : MULTICAST_PORT;
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces.hasMoreElements() && scanning) {
                NetworkInterface ni = ifaces.nextElement();
                if (!ni.isUp() || ni.isLoopback()) continue;
                for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                    InetAddress addr = ia.getAddress();
                    if (!(addr instanceof Inet4Address)) continue;
                    byte[] base = addr.getAddress();
                    int myLast = base[3] & 0xff;
                    Log.i(TAG, "subnetScan: 探测网段 " + addr.getHostAddress() + "/24");
                    for (int h = 1; h <= 254; h++) {
                        if (!scanning) break;
                        if (h == myLast) continue;
                        byte[] ipb = base.clone();
                        ipb[3] = (byte) h;
                        final String ip = InetAddress.getByAddress(ipb).getHostAddress();
                        final int fPort = port;
                        scanExecutor.submit(() -> probeRegister(ip, fPort, selfCode, myPort));
                        // 双端口兜底：探测 配对服务（端口+1）的 /info ——
                        // 对方接收服务器未启动时也能被发现（配对/在线状态用）
                        scanExecutor.submit(() -> probeInfo(ip, fPort + 1, selfCode));
                    }
                }
            }
            Log.i(TAG, "subnetScan: 探测完成");
        } catch (Exception e) {
            Log.e(TAG, "subnetScan: 异常", e);
        }
    }

    /** 对单个主机发 register 请求；200 且 fingerprint 非本机则入列表 */
    private void probeRegister(String ip, int port, String selfCode, int myPort) {
        HttpURLConnection conn = null;
        try {
            // register 报文与 announce 同构（alias/fingerprint/port/protocol 等字段一致）
            byte[] body = buildAnnounceJson(myPort, selfCode).getBytes(StandardCharsets.UTF_8);
            URL url = new URL("http://" + ip + ":" + port + "/api/localsend/v2/register");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(400);
            conn.setReadTimeout(400);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Content-Length", String.valueOf(body.length));
            conn.getOutputStream().write(body);
            int resp = conn.getResponseCode();
            if (resp == 200) {
                // P2 修复：流式 JSON 解析替代 readAllBytes（响应 <1KB，但保持一致性）
                android.util.JsonReader jr = new android.util.JsonReader(
                        new java.io.InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
                String fp = null, alias = ip;
                int devPort = port;
                jr.beginObject();
                while (jr.hasNext()) {
                    String k = jr.nextName();
                    if ("fingerprint".equals(k)) fp = jr.nextString();
                    else if ("alias".equals(k)) alias = jr.nextString();
                    else if ("port".equals(k)) devPort = jr.nextInt();
                    else jr.skipValue();
                }
                jr.endObject();
                jr.close();
                if (fp != null && !fp.isEmpty() && !fp.equals(selfCode)) {
                    synchronized (scanResults) {
                        for (ScannedDevice d : scanResults) {
                            if (d.fingerprint.equals(fp)) return;
                        }
                        scanResults.add(new ScannedDevice(alias, fp, ip, devPort, System.currentTimeMillis()));
                    }
                    Log.i(TAG, "扫描到设备(子网) alias=" + alias + " ip=" + ip + " port=" + devPort);
                }
            }
        } catch (Exception ignored) {
            // 非目标主机 / 连接超时 / 无服务
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /** 探测对方配对服务（端口+1）的 /info：接收服务器未启动时也能发现对方 */
    private void probeInfo(String ip, int port, String selfCode) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL("http://" + ip + ":" + port + "/api/localsend/v2/info");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(400);
            conn.setReadTimeout(400);
            int resp = conn.getResponseCode();
            if (resp == 200) {
                // P2 修复：流式 JSON 解析替代 readAllBytes（响应 <1KB，但保持一致性）
                android.util.JsonReader jr = new android.util.JsonReader(
                        new java.io.InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
                String fp = null, alias = ip;
                int devPort = 53317;
                jr.beginObject();
                while (jr.hasNext()) {
                    String k = jr.nextName();
                    if ("fingerprint".equals(k)) fp = jr.nextString();
                    else if ("alias".equals(k)) alias = jr.nextString();
                    else if ("port".equals(k)) devPort = jr.nextInt();
                    else jr.skipValue();
                }
                jr.endObject();
                jr.close();
                if (fp != null && !fp.isEmpty() && !fp.equals(selfCode)) {
                    synchronized (scanResults) {
                        for (ScannedDevice d : scanResults) {
                            if (d.fingerprint.equals(fp)) return;
                        }
                        scanResults.add(new ScannedDevice(alias, fp, ip, devPort, System.currentTimeMillis()));
                    }
                    Log.i(TAG, "扫描到设备(配对服务) alias=" + alias + " ip=" + ip + " port=" + devPort);
                }
            }
        } catch (Exception ignored) {
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    // ---------------------------------------------------------------- SAF 目录选择与遍历

    /** pickDirectory 的 requestCode（已在 @CapacitorPlugin requestCodes 中注册） */
    static final int REQ_PICK_DIRECTORY = 7001;

    /**
     * 通过 SAF（ACTION_OPEN_DOCUMENT_TREE）让用户选择备份根目录。
     * 返回持久化 tree URI（content://），App 重启后仍可访问。
     */
    /**
     * 通过 SAF（ACTION_OPEN_DOCUMENT_TREE）让用户选择备份根目录。
     * 返回持久化 tree URI（content://），App 重启后仍可访问。
     *
     * 用 Capacitor 6 推荐的 @ActivityCallback 模式接收结果：
     * ActivityResultLauncher 在插件加载时注册，不依赖旧版 requestCode 路由——
     * 旧版（startActivityForResult(int) + handleOnActivityResult）在本插件上
     * 活动结果会丢失（选择器返回后 JS 永远等不到结果 → 表现为"操作超时/卡死"）。
     */
    @PluginMethod
    public void pickDirectory(PluginCall call) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
                | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(call, intent, "pickDirectoryResult");
    }

    @ActivityCallback
    private void pickDirectoryResult(PluginCall call, ActivityResult result) {
        if (result.getResultCode() != Activity.RESULT_OK || result.getData() == null
                || result.getData().getData() == null) {
            Log.i(TAG, "pickDirectory: 用户未选择目录");
            call.reject("未选择目录");
            return;
        }
        Uri treeUri = result.getData().getData();
        // 持久化授权：重启后 content:// URI 仍可访问（SAF 模式下读写权限来自这里）
        boolean persisted = false;
        try {
            getContext().getContentResolver().takePersistableUriPermission(
                    treeUri, Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            persisted = true;
        } catch (Exception e) {
            Log.w(TAG, "takePersistableUriPermission 失败（重启后需重新授权目录）", e);
        }
        Log.i(TAG, "pickDirectory: 已选择 " + treeUri + " 持久化=" + persisted);
        call.resolve(new JSObject().put("uri", treeUri.toString()).put("persisted", persisted));
    }

    /** 列出目录子项：{name, type: directory|file, size, mtime}。
     *  用 DocumentFile 遍历：内部自行处理子目录 tree URI 的 documentId 编码，
     *  规避部分 ROM 上 children URI 解析失败（Invalid/Unsupported Uri）。 */
    @PluginMethod
    public void readdir(PluginCall call) {
        try {
            String uri = call.getString("uri");
            String relPath = call.getString("relPath", "");
            if (uri == null || uri.isEmpty()) {
                call.reject("缺少 uri");
                return;
            }
            DocumentFile root = DocumentFile.fromTreeUri(getContext(), Uri.parse(uri));
            DocumentFile dir = docResolve(root, relPath);
            if (dir == null || !dir.isDirectory()) {
                call.reject("目录不存在: " + relPath);
                return;
            }
            JSONArray files = new JSONArray();
            for (DocumentFile f : dir.listFiles()) {
                JSONObject item = new JSONObject();
                item.put("name", f.getName() == null ? "" : f.getName());
                item.put("type", f.isDirectory() ? "directory" : "file");
                item.put("size", f.length());
                item.put("mtime", f.lastModified());
                files.put(item);
            }
            call.resolve(new JSObject().put("files", files));
        } catch (Exception e) {
            Log.e(TAG, "readdir 失败", e);
            call.reject("readdir 失败: " + e.getMessage());
        }
    }

    /** 读取文件内容为 base64（与 @capacitor/filesystem readFile 同格式）
     *  安全修复：禁止大文件（>20MB 原文件）读入内存，避免 Base64 编码时 OOM。
     *  硬上限取 20MB 原文件 → ~27MB 编码字符串，在 512MB 堆的 32-bit Android 上安全。 */
    @PluginMethod
    public void readFile(PluginCall call) {
        try {
            String uri = call.getString("uri");
            String relPath = call.getString("relPath", "");
            if (uri == null || uri.isEmpty()) {
                call.reject("缺少 uri");
                return;
            }
            DocumentFile root = DocumentFile.fromTreeUri(getContext(), Uri.parse(uri));
            DocumentFile file = docResolve(root, relPath);
            if (file == null || !file.isFile()) {
                call.reject("文件不存在: " + relPath);
                return;
            }
            long fileSize = file.length();
            // Base64 编码上限：~27MB（20MB 原文件 × 1.37）；超限直接拒绝，防止 OOM
            final long MAX_ORIGINAL_BYTES = 20 * 1024 * 1024;
            if (fileSize > MAX_ORIGINAL_BYTES) {
                Log.w(TAG, "readFile: 文件过大 (" + fileSize + "B)，拒绝读取以防止 OOM");
                call.reject("文件过大，无法读取（最大支持 " + (MAX_ORIGINAL_BYTES / 1024 / 1024) + "MB）");
                return;
            }
            try (InputStream in = getContext().getContentResolver().openInputStream(file.getUri())) {
                if (in == null) {
                    call.reject("无法打开文件");
                    return;
                }
                    // Base64.NO_WRAP → 无折行，编码后长度 = ((n + 2) / 3) * 4
                int estimatedB64 = (int) ((fileSize + 2) / 3 * 4);
                java.io.ByteArrayOutputStream b64out = new java.io.ByteArrayOutputStream(estimatedB64);
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) != -1) {
                    // 分块渐进编码：每次读取后立即 encode，避免全量 readAllBytes
                    byte[] encodedBytes = android.util.Base64.encodeToString(buf, 0, n, android.util.Base64.NO_WRAP).getBytes(StandardCharsets.UTF_8);
                    b64out.write(encodedBytes, 0, encodedBytes.length);
                }
                call.resolve(new JSObject().put("data", b64out.toString(StandardCharsets.UTF_8.name())));
            }
        } catch (Exception e) {
            Log.e(TAG, "readFile 失败", e);
            call.reject("readFile 失败: " + e.getMessage());
        }
    }

    /** 文件状态：{type, size, mtime} */
    @PluginMethod
    public void stat(PluginCall call) {
        try {
            String uri = call.getString("uri");
            String relPath = call.getString("relPath", "");
            if (uri == null || uri.isEmpty()) {
                call.reject("缺少 uri");
                return;
            }
            DocumentFile root = DocumentFile.fromTreeUri(getContext(), Uri.parse(uri));
            DocumentFile file = docResolve(root, relPath);
            if (file == null) {
                call.reject("文件不存在: " + relPath);
                return;
            }
            call.resolve(new JSObject()
                    .put("type", file.isDirectory() ? "directory" : "file")
                    .put("size", file.length())
                    .put("mtime", file.lastModified()));
        } catch (Exception e) {
            Log.e(TAG, "stat 失败", e);
            call.reject("stat 失败: " + e.getMessage());
        }
    }

    /** 从 tree URI 沿相对路径逐级解析文档（DocumentFile，处理子目录编码） */
    private DocumentFile docResolve(DocumentFile root, String relPath) {
        DocumentFile cur = root;
        if (relPath != null && !relPath.isEmpty()) {
            for (String part : relPath.split("/")) {
                if (part.isEmpty()) continue;
                DocumentFile next = cur.findFile(part);
                if (next == null) {
                    return null;
                }
                cur = next;
            }
        }
        return cur;
    }

    /** 在目录下确保子目录存在（不存在则创建），返回子目录 DocumentFile */
    private DocumentFile ensureDirDoc(DocumentFile parent, String dirName) {
        DocumentFile existing = parent.findFile(dirName);
        if (existing != null) {
            return existing;
        }
        return parent.createDirectory(dirName);
    }

    /** 镜像模式：把对端多余文件移动到 <接收目录>/delete/ 下（假删除，保留原相对路径） */
    private int moveToDelete(String body) {
        try {
            JSONObject o = new JSONObject(body);
            JSONArray files = o.optJSONArray("files");
            if (files == null || rootUri == null) return 0;
            DocumentFile root = DocumentFile.fromTreeUri(getContext(), Uri.parse(rootUri));
            if (root == null) return 0;
            DocumentFile deleteDir = root.findFile("delete");
            if (deleteDir == null) deleteDir = root.createDirectory("delete");
            if (deleteDir == null) return 0;
            int moved = 0;
            for (int i = 0; i < files.length(); i++) {
                String rel = files.optString(i, "");
                if (rel.isEmpty() || rel.contains("..")) continue;
                DocumentFile src = docResolve(root, rel);
                if (src == null || !src.exists()) continue;
                // 目标：delete/<relPath>，逐级创建目录
                String[] parts = rel.split("/");
                DocumentFile dstDir = deleteDir;
                for (int p = 0; p < parts.length - 1; p++) {
                    dstDir = ensureDirDoc(dstDir, parts[p]);
                }
                DocumentFile dst = dstDir.findFile(parts[parts.length - 1]);
                if (dst == null) dst = dstDir.createFile(src.getType(), parts[parts.length - 1]);
                if (dst != null && copyDoc(src, dst)) {
                    src.delete();
                    moved++;
                }
            }
            Log.i(TAG, "镜像模式移动多余文件到 delete: " + moved + " 个");
            return moved;
        } catch (Exception e) {
            Log.w(TAG, "moveToDelete 失败", e);
            return 0;
        }
    }

    /** 复制 DocumentFile 内容（SAF 无跨目录 rename，用复制+删除实现假删除） */
    private boolean copyDoc(DocumentFile src, DocumentFile dst) {
        try (InputStream in = getContext().getContentResolver().openInputStream(src.getUri());
             OutputStream out = getContext().getContentResolver().openOutputStream(dst.getUri(), "w")) {
            if (in == null || out == null) return false;
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            return true;
        } catch (Exception e) {
            Log.w(TAG, "copyDoc 失败", e);
            return false;
        }
    }

    // ---------------------------------------------------------------- server

    private void acceptLoop() {
        Log.d(TAG, "acceptLoop: 开始监听连接");
        while (running.get()) {
            try {
                Socket client = serverSocket.accept();
                Log.d(TAG, "acceptLoop: 接受新连接 " + client.getInetAddress());
                // 每连接独立线程：大文件上传不阻塞其他设备的请求（accept 循环只负责 accept）
                if (clientPool != null) {
                    clientPool.submit(() -> handleClient(client));
                } else {
                    handleClient(client);
                }
            } catch (IOException e) {
                if (!running.get()) {
                    break;
                }
                Log.e(TAG, "acceptLoop: 连接处理异常", e);
            }
        }
        Log.i(TAG, "acceptLoop: 停止监听");
    }

    private void handleClient(Socket client) {
        try (Socket ignored = client) {
            client.setSoTimeout(120_000);
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();

            String requestLine = readLine(in);
            if (requestLine == null) {
                return;
            }
            Log.d(TAG, "handleClient: 请求行 " + requestLine);
            String[] parts = requestLine.split(" ");
            if (parts.length < 2) {
                return;
            }
            String pathWithQuery = parts[1];

            // 读取请求头
            int contentLength = 0;
            boolean chunked = false;
            String line;
            while ((line = readLine(in)) != null && !line.isEmpty()) {
                String lower = line.toLowerCase(Locale.ROOT);
                if (lower.startsWith("content-length:")) {
                    try {
                        contentLength = Integer.parseInt(line.substring(line.indexOf(':') + 1).trim());
                    } catch (NumberFormatException nfe) {
                        Log.w(TAG, "handleClient: 非法 Content-Length，按 0 处理");
                    }
                } else if (lower.startsWith("transfer-encoding:")) {
                    // 流式上传（LocalSend crate 客户端用 chunked 发送未知长度 body）
                    chunked = lower.contains("chunked");
                }
            }

            String path = pathWithQuery;
            String query = "";
            int q = pathWithQuery.indexOf('?');
            if (q >= 0) {
                path = pathWithQuery.substring(0, q);
                query = pathWithQuery.substring(q + 1);
            }

            switch (path) {
                case "/api/localsend/v2/info":
                case "/api/localsend/v2/register":
                    respondJson(out, 200, deviceInfo());
                    break;
                case "/api/localsend/v2/verify": {
                    String body = readBody(in, contentLength);
                    String clientIp = client.getInetAddress() == null
                            ? "" : client.getInetAddress().getHostAddress();
                    respondJson(out, 200, verifyCode(body, clientIp));
                    break;
                }
                case "/api/localsend/v2/unpair": {
                    String body = readBody(in, contentLength);
                    handleUnpair(body);
                    respondJson(out, 200, "{\"ok\":true}");
                    break;
                }
                case "/api/localsend/v2/sync-dir": {
                    String body = readBody(in, contentLength);
                    handleSyncDir(body);
                    respondJson(out, 200, "{\"ok\":true}");
                    break;
                }
                case "/api/localsend/v2/prepare-upload": {
                    String body = readBody(in, contentLength);
                    prepareUpload(out, body, client.getInetAddress() == null
                            ? "" : client.getInetAddress().getHostAddress());
                    break;
                }
                case "/api/localsend/v2/upload": {
                    uploadFile(out, parseQuery(query), in, client, contentLength, chunked);
                    break;
                }
                case "/api/localsend/v2/cancel":
                    Log.d(TAG, "handleClient: 取消会话");
                    respondText(out, 200, "OK");
                    break;
                // === scheduler v1 扩展端点 ===
                case "/api/localsend/v2/session/heartbeat": {
                    // 心跳：接收端收到后返回 200，发送端据此判断接收端存活
                    String body = readBody(in, contentLength);
                    handleHeartbeat(body);
                    respondJson(out, 200, "{\"ok\":true}");
                    break;
                }
                case "/api/localsend/v2/session/abort": {
                    // 中止会话：接收端收到后清理会话状态
                    String body = readBody(in, contentLength);
                    handleAbort(body);
                    respondJson(out, 200, "{\"ok\":true}");
                    break;
                }
                default:
                    // scheduler v1 动态路由：/file/{fileId}/diff 和 /file/{fileId}/verify
                    if (path.startsWith("/api/localsend/v2/file/") && path.endsWith("/diff")) {
                        String fileId = path.substring("/api/localsend/v2/file/".length(), path.length() - "/diff".length());
                        handleFileDiff(out, fileId, query, in);
                    } else if (path.startsWith("/api/localsend/v2/file/") && path.endsWith("/verify")) {
                        String fileId = path.substring("/api/localsend/v2/file/".length(), path.length() - "/verify".length());
                        handleFileVerify(out, fileId);
                    } else {
                        Log.w(TAG, "handleClient: 未知路径 404 " + path);
                        respondText(out, 404, "Not Found");
                    }
            }
        } catch (Exception e) {
            // 单连接错误不中断服务器
            Log.e(TAG, "handleClient: 连接处理异常", e);
        }
    }

    private void prepareUpload(OutputStream out, String body, String clientIp) {
        try {
            JSONObject req = new JSONObject(body);
            JSONObject files = req.optJSONObject("files");
            String sessionId = UUID.randomUUID().toString();
            Map<String, SessionFile> fileMap = new HashMap<>();
            long totalBytes = 0;
            if (files != null) {
                java.util.Iterator<String> keys = files.keys();
                while (keys.hasNext()) {
                    String fileId = keys.next();
                    // 文件名来自 prepare-upload 的 files[fileId].fileName（对齐 LocalSend 协议，
                    // upload 阶段客户端不会携带 fileName）；fileType 用于识别批量 tar 聚合等
                    JSONObject meta = files.optJSONObject(fileId);
                    String fileName = meta == null ? "" : meta.optString("fileName", "");
                    String fileType = meta == null ? "" : meta.optString("fileType", "");
                    // scheduler v1 扩展字段
                    String merkleRoot = meta == null ? null : meta.optString("merkleRoot", null);
                    String[] pieceHashes = null;
                    long chunkSize = 0;
                    if (meta != null && meta.has("pieceHashes")) {
                        JSONArray arr = meta.getJSONArray("pieceHashes");
                        pieceHashes = new String[arr.length()];
                        for (int i = 0; i < arr.length(); i++) {
                            pieceHashes[i] = arr.optString(i, "");
                        }
                        chunkSize = meta.optLong("chunkSize", 0);
                    }
                    fileMap.put(fileId, new SessionFile(UUID.randomUUID().toString(), fileName, fileType, merkleRoot, pieceHashes, chunkSize));
                    if (meta != null) totalBytes += meta.optLong("size", 0);
                }
            }
            if (fileMap.isEmpty()) {
                // 与 LocalSend core 服务端一致：无文件直接拒绝
                Log.w(TAG, "prepareUpload: 无文件被提供");
                respondText(out, 400, "No files provided");
                return;
            }
            // 清理孤立会话（prepare-upload 后客户端断开未上传，超 5 分钟自动清除，防内存泄漏）
            long now = System.currentTimeMillis();
            synchronized (sessions) {
                sessions.entrySet().removeIf(e -> {
                    long start = sessionStart.containsKey(e.getKey()) ? sessionStart.get(e.getKey()) : 0L;
                    return start > 0 && now - start > 5 * 60 * 1000;
                });
                sessionBytes.keySet().retainAll(sessions.keySet());
                sessionStart.keySet().retainAll(sessions.keySet());
                sessionCount.keySet().retainAll(sessions.keySet());
                sessionTotalBytes.keySet().retainAll(sessions.keySet());
                sessions.put(sessionId, fileMap);
                sessionBytes.put(sessionId, 0L);
                sessionStart.put(sessionId, System.currentTimeMillis());
                sessionCount.put(sessionId, fileMap.size());
                sessionTotalBytes.put(sessionId, totalBytes);
            }
            Log.d(TAG, "prepareUpload: 新建会话 " + mask(sessionId) + " 文件数=" + fileMap.size() + " 总字节=" + totalBytes);
            // 接收确认：通知前端弹窗（发送者/文件数/总大小），阻塞等待用户同意。
            // 45 秒超时自动接受（备份场景发起端已配对授权，避免长时间挂起）。
            // senderName 来自 prepare-upload 请求的 info.alias（LocalSend 协议发送方必带），缺失回退 IP
            String senderName = "";
            JSONObject info = req.optJSONObject("info");
            if (info != null) senderName = info.optString("alias", "");
            try {
                notifyListeners("incoming-request", new JSObject()
                        .put("sessionId", sessionId)
                        .put("count", fileMap.size())
                        .put("totalBytes", totalBytes)
                        .put("senderIp", clientIp)
                        .put("senderName", senderName));
            } catch (Exception ignored) {
            }
            boolean approved;
            CompletableFuture<Boolean> approval = new CompletableFuture<>();
            synchronized (pendingApprovals) {
                pendingApprovals.put(sessionId, approval);
            }
            try {
                approved = approval.get(45, TimeUnit.SECONDS);
            } catch (Exception e) {
                // 超时：仅已配对来源（IP 匹配）自动接受；非配对来源默认拒绝（防局域网未授权设备试探）
                approved = isTrustedPeer(clientIp);
            } finally {
                synchronized (pendingApprovals) {
                    pendingApprovals.remove(sessionId);
                }
            }
            if (!approved) {
                Log.w(TAG, "prepareUpload: 用户拒绝接收 session=" + mask(sessionId));
                try { respondText(out, 403, "declined by user"); } catch (IOException ignored) {}
                return;
            }
            Log.d(TAG, "prepareUpload: 用户同意接收 session=" + mask(sessionId) + " 文件数=" + fileMap.size());
            JSONObject resp = new JSONObject();
            resp.put("sessionId", sessionId);
            JSONObject filesResp = new JSONObject();
            for (Map.Entry<String, SessionFile> e : fileMap.entrySet()) {
                filesResp.put(e.getKey(), e.getValue().token);
            }
            resp.put("files", filesResp);
            respondJson(out, 200, resp.toString());
        } catch (Exception e) {
            Log.e(TAG, "prepareUpload: 处理失败", e);
            try { respondText(out, 500, "prepare-upload error: " + e.getMessage()); } catch (IOException ignored) {}
        }
    }

    /** 前端接收确认弹窗的响应：接受 / 拒绝接收会话（解除 prepare-upload 阻塞等待） */
    @PluginMethod
    public void resolveIncoming(PluginCall call) {
        String sessionId = call.getString("sessionId", "");
        boolean accept = call.getBoolean("accept", true);
        CompletableFuture<Boolean> f;
        synchronized (pendingApprovals) {
            f = pendingApprovals.remove(sessionId);
        }
        if (f != null) {
            f.complete(accept);
        }
        call.resolve();
    }

    private void uploadFile(OutputStream out, Map<String, String> params, InputStream in, Socket client,
            int contentLength, boolean chunked) {
        try {
            String sessionId = params.get("sessionId");
            String fileId = params.get("fileId");
            String token = params.get("token");
            if (sessionId == null || fileId == null || token == null) {
                Log.w(TAG, "uploadFile: 缺少 query 参数");
                respondText(out, 400, "missing query params");
                return;
            }
            // token 与文件名均从会话按 fileId 查找
            String storedToken;
            String fileName;
            String fileType;
            synchronized (sessions) {
                Map<String, SessionFile> session = sessions.get(sessionId);
                SessionFile file = session == null ? null : session.get(fileId);
                storedToken = file == null ? null : file.token;
                fileName = file == null ? null : file.fileName;
                fileType = file == null ? null : file.fileType;
            }
            if (storedToken == null || !storedToken.equals(token)) {
                Log.w(TAG, "uploadFile: token 校验失败 session=" + mask(sessionId) + " fileId=" + fileId);
                respondText(out, 401, "invalid token");
                return;
            }
            if (fileName == null || fileName.isEmpty()) {
                Log.w(TAG, "uploadFile: 会话中无文件名 fileId=" + fileId);
                respondText(out, 400, "unknown fileId");
                return;
            }

            Log.d(TAG, "uploadFile: 开始接收 " + fileName + " session=" + mask(sessionId));
            // 大文件分片：落盘路径 = __chunked__/{pct}/{index}（total 段仅用于合并判断，不能作为文件名——
            // 否则分片会写成 __chunked__/{pct}/{index}/{total}，目录结构错乱导致合并失败）
            String saveRel = fileName;
            if (fileName != null && fileName.startsWith("__chunked__/")) {
                String[] seg = fileName.split("/");
                if (seg.length == 4) {
                    // 落盘到 .chunks/{pct}/{index}（与合并/断点查询一致；__chunked__ 是传输路径，.chunks 是存储路径）
                    saveRel = ".chunks/" + seg[1] + "/" + seg[2];
                }
            }
            // 流式接收（分块写临时文件 → 流式解密写 SAF），内存 O(1)，支持任意大文件
            long savedSize = saveToSafStream(saveRel, in, contentLength, chunked, sessionId, saveRel);
            if (savedSize >= 0) {
                Log.i(TAG, "uploadFile: 接收完成 " + fileName + " (" + savedSize + "B)");
                // 大文件分片续传：fileName = __chunked__/{pct}/{index}/{total} → 到齐后合并为正式文件
                // v4.4: 使用三层合并架构（私有缓存 → 校验 → SAF 提交）
                if (fileName != null && fileName.startsWith("__chunked__/")) {
                    tryMergeChunkedV4(fileName);
                } else if (fileType != null && fileType.equals("application/x-batch-agg")) {
                    // tiny 批量聚合：识别 x-batch-agg → 解包为独立文件（批次 ≤ 1MB 级，读入内存可接受）
                    unpackTarBatch(fileName);
                }
                respondText(out, 200, "OK");
                // 通知本机前端"正在接收"（带大小）+ 回执给发送方
                try {
                    notifyListeners("file-received", new JSObject()
                            .put("fileName", fileName)
                            .put("bytes", savedSize));
                } catch (Exception ignored2) {
                }
                sendReceipt(client, fileName);
                // 会话累计：全部文件接收完成 → 上报整批完成事件（文件数/字节/耗时，写入接收历史）
                synchronized (sessions) {
                    Map<String, SessionFile> session = sessions.get(sessionId);
                    if (session != null) {
                        session.remove(fileId);
                        long acc = sessionBytes.containsKey(sessionId) ? sessionBytes.get(sessionId) : 0L;
                        sessionBytes.put(sessionId, acc + savedSize);
                        if (session.isEmpty()) {
                            // 注意：不用 Map.getOrDefault（API 24+），minSdk 23 需兼容写法
                            long total = sessionBytes.containsKey(sessionId) ? sessionBytes.get(sessionId) : 0L;
                            long start = sessionStart.containsKey(sessionId) ? sessionStart.get(sessionId) : System.currentTimeMillis();
                            int count = sessionCount.containsKey(sessionId) ? sessionCount.get(sessionId) : 0;
                            sessions.remove(sessionId);
                            sessionBytes.remove(sessionId);
                            sessionStart.remove(sessionId);
                            sessionCount.remove(sessionId);
                            try {
                                notifyListeners("receive-complete", new JSObject()
                                        .put("count", count)
                                        .put("bytes", total)
                                        .put("durationMs", System.currentTimeMillis() - start));
                            } catch (Exception ignored2) {
                            }
                        }
                    }
                }
            } else {
                Log.e(TAG, "uploadFile: 写入失败 " + fileName);
                respondText(out, 500, "write failed");
            }
        } catch (Exception e) {
            Log.e(TAG, "uploadFile: 处理异常", e);
            try { respondText(out, 500, "upload error: " + e.getMessage()); } catch (IOException ignored) {}
        }
    }

    /** 读固定长度字节 */
    private byte[] readBodyBytes(InputStream in, int length) throws IOException {
        byte[] buf = new byte[length];
        int off = 0;
        while (off < length) {
            int n = in.read(buf, off, length - off);
            if (n == -1) throw new IOException("body 截断: 期望 " + length + " 实际 " + off);
            off += n;
        }
        return buf;
    }

    /** 读 chunked transfer encoding body */
    private byte[] readBodyChunked(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        while (true) {
            String line = readLine(in);
            if (line == null) break;
            int size = Integer.parseInt(line.trim(), 16);
            if (size == 0) {
                // 读结尾 trailer（可能有多行，到空行）
                while ((line = readLine(in)) != null && !line.isEmpty()) {}
                break;
            }
            byte[] chunk = readBodyBytes(in, size);
            buf.write(chunk);
            readLine(in); // 吃掉 chunk 后的 \r\n
        }
        return buf.toByteArray();
    }

    /** 向发送方发送文件接收回执（POST 对方配对服务 /file-receipt） */
    private void sendReceipt(Socket client, String fileName) {
        if (client == null || client.getInetAddress() == null) {
            return;
        }
        final String senderIp = client.getInetAddress().getHostAddress();
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                JSONObject payload = new JSONObject();
                payload.put("fileName", fileName);
                byte[] body = payload.toString().getBytes(StandardCharsets.UTF_8);
                URL url = new URL("http://" + senderIp + ":" + (MULTICAST_PORT + 1)
                        + "/api/localsend/v2/file-receipt");
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(2000);
                conn.setReadTimeout(2000);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Content-Length", String.valueOf(body.length));
                conn.getOutputStream().write(body);
                conn.getResponseCode();
            } catch (Exception ignored) {
            } finally {
                if (conn != null) conn.disconnect();
            }
        }).start();
    }

    /**
     * 原生 prepare-upload（手机 → 电脑方向）。
     * 必须走原生 HTTP：WebView fetch/XHR 受 CORS 同源策略限制，
     * 而目标端（localsend crate server）响应无 CORS 头，会被浏览器拦截，
     * 导致手机端"从没同步成功"。原生 HttpURLConnection 无此限制。
     */
    @PluginMethod
    public void prepareUploadTo(PluginCall call) {
        final String targetIp = call.getString("targetIp");
        final int targetPort = call.getInt("targetPort", 53317);
        final String body = call.getString("body", "");
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                byte[] payload = body.getBytes(StandardCharsets.UTF_8);
                URL url = new URL("http://" + targetIp + ":" + targetPort
                        + "/api/localsend/v2/prepare-upload");
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(30000);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Content-Length", String.valueOf(payload.length));
                conn.getOutputStream().write(payload);
                int resp = conn.getResponseCode();
                if (resp == 204) {
                    // 无文件需要传输
                    call.resolve(new JSObject().put("sessionId", "").put("files", new JSONObject()));
                    return;
                }
                byte[] data = readAllBytes(conn.getInputStream());
                JSONObject o = new JSONObject(new String(data, StandardCharsets.UTF_8));
                JSObject res = new JSObject();
                res.put("sessionId", o.optString("sessionId"));
                JSONObject files = o.optJSONObject("files");
                res.put("files", files == null ? new JSONObject() : files);
                call.resolve(res);
            } catch (Exception e) {
                Log.e(TAG, "prepareUploadTo 失败", e);
                call.reject("prepare-upload 失败: " + e.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }
        }).start();
    }

    /** 原生取消会话（手机 → 电脑方向，绕开 CORS） */
    @PluginMethod
    public void cancelSessionTo(PluginCall call) {
        final String targetIp = call.getString("targetIp");
        final int targetPort = call.getInt("targetPort", 53317);
        final String sessionId = call.getString("sessionId");
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                URL url = new URL("http://" + targetIp + ":" + targetPort
                        + "/api/localsend/v2/cancel?sessionId="
                        + java.net.URLEncoder.encode(sessionId, "UTF-8"));
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(10000);
                conn.getResponseCode();
                call.resolve();
            } catch (Exception e) {
                Log.e(TAG, "cancelSessionTo 失败", e);
                call.reject("cancel 失败: " + e.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }
        }).start();
    }

    /** 获取对端接收目录的当前清单（GET 对方配对服务 /api/backup/v1/manifest，三路对比增量备份用） */
    @PluginMethod
    public void getPeerManifest(PluginCall call) {
        final String ip = call.getString("ip");
        final int port = call.getInt("port", 53317);
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                URL url = new URL("http://" + ip + ":" + (port + 1) + "/api/backup/v1/manifest");
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(3000);
                conn.setReadTimeout(5000);
                int resp = conn.getResponseCode();
                if (resp != 200) {
                    call.reject("对端清单获取失败 HTTP " + resp);
                    return;
                }
                String json = new String(readAllBytes(conn.getInputStream()), StandardCharsets.UTF_8);
                call.resolve(new JSObject(json));
            } catch (Exception e) {
                call.reject("获取对端清单失败: " + e.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }
        }).start();
    }

    /** 流式上传（手机 → 电脑方向，替代 WebView 全量读入内存的旧方式）：
     * 分块读 SAF 文件 → AES-256-GCM 流式加密（LSBK||nonce||ct+tag）→ HTTP 流式 POST。
     * 内存占用 O(1)，大文件不再卡顿/OOM；发送字节数 = 明文 + 32，与上报 size 一致。
     */
    @PluginMethod
    public void streamUpload(PluginCall call) {
        final String uri = call.getString("uri");
        final String relPath = call.getString("relPath");
        final String targetIp = call.getString("targetIp");
        final int targetPort = call.getInt("targetPort", 53317);
        final String sessionId = call.getString("sessionId");
        final String fileId = call.getString("fileId");
        final String token = call.getString("token");
        final String targetCode = call.getString("targetCode", "");
        // 分片续传：offset = 起始字节偏移，size = 本片字节数（0 = 到文件尾）
        final long offset = call.getLong("offset", 0L);
        final long size = call.getLong("size", 0L);
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                DocumentFile root = DocumentFile.fromTreeUri(getContext(), Uri.parse(uri));
                DocumentFile fileDoc = docResolve(root, relPath);
                if (fileDoc == null) {
                    call.reject("文件不存在: " + relPath);
                    return;
                }
                long total = fileDoc.length();
                long readLen = size > 0 ? Math.min(size, Math.max(0, total - offset)) : Math.max(0, total - offset);
                boolean encrypted = targetCode != null && !targetCode.isEmpty();
                final long BLOCK = 8 * 1024 * 1024; // 8MB 分块（与 Rust encrypt_stream 一致）
                // 多块 GCM 格式开销：LSBK(4)+ver(4)+blockSize(4) 头 + 每块(nonce12+ctLen4+tag16)
                long streamLen = readLen;
                if (encrypted) {
                    long blocks = (readLen + BLOCK - 1) / BLOCK;
                    streamLen = readLen + 12 + 32 * blocks;
                }
                String url = "http://" + targetIp + ":" + targetPort + "/api/localsend/v2/upload"
                        + "?sessionId=" + java.net.URLEncoder.encode(sessionId, "UTF-8")
                        + "&fileId=" + java.net.URLEncoder.encode(fileId, "UTF-8")
                        + "&token=" + java.net.URLEncoder.encode(token, "UTF-8");
                conn = (HttpURLConnection) new URL(url).openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/octet-stream");
                conn.setDoOutput(true);
                conn.setConnectTimeout(30000);
                conn.setReadTimeout(120000);
                if (android.os.Build.VERSION.SDK_INT >= 26) {
                    conn.setFixedLengthStreamingMode(streamLen);
                } else {
                    conn.setFixedLengthStreamingMode((int) Math.min(streamLen, Integer.MAX_VALUE));
                }

                try (InputStream in = getContext().getContentResolver().openInputStream(fileDoc.getUri());
                     OutputStream rawOut = conn.getOutputStream()) {
                    byte[] buf = new byte[encrypted ? (int) BLOCK : 128 * 1024];
                    int n;
                    long sent = 0;
                    long lastEmit = System.currentTimeMillis();
                    // 分片续传：跳过已收字节，只上传本片
                    if (offset > 0) in.skip(offset);
                    long remaining = readLen;
                    if (encrypted) {
                        byte[] keyBytes = MessageDigest.getInstance("SHA-256")
                                .digest(targetCode.getBytes(StandardCharsets.UTF_8));
                        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
                        // 多块 GCM 流式格式（与 Rust encrypt_stream / Java decryptToSaf 兼容）：
                        // LSBK || 00 00 00 01 || blockSize_le_u32 || (nonce12 || ctLen_le_u32 || ct || tag16)×N
                        // 内存 O(8MB)，大文件不再整块读入（流式零拷贝）
                        rawOut.write(new byte[]{'L', 'S', 'B', 'K'});
                        rawOut.write(new byte[]{0, 0, 0, 1});
                        byte[] bs = new byte[4];
                        bs[0] = (byte) (BLOCK & 0xFF);
                        bs[1] = (byte) ((BLOCK >> 8) & 0xFF);
                        bs[2] = (byte) ((BLOCK >> 16) & 0xFF);
                        bs[3] = (byte) ((BLOCK >> 24) & 0xFF);
                        rawOut.write(bs);
                        while (remaining > 0) {
                            int toRead = (int) Math.min(buf.length, remaining);
                            n = in.read(buf, 0, toRead);
                            if (n == -1) break;
                            byte[] nonce = new byte[12];
                            new java.security.SecureRandom().nextBytes(nonce);
                            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                            c.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(16 * 8, nonce));
                            byte[] ct = c.doFinal(buf, 0, n);
                            rawOut.write(nonce);
                            byte[] clen = new byte[4];
                            clen[0] = (byte) (n & 0xFF);
                            clen[1] = (byte) ((n >> 8) & 0xFF);
                            clen[2] = (byte) ((n >> 16) & 0xFF);
                            clen[3] = (byte) ((n >> 24) & 0xFF);
                            rawOut.write(clen);
                            rawOut.write(ct);
                            sent += n;
                            remaining -= n;
                            // 发送进度事件（限频 500ms）：明文比例
                            long now = System.currentTimeMillis();
                            if (now - lastEmit >= 500) {
                                lastEmit = now;
                                try {
                                    notifyListeners("upload-progress", new JSObject()
                                            .put("relPath", relPath)
                                            .put("bytesSent", sent)
                                            .put("totalBytes", total));
                                } catch (Exception ignored) {
                                }
                            }
                        }
                    } else {
                        // 未加密：流式原样拷贝
                        while (remaining > 0) {
                            int toRead = (int) Math.min(buf.length, remaining);
                            n = in.read(buf, 0, toRead);
                            if (n == -1) break;
                            rawOut.write(buf, 0, n);
                            remaining -= n;
                            sent += n;
                            long now = System.currentTimeMillis();
                            if (now - lastEmit >= 500) {
                                lastEmit = now;
                                try {
                                    notifyListeners("upload-progress", new JSObject()
                                            .put("relPath", relPath)
                                            .put("bytesSent", sent)
                                            .put("totalBytes", total));
                                } catch (Exception ignored) {
                                }
                            }
                        }
                    }
                    rawOut.flush();
                    Log.i(TAG, "streamUpload 完成: " + relPath + " 明文=" + sent + "B 加密=" + encrypted);
                }
                int resp = conn.getResponseCode();
                if (resp == 200) {
                    call.resolve(new JSObject().put("ok", true));
                } else {
                    call.reject("upload failed: HTTP " + resp);
                }
            } catch (Exception e) {
                Log.e(TAG, "streamUpload 失败: " + relPath, e);
                call.reject("streamUpload 失败: " + e.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }
        }).start();
    }

    // ---------------------------------------------------------------- SAF 写入

    /**
     * 流式接收文件：分块读网络流 → 写应用缓存临时文件 → 流式解密/拷贝 → 写 SAF 目标。
     * 内存占用 O(1)，支持任意大文件（修复 800MB 级文件整体读入导致 OOM 的问题）。
     * 支持 Content-Length / chunked / EOF 三种传输模式。
     * @return 写入的明文长度（成功）；-1（失败）
     */
    private long saveToSafStream(String relPath, InputStream in, long contentLength, boolean chunked,
                                 String sessionId, String fileName) {
        File tmp = null;
        long received = 0;
        long lastEmit = System.currentTimeMillis();
        try {
            tmp = File.createTempFile("recv_", ".bin", getContext().getCacheDir());
            try (FileOutputStream fos = new FileOutputStream(tmp)) {
                if (chunked) {
                    while (true) {
                        String line = readLine(in);
                        if (line == null) break;
                        int size;
                        try {
                            size = Integer.parseInt(line.trim(), 16);
                        } catch (NumberFormatException nfe) {
                            break;
                        }
                        if (size == 0) {
                            // 读结尾 trailer（可能有多行，到空行）
                            while ((line = readLine(in)) != null && !line.isEmpty()) {}
                            break;
                        }
                        int remain = size;
                        byte[] chunk = new byte[Math.min(size, 128 * 1024)];
                        while (remain > 0) {
                            int n = in.read(chunk, 0, Math.min(chunk.length, remain));
                            if (n == -1) throw new IOException("chunk 截断");
                            fos.write(chunk, 0, n);
                            received += n;
                            remain -= n;
                        }
                        readLine(in); // 吃掉 chunk 后的 \r\n
                        long now = System.currentTimeMillis();
                        if (now - lastEmit >= 500) {
                            lastEmit = now;
                            emitReceiveProgress(sessionId, fileName, received);
                        }
                    }
                } else if (contentLength > 0) {
                    long remain = contentLength;
                    byte[] buf = new byte[128 * 1024];
                    while (remain > 0) {
                        int n = in.read(buf, 0, (int) Math.min(buf.length, remain));
                        if (n == -1) {
                            // 发送端中途断开：必须判定失败，否则半截数据被当作完整文件保存
                            throw new IOException("body 截断: 期望 " + contentLength + " 实际 " + received);
                        }
                        fos.write(buf, 0, n);
                        received += n;
                        remain -= n;
                        long now = System.currentTimeMillis();
                        if (now - lastEmit >= 500) {
                            lastEmit = now;
                            emitReceiveProgress(sessionId, fileName, received);
                        }
                    }
                } else {
                    // EOF 模式兜底
                    byte[] buf = new byte[128 * 1024];
                    int n;
                    while ((n = in.read(buf)) != -1) {
                        fos.write(buf, 0, n);
                        received += n;
                        long now = System.currentTimeMillis();
                        if (now - lastEmit >= 500) {
                            lastEmit = now;
                            emitReceiveProgress(sessionId, fileName, received);
                        }
                    }
                }
                fos.flush();
            }
            return decryptToSaf(relPath, tmp, received);
        } catch (Exception e) {
            Log.e(TAG, "saveToSafStream: 接收异常 relPath=" + relPath, e);
            return -1;
        } finally {
            if (tmp != null) tmp.delete();
        }
    }

    /** 接收进度事件（限频 500ms）：累计字节 / 会话总字节 / 已完成文件数 */
    private void emitReceiveProgress(String sessionId, String fileName, long receivedBytes) {
        try {
            long total = 0L;
            int totalFiles = 0;
            int doneFiles = 0;
            synchronized (sessions) {
                if (sessionTotalBytes.containsKey(sessionId)) {
                    total = sessionTotalBytes.get(sessionId);
                }
                Map<String, SessionFile> s = sessions.get(sessionId);
                if (s != null) {
                    totalFiles = sessionCount.containsKey(sessionId) ? sessionCount.get(sessionId) : s.size();
                    doneFiles = totalFiles - s.size();
                }
            }
            notifyListeners("receive-progress", new JSObject()
                    .put("sessionId", sessionId)
                    .put("fileName", fileName)
                    .put("receivedBytes", receivedBytes)
                    .put("totalBytes", total)
                    .put("receivedCount", doneFiles)
                    .put("totalCount", totalFiles));
        } catch (Exception ignored) {
        }
    }

    /**
     * v4.4 三层合并架构入口：
     * - 分片文件（.chunks/）写入私有缓存目录，不写 SAF
     * - 非分片文件继续写入 SAF
     *
     * @return 写入的明文长度
     */
    private long decryptToSaf(String relPath, File tmp, long receivedLen) {
        // v4.4: 分片文件写入私有缓存，不走 SAF
        boolean isChunkPart = relPath.startsWith("__chunked__/") || relPath.startsWith(".chunks/");
        if (isChunkPart) {
            return decryptToPrivateCache(relPath, tmp, receivedLen);
        }
        // 非分片文件继续走原有 SAF 逻辑
        return decryptToSafInternal(relPath, tmp, receivedLen);
    }

    /**
     * v4.4: 分片解密写入私有缓存（第一层）
     * 路径映射：.chunks/{pct}/{index} → {cacheDir}/session_chunks/.chunks/{pct}/{index}
     */
    private long decryptToPrivateCache(String relPath, File tmp, long receivedLen) {
        try {
            // 构建私有缓存路径
            File privateFile = getChunkPrivateFile(relPath);
            File parentDir = privateFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }

            // 判断加密格式
            boolean lsbk;
            try (FileInputStream fis = new FileInputStream(tmp)) {
                byte[] head = new byte[4];
                int h = fis.read(head);
                lsbk = h == 4 && head[0] == 'L' && head[1] == 'S' && head[2] == 'B' && head[3] == 'K';
            }

            // 解密并写入私有缓存文件
            long wrote = 0;
            try (FileOutputStream fos = new FileOutputStream(privateFile)) {
                if (lsbk) {
                    try (FileInputStream fis = new FileInputStream(tmp);
                         BufferedInputStream bis = new BufferedInputStream(fis)) {
                        bis.read(new byte[4]); // 跳过 LSBK
                        byte[] ver = new byte[4];
                        int vn = bis.read(ver);
                        boolean multiBlock = vn == 4 && ver[0] == 0 && ver[1] == 0 && ver[2] == 0 && ver[3] == 1;
                        byte[] keyBytes = MessageDigest.getInstance("SHA-256")
                                .digest(effectiveSelfCode().getBytes(StandardCharsets.UTF_8));
                        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
                        if (multiBlock) {
                            byte[] bs = new byte[4];
                            bis.read(bs);
                            byte[] clenB = new byte[4];
                            while (true) {
                                byte[] nonce = new byte[12];
                                int nn = readFully(bis, nonce);
                                if (nn == 0) break;
                                if (nn < 12) throw new IOException("分块 nonce 不完整");
                                int r = readFully(bis, clenB);
                                if (r == 0) break;
                                int clen = (clenB[0] & 0xFF) | ((clenB[1] & 0xFF) << 8)
                                        | ((clenB[2] & 0xFF) << 16) | ((clenB[3] & 0xFF) << 24);
                                byte[] ctBlock = new byte[clen + 16];
                                int got = readFully(bis, ctBlock);
                                if (got == 0) break;
                                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                                c.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(16 * 8, nonce));
                                java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(ctBlock, 0, got);
                                try (javax.crypto.CipherInputStream cis =
                                        new javax.crypto.CipherInputStream(bais, c)) {
                                    byte[] buf = new byte[128 * 1024];
                                    int n;
                                    while ((n = cis.read(buf)) != -1) {
                                        fos.write(buf, 0, n);
                                        wrote += n;
                                    }
                                }
                            }
                        } else {
                            byte[] nonce = new byte[12];
                            System.arraycopy(ver, 0, nonce, 0, 4);
                            int nn = bis.read(nonce, 4, 8);
                            if (nn != 8) throw new IOException("加密数据头不完整");
                            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(16 * 8, nonce));
                            byte[] buf = new byte[128 * 1024];
                            try (javax.crypto.CipherInputStream cis = new javax.crypto.CipherInputStream(bis, cipher)) {
                                int n;
                                while ((n = cis.read(buf)) != -1) {
                                    fos.write(buf, 0, n);
                                    wrote += n;
                                }
                            }
                        }
                    }
                } else {
                    try (FileInputStream fis = new FileInputStream(tmp)) {
                        byte[] buf = new byte[128 * 1024];
                        int n;
                        while ((n = fis.read(buf)) != -1) {
                            fos.write(buf, 0, n);
                            wrote += n;
                        }
                    }
                }
                fos.flush();
            }

            Log.i(TAG, "decryptToPrivateCache: 保存分片 " + relPath + " (" + wrote + "B)");
            return wrote;
        } catch (Exception e) {
            Log.e(TAG, "decryptToPrivateCache: 写入异常 relPath=" + relPath, e);
            return -1;
        }
    }

    /**
     * v4.4: 获取分片对应的私有缓存文件
     * .chunks/{pct}/{index} → {cacheDir}/session_chunks/.chunks/{pct}/{index}
     */
    private File getChunkPrivateFile(String relPath) {
        String chunkRel = relPath;
        if (chunkRel.startsWith(".chunks/")) {
            chunkRel = chunkRel.substring(8);
        } else if (chunkRel.startsWith("__chunked__/")) {
            chunkRel = chunkRel.substring(12);
        }
        File cacheDir = new File(getContext().getCacheDir(), PRIVATE_CACHE_DIR);
        return new File(cacheDir, ".chunks/" + chunkRel);
    }

    /**
     * v4.4: 获取合并临时文件路径 (.part_tmp/{pct})
     */
    private File getPartTmpFile(String pct) {
        File cacheDir = new File(getContext().getCacheDir(), PRIVATE_CACHE_DIR);
        return new File(cacheDir, PART_TMP_DIR + "/" + pct);
    }

    /**
     * v4.4: 获取合并就绪文件路径 (.part_ready/{pct})
     */
    private File getPartReadyFile(String pct) {
        File cacheDir = new File(getContext().getCacheDir(), PRIVATE_CACHE_DIR);
        return new File(cacheDir, PART_READY_DIR + "/" + pct);
    }

    /**
     * v4.4: 三层合并（第二层 + 第三层）
     *
     * Phase 2: 私有缓存内合并 → .part_tmp/{pct} → 校验 → .part_ready/{pct}
     * Phase 3: 从 .part_ready/{pct} 一次性拷贝到 SAF → 删除 .part_ready/{pct}
     *
     * @param relPath 原始路径，如 __chunked__/{pct}/0/{total}
     */
    private void tryMergeChunkedV4(String relPath) {
        try {
            String[] parts = relPath.split("/");
            if (parts.length != 4) return;
            String pct = parts[1];
            int total;
            try {
                total = Integer.parseInt(parts[3]);
            } catch (NumberFormatException nfe) {
                return;
            }

            // Phase 1: 检查私有缓存中的分片是否到齐
            File cacheDir = new File(getContext().getCacheDir(), PRIVATE_CACHE_DIR);
            File chunksDir = new File(cacheDir, ".chunks/" + pct);

            if (!chunksDir.exists() || !chunksDir.isDirectory()) {
                return;
            }

            File[] chunkFiles = chunksDir.listFiles();
            if (chunkFiles == null || chunkFiles.length != total) {
                return; // 严格到齐
            }

            // 校验索引
            Arrays.sort(chunkFiles, (a, b) -> Long.compare(parseChunkIndex(a.getName()), parseChunkIndex(b.getName())));
            for (int k = 0; k < chunkFiles.length; k++) {
                if (parseChunkIndex(chunkFiles[k].getName()) != k) {
                    Log.e(TAG, "分片索引不连续，清理: " + pct);
                    for (File cf : chunkFiles) cf.delete();
                    chunksDir.delete();
                    return;
                }
            }

            // 计算合并后预期大小
            long expectedSize = 0;
            for (File cf : chunkFiles) expectedSize += cf.length();

            // Phase 2: 私有缓存内合并到 .part_tmp
            File partTmpFile = getPartTmpFile(pct);
            File partTmpDir = partTmpFile.getParentFile();
            if (partTmpDir != null && !partTmpDir.exists()) {
                partTmpDir.mkdirs();
            }

            try (FileOutputStream fos = new FileOutputStream(partTmpFile)) {
                byte[] buf = new byte[64 * 1024];
                for (File cf : chunkFiles) {
                    try (FileInputStream fis = new FileInputStream(cf)) {
                        int n;
                        while ((n = fis.read(buf)) != -1) {
                            fos.write(buf, 0, n);
                        }
                    }
                }
                fos.flush();
            }

            // 校验后 rename 到 .part_ready
            File partReadyFile = getPartReadyFile(pct);
            File partReadyDir = partReadyFile.getParentFile();
            if (partReadyDir != null && !partReadyDir.exists()) {
                partReadyDir.mkdirs();
            }

            if (!partTmpFile.renameTo(partReadyFile)) {
                Log.e(TAG, "Phase 2 重命名失败");
                partTmpFile.delete();
                return;
            }
            Log.i(TAG, "Phase 2 完成: .part_ready/" + pct + " (" + partReadyFile.length() + "B)");

            // Phase 3: 从 .part_ready 一次性拷贝到 SAF
            String realName = pctDecode(pct);

            DocumentFile root = DocumentFile.fromTreeUri(getContext(), Uri.parse(rootUri));
            String[] nameParts = realName.split("/");
            DocumentFile targetParent = root;
            for (int i = 0; i < nameParts.length - 1; i++) {
                targetParent = ensureDirDoc(targetParent, nameParts[i]);
                if (targetParent == null) {
                    partReadyFile.delete();
                    return;
                }
            }
            String targetName = nameParts[nameParts.length - 1];

            // 冲突检测
            DocumentFile existing = targetParent.findFile(targetName);
            if (existing != null && existing.length() == expectedSize) {
                Log.i(TAG, "目标已存在且大小一致，跳过: " + realName);
            } else {
                String finalName = targetName;
                if (existing != null) {
                    finalName = conflictRename(targetName, System.currentTimeMillis());
                    while (targetParent.findFile(finalName) != null) {
                        finalName = conflictRename(targetName, System.currentTimeMillis());
                    }
                }
                DocumentFile targetFile = targetParent.createFile("application/octet-stream", finalName);
                if (targetFile == null) {
                    Log.e(TAG, "Phase 3: 无法创建目标文件");
                    partReadyFile.delete();
                    return;
                }

                try (OutputStream os = getContext().getContentResolver().openOutputStream(targetFile.getUri())) {
                    if (os == null) {
                        partReadyFile.delete();
                        return;
                    }
                    try (FileInputStream fis = new FileInputStream(partReadyFile)) {
                        byte[] buf = new byte[64 * 1024];
                        int n;
                        while ((n = fis.read(buf)) != -1) {
                            os.write(buf, 0, n);
                        }
                    }
                    os.flush();
                }
                Log.i(TAG, "Phase 3 完成: 提交到 SAF: " + realName);
            }

            partReadyFile.delete();

            // 清理分片
            for (File cf : chunkFiles) cf.delete();
            chunksDir.delete();

            Log.i(TAG, "v4.4 三层合并完成: " + realName + " (" + total + " 片)");
        } catch (Exception e) {
            Log.e(TAG, "v4.4 三层合并失败", e);
        }
    }

    /**
     * 原有 SAF 解密逻辑（保留用于非分片文件）
     * 流式解密/拷贝临时文件 → SAF 目标（内存 O(1)）。
     * LSBK 魔数头 → AES-GCM 流式解密；否则原样拷贝（外部明文）。
     * 冲突检测：同大小 → 覆盖；不同 → 重命名（永不覆盖）。
     * @return 写入的明文长度
     */
    private long decryptToSafInternal(String relPath, File tmp, long receivedLen) {
        try {
            DocumentFile root = DocumentFile.fromTreeUri(getContext(), Uri.parse(rootUri));
            String[] parts = relPath.split("/");
            DocumentFile parent = root;
            // 逐级进入/创建目录
            for (int i = 0; i < parts.length - 1; i++) {
                parent = ensureDirDoc(parent, parts[i]);
                if (parent == null) {
                    return -1;
                }
            }
            String name = parts[parts.length - 1];
            // 判断加密格式：LSBK 魔数头（多块流式 v1 / 单块旧格式）
            boolean lsbk;
            long plainLen;
            try (FileInputStream fis = new FileInputStream(tmp)) {
                byte[] head = new byte[4];
                int h = fis.read(head);
                lsbk = h == 4 && head[0] == 'L' && head[1] == 'S' && head[2] == 'B' && head[3] == 'K';
                if (lsbk) {
                    byte[] ver = new byte[4];
                    int vn = fis.read(ver);
                    if (vn == 4 && ver[0] == 0 && ver[1] == 0 && ver[2] == 0 && ver[3] == 1) {
                        // 多块流式格式：LSBK(4) + ver(4) + blockSize(4) + 块(12+4+ct+16)×N
                        byte[] bs = new byte[4];
                        fis.read(bs);
                        long blockSize = (bs[0] & 0xFF) | ((bs[1] & 0xFF) << 8)
                                | ((bs[2] & 0xFF) << 16) | ((long) (bs[3] & 0xFF) << 24);
                        long body = Math.max(0, receivedLen - 12);
                        long blocks = blockSize > 0 ? (body + blockSize + 31) / (blockSize + 32) : 0;
                        plainLen = Math.max(0, receivedLen - 12 - 32 * blocks);
                    } else {
                        // 单块格式（手机端发送 / 旧版）：LSBK(4) + nonce(12) + ct+tag
                        plainLen = Math.max(0, receivedLen - 32);
                    }
                } else {
                    plainLen = receivedLen;
                }
            }
            // 冲突检测：同名且大小不同 → 重命名；大小相同 → 覆盖（避免重复副本）
            // 分片落盘路径（__chunked__/…）不参与冲突重命名——否则 part 名被改导致合并错乱
            DocumentFile existing = parent.findFile(name);
            DocumentFile file;
            boolean isChunkPart = relPath.startsWith("__chunked__/") || relPath.startsWith(".chunks/");
            if (existing != null && (existing.length() == plainLen || isChunkPart)) {
                file = existing; // 同大小覆盖 / 分片直接覆盖
            } else {
                if (existing != null) {
                    name = conflictRename(name, System.currentTimeMillis());
                    while (parent.findFile(name) != null) {
                        name = conflictRename(name, System.currentTimeMillis());
                    }
                }
                file = parent.createFile("application/octet-stream", name);
            }
            if (file == null) {
                return -1;
            }
            long wrote = 0;
            try (OutputStream os = getContext().getContentResolver().openOutputStream(file.getUri())) {
                if (os == null) {
                    return -1;
                }
                if (lsbk) {
                    try (FileInputStream fis = new FileInputStream(tmp);
                         BufferedInputStream bis = new BufferedInputStream(fis)) {
                        bis.read(new byte[4]); // 跳过 LSBK
                        byte[] ver = new byte[4];
                        int vn = bis.read(ver);
                        boolean multiBlock = vn == 4 && ver[0] == 0 && ver[1] == 0 && ver[2] == 0 && ver[3] == 1;
                        byte[] keyBytes = MessageDigest.getInstance("SHA-256")
                                .digest(effectiveSelfCode().getBytes(StandardCharsets.UTF_8));
                        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
                        if (multiBlock) {
                            // 多块流式格式：使用 CipherInputStream 流式解密（每块独立 nonce + tag）
                            // P2 修复：用 CipherInputStream 替代整块 doFinal，避免 clen+16 字节的 byte[] 堆分配
                            byte[] bs = new byte[4];
                            bis.read(bs); // block_size（仅信息）
                            byte[] clenB = new byte[4];
                            while (true) {
                                byte[] nonce = new byte[12];
                                int nn = readFully(bis, nonce);
                                if (nn == 0) break; // EOF：正常结束
                                if (nn < 12) throw new IOException("分块 nonce 不完整");
                                int r = readFully(bis, clenB);
                                if (r == 0) break;
                                int clen = (clenB[0] & 0xFF) | ((clenB[1] & 0xFF) << 8)
                                        | ((clenB[2] & 0xFF) << 16) | ((clenB[3] & 0xFF) << 24);
                                // 分配 clen+16 字节读入加密块内容，再用 CipherInputStream 流式解密（内存 O(cipher_in_chunk)）
                                byte[] ctBlock = new byte[clen + 16];
                                int got = readFully(bis, ctBlock);
                                if (got == 0) break;
                                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                                c.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(16 * 8, nonce));
                                java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(ctBlock, 0, got);
                                try (javax.crypto.CipherInputStream cis =
                                        new javax.crypto.CipherInputStream(bais, c)) {
                                    byte[] buf = new byte[128 * 1024];
                                    int n;
                                    while ((n = cis.read(buf)) != -1) {
                                        os.write(buf, 0, n);
                                        wrote += n;
                                    }
                                }
                            }
                        } else {
                            // 单块格式（手机端 CipherOutputStream 流式 GCM）：ver 是 nonce 前 4 字节
                            byte[] nonce = new byte[12];
                            System.arraycopy(ver, 0, nonce, 0, 4);
                            int nn = bis.read(nonce, 4, 8);
                            if (nn != 8) throw new IOException("加密数据头不完整");
                            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(16 * 8, nonce));
                            byte[] buf = new byte[128 * 1024];
                            try (javax.crypto.CipherInputStream cis = new javax.crypto.CipherInputStream(bis, cipher)) {
                                int n;
                                while ((n = cis.read(buf)) != -1) {
                                    os.write(buf, 0, n);
                                    wrote += n;
                                }
                            }
                        }
                    }
                } else {
                    try (FileInputStream fis = new FileInputStream(tmp)) {
                        byte[] buf = new byte[128 * 1024];
                        int n;
                        while ((n = fis.read(buf)) != -1) {
                            os.write(buf, 0, n);
                            wrote += n;
                        }
                    }
                }
                os.flush();
            }
            Log.i(TAG, "decryptToSaf: 保存完成 " + name + " 明文=" + wrote + "B 加密=" + lsbk);
            return wrote; // 明文长度（解密/拷贝实际写入字节数，最准确）
        } catch (Exception e) {
            Log.e(TAG, "decryptToSaf: 写入异常 relPath=" + relPath, e);
            return -1;
        }
    }

    /** 读输入流全部字节 */
    private byte[] readAllBytes(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        byte[] chunk = new byte[64 * 1024];
        int n;
        while ((n = in.read(chunk)) != -1) {
            buf.write(chunk, 0, n);
        }
        return buf.toByteArray();
    }

    /**
     * tiny 批量聚合解包（自定义格式）：读取 __batch__.agg → 按成员 relPath 写入 SAF 根目录 → 删除本体。
     * 成员名/大小由 tar 头自描述（发送方不依赖自定义 metadata 字段，协议兼容）。
     *
     * 安全修复：流式解析 — 将 SAF 文件流式复制到临时文件，再从临时文件流式读取解析，
     * 全程内存占用 = O(单成员大小)，不再将整个 tar 聚合体（可达数百 MB）读入堆。
     * 硬上限：单成员 >100MB 时放弃（异常聚合体/攻击流量），避免临时文件撑爆存储。
     */
    private void unpackTarBatch(String batchRelPath) {
        File tmpTar = null;
        InputStream tarIn = null;
        try {
            DocumentFile root = DocumentFile.fromTreeUri(getContext(), Uri.parse(rootUri));
            String[] parts = batchRelPath.split("/");
            DocumentFile parent = root;
            for (int i = 0; i < parts.length - 1; i++) {
                DocumentFile d = parent.findFile(parts[i]);
                if (d == null || !d.isDirectory()) return;
                parent = d;
            }
            DocumentFile batchFile = parent.findFile(parts[parts.length - 1]);
            if (batchFile == null) {
                Log.w(TAG, "批量 tar 文件不存在: " + batchRelPath);
                return;
            }
            // 流式写入临时文件（避免全量 readAllBytes 撑爆堆）
            tarIn = getContext().getContentResolver().openInputStream(batchFile.getUri());
            if (tarIn == null) return;
            tmpTar = File.createTempFile("batch_", ".bin", getContext().getCacheDir());
            try (FileOutputStream fos = new FileOutputStream(tmpTar)) {
                byte[] buf = new byte[64 * 1024];
                int n;
                while ((n = tarIn.read(buf)) != -1) fos.write(buf, 0, n);
            } finally {
                tarIn.close();
                tarIn = null;
            }
            // 流式解析自定义聚合格式：[u32 LE 文件名长度][文件名][u64 LE 文件大小][文件内容] 循环
            try (FileInputStream fis = new FileInputStream(tmpTar)) {
                byte[] header = new byte[12]; // name_len(4) + size(8) max name=4GB
                int count = 0;
                while (true) {
                    // 读取文件名长度（固定 4 字节）
                    int got = readFully(fis, header, 0, 4);
                    if (got < 4) break; // EOF
                    int nameLen = (header[0] & 0xFF) | ((header[1] & 0xFF) << 8)
                            | ((header[2] & 0xFF) << 16) | ((header[3] & 0xFF) << 24);
                    if (nameLen <= 0 || nameLen > 4096) {
                        Log.w(TAG, "unpackTarBatch: 非法文件名长度 " + nameLen + "，中断");
                        break;
                    }
                    // 读取文件名
                    byte[] nameBytes = new byte[nameLen];
                    if (readFully(fis, nameBytes, 0, nameLen) < nameLen) break;
                    String name = new String(nameBytes, StandardCharsets.UTF_8);
                    // 读取文件大小（固定 8 字节）
                    if (readFully(fis, header, 0, 8) < 8) break;
                    long size = 0;
                    for (int i = 0; i < 8; i++) {
                        size |= ((long) (header[i] & 0xFF)) << (8 * i);
                    }
                    // 安全上限：单成员 >100MB 放弃（异常聚合体）
                    final long MAX_MEMBER_SIZE = 100 * 1024 * 1024;
                    if (size > MAX_MEMBER_SIZE) {
                        Log.w(TAG, "unpackTarBatch: 成员过大 " + size + "B（>" + MAX_MEMBER_SIZE + "），放弃解包");
                        break;
                    }
                    String rel = sanitizeRelPath(name);
                    if (!rel.isEmpty()) {
                        // 流式写成员：分块从临时文件读 → SAF 输出流
                        if (writeTarMemberStreaming(fis, rel, size)) count++;
                    }
                    // 已读取完此成员，指针已在下一成员起始位置（无需额外推进）
                }
                Log.i(TAG, "批量聚合解包完成: " + count + " 个成员");
            }
            batchFile.delete();
        } catch (Exception e) {
            Log.e(TAG, "解包批量 tar 失败", e);
        } finally {
            if (tarIn != null) { try { tarIn.close(); } catch (Exception ignored) {} }
            if (tmpTar != null) tmpTar.delete();
        }
    }

    /** 写入单个 tar 成员到 SAF（目录层级 + 冲突重命名，与 decryptToSaf 同规则） */
    private boolean writeTarMember(String rel, byte[] tar, int dataStart, long size) {
        try {
            DocumentFile root = DocumentFile.fromTreeUri(getContext(), Uri.parse(rootUri));
            String[] parts = rel.split("/");
            DocumentFile parent = root;
            for (int i = 0; i < parts.length - 1; i++) {
                parent = ensureDirDoc(parent, parts[i]);
                if (parent == null) return false;
            }
            String name = parts[parts.length - 1];
            DocumentFile existing = parent.findFile(name);
            DocumentFile file;
            if (existing != null && existing.length() == size) {
                file = existing; // 同大小 → 覆盖
            } else {
                if (existing != null) {
                    name = conflictRename(name, System.currentTimeMillis());
                    while (parent.findFile(name) != null) {
                        name = conflictRename(name, System.currentTimeMillis());
                    }
                }
                file = parent.createFile("application/octet-stream", name);
            }
            if (file == null) return false;
            try (OutputStream os = getContext().getContentResolver().openOutputStream(file.getUri())) {
                if (os == null) return false;
                os.write(tar, dataStart, (int) size);
                os.flush();
            }
            return true;
        } catch (Exception e) {
            Log.e(TAG, "tar 成员写入失败 " + rel, e);
            return false;
        }
    }

    /**
     * 流式写入 tar 成员（从输入流读取固定字节数写入 SAF）。
     * 用于 unpackTarBatch 的流式化解包：每次只持有单成员数据，不将整个 tar 读入内存。
     * @param tarIn  临时文件输入流（当前位置为成员数据起始）
     * @param rel    相对路径
     * @param size   成员字节数（精确读取，避免多成员数据粘在一起）
     */
    private boolean writeTarMemberStreaming(InputStream tarIn, String rel, long size) {
        try {
            DocumentFile root = DocumentFile.fromTreeUri(getContext(), Uri.parse(rootUri));
            String[] parts = rel.split("/");
            DocumentFile parent = root;
            for (int i = 0; i < parts.length - 1; i++) {
                parent = ensureDirDoc(parent, parts[i]);
                if (parent == null) return false;
            }
            String name = parts[parts.length - 1];
            DocumentFile existing = parent.findFile(name);
            DocumentFile file;
            if (existing != null && existing.length() == size) {
                file = existing; // 同大小 → 覆盖
            } else {
                if (existing != null) {
                    name = conflictRename(name, System.currentTimeMillis());
                    while (parent.findFile(name) != null) {
                        name = conflictRename(name, System.currentTimeMillis());
                    }
                }
                file = parent.createFile("application/octet-stream", name);
            }
            if (file == null) return false;
            try (OutputStream os = getContext().getContentResolver().openOutputStream(file.getUri())) {
                if (os == null) return false;
                // 流式写：每次读固定 size 字节，不过度读取（保护后续成员数据不被超前消费）
                long remaining = size;
                byte[] buf = new byte[64 * 1024];
                while (remaining > 0) {
                    int toRead = (int) Math.min(buf.length, remaining);
                    int got = tarIn.read(buf, 0, toRead);
                    if (got == -1) break; // EOF（不应提前发生）
                    os.write(buf, 0, got);
                    remaining -= got;
                }
                os.flush();
            }
            return true;
        } catch (Exception e) {
            Log.e(TAG, "tar 成员写入失败(流式) " + rel, e);
            return false;
        }
    }

    /** tar 成员路径安全过滤：去掉空段/`.`/`..` */
    private static String sanitizeRelPath(String name) {
        StringBuilder sb = new StringBuilder();
        for (String comp : name.split("/")) {
            if (comp.isEmpty() || comp.equals(".") || comp.equals("..")) continue;
            if (sb.length() > 0) sb.append('/');
            sb.append(comp);
        }
        return sb.toString();
    }

    private static long parseChunkIndex(String s) {
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException nfe) {
            return Long.MAX_VALUE;
        }
    }

    /** 读满 buf.length 字节（EOF 提前返回已读字节数） */
    private static int readFully(InputStream in, byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int n = in.read(buf, off, buf.length - off);
            if (n == -1) break;
            off += n;
        }
        return off;
    }

    /** 读满 len 字节到 buf[off,off+len)（EOF 提前返回已读字节数） */
    private static int readFully(InputStream in, byte[] buf, int off, int len) throws IOException {
        int remaining = len;
        while (remaining > 0) {
            int n = in.read(buf, off, remaining);
            if (n == -1) break;
            off += n;
            remaining -= n;
        }
        return len - remaining;
    }

    private static String pctEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20");
        } catch (Exception e) {
            return s;
        }
    }

    private static String pctDecode(String s) {
        try {
            return java.net.URLDecoder.decode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    /**
     * 传输层 AES-256-GCM 解密（与 Rust crypto.rs / shared-core transfer.ts 同格式）：
     * `LSBK(4) || nonce(12) || ciphertext+tag(16)`，密钥 = SHA-256(本机连接码)。
     * 非 LSBK 开头（外部明文，如官方 LocalSend 传入）→ 原样返回，不误伤。
     */
    private byte[] maybeDecrypt(byte[] data) {
        if (data.length < 4 || data[0] != 'L' || data[1] != 'S' || data[2] != 'B' || data[3] != 'K') {
            return data;
        }
        try {
            byte[] body = Arrays.copyOfRange(data, 4, data.length);
            if (body.length < 12 + 16) {
                Log.w(TAG, "maybeDecrypt: 加密数据长度不足，按原样保存");
                return data;
            }
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = md.digest((selfCode == null ? "" : selfCode).getBytes(StandardCharsets.UTF_8));
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            byte[] nonce = Arrays.copyOfRange(body, 0, 12);
            byte[] ciphertext = Arrays.copyOfRange(body, 12, body.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(16 * 8, nonce));
            byte[] plain = cipher.doFinal(ciphertext);
            Log.i(TAG, "maybeDecrypt: 解密成功 " + data.length + "B → " + plain.length + "B");
            return plain;
        } catch (Exception e) {
            Log.e(TAG, "maybeDecrypt: 解密失败，按原样保存（密钥不匹配或数据损坏）", e);
            return data;
        }
    }

    private String conflictRename(String name, long millis) {
        // MMDDhhmmss（UTC）
        SimpleDateFormat fmt = new SimpleDateFormat("MMddHHmmss", Locale.ROOT);
        fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
        String suffix = fmt.format(new Date(millis));
        int dot = name.lastIndexOf('.');
        if (dot > 0) {
            return name.substring(0, dot) + "_" + suffix + name.substring(dot);
        }
        return name + "_" + suffix;
    }

    /** 脱敏：只保留前 2 + 后 2 字符，用于日志中记录连接码/会话 ID */
    private static String mask(String secret) {
        if (secret == null || secret.isEmpty()) {
            return "";
        }
        if (secret.length() <= 4) {
            return "****";
        }
        return secret.substring(0, 2) + "****" + secret.substring(secret.length() - 2);
    }

    // ---------------------------------------------------------------- 响应

    private String deviceInfo() {
        try {
            JSONObject info = new JSONObject();
            // 设备名 + 公开 deviceId —— 连接码不暴露在 register/info 响应中
            info.put("alias", deviceName());
            info.put("version", "2.2");
            info.put("deviceModel", android.os.Build.MODEL);
            info.put("deviceType", "mobile");
            info.put("fingerprint", deviceId());
            info.put("port", serverSocket == null ? 53317 : serverSocket.getLocalPort());
            info.put("protocol", "http");
            info.put("download", false);
            return info.toString();
        } catch (Exception e) {
            return "{}";
        }
    }

    /** 连接码本地比对（/verify 端点）。
     *  body: {code?, deviceId?, name?, myCode?, port?}
     *  - code 非空且匹配本机码 → 配对成功：记录对方信任信息（deviceId→{name,ip,port,指纹=对方码}），
     *    实现双端配对同步；myCode 为对方本机码（用于加密回传）。
     *  - code 为空 → 连接问候：校验对方 deviceId 是否在本机信任列表（防"绕过设备码直接连接"）。
     */
    private String verifyCode(String body, String clientIp) {
        try {
            JSONObject o = new JSONObject(body);
            String entered = normalizeCode(o.optString("code", ""));
            boolean ok;
            String reason = "";
            if (!entered.isEmpty()) {
                // 用有效本机码比对（接收服务未启动时也能验证，见 effectiveSelfCode）
                ok = entered.equals(normalizeCode(effectiveSelfCode()));
                if (ok) {
                    String deviceId = o.optString("deviceId", "");
                    if (!deviceId.isEmpty() && !deviceId.equals(deviceId())) {
                        String name = o.optString("name", "未知设备");
                        // 配对双向确认：通知前端弹窗「是否同意与 xx 配对」，阻塞等待被动方确认
                        boolean approved = waitPairingConfirm(deviceId, name, clientIp);
                        if (approved) {
                            JSONObject peer = new JSONObject();
                            peer.put("name", name);
                            peer.put("ip", clientIp);
                            peer.put("port", o.optInt("port", 53317));
                            peer.put("fingerprint", o.optString("myCode", ""));
                            peer.put("at", System.currentTimeMillis());
                            synchronized (pairedPeers) {
                                pairedPeers.put(deviceId, peer);
                            }
                            persistPairedPeers();
                            Log.i(TAG, "配对确认（被动方已同意）: deviceId=" + mask(deviceId) + " name=" + name);
                            // 实时通知前端刷新已配对设备（对方验证本机码通过）
                            try {
                                notifyListeners("paired-updated", new JSObject());
                            } catch (Exception ignored) {
                            }
                        } else {
                            Log.w(TAG, "被动方拒绝配对: deviceId=" + mask(deviceId));
                            ok = false;
                            reason = "rejected";
                        }
                    }
                }
                if (!ok && reason.isEmpty()) reason = "code_mismatch";
            } else {
                // 连接问候：校验对方是否仍被本机信任（probe=true 为状态探测，不触发已连接事件）
                String deviceId = o.optString("deviceId", "");
                boolean probe = o.optBoolean("probe", false);
                synchronized (pairedPeers) {
                    ok = !deviceId.isEmpty() && pairedPeers.containsKey(deviceId);
                }
                if (ok && !probe) {
                    // 通知前端：对方已连接本机（实时状态，让被连方感知）
                    try {
                        JSObject payload = new JSObject();
                        payload.put("deviceId", deviceId);
                        payload.put("name", o.optString("name", ""));
                        notifyListeners("peer-connected", payload);
                    } catch (Exception ignored) {
                    }
                }
            }
            Log.i(TAG, "verify: 连接码验证" + (ok ? "通过" : "失败/未信任"));
            return "{\"ok\":" + ok + ",\"reason\":\"" + reason + "\"}";
        } catch (Exception e) {
            return "{\"ok\":false}";
        }
    }

    /** 配对双向确认：通知前端弹窗，阻塞等待同意（45s 超时默认拒绝，防未授权主动方） */
    private boolean waitPairingConfirm(String deviceId, String name, String clientIp) {
        try {
            notifyListeners("pairing-request", new JSObject()
                    .put("deviceId", deviceId)
                    .put("name", name)
                    .put("ip", clientIp));
        } catch (Exception ignored) {
        }
        CompletableFuture<Boolean> f = new CompletableFuture<>();
        synchronized (pendingPairings) {
            pendingPairings.put(deviceId, f);
        }
        try {
            return f.get(45, TimeUnit.SECONDS);
        } catch (Exception e) {
            return false; // 超时默认拒绝
        } finally {
            synchronized (pendingPairings) {
                pendingPairings.remove(deviceId);
            }
        }
    }

    /** 前端响应「配对确认」弹窗：同意/拒绝配对请求（解除 verifyCode 阻塞等待） */
    @PluginMethod
    public void resolvePairing(PluginCall call) {
        String deviceId = call.getString("deviceId", "");
        boolean accept = call.getBoolean("accept", false);
        CompletableFuture<Boolean> f;
        synchronized (pendingPairings) {
            f = pendingPairings.remove(deviceId);
        }
        if (f != null) f.complete(accept);
        call.resolve();
    }

    /** 记录对方同步过来的目录映射（/sync-dir 端点） */
    private void handleSyncDir(String body) {
        try {
            JSONObject o = new JSONObject(body);
            String dir = o.optString("direction", "");
            String name = o.optString("name", "");
            if (!dir.isEmpty() && !name.isEmpty()) {
                synchronized (syncedDirs) {
                    syncedDirs.put(dir, name);
                }
                Log.i(TAG, "sync-dir: direction=" + dir + " name=" + name);
            }
        } catch (Exception ignored) {
        }
    }

    /** 收到对方解除配对（/unpair 端点）：从信任列表删除并通知前端 */
    private void handleUnpair(String body) {
        try {
            JSONObject o = new JSONObject(body);
            String deviceId = o.optString("deviceId", "");
            if (!deviceId.isEmpty()) {
                synchronized (pairedPeers) {
                    pairedPeers.remove(deviceId);
                }
                persistPairedPeers();
                Log.i(TAG, "收到解除配对: deviceId=" + mask(deviceId));
                try {
                    notifyListeners("pair-unpaired", new JSObject().put("deviceId", deviceId));
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }
    }

    /** 收到对方断开连接（/api/backup/v1/disconnect）：通知前端清除"已连接"状态（不解除配对） */
    private void handleDisconnect(String body) {
        try {
            JSONObject o = new JSONObject(body);
            String deviceId = o.optString("deviceId", "");
            if (!deviceId.isEmpty()) {
                Log.i(TAG, "收到断开连接: deviceId=" + mask(deviceId));
                try {
                    notifyListeners("peer-disconnected", new JSObject().put("deviceId", deviceId));
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }
    }

    /** 规范化连接码：去分隔符、统一大写 */
    private static String normalizeCode(String c) {
        return (c == null ? "" : c).replaceAll("[^A-Za-z0-9]", "").toUpperCase(Locale.ROOT);
    }

    private void respondJson(OutputStream out, int code, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        String head = "HTTP/1.1 " + code + " " + reason(code) + "\r\n"
                + "Content-Type: application/json\r\n"
                + "Content-Length: " + body.length + "\r\n"
                + "Connection: close\r\n\r\n";
        out.write(head.getBytes(StandardCharsets.UTF_8));
        out.write(body);
        out.flush();
    }

    private void respondText(OutputStream out, int code, String text) throws IOException {
        respondJson(out, code, "{\"message\":\"" + text.replace("\"", "'") + "\"}");
    }

    private String reason(int code) {
        switch (code) {
            case 200: return "OK";
            case 204: return "No Content";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 404: return "Not Found";
            case 500: return "Internal Server Error";
            default: return "Unknown";
        }
    }

    // ---------------------------------------------------------------- HTTP 工具

    private String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                break;
            }
            if (b != '\r') {
                sb.append((char) b);
            }
            if (sb.length() > 16384) {
                throw new IOException("header too long");
            }
        }
        return sb.length() == 0 && b == -1 ? null : sb.toString();
    }

    private String readBody(InputStream in, int contentLength) throws IOException {
        if (contentLength <= 0) {
            return "";
        }
        // 安全上限：防止恶意/畸形 Content-Length 导致 OOM
        if (contentLength > 10 * 1024 * 1024) {
            Log.w(TAG, "readBody: Content-Length 过大 (" + contentLength + "B)，截断为 10MB");
            contentLength = 10 * 1024 * 1024;
        }
        byte[] buf = new byte[contentLength];
        int off = 0;
        while (off < contentLength) {
            int n = in.read(buf, off, contentLength - off);
            if (n == -1) {
                break;
            }
            off += n;
        }
        return new String(buf, 0, off, StandardCharsets.UTF_8);
    }

    private Map<String, String> parseQuery(String query) {
        Map<String, String> params = new HashMap<>();
        if (query == null || query.isEmpty()) {
            return params;
        }
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) {
                continue;
            }
            try {
                String key = URLDecoder.decode(pair.substring(0, eq), "UTF-8");
                String value = URLDecoder.decode(pair.substring(eq + 1), "UTF-8");
                params.put(key, value);
            } catch (Exception ignored) {
            }
        }
        return params;
    }

    // ============================================================
    // scheduler v1 扩展协议处理
    // ============================================================

    /** scheduler v1: 心跳 */
    private void handleHeartbeat(String body) {
        try {
            JSONObject o = new JSONObject(body);
            String sessionId = o.optString("sessionId", "");
            if (!sessionId.isEmpty()) {
                synchronized (sessions) {
                    sessionStart.put(sessionId, System.currentTimeMillis());
                }
                Log.d(TAG, "handleHeartbeat: session=" + mask(sessionId));
            }
        } catch (Exception e) {
            Log.w(TAG, "handleHeartbeat: 解析失败", e);
        }
    }

    /** scheduler v1: 中止会话 */
    private void handleAbort(String body) {
        try {
            JSONObject o = new JSONObject(body);
            String sessionId = o.optString("sessionId", "");
            if (!sessionId.isEmpty()) {
                synchronized (sessions) {
                    sessions.remove(sessionId);
                    sessionBytes.remove(sessionId);
                    sessionStart.remove(sessionId);
                    sessionCount.remove(sessionId);
                    sessionTotalBytes.remove(sessionId);
                }
                Log.d(TAG, "handleAbort: session=" + mask(sessionId));
            }
        } catch (Exception e) {
            Log.w(TAG, "handleAbort: 解析失败", e);
        }
    }

    /** scheduler v1: GET /file/{fileId}/diff - 探测块是否存在 + SHA-256 校验
     * 协议契约：
     * - 206 + Content-Range: 块存在且 ETag 匹配
     * - 412: 块存在但 SHA-256 不匹配（NACK）
     * - 416 + Content-Range: bytes * /{total}: Range 不满足
     * - 200: ETag 不匹配（文件已变），需全量重传
     */
    private void handleFileDiff(OutputStream out, String fileId, String query, InputStream in) throws IOException {
        // 解析 Range 和 If-Range 头（从 query 参数传入）
        Map<String, String> params = parseQuery(query);
        String rangeHeader = params.get("range"); // bytes=start-end
        String ifRange = params.get("ifRange");   // 带双引号的 ETag

        String sessionId = params.get("sessionId");
        long rangeStart = 0, rangeEnd = 0;
        boolean hasRange = false;

        if (rangeHeader != null && rangeHeader.startsWith("bytes=")) {
            String[] parts = rangeHeader.substring(6).split("-");
            if (parts.length == 2) {
                try {
                    rangeStart = Long.parseLong(parts[0]);
                    rangeEnd = Long.parseLong(parts[1]);
                    hasRange = true;
                } catch (NumberFormatException e) {
                }
            }
        }

        // 查找文件
        String storedToken = null;
        String fileName = null;
        synchronized (sessions) {
            if (sessionId != null) {
                Map<String, SessionFile> session = sessions.get(sessionId);
                if (session != null) {
                    SessionFile f = session.get(fileId);
                    if (f != null) {
                        storedToken = f.token;
                        fileName = f.fileName;
                    }
                }
            }
        }

        if (fileName == null) {
            respondJson(out, 416, "{\"error\":\"file_not_found\"}");
            return;
        }

        // 读取块的 SHA-256（从 If-Range 解析，去掉双引号）
        String expectedSha256 = ifRange;
        if (expectedSha256 != null && expectedSha256.startsWith("\"") && expectedSha256.endsWith("\"")) {
            expectedSha256 = expectedSha256.substring(1, expectedSha256.length() - 1);
        }

        // 检查块是否在范围内
        long fileSize = 0;
        DocumentFile root = DocumentFile.fromTreeUri(getContext(), Uri.parse(rootUri));
        DocumentFile targetFile = findFileRecursive(root, fileName);

        if (targetFile != null) {
            fileSize = targetFile.length();
        }

        if (hasRange && rangeStart >= fileSize) {
            // 416: Range Not Satisfiable，必须带 Content-Range: bytes */{total}
            try {
                out.write(("HTTP/1.1 416\r\n").getBytes());
                out.write(("Content-Range: bytes */" + fileSize + "\r\n").getBytes());
                out.write("Content-Type: application/json\r\n\r\n".getBytes());
                out.write(("{\"error\":\"range_not_satisfiable\",\"actualSize\":" + fileSize + "}").getBytes());
                out.flush();
            } catch (Exception e) {
                Log.w(TAG, "handleFileDiff: 416 响应失败", e);
            }
            return;
        }

        // 读取块数据并计算 SHA-256
        try {
            byte[] chunkData;
            if (targetFile != null && hasRange) {
                // 读取指定范围
                try (InputStream fis = getContext().getContentResolver().openInputStream(targetFile.getUri())) {
                    fis.skip(rangeStart);
                    long toRead = rangeEnd - rangeStart + 1;
                    chunkData = new byte[(int) toRead];
                    int totalRead = 0;
                    while (totalRead < toRead) {
                        int n = fis.read(chunkData, totalRead, (int) (toRead - totalRead));
                        if (n <= 0) break;
                        totalRead += n;
                    }
                }
            } else if (targetFile != null) {
                // 读整个文件
                try (InputStream fis = getContext().getContentResolver().openInputStream(targetFile.getUri())) {
                    chunkData = new byte[(int) targetFile.length()];
                    int totalRead = 0;
                    while (totalRead < chunkData.length) {
                        int n = fis.read(chunkData, totalRead, chunkData.length - totalRead);
                        if (n <= 0) break;
                        totalRead += n;
                    }
                }
            } else {
                respondJson(out, 416, "{\"error\":\"file_not_found\"}");
                return;
            }

            // 计算 SHA-256
            String actualSha256 = sha256Hex(chunkData);

            // 比较
            if (expectedSha256 != null && !expectedSha256.equals(actualSha256)) {
                // 412: SHA-256 不匹配（NACK）
                respondJson(out, 412, "{\"type\":\"chunk_nack\",\"expected\":\"" + expectedSha256 + "\",\"actual\":\"" + actualSha256 + "\"}");
                return;
            }

            // 200: ETag 不匹配（文件已变）或者 206: 块匹配
            if (expectedSha256 == null || !expectedSha256.equals(actualSha256)) {
                // 文件已变
                respondJson(out, 200, "{\"type\":\"file_changed\"}");
            } else {
                // 206: 块存在且匹配
                out.write(("HTTP/1.1 206\r\n").getBytes());
                out.write(("Content-Range: bytes " + rangeStart + "-" + rangeEnd + "/" + fileSize + "\r\n").getBytes());
                out.write("Content-Type: application/octet-stream\r\n\r\n".getBytes());
                out.write(chunkData);
                out.flush();
            }
        } catch (Exception e) {
            Log.e(TAG, "handleFileDiff: 处理异常", e);
            respondJson(out, 500, "{\"error\":\"" + e.getMessage() + "\"}");
        }
    }

    /** scheduler v1: GET /file/{fileId}/verify - 整体文件校验 */
    private void handleFileVerify(OutputStream out, String fileId) throws IOException {
        // 查找文件并计算整体 SHA-256
        String sessionId = null;
        String fileName = null;
        synchronized (sessions) {
            for (Map.Entry<String, Map<String, SessionFile>> entry : sessions.entrySet()) {
                SessionFile f = entry.getValue().get(fileId);
                if (f != null) {
                    sessionId = entry.getKey();
                    fileName = f.fileName;
                    break;
                }
            }
        }

        if (fileName == null) {
            respondJson(out, 404, "{\"success\":false,\"reason\":\"file_not_found\"}");
            return;
        }

        try {
            DocumentFile root = DocumentFile.fromTreeUri(getContext(), Uri.parse(rootUri));
            DocumentFile targetFile = findFileRecursive(root, fileName);

            if (targetFile == null) {
                respondJson(out, 404, "{\"success\":false,\"reason\":\"file_not_found\"}");
                return;
            }

            // 计算整个文件的 SHA-256
            String fileSha256 = computeFileSha256(targetFile);
            respondJson(out, 200, "{\"success\":true,\"sha256\":\"" + fileSha256 + "\"}");
        } catch (Exception e) {
            Log.e(TAG, "handleFileVerify: 异常", e);
            respondJson(out, 422, "{\"success\":false,\"reason\":\"sha256_error: " + e.getMessage() + "\"}");
        }
    }

    /** 计算文件的 SHA-256（8KB 缓冲区） */
    private String computeFileSha256(DocumentFile file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream fis = getContext().getContentResolver().openInputStream(file.getUri())) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = fis.read(buf)) > 0) {
                md.update(buf, 0, n);
            }
        }
        byte[] digest = md.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /** 计算字节数组的 SHA-256 */
    private String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /** 递归查找文件 */
    private DocumentFile findFileRecursive(DocumentFile dir, String relPath) {
        if (relPath == null || relPath.isEmpty()) return null;
        String[] parts = relPath.split("/");
        DocumentFile current = dir;
        for (String part : parts) {
            if (part.isEmpty() || part.equals(".")) continue;
            if (current == null || !current.isDirectory()) return null;
            DocumentFile[] children = current.listFiles();
            DocumentFile next = null;
            for (DocumentFile child : children) {
                if (child.getName() != null && child.getName().equals(part)) {
                    next = child;
                    break;
                }
            }
            current = next;
        }
        return current;
    }
}
