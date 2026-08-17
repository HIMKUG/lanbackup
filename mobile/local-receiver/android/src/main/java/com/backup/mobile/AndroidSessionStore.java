package com.backup.mobile;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * AndroidSessionStore - 三层状态会话存储
 *
 * 热状态（内存）：ConcurrentHashMap，实时更新的传输进度
 * 温状态（SharedPreferences）：会话元数据，重启后可恢复
 * 冷状态（SQLite）：历史传输记录，持久化归档
 *
 * 生命周期：
 * - 创建会话：热 → 温（定期刷入）
 * - 更新进度：热 → 温（定期刷入）
 * - 会话完成：热 → 温 → 冷（归档）
 * - 重启恢复：从温状态加载到热状态
 */
public class AndroidSessionStore {
    private static final String TAG = "AndroidSessionStore";
    private static final String PREFS_NAME = "session_store";
    private static final String KEY_SESSIONS = "sessions";
    private static final String KEY_ACTIVE_SESSION = "active_session_id";
    private static final String KEY_ACTIVE_SESSION_DATA = "active_session_data";

    // 定期刷入温状态的间隔（毫秒）
    private static final long FLUSH_INTERVAL_MS = 5000;

    private static AndroidSessionStore instance;

    // 热状态：内存缓存
    private final ConcurrentHashMap<String, SessionState> hotCache;

    // 活跃会话 ID
    private volatile String activeSessionId;

    // 温状态：SharedPreferences
    private final SharedPreferences prefs;

    // 冷状态：SQLite
    private final SessionDatabase db;

    // 定期刷入线程
    private final ScheduledExecutorService flushExecutor;

    // 主线程 Handler（用于回调）
    private final Handler mainHandler;

    // 待刷入的脏标记
    private final ConcurrentHashMap<String, Boolean> dirtySessions;

    public static synchronized AndroidSessionStore getInstance(Context context) {
        if (instance == null) {
            instance = new AndroidSessionStore(context.getApplicationContext());
        }
        return instance;
    }

    private AndroidSessionStore(Context context) {
        this.hotCache = new ConcurrentHashMap<>();
        this.dirtySessions = new ConcurrentHashMap<>();
        this.prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        this.db = SessionDatabase.getInstance(context);
        this.mainHandler = new Handler(Looper.getMainLooper());
        this.flushExecutor = Executors.newSingleThreadScheduledExecutor();

        // 定期刷入脏会话到温状态
        this.flushExecutor.scheduleAtFixedRate(() -> {
            try {
                flushDirtySessions();
            } catch (Exception e) {
                Log.e(TAG, "定期刷入失败", e);
            }
        }, FLUSH_INTERVAL_MS, FLUSH_INTERVAL_MS, TimeUnit.MILLISECONDS);

        // 从温状态恢复活跃会话
        restoreFromWarmState();

        Log.i(TAG, "AndroidSessionStore 初始化完成");
    }

    // ================================================================
    // ISessionStore 接口实现
    // ================================================================

    /**
     * 创建新会话
     */
    public void createSession(@NonNull SessionState session) {
        if (session.id == null || session.id.isEmpty()) {
            throw new IllegalArgumentException("session.id 不能为空");
        }

        // 写入热状态
        hotCache.put(session.id, session);
        activeSessionId = session.id;

        // 标记为脏，等待定期刷入
        dirtySessions.put(session.id, Boolean.TRUE);

        Log.d(TAG, "创建会话: " + session.id);
    }

    /**
     * 更新会话（部分更新）
     */
    public void updateSession(@NonNull String sessionId, @Nullable SessionUpdate update) {
        SessionState session = hotCache.get(sessionId);
        if (session == null) {
            Log.w(TAG, "更新会话失败，找不到: " + sessionId);
            return;
        }

        boolean modified = false;

        if (update.files != null) {
            session.files = update.files;
            modified = true;
        }
        if (update.peers != null) {
            session.peers = update.peers;
            modified = true;
        }
        if (update.progress != null) {
            session.progress = update.progress;
            modified = true;
        }
        if (update.status != null) {
            session.status = update.status;
            modified = true;
        }

        if (modified) {
            session.updatedAt = System.currentTimeMillis();
            dirtySessions.put(sessionId, Boolean.TRUE);
        }
    }

    /**
     * 获取指定会话
     */
    @Nullable
    public SessionState getSession(@NonNull String sessionId) {
        SessionState session = hotCache.get(sessionId);
        if (session != null) {
            return session;
        }

        // 尝试从温状态加载
        session = loadSessionFromWarmState(sessionId);
        if (session != null) {
            hotCache.put(sessionId, session);
        }
        return session;
    }

    /**
     * 列出所有会话
     */
    @NonNull
    public List<SessionState> listSessions() {
        return new ArrayList<>(hotCache.values());
    }

    /**
     * 删除会话
     */
    public void deleteSession(@NonNull String sessionId) {
        hotCache.remove(sessionId);
        dirtySessions.remove(sessionId);

        if (activeSessionId != null && activeSessionId.equals(sessionId)) {
            activeSessionId = null;
        }

        // 从温状态删除
        removeSessionFromWarmState(sessionId);

        Log.d(TAG, "删除会话: " + sessionId);
    }

    /**
     * 获取活跃会话
     */
    @Nullable
    public SessionState getActiveSession() {
        if (activeSessionId == null) {
            return null;
        }
        return getSession(activeSessionId);
    }

    /**
     * 设置活跃会话
     */
    public void setActiveSession(@Nullable String sessionId) {
        this.activeSessionId = sessionId;
        prefs.edit().putString(KEY_ACTIVE_SESSION, sessionId).apply();
    }

    /**
     * 批量更新进度
     */
    public void updateProgress(@NonNull String sessionId, @NonNull Map<String, TransferProgress> progress) {
        SessionState session = hotCache.get(sessionId);
        if (session == null) {
            Log.w(TAG, "更新进度失败，找不到会话: " + sessionId);
            return;
        }

        for (Map.Entry<String, TransferProgress> entry : progress.entrySet()) {
            session.progress.put(entry.getKey(), entry.getValue());
        }
        session.updatedAt = System.currentTimeMillis();
        dirtySessions.put(sessionId, Boolean.TRUE);
    }

    /**
     * 标记会话完成
     */
    public void completeSession(@NonNull String sessionId) {
        SessionState session = hotCache.get(sessionId);
        if (session != null) {
            session.status = SessionStatus.COMPLETED;
            session.updatedAt = System.currentTimeMillis();
            dirtySessions.put(sessionId, Boolean.TRUE);

            // 立即刷入冷状态
            archiveToColdState(session);
        }
    }

    /**
     * 标记会话失败
     */
    public void failSession(@NonNull String sessionId, @Nullable String error) {
        SessionState session = hotCache.get(sessionId);
        if (session != null) {
            session.status = SessionStatus.FAILED;
            session.updatedAt = System.currentTimeMillis();
            dirtySessions.put(sessionId, Boolean.TRUE);

            // 立即刷入冷状态
            archiveToColdState(session);
        }
    }

    /**
     * 销毁实例（应用退出时调用）
     */
    public void destroy() {
        flushExecutor.shutdown();
        try {
            flushDirtySessions();
        } catch (Exception e) {
            Log.e(TAG, "销毁前刷入失败", e);
        }
        instance = null;
    }

    // ================================================================
    // 内部方法
    // ================================================================

    /**
     * 定期刷入脏会话到温状态
     */
    private void flushDirtySessions() {
        if (dirtySessions.isEmpty()) {
            return;
        }

        for (String sessionId : dirtySessions.keySet()) {
            SessionState session = hotCache.get(sessionId);
            if (session != null) {
                saveSessionToWarmState(session);
            }
        }
        dirtySessions.clear();
    }

    /**
     * 保存会话到温状态（SharedPreferences）
     */
    private void saveSessionToWarmState(@NonNull SessionState session) {
        try {
            JSONObject json = sessionToJson(session);
            prefs.edit()
                    .putString(KEY_SESSIONS + "/" + session.id, json.toString())
                    .apply();

            if (session.id.equals(activeSessionId)) {
                prefs.edit().putString(KEY_ACTIVE_SESSION_DATA, json.toString()).apply();
            }
        } catch (Exception e) {
            Log.e(TAG, "保存会话到温状态失败: " + session.id, e);
        }
    }

    /**
     * 从温状态加载会话
     */
    @Nullable
    private SessionState loadSessionFromWarmState(@NonNull String sessionId) {
        String jsonStr = prefs.getString(KEY_SESSIONS + "/" + sessionId, null);
        if (jsonStr == null) {
            return null;
        }
        try {
            JSONObject json = new JSONObject(jsonStr);
            return jsonToSession(json);
        } catch (Exception e) {
            Log.e(TAG, "从温状态加载会话失败: " + sessionId, e);
            return null;
        }
    }

    /**
     * 从温状态删除会话
     */
    private void removeSessionFromWarmState(@NonNull String sessionId) {
        prefs.edit()
                .remove(KEY_SESSIONS + "/" + sessionId)
                .apply();
    }

    /**
     * 从温状态恢复活跃会话
     */
    private void restoreFromWarmState() {
        String savedActiveId = prefs.getString(KEY_ACTIVE_SESSION, null);
        if (savedActiveId != null) {
            activeSessionId = savedActiveId;
            SessionState session = loadSessionFromWarmState(savedActiveId);
            if (session != null) {
                hotCache.put(savedActiveId, session);
                Log.i(TAG, "从温状态恢复活跃会话: " + savedActiveId);
            }
        }
    }

    /**
     * 归档会话到冷状态（SQLite）
     */
    private void archiveToColdState(@NonNull SessionState session) {
        try {
            // 写入 sessions 表
            String filesJson = new JSONArray().toString();
            String peersJson = new JSONArray().toString();
            db.insertSession(
                    session.id,
                    filesJson,
                    peersJson,
                    session.createdAt
            );

            // 写入历史记录
            for (Map.Entry<String, TransferProgress> entry : session.progress.entrySet()) {
                TransferProgress p = entry.getValue();
                db.addTransferHistory(
                        session.id,
                        entry.getKey(),
                        p.totalBytes,
                        null, null
                );
            }

            // 从温状态删除（已归档）
            removeSessionFromWarmState(session.id);

            Log.i(TAG, "会话归档到冷状态: " + session.id);
        } catch (Exception e) {
            Log.e(TAG, "归档会话到冷状态失败: " + session.id, e);
        }
    }

    // ================================================================
    // JSON 序列化工具
    // ================================================================

    @NonNull
    private JSONObject sessionToJson(@NonNull SessionState session) throws JSONException {
        JSONObject json = new JSONObject();
        json.put("id", session.id);
        json.put("createdAt", session.createdAt);
        json.put("updatedAt", session.updatedAt);
        json.put("status", session.status.name().toLowerCase());

        JSONArray files = new JSONArray();
        if (session.files != null) {
            for (FileManifest f : session.files) {
                JSONObject fileJson = new JSONObject();
                fileJson.put("id", f.id);
                fileJson.put("fileName", f.fileName);
                fileJson.put("size", f.size);
                fileJson.put("sha256", f.sha256);
                files.put(fileJson);
            }
        }
        json.put("files", files);

        JSONArray peers = new JSONArray();
        if (session.peers != null) {
            for (PeerInfo p : session.peers) {
                JSONObject peerJson = new JSONObject();
                peerJson.put("peerId", p.peerId);
                peerJson.put("alias", p.alias);
                peerJson.put("ip", p.ip);
                peerJson.put("port", p.port);
                peerJson.put("status", p.status.name().toLowerCase());
                peers.put(peerJson);
            }
        }
        json.put("peers", peers);

        JSONObject progress = new JSONObject();
        if (session.progress != null) {
            for (Map.Entry<String, TransferProgress> entry : session.progress.entrySet()) {
                JSONObject pJson = new JSONObject();
                pJson.put("fileId", entry.getValue().fileId);
                pJson.put("sentBytes", entry.getValue().sentBytes);
                pJson.put("totalBytes", entry.getValue().totalBytes);
                pJson.put("piecesCompleted", entry.getValue().piecesCompleted);
                pJson.put("piecesTotal", entry.getValue().piecesTotal);
                pJson.put("retryCount", entry.getValue().retryCount);
                pJson.put("lastError", entry.getValue().lastError);
                progress.put(entry.getKey(), pJson);
            }
        }
        json.put("progress", progress);

        return json;
    }

    @NonNull
    private SessionState jsonToSession(@NonNull JSONObject json) throws JSONException {
        SessionState session = new SessionState();
        session.id = json.getString("id");
        session.createdAt = json.optLong("createdAt", System.currentTimeMillis());
        session.updatedAt = json.optLong("updatedAt", System.currentTimeMillis());
        session.status = SessionStatus.valueOf(json.optString("status", "active").toUpperCase());

        JSONArray files = json.optJSONArray("files");
        if (files != null) {
            session.files = new ArrayList<>();
            for (int i = 0; i < files.length(); i++) {
                JSONObject fJson = files.getJSONObject(i);
                FileManifest f = new FileManifest();
                f.id = fJson.getString("id");
                f.fileName = fJson.optString("fileName", "");
                f.size = fJson.optLong("size", 0);
                f.sha256 = fJson.optString("sha256", "");
                session.files.add(f);
            }
        }

        JSONArray peers = json.optJSONArray("peers");
        if (peers != null) {
            session.peers = new ArrayList<>();
            for (int i = 0; i < peers.length(); i++) {
                JSONObject pJson = peers.getJSONObject(i);
                PeerInfo p = new PeerInfo();
                p.peerId = pJson.getString("peerId");
                p.alias = pJson.optString("alias", "");
                p.ip = pJson.optString("ip", "");
                p.port = (short) pJson.optInt("port", 0);
                p.status = PeerStatus.valueOf(pJson.optString("status", "connected").toUpperCase());
                session.peers.add(p);
            }
        }

        JSONObject progress = json.optJSONObject("progress");
        if (progress != null) {
            session.progress = new HashMap<>();
            java.util.Iterator<String> keys = progress.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                JSONObject pJson = progress.getJSONObject(key);
                TransferProgress p = new TransferProgress();
                p.fileId = pJson.getString("fileId");
                p.sentBytes = pJson.optLong("sentBytes", 0);
                p.totalBytes = pJson.optLong("totalBytes", 0);
                p.piecesCompleted = (int) pJson.optLong("piecesCompleted", 0);
                p.piecesTotal = (int) pJson.optLong("piecesTotal", 0);
                p.retryCount = (int) pJson.optLong("retryCount", 0);
                p.lastError = pJson.has("lastError") && !pJson.isNull("lastError")
                        ? pJson.getString("lastError") : null;
                session.progress.put(key, p);
            }
        }

        return session;
    }

    // ================================================================
    // 类型定义（与 shared-core/src/session-store.ts 对齐）
    // ================================================================

    public enum SessionStatus {
        ACTIVE, COMPLETED, ABORTED, FAILED
    }

    public enum PeerStatus {
        CONNECTED, DISCONNECTED
    }

    public static class SessionState {
        public String id;
        public List<FileManifest> files = new ArrayList<>();
        public List<PeerInfo> peers = new ArrayList<>();
        public Map<String, TransferProgress> progress = new HashMap<>();
        public long createdAt;
        public long updatedAt;
        public SessionStatus status = SessionStatus.ACTIVE;
    }

    public static class FileManifest {
        public String id;
        public String fileName;
        public long size;
        public String sha256;
        public String merkleRoot;
        public List<String> pieceHashes;
        public long chunkSize;
    }

    public static class PeerInfo {
        public String peerId;
        public String alias;
        public String ip;
        public int port;
        public PeerStatus status = PeerStatus.CONNECTED;
    }

    public static class TransferProgress {
        public String fileId;
        public long sentBytes;
        public long totalBytes;
        public int piecesCompleted;
        public int piecesTotal;
        public int retryCount;
        public String lastError;
    }

    public static class SessionUpdate {
        public List<FileManifest> files;
        public List<PeerInfo> peers;
        public Map<String, TransferProgress> progress;
        public SessionStatus status;
    }
}
