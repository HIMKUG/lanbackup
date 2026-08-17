package com.backup.mobile;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;

import androidx.annotation.Nullable;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * SessionDatabase - 冷状态持久化（SQLite WAL 模式）
 *
 * 存储历史传输记录，与 DataStore（温状态）配合使用。
 *
 * 三层状态分离：
 * - 热状态（内存）：传输中的实时进度
 * - 温状态（DataStore）：会话元数据，可恢复
 * - 冷状态（SQLite）：历史记录，持久化归档
 */
public class SessionDatabase extends SQLiteOpenHelper {
    private static final String TAG = "SessionDatabase";
    private static final String DATABASE_NAME = "backup_sessions.db";
    private static final int DATABASE_VERSION = 1;

    // 表名
    private static final String TABLE_SESSIONS = "sessions";
    private static final String TABLE_TRANSFER_HISTORY = "transfer_history";

    // sessions 表字段
    private static final String COL_SESSION_ID = "session_id";
    private static final String COL_FILES = "files";           // JSON array
    private static final String COL_PEERS = "peers";           // JSON array
    private static final String COL_STATUS = "status";          // active/completed/aborted/failed
    private static final String COL_CREATED_AT = "created_at";
    private static final String COL_UPDATED_AT = "updated_at";

    // transfer_history 表字段
    private static final String COL_HISTORY_ID = "id";
    private static final String COL_HISTORY_SESSION_ID = "session_id";
    private static final String COL_FILE_NAME = "file_name";
    private static final String COL_FILE_SIZE = "file_size";
    private static final String COL_SENDER_IP = "sender_ip";
    private static final String COL_SENDER_NAME = "sender_name";
    private static final String COL_COMPLETED_AT = "completed_at";
    private static final String COL_ERROR = "error";           // nullable

    private static SessionDatabase instance;

    public static synchronized SessionDatabase getInstance(Context context) {
        if (instance == null) {
            instance = new SessionDatabase(context.getApplicationContext());
        }
        return instance;
    }

    private SessionDatabase(@Nullable Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        // 启用 WAL 模式（写入并发更好）
        db.execSQL("PRAGMA journal_mode=WAL");
        // busy_timeout 防止锁等待
        db.execSQL("PRAGMA busy_timeout=5000");
        // synchronous=NORMAL（WAL 模式下安全且更快）
        db.execSQL("PRAGMA synchronous=NORMAL");

        // sessions 表：会话元数据
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_SESSIONS + " ("
                + COL_SESSION_ID + " TEXT PRIMARY KEY,"
                + COL_FILES + " TEXT,"          // JSON array of file manifests
                + COL_PEERS + " TEXT,"           // JSON array of peer info
                + COL_STATUS + " TEXT NOT NULL DEFAULT 'active',"
                + COL_CREATED_AT + " INTEGER NOT NULL,"
                + COL_UPDATED_AT + " INTEGER NOT NULL"
                + ")");

        // transfer_history 表：历史传输记录
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_TRANSFER_HISTORY + " ("
                + COL_HISTORY_ID + " INTEGER PRIMARY KEY AUTOINCREMENT,"
                + COL_HISTORY_SESSION_ID + " TEXT NOT NULL,"
                + COL_FILE_NAME + " TEXT NOT NULL,"
                + COL_FILE_SIZE + " INTEGER NOT NULL,"
                + COL_SENDER_IP + " TEXT,"
                + COL_SENDER_NAME + " TEXT,"
                + COL_COMPLETED_AT + " INTEGER NOT NULL,"
                + COL_ERROR + " TEXT,"
                + "FOREIGN KEY(" + COL_HISTORY_SESSION_ID + ") REFERENCES " + TABLE_SESSIONS + "(" + COL_SESSION_ID + ")"
                + ")");

        // 索引：按时间查询历史记录
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_history_completed ON " + TABLE_TRANSFER_HISTORY + "(" + COL_COMPLETED_AT + " DESC)");
        // 索引：按 session 查询
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_history_session ON " + TABLE_TRANSFER_HISTORY + "(" + COL_HISTORY_SESSION_ID + ")");

        Log.i(TAG, "SessionDatabase 创建完成（WAL 模式）");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        // 未来版本升级逻辑
        Log.w(TAG, "SessionDatabase 升级: " + oldVersion + " -> " + newVersion);
    }

    // ================================================================
    // 会话操作
    // ================================================================

    /**
     * 插入新会话
     */
    public long insertSession(String sessionId, String filesJson, String peersJson, long createdAt) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(COL_SESSION_ID, sessionId);
        values.put(COL_FILES, filesJson);
        values.put(COL_PEERS, peersJson);
        values.put(COL_STATUS, "active");
        values.put(COL_CREATED_AT, createdAt);
        values.put(COL_UPDATED_AT, createdAt);
        return db.insertWithOnConflict(TABLE_SESSIONS, null, values, SQLiteDatabase.CONFLICT_REPLACE);
    }

    /**
     * 更新会话状态
     */
    public int updateSessionStatus(String sessionId, String status) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(COL_STATUS, status);
        values.put(COL_UPDATED_AT, System.currentTimeMillis());
        return db.update(TABLE_SESSIONS, values, COL_SESSION_ID + " = ?", new String[]{sessionId});
    }

    /**
     * 获取活跃会话列表
     */
    public List<String> getActiveSessionIds() {
        List<String> result = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.query(TABLE_SESSIONS,
                new String[]{COL_SESSION_ID},
                COL_STATUS + " = ?",
                new String[]{"active"},
                null, null,
                COL_CREATED_AT + " DESC");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                result.add(cursor.getString(0));
            }
            cursor.close();
        }
        return result;
    }

    /**
     * 获取会话元数据
     */
    @Nullable
    public SessionRecord getSession(String sessionId) {
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.query(TABLE_SESSIONS,
                null,
                COL_SESSION_ID + " = ?",
                new String[]{sessionId},
                null, null, null);
        if (cursor == null) return null;
        try {
            if (cursor.moveToFirst()) {
                return new SessionRecord(
                        cursor.getString(cursor.getColumnIndexOrThrow(COL_SESSION_ID)),
                        cursor.getString(cursor.getColumnIndexOrThrow(COL_FILES)),
                        cursor.getString(cursor.getColumnIndexOrThrow(COL_PEERS)),
                        cursor.getString(cursor.getColumnIndexOrThrow(COL_STATUS)),
                        cursor.getLong(cursor.getColumnIndexOrThrow(COL_CREATED_AT)),
                        cursor.getLong(cursor.getColumnIndexOrThrow(COL_UPDATED_AT))
                );
            }
            return null;
        } finally {
            cursor.close();
        }
    }

    /**
     * 删除会话及其关联历史
     */
    public int deleteSession(String sessionId) {
        SQLiteDatabase db = getWritableDatabase();
        db.delete(TABLE_TRANSFER_HISTORY, COL_HISTORY_SESSION_ID + " = ?", new String[]{sessionId});
        return db.delete(TABLE_SESSIONS, COL_SESSION_ID + " = ?", new String[]{sessionId});
    }

    // ================================================================
    // 历史记录操作
    // ================================================================

    /**
     * 添加传输历史记录
     */
    public long addTransferHistory(String sessionId, String fileName, long fileSize,
                                   @Nullable String senderIp, @Nullable String senderName) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(COL_HISTORY_SESSION_ID, sessionId);
        values.put(COL_FILE_NAME, fileName);
        values.put(COL_FILE_SIZE, fileSize);
        values.put(COL_SENDER_IP, senderIp);
        values.put(COL_SENDER_NAME, senderName);
        values.put(COL_COMPLETED_AT, System.currentTimeMillis());
        return db.insert(TABLE_TRANSFER_HISTORY, null, values);
    }

    /**
     * 添加失败记录
     */
    public long addFailedTransfer(String sessionId, String fileName, long fileSize,
                                  @Nullable String senderIp, @Nullable String senderName,
                                  @Nullable String error) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(COL_HISTORY_SESSION_ID, sessionId);
        values.put(COL_FILE_NAME, fileName);
        values.put(COL_FILE_SIZE, fileSize);
        values.put(COL_SENDER_IP, senderIp);
        values.put(COL_SENDER_NAME, senderName);
        values.put(COL_COMPLETED_AT, System.currentTimeMillis());
        values.put(COL_ERROR, error);
        return db.insert(TABLE_TRANSFER_HISTORY, null, values);
    }

    /**
     * 获取最近的历史记录（分页）
     */
    public List<TransferHistoryRecord> getRecentHistory(int limit, int offset) {
        List<TransferHistoryRecord> result = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.query(TABLE_TRANSFER_HISTORY,
                null, null, null, null, null,
                COL_COMPLETED_AT + " DESC",
                String.valueOf(limit));
        if (cursor != null) {
            while (cursor.moveToNext()) {
                result.add(new TransferHistoryRecord(
                        cursor.getLong(cursor.getColumnIndexOrThrow(COL_HISTORY_ID)),
                        cursor.getString(cursor.getColumnIndexOrThrow(COL_HISTORY_SESSION_ID)),
                        cursor.getString(cursor.getColumnIndexOrThrow(COL_FILE_NAME)),
                        cursor.getLong(cursor.getColumnIndexOrThrow(COL_FILE_SIZE)),
                        cursor.isNull(cursor.getColumnIndexOrThrow(COL_SENDER_IP)) ? null : cursor.getString(cursor.getColumnIndexOrThrow(COL_SENDER_IP)),
                        cursor.isNull(cursor.getColumnIndexOrThrow(COL_SENDER_NAME)) ? null : cursor.getString(cursor.getColumnIndexOrThrow(COL_SENDER_NAME)),
                        cursor.getLong(cursor.getColumnIndexOrThrow(COL_COMPLETED_AT)),
                        cursor.isNull(cursor.getColumnIndexOrThrow(COL_ERROR)) ? null : cursor.getString(cursor.getColumnIndexOrThrow(COL_ERROR))
                ));
            }
            cursor.close();
        }
        return result;
    }

    // ================================================================
    // 记录类型
    // ================================================================

    public static class SessionRecord {
        public final String sessionId;
        public final String filesJson;
        public final String peersJson;
        public final String status;
        public final long createdAt;
        public final long updatedAt;

        public SessionRecord(String sessionId, String filesJson, String peersJson,
                            String status, long createdAt, long updatedAt) {
            this.sessionId = sessionId;
            this.filesJson = filesJson;
            this.peersJson = peersJson;
            this.status = status;
            this.createdAt = createdAt;
            this.updatedAt = updatedAt;
        }
    }

    public static class TransferHistoryRecord {
        public final long id;
        public final String sessionId;
        public final String fileName;
        public final long fileSize;
        @Nullable public final String senderIp;
        @Nullable public final String senderName;
        public final long completedAt;
        @Nullable public final String error;

        public TransferHistoryRecord(long id, String sessionId, String fileName, long fileSize,
                                     @Nullable String senderIp, @Nullable String senderName,
                                     long completedAt, @Nullable String error) {
            this.id = id;
            this.sessionId = sessionId;
            this.fileName = fileName;
            this.fileSize = fileSize;
            this.senderIp = senderIp;
            this.senderName = senderName;
            this.completedAt = completedAt;
            this.error = error;
        }
    }
}
