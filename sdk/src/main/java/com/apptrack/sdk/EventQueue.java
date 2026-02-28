package com.apptrack.sdk;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class EventQueue {

    private static final String TAG         = "AppTrack.Queue";
    private static final String PREFS_QUEUE = "apptrack_queue";
    private static final String KEY_QUEUE   = "pending_events";
    private static final int    MAX_RETRY   = 3;
    private static final int    TIMEOUT_MS  = 10000;

    private static final ExecutorService executor = Executors.newSingleThreadExecutor();

    // ─── Enqueue ──────────────────────────────────────────────────────────
    public static void enqueue(Context context, String url, String apiKey,
                                Map<String, Object> payload) {
        saveToQueue(context, url, apiKey, payload);
        executor.execute(() -> flush(context));
    }

    // ─── Flush Queue ──────────────────────────────────────────────────────
    public static void flush(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(
            PREFS_QUEUE, Context.MODE_PRIVATE);
        String raw = prefs.getString(KEY_QUEUE, "[]");

        JSONArray queue;
        try { queue = new JSONArray(raw); }
        catch (Exception e) { queue = new JSONArray(); }

        if (queue.length() == 0) return;

        JSONArray remaining = new JSONArray();

        for (int i = 0; i < queue.length(); i++) {
            try {
                JSONObject item       = queue.getJSONObject(i);
                String itemUrl        = item.getString("url");
                String itemApiKey     = item.getString("api_key");
                JSONObject itemPayload = item.getJSONObject("payload");
                int retries           = item.optInt("retries", 0);

                boolean success = sendRequest(itemUrl, itemApiKey, itemPayload);

                if (!success && retries < MAX_RETRY) {
                    item.put("retries", retries + 1);
                    remaining.put(item);
                    Log.d(TAG, "Will retry: " + itemUrl + " attempt=" + (retries + 1));
                } else if (success) {
                    Log.d(TAG, "✅ Sent: " + itemUrl);
                } else {
                    Log.w(TAG, "❌ Max retries reached, dropping: " + itemUrl);
                }
            } catch (Exception e) {
                Log.e(TAG, "Queue error: " + e.getMessage());
            }
        }

        prefs.edit().putString(KEY_QUEUE, remaining.toString()).apply();
    }

    // ─── HTTP POST with AES-256 Encryption ───────────────────────────────
    private static boolean sendRequest(String urlStr, String apiKey, JSONObject payload) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("X-API-Key", apiKey);
            conn.setRequestProperty("Accept",    "application/json");
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setDoOutput(true);

            String jsonStr = payload.toString();

            // Encrypt payload
            String encrypted = PayloadEncryptor.encrypt(jsonStr, apiKey);

            byte[] body;
            if (encrypted != null) {
                // Send encrypted wrapper
                conn.setRequestProperty("Content-Type",       "application/json");
                conn.setRequestProperty("X-Payload-Encrypted", "1");
                JSONObject wrapper = new JSONObject();
                wrapper.put("enc", encrypted);
                body = wrapper.toString().getBytes(StandardCharsets.UTF_8);
                Log.d(TAG, "Sending encrypted payload");
            } else {
                // Fallback — plain JSON (should not happen)
                conn.setRequestProperty("Content-Type", "application/json");
                body = jsonStr.getBytes(StandardCharsets.UTF_8);
                Log.w(TAG, "Encryption failed, sending plain");
            }

            try (OutputStream os = conn.getOutputStream()) {
                os.write(body);
            }

            int code = conn.getResponseCode();
            Log.d(TAG, "Response: " + code + " → " + urlStr);
            return code >= 200 && code < 300;

        } catch (Exception e) {
            Log.e(TAG, "Request failed: " + e.getMessage());
            return false;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    // ─── Save to Queue ────────────────────────────────────────────────────
    private static void saveToQueue(Context context, String url, String apiKey,
                                     Map<String, Object> payload) {
        try {
            SharedPreferences prefs = context.getSharedPreferences(
                PREFS_QUEUE, Context.MODE_PRIVATE);
            String raw   = prefs.getString(KEY_QUEUE, "[]");
            JSONArray queue = new JSONArray(raw);

            JSONObject item = new JSONObject();
            item.put("url",       url);
            item.put("api_key",   apiKey);
            item.put("payload",   mapToJson(payload));
            item.put("retries",   0);
            item.put("queued_at", System.currentTimeMillis());

            queue.put(item);
            prefs.edit().putString(KEY_QUEUE, queue.toString()).apply();

        } catch (Exception e) {
            Log.e(TAG, "Save to queue failed: " + e.getMessage());
        }
    }

    // ─── Map → JSONObject ─────────────────────────────────────────────────
    @SuppressWarnings("unchecked")
    static JSONObject mapToJson(Map<String, Object> map) {
        JSONObject json = new JSONObject();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            try {
                Object val = entry.getValue();
                if (val instanceof Map) {
                    json.put(entry.getKey(), mapToJson((Map<String, Object>) val));
                } else if (val instanceof java.util.List) {
                    JSONArray arr = new JSONArray();
                    for (Object item : (java.util.List<?>) val) {
                        if (item instanceof Map) {
                            arr.put(mapToJson((Map<String, Object>) item));
                        } else {
                            arr.put(item);
                        }
                    }
                    json.put(entry.getKey(), arr);
                } else {
                    json.put(entry.getKey(), val);
                }
            } catch (Exception e) {
                Log.e(TAG, "JSON error: " + e.getMessage());
            }
        }
        return json;
    }
}
