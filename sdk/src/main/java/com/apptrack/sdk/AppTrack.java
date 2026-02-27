package com.apptrack.sdk;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * AppTrack MMP SDK
 * Usage:
 *   AppTrack.init(context, "oa_YOUR_API_KEY", "com.your.app");
 *   AppTrack.trackEvent(context, "level_complete", data);
 */
public class AppTrack {

    private static final String TAG = "AppTrack";
    private static final String PREFS_NAME = "apptrack_prefs";
    private static final String KEY_UID = "at_uid";
    private static final String KEY_INSTALL_DATE = "at_install_date";
    private static final String KEY_FIRST_LAUNCH = "at_first_launch";
    private static final String KEY_COUNTER = "at_counter";
    private static final String KEY_CLICKID = "at_clickid";
    private static final String KEY_CAMPAIGN_ID = "at_campaign_id";
    private static final String KEY_INSTALL_SENT = "at_install_sent";

    // ─── URL hardcoded in SDK ─────────────────────────────────────────────
    private static final String SERVER_URL = "https://track.apptrack.in";

    private static String apiKey;
    private static String appId;
    private static boolean isDebug = false;
    private static boolean initialized = false;

    // ─── Init ─────────────────────────────────────────────────────────────
    // Simple: user sirf apiKey aur appId deta hai
    public static void init(Context context, String apiKey, String appId) {
        AppTrack.apiKey  = apiKey;
        AppTrack.appId   = appId;
        AppTrack.initialized = true;

        // Auto-detect debug build
        try {
            int flags = context.getPackageManager()
                .getApplicationInfo(context.getPackageName(), 0).flags;
            AppTrack.isDebug = (flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        } catch (Exception e) {
            AppTrack.isDebug = false;
        }

        SharedPreferences prefs = getPrefs(context);

        // First launch setup
        if (!prefs.contains(KEY_INSTALL_DATE)) {
            prefs.edit()
                .putString(KEY_INSTALL_DATE, String.valueOf(System.currentTimeMillis()))
                .putString(KEY_FIRST_LAUNCH, String.valueOf(System.currentTimeMillis()))
                .apply();
        }

        // Launch counter
        int counter = prefs.getInt(KEY_COUNTER, 0) + 1;
        prefs.edit().putInt(KEY_COUNTER, counter).apply();

        Log.d(TAG, "AppTrack initialized | appId=" + appId
            + " counter=" + counter + " debug=" + isDebug);

        // Read referrer and send install (background)
        new Thread(() -> {
            ReferrerReceiver.readReferrer(context, (clickid, campaignId) -> {
                if (clickid != null) {
                    prefs.edit()
                        .putString(KEY_CLICKID, clickid)
                        .putString(KEY_CAMPAIGN_ID, campaignId != null ? campaignId : "")
                        .apply();
                    Log.d(TAG, "Referrer parsed | clickid=" + clickid);
                }
                if (!prefs.getBoolean(KEY_INSTALL_SENT, false)) {
                    sendInstall(context);
                }
            });
        }).start();
    }

    // ─── Track Event ──────────────────────────────────────────────────────
    public static void trackEvent(Context context, String eventName, Map<String, Object> data) {
        if (!initialized) {
            Log.w(TAG, "AppTrack not initialized!");
            return;
        }
        if (data == null) data = new HashMap<>();

        SharedPreferences prefs = getPrefs(context);
        String uid        = getOrCreateUid(prefs);
        String deviceId   = DeviceInfo.getDeviceId(context);
        String clickid    = prefs.getString(KEY_CLICKID, null);
        String campaignId = prefs.getString(KEY_CAMPAIGN_ID, null);
        String eventUuid  = UUID.randomUUID().toString();

        Map<String, Object> payload = new HashMap<>();
        payload.put("app_id",      appId);
        payload.put("uid",         uid);
        payload.put("device_id",   deviceId);
        payload.put("event_name",  eventName);
        payload.put("event_uuid",  eventUuid);
        payload.put("data",        data);
        payload.put("is_debug",    isDebug);   // ← debug flag

        if (clickid    != null) payload.put("clickid",     clickid);
        if (campaignId != null && !campaignId.isEmpty()) payload.put("campaign_id", campaignId);

        // GAID
        String gaid = DeviceInfo.getGAID(context);
        if (gaid != null) payload.put("advertising_id", gaid);

        // HMAC signature
        String sigPayload = uid + ":" + eventName + ":" + eventUuid;
        payload.put("sig", DeviceInfo.computeHMAC(sigPayload, apiKey));

        EventQueue.enqueue(context, SERVER_URL + "/v1/event", apiKey, payload);
        Log.d(TAG, "Event queued: " + eventName);
    }

    // Convenience — no data
    public static void trackEvent(Context context, String eventName) {
        trackEvent(context, eventName, new HashMap<>());
    }

    // ─── Send Install ─────────────────────────────────────────────────────
    private static void sendInstall(Context context) {
        SharedPreferences prefs = getPrefs(context);
        String uid        = getOrCreateUid(prefs);
        String deviceId   = DeviceInfo.getDeviceId(context);
        String clickid    = prefs.getString(KEY_CLICKID, null);
        String campaignId = prefs.getString(KEY_CAMPAIGN_ID, null);

        Map<String, Object> payload = new HashMap<>();
        payload.put("app_id",            appId);
        payload.put("uid",               uid);
        payload.put("device_id",         deviceId);
        payload.put("install_date",      prefs.getString(KEY_INSTALL_DATE, ""));
        payload.put("first_launch_date", prefs.getString(KEY_FIRST_LAUNCH, ""));
        payload.put("counter",           prefs.getInt(KEY_COUNTER, 1));
        payload.put("is_debug",          isDebug);   // ← debug flag — server fraud skip karega

        if (clickid    != null) payload.put("clickid",     clickid);
        if (campaignId != null && !campaignId.isEmpty()) payload.put("campaign_id", campaignId);

        // Device info for fraud detection
        payload.put("device_model",   Build.MODEL);
        payload.put("brand",          Build.BRAND);
        payload.put("cpu_abi",        Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "");
        payload.put("os_version",     String.valueOf(Build.VERSION.SDK_INT));
        payload.put("build_id",       Build.DISPLAY);
        payload.put("last_boot_time", System.currentTimeMillis() - android.os.SystemClock.elapsedRealtime());

        // GAID
        String gaid = DeviceInfo.getGAID(context);
        if (gaid != null) payload.put("advertising_id", gaid);

        // App Set ID
        String appSetId = DeviceInfo.getAppSetId(context);
        if (appSetId != null) payload.put("app_set_id", appSetId);

        // Network + carrier
        payload.put("network",         DeviceInfo.getNetworkType(context));
        payload.putAll(DeviceInfo.getCarrierInfo(context));

        // Install source
        payload.put("install_source",  DeviceInfo.getInstallSource(context));

        // IVC — Play Store se install hua ya nahi
        payload.put("ivc",             DeviceInfo.getIVC(context));

        // Sensors WITH values (sVS, sVE) — emulator detection
        payload.put("sensors",         DeviceInfo.getSensorList(context));

        // Screen info
        payload.put("screen",          DeviceInfo.getScreenInfo(context));

        // App version
        payload.put("app_version",     DeviceInfo.getAppVersion(context));

        // HMAC signature
        String sigPayload = uid + ":" + deviceId + ":" + appId;
        payload.put("sig", DeviceInfo.computeHMAC(sigPayload, apiKey));

        EventQueue.enqueue(context, SERVER_URL + "/v1/install", apiKey, payload);

        prefs.edit().putBoolean(KEY_INSTALL_SENT, true).apply();
        Log.d(TAG, "Install sent | uid=" + uid + " clickid=" + clickid
            + " debug=" + isDebug + " ivc=" + DeviceInfo.getIVC(context));
    }

    // ─── Helpers ──────────────────────────────────────────────────────────
    private static String getOrCreateUid(SharedPreferences prefs) {
        String uid = prefs.getString(KEY_UID, null);
        if (uid == null) {
            uid = System.currentTimeMillis() + "-" + Math.abs(UUID.randomUUID().getLeastSignificantBits());
            prefs.edit().putString(KEY_UID, uid).apply();
        }
        return uid;
    }

    private static SharedPreferences getPrefs(Context context) {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static String getUid(Context context) {
        return getPrefs(context).getString(KEY_UID, null);
    }

    public static boolean isInitialized() {
        return initialized;
    }

    public static boolean isDebugBuild() {
        return isDebug;
    }
}
