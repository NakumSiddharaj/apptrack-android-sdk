package com.apptrack.sdk;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.SystemClock;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class AppTrack {

    private static final String TAG = "AppTrack";
    private static final String PREFS_NAME = "apptrack_prefs";
    private static final String KEY_UID           = "at_uid";
    private static final String KEY_INSTALL_DATE  = "at_install_date";
    private static final String KEY_FIRST_LAUNCH  = "at_first_launch";
    private static final String KEY_COUNTER       = "at_counter";
    private static final String KEY_CLICKID       = "at_clickid";
    private static final String KEY_CAMPAIGN_ID   = "at_campaign_id";
    private static final String KEY_INSTALL_SENT  = "at_install_sent";
    private static final String KEY_LAST_LAUNCH   = "at_last_launch";
    private static final String KEY_PREV_SESSION  = "at_prev_session";
    private static final String KEY_IA_COUNTER    = "at_ia_counter";

    private static final String SERVER_URL = "https://track.apptrack.in";

    private static String  apiKey;
    private static String  appId;
    private static boolean isDebug     = false;
    private static boolean initialized = false;
    private static long    sessionStart = 0;

    // ─── Init ─────────────────────────────────────────────────────────────
    public static void init(Context context, String apiKey, String appId) {
        AppTrack.apiKey       = apiKey;
        AppTrack.appId        = appId;
        AppTrack.initialized  = true;
        AppTrack.sessionStart = System.currentTimeMillis();

        try {
            int flags = context.getPackageManager()
                .getApplicationInfo(context.getPackageName(), 0).flags;
            AppTrack.isDebug =
                (flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        } catch (Exception e) { AppTrack.isDebug = false; }

        SharedPreferences prefs = getPrefs(context);

        if (!prefs.contains(KEY_INSTALL_DATE)) {
            prefs.edit()
                .putString(KEY_INSTALL_DATE, String.valueOf(System.currentTimeMillis()))
                .putString(KEY_FIRST_LAUNCH,  String.valueOf(System.currentTimeMillis()))
                .apply();
        }

        int  counter      = prefs.getInt(KEY_COUNTER,    0) + 1;
        int  iaCounter    = prefs.getInt(KEY_IA_COUNTER, 0) + 1;
        long lastLaunch   = prefs.getLong(KEY_LAST_LAUNCH, 0);
        long prevSession  = prefs.getLong(KEY_PREV_SESSION, 0);
        long timeSinceLast = lastLaunch > 0
            ? (System.currentTimeMillis() - lastLaunch) / 1000 : 0;

        prefs.edit()
            .putInt(KEY_COUNTER,      counter)
            .putInt(KEY_IA_COUNTER,   iaCounter)
            .putLong(KEY_LAST_LAUNCH, System.currentTimeMillis())
            .apply();

        Log.d(TAG, "AppTrack initialized | appId=" + appId
            + " counter=" + counter + " debug=" + isDebug);

        final long finalTimeSinceLast = timeSinceLast;
        final long finalPrevSession   = prevSession;
        final int  finalIaCounter     = iaCounter;

        new Thread(() -> {
            ReferrerReceiver.readReferrer(context, (clickid, campaignId) -> {
                if (clickid != null) {
                    prefs.edit()
                        .putString(KEY_CLICKID,     clickid)
                        .putString(KEY_CAMPAIGN_ID, campaignId != null ? campaignId : "")
                        .apply();
                    Log.d(TAG, "Referrer parsed | clickid=" + clickid);
                }
                if (!prefs.getBoolean(KEY_INSTALL_SENT, false)) {
                    sendInstall(context, finalTimeSinceLast,
                        finalPrevSession, finalIaCounter);
                }
            });
        }).start();
    }

    // ─── Track Event ──────────────────────────────────────────────────────
    public static void trackEvent(Context context, String eventName,
                                   Map<String, Object> data) {
        if (!initialized) { Log.w(TAG, "Not initialized!"); return; }
        if (data == null) data = new HashMap<>();

        SharedPreferences prefs    = getPrefs(context);
        String uid        = getOrCreateUid(prefs);
        String deviceId   = DeviceInfo.getDeviceId(context);
        String clickid    = prefs.getString(KEY_CLICKID,    null);
        String campaignId = prefs.getString(KEY_CAMPAIGN_ID, null);
        String eventUuid  = UUID.randomUUID().toString();

        Map<String, Object> payload = new HashMap<>();
        payload.put("app_id",     appId);
        payload.put("uid",        uid);
        payload.put("device_id",  deviceId);
        payload.put("event_name", eventName);
        payload.put("event_uuid", eventUuid);
        payload.put("data",       data);
        payload.put("is_debug",   isDebug);

        if (clickid    != null) payload.put("clickid",     clickid);
        if (campaignId != null && !campaignId.isEmpty())
            payload.put("campaign_id", campaignId);

        String gaid = DeviceInfo.getGAID(context);
        if (gaid != null) payload.put("advertising_id", gaid);

        String sigPayload = uid + ":" + eventName + ":" + eventUuid;
        payload.put("sig", DeviceInfo.computeHMAC(sigPayload, apiKey));

        EventQueue.enqueue(context, SERVER_URL + "/v1/event", apiKey, payload);
        Log.d(TAG, "Event queued: " + eventName);
    }

    public static void trackEvent(Context context, String eventName) {
        trackEvent(context, eventName, new HashMap<>());
    }

    // ─── Send Install ─────────────────────────────────────────────────────
    private static void sendInstall(Context context, long timeSinceLast,
                                     long prevSessionDur, int iaCounter) {
        SharedPreferences prefs = getPrefs(context);
        String uid        = getOrCreateUid(prefs);
        String deviceId   = DeviceInfo.getDeviceId(context);
        String clickid    = prefs.getString(KEY_CLICKID,    null);
        String campaignId = prefs.getString(KEY_CAMPAIGN_ID, null);

        Map<String, Object> payload = new HashMap<>();

        // ── Core ──────────────────────────────────────────────────────────
        payload.put("app_id",            appId);
        payload.put("uid",               uid);
        payload.put("device_id",         deviceId);
        payload.put("install_date",      prefs.getString(KEY_INSTALL_DATE, ""));
        payload.put("first_launch_date", prefs.getString(KEY_FIRST_LAUNCH, ""));
        payload.put("counter",           prefs.getInt(KEY_COUNTER, 1));
        payload.put("is_debug",          isDebug);

        if (clickid    != null) payload.put("clickid",     clickid);
        if (campaignId != null && !campaignId.isEmpty())
            payload.put("campaign_id", campaignId);

        // ── Device Hardware ───────────────────────────────────────────────
        payload.put("device_model",  Build.MODEL);
        payload.put("brand",         Build.BRAND);
        payload.put("product",       Build.PRODUCT);
        payload.put("device",        Build.DEVICE);
        payload.put("cpu_abi",       Build.SUPPORTED_ABIS.length > 0
                                         ? Build.SUPPORTED_ABIS[0] : "");
        payload.put("cpu_abi2",      DeviceInfo.getCpuAbi2());
        payload.put("arch",          DeviceInfo.getCpuArch());
        payload.put("build_id",      Build.DISPLAY);
        payload.put("os_version",    String.valueOf(Build.VERSION.SDK_INT));
        payload.put("os_release",    Build.VERSION.RELEASE);
        payload.put("target_sdk",    DeviceInfo.getTargetSdkVersion(context));
        payload.put("last_boot_time",
            System.currentTimeMillis() - SystemClock.elapsedRealtime());

        // ── Battery ───────────────────────────────────────────────────────
        float battery = DeviceInfo.getBatteryLevel(context);
        if (battery >= 0) payload.put("battery_level", battery);

        // ── Disk ──────────────────────────────────────────────────────────
        Map<String, Long> disk = DeviceInfo.getDiskInfo();
        if (!disk.isEmpty()) {
            payload.put("disk_free",  disk.get("free_mb"));
            payload.put("disk_total", disk.get("total_mb"));
        }

        // ── Language ──────────────────────────────────────────────────────
        payload.put("lang",      DeviceInfo.getLanguage(context));
        payload.put("lang_code", DeviceInfo.getLanguageCode(context));

        // ── Country ───────────────────────────────────────────────────────
        String country = DeviceInfo.getCountry(context);
        if (country != null) payload.put("country", country);

        // ── Session ───────────────────────────────────────────────────────
        payload.put("time_since_last_launch", timeSinceLast);
        payload.put("prev_session_dur",       prevSessionDur);
        payload.put("ia_counter",             iaCounter);

        // ── App Info ──────────────────────────────────────────────────────
        payload.put("app_version",      DeviceInfo.getAppVersion(context));
        payload.put("app_version_code", DeviceInfo.getAppVersionCode(context));
        payload.put("is_preinstalled",  DeviceInfo.isPreinstalled(context));

        // ── GAID ──────────────────────────────────────────────────────────
        String gaid = DeviceInfo.getGAID(context);
        if (gaid != null) {
            payload.put("advertising_id",        gaid);
            payload.put("advertiser_id_enabled", DeviceInfo.isGaidWithGps(context));
        }

        // ── App Set ID ────────────────────────────────────────────────────
        String appSetId = DeviceInfo.getAppSetId(context);
        if (appSetId != null) payload.put("app_set_id", appSetId);

        // ── Network + Carrier ─────────────────────────────────────────────
        payload.put("network", DeviceInfo.getNetworkType(context));
        payload.putAll(DeviceInfo.getCarrierInfo(context));

        // ── Install Source ────────────────────────────────────────────────
        payload.put("install_source", DeviceInfo.getInstallSource(context));

        // ── Open Referrer ─────────────────────────────────────────────────
        String openRef = DeviceInfo.getOpenReferrer(context);
        if (openRef != null) payload.put("open_referrer", openRef);

        // ── IVC ───────────────────────────────────────────────────────────
        payload.put("ivc", DeviceInfo.getIVC(context));

        // ── Sensors ───────────────────────────────────────────────────────
        payload.put("sensors", DeviceInfo.getSensorList(context));

        // ── Screen ────────────────────────────────────────────────────────
        payload.put("screen", DeviceInfo.getScreenInfo(context));

        // ── HMAC ──────────────────────────────────────────────────────────
        String sigPayload = uid + ":" + deviceId + ":" + appId;
        payload.put("sig", DeviceInfo.computeHMAC(sigPayload, apiKey));

        // ── Play Integrity — last step, send after token ──────────────────
        final String finalUid      = uid;
        final String finalClickid  = clickid;
        final float  finalBattery  = battery;
        final String finalCountry  = country;

        PlayIntegrity.getToken(context, (token, err) -> {
            if (token != null) {
                payload.put("integrity_token", token);
                Log.d(TAG, "Play Integrity ✅");
            } else {
                Log.d(TAG, "Play Integrity unavailable: " + err);
            }

            EventQueue.enqueue(context, SERVER_URL + "/v1/install", apiKey, payload);
            prefs.edit().putBoolean(KEY_INSTALL_SENT, true).apply();

            Log.d(TAG, "Install sent | uid=" + finalUid
                + " clickid=" + finalClickid
                + " debug=" + isDebug
                + " ivc=" + DeviceInfo.getIVC(context)
                + " battery=" + finalBattery
                + " country=" + finalCountry);
        });
    }

    // ─── Session end ──────────────────────────────────────────────────────
    public static void onPause(Context context) {
        if (sessionStart > 0) {
            long dur = (System.currentTimeMillis() - sessionStart) / 1000;
            getPrefs(context).edit().putLong(KEY_PREV_SESSION, dur).apply();
        }
    }

    // ─── Helpers ──────────────────────────────────────────────────────────
    private static String getOrCreateUid(SharedPreferences prefs) {
        String uid = prefs.getString(KEY_UID, null);
        if (uid == null) {
            uid = System.currentTimeMillis() + "-"
                + Math.abs(UUID.randomUUID().getLeastSignificantBits());
            prefs.edit().putString(KEY_UID, uid).apply();
        }
        return uid;
    }

    private static SharedPreferences getPrefs(Context context) {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static String  getUid(Context context) {
        return getPrefs(context).getString(KEY_UID, null);
    }
    public static boolean isInitialized() { return initialized; }
    public static boolean isDebugBuild()  { return isDebug; }
}
