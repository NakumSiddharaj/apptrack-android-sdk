package com.apptrack.sdk;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.DisplayMetrics;
import android.view.WindowManager;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class DeviceInfo {

    private static String cachedGaid = null;
    private static String cachedAppSetId = null;

    // ─── GAID (Google Advertising ID) ────────────────────
    public static String getGAID(Context context) {
        if (cachedGaid != null) return cachedGaid;
        try {
            // Use reflection — no compile-time dependency on play-services
            Class<?> adIdClient = Class.forName("com.google.android.gms.ads.identifier.AdvertisingIdClient");
            Method getAdInfo = adIdClient.getMethod("getAdvertisingIdInfo", Context.class);
            Object adInfo = getAdInfo.invoke(null, context);
            Method getId = adInfo.getClass().getMethod("getId");
            Method isLimitAd = adInfo.getClass().getMethod("isLimitAdTrackingEnabled");
            String id = (String) getId.invoke(adInfo);
            boolean limited = (boolean) isLimitAd.invoke(adInfo);
            if (!limited && id != null) {
                cachedGaid = id;
                return id;
            }
        } catch (Exception e) {
            // GAID not available
        }
        return null;
    }

    // ─── App Set ID (Google fraud signal) ─────────────────
    public static String getAppSetId(Context context) {
        if (cachedAppSetId != null) return cachedAppSetId;
        try {
            Class<?> appSetIdClient = Class.forName("com.google.android.gms.appset.AppSet");
            Method getClient = appSetIdClient.getMethod("getClient", Context.class);
            Object client = getClient.invoke(null, context);
            // Simplified — returns null if not available
        } catch (Exception e) {
            // Not available
        }
        return null;
    }

    // ─── Stable Device ID ────────────────────────────────
    public static String getDeviceId(Context context) {
        try {
            String androidId = Settings.Secure.getString(
                context.getContentResolver(),
                Settings.Secure.ANDROID_ID
            );
            if (androidId != null && !androidId.equals("9774d56d682e549c")) {
                return androidId;
            }
        } catch (Exception e) { }
        // Fallback — UUID stored in prefs
        android.content.SharedPreferences prefs = context.getSharedPreferences(
            "apptrack_device", Context.MODE_PRIVATE);
        String stored = prefs.getString("device_id", null);
        if (stored == null) {
            stored = UUID.randomUUID().toString();
            prefs.edit().putString("device_id", stored).apply();
        }
        return stored;
    }

    // ─── Sensor List (emulator detection) ─────────────────
    public static List<Map<String, Object>> getSensorList(Context context) {
        List<Map<String, Object>> sensors = new ArrayList<>();
        try {
            SensorManager sm = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
            if (sm != null) {
                // Only key sensors
                int[] types = {
                    Sensor.TYPE_ACCELEROMETER,
                    Sensor.TYPE_MAGNETIC_FIELD,
                    Sensor.TYPE_GYROSCOPE
                };
                for (int type : types) {
                    Sensor s = sm.getDefaultSensor(type);
                    if (s != null) {
                        Map<String, Object> info = new HashMap<>();
                        info.put("sT", type);
                        info.put("sN", s.getName());
                        info.put("sV", s.getVendor());
                        sensors.add(info);
                    }
                }
            }
        } catch (Exception e) { }
        return sensors;
    }

    // ─── Network Type ─────────────────────────────────────
    public static String getNetworkType(Context context) {
        try {
            ConnectivityManager cm = (ConnectivityManager)
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                NetworkInfo info = cm.getActiveNetworkInfo();
                if (info != null && info.isConnected()) {
                    return info.getType() == ConnectivityManager.TYPE_WIFI ? "WIFI" : "CELLULAR";
                }
            }
        } catch (Exception e) { }
        return "UNKNOWN";
    }

    // ─── Carrier Info ─────────────────────────────────────
    public static Map<String, String> getCarrierInfo(Context context) {
        Map<String, String> info = new HashMap<>();
        try {
            TelephonyManager tm = (TelephonyManager)
                context.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm != null) {
                info.put("carrier", tm.getNetworkOperatorName());
                String operator = tm.getNetworkOperator();
                if (operator != null && operator.length() >= 5) {
                    info.put("mcc", operator.substring(0, 3));
                    info.put("mnc", operator.substring(3));
                }
            }
        } catch (Exception e) { }
        return info;
    }

    // ─── Install Source ───────────────────────────────────
    public static String getInstallSource(Context context) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                PackageManager pm = context.getPackageManager();
                var info = pm.getInstallSourceInfo(context.getPackageName());
                String src = info.getInitiatingPackageName();
                return src != null ? src : "unknown";
            } else {
                String src = context.getPackageManager()
                    .getInstallerPackageName(context.getPackageName());
                return src != null ? src : "unknown";
            }
        } catch (Exception e) {
            return "unknown";
        }
    }

    // ─── App Version ──────────────────────────────────────
    public static String getAppVersion(Context context) {
        try {
            PackageInfo pi = context.getPackageManager()
                .getPackageInfo(context.getPackageName(), 0);
            return pi.versionName;
        } catch (Exception e) {
            return "unknown";
        }
    }

    // ─── Screen Info ──────────────────────────────────────
    public static Map<String, Object> getScreenInfo(Context context) {
        Map<String, Object> screen = new HashMap<>();
        try {
            DisplayMetrics dm = new DisplayMetrics();
            WindowManager wm = (WindowManager) context.getSystemService(Context.WINDOW_SERVICE);
            if (wm != null) {
                wm.getDefaultDisplay().getMetrics(dm);
                screen.put("x_px", dm.widthPixels);
                screen.put("y_px", dm.heightPixels);
                screen.put("dpi",  dm.densityDpi);
            }
        } catch (Exception e) { }
        return screen;
    }

    // ─── Full Device Summary ──────────────────────────────
    public static Map<String, Object> getFullDeviceInfo(Context context) {
        Map<String, Object> info = new HashMap<>();
        info.put("model",       Build.MODEL);
        info.put("brand",       Build.BRAND);
        info.put("device",      Build.DEVICE);
        info.put("product",     Build.PRODUCT);
        info.put("cpu_abi",     Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "");
        info.put("sdk",         Build.VERSION.SDK_INT);
        info.put("os_version",  Build.VERSION.RELEASE);
        info.put("build_id",    Build.DISPLAY);
        info.put("sensors",     getSensorList(context));
        info.put("network",     getNetworkType(context));
        info.put("screen",      getScreenInfo(context));
        info.putAll(getCarrierInfo(context));
        return info;
    }
}
