package com.apptrack.sdk;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.DisplayMetrics;
import android.view.WindowManager;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class DeviceInfo {

    private static String cachedGaid = null;
    private static float[] lastAccelerometer = null;
    private static float[] lastGyroscope = null;
    private static float[] lastMagnetic = null;

    // ─── GAID ────────────────────────────────────────────────────────────
    public static String getGAID(Context context) {
        if (cachedGaid != null) return cachedGaid;
        try {
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
        } catch (Exception e) { }
        return null;
    }

    // ─── App Set ID ───────────────────────────────────────────────────────
    public static String getAppSetId(Context context) {
        try {
            Class<?> appSetIdClient = Class.forName("com.google.android.gms.appset.AppSet");
            Method getClient = appSetIdClient.getMethod("getClient", Context.class);
            getClient.invoke(null, context);
        } catch (Exception e) { }
        return null;
    }

    // ─── Stable Device ID ─────────────────────────────────────────────────
    public static String getDeviceId(Context context) {
        try {
            String androidId = Settings.Secure.getString(
                context.getContentResolver(), Settings.Secure.ANDROID_ID);
            if (androidId != null && !androidId.equals("9774d56d682e549c")) {
                return androidId;
            }
        } catch (Exception e) { }
        android.content.SharedPreferences prefs = context.getSharedPreferences(
            "apptrack_device", Context.MODE_PRIVATE);
        String stored = prefs.getString("device_id", null);
        if (stored == null) {
            stored = UUID.randomUUID().toString();
            prefs.edit().putString("device_id", stored).apply();
        }
        return stored;
    }

    // ─── Sensor List WITH VALUES (sVS, sVE) ──────────────────────────────
    // AppsFlyer style: sVS = sensor values start, sVE = sensor values end
    public static List<Map<String, Object>> getSensorList(Context context) {
        List<Map<String, Object>> sensors = new ArrayList<>();
        try {
            SensorManager sm = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
            if (sm == null) return sensors;

            // Read current sensor values (one-shot)
            readSensorValues(sm);

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

                    // Add sensor values like AppsFlyer does
                    float[] vals = getSensorValues(type);
                    if (vals != null) {
                        List<Float> vList = new ArrayList<>();
                        for (float v : vals) vList.add(v);
                        info.put("sVS", vList);  // start values
                        info.put("sVE", vList);  // end values (same for simplicity)
                    }
                    sensors.add(info);
                }
            }
        } catch (Exception e) { }
        return sensors;
    }

    private static void readSensorValues(SensorManager sm) {
        try {
            // Read accelerometer
            Sensor accel = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);
            if (accel != null) {
                sm.registerListener(new SensorEventListener() {
                    @Override
                    public void onSensorChanged(SensorEvent event) {
                        lastAccelerometer = event.values.clone();
                        ((SensorManager) event.sensor.getClass()
                            .getDeclaredMethod("getSystemService")
                            .invoke(null)).unregisterListener(this);
                    }
                    @Override public void onAccuracyChanged(Sensor s, int a) {}
                }, accel, SensorManager.SENSOR_DELAY_FASTEST);
            }
        } catch (Exception e) {
            // Silent — sensor read is best-effort
        }
    }

    private static float[] getSensorValues(int type) {
        switch (type) {
            case Sensor.TYPE_ACCELEROMETER: return lastAccelerometer;
            case Sensor.TYPE_GYROSCOPE:     return lastGyroscope;
            case Sensor.TYPE_MAGNETIC_FIELD: return lastMagnetic;
        }
        return null;
    }

    // ─── Network Type ─────────────────────────────────────────────────────
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

    // ─── Carrier Info ─────────────────────────────────────────────────────
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

    // ─── Install Source ───────────────────────────────────────────────────
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

    // ─── IVC — Install Verification Check ────────────────────────────────
    // true = installed from Play Store properly
    public static boolean getIVC(Context context) {
        try {
            String src = getInstallSource(context);
            return "com.android.vending".equals(src);
        } catch (Exception e) {
            return false;
        }
    }

    // ─── App Version ──────────────────────────────────────────────────────
    public static String getAppVersion(Context context) {
        try {
            PackageInfo pi = context.getPackageManager()
                .getPackageInfo(context.getPackageName(), 0);
            return pi.versionName;
        } catch (Exception e) {
            return "unknown";
        }
    }

    // ─── Screen Info ──────────────────────────────────────────────────────
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
                screen.put("xdp",  String.valueOf(dm.xdpi));
                screen.put("ydp",  String.valueOf(dm.ydpi));
            }
        } catch (Exception e) { }
        return screen;
    }

    // ─── HMAC-SHA256 Signature ────────────────────────────────────────────
    // Signs payload with API key — server can verify request authenticity
    public static String computeHMAC(String payload, String apiKey) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec key = new SecretKeySpec(
                apiKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(key);
            byte[] bytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) sb.append(String.format("%02X", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    // ─── Full Device Summary ──────────────────────────────────────────────
    public static Map<String, Object> getFullDeviceInfo(Context context) {
        Map<String, Object> info = new HashMap<>();
        info.put("model",      Build.MODEL);
        info.put("brand",      Build.BRAND);
        info.put("device",     Build.DEVICE);
        info.put("product",    Build.PRODUCT);
        info.put("cpu_abi",    Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "");
        info.put("sdk",        Build.VERSION.SDK_INT);
        info.put("os_version", Build.VERSION.RELEASE);
        info.put("build_id",   Build.DISPLAY);
        info.put("sensors",    getSensorList(context));
        info.put("network",    getNetworkType(context));
        info.put("screen",     getScreenInfo(context));
        info.put("ivc",        getIVC(context));
        info.put("install_source", getInstallSource(context));
        info.putAll(getCarrierInfo(context));
        return info;
    }
}
