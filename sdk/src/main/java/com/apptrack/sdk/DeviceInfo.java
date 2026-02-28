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
import android.os.BatteryManager;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class DeviceInfo {

    private static String cachedGaid = null;
    private static String cachedAppSetId = null;
    private static float[] lastAccelerometer = null;
    private static float[] lastGyroscope = null;
    private static float[] lastMagnetic = null;

    // ─── GAID ─────────────────────────────────────────────────────────────
    public static String getGAID(Context context) {
        if (cachedGaid != null) return cachedGaid;
        try {
            Class<?> adIdClient = Class.forName(
                "com.google.android.gms.ads.identifier.AdvertisingIdClient");
            Method getAdInfo = adIdClient.getMethod("getAdvertisingIdInfo", Context.class);
            Object adInfo = getAdInfo.invoke(null, context);
            Method getId = adInfo.getClass().getMethod("getId");
            Method isLimitAd = adInfo.getClass().getMethod("isLimitAdTrackingEnabled");
            String id = (String) getId.invoke(adInfo);
            boolean limited = (boolean) isLimitAd.invoke(adInfo);
            cachedGaid = id;
            return id;
        } catch (Exception e) { }
        return null;
    }

    public static boolean isGaidWithGps(Context context) {
        try {
            Class<?> adIdClient = Class.forName(
                "com.google.android.gms.ads.identifier.AdvertisingIdClient");
            Method getAdInfo = adIdClient.getMethod("getAdvertisingIdInfo", Context.class);
            Object adInfo = getAdInfo.invoke(null, context);
            Method isLimitAd = adInfo.getClass().getMethod("isLimitAdTrackingEnabled");
            return !(boolean) isLimitAd.invoke(adInfo);
        } catch (Exception e) { }
        return false;
    }

    // ─── App Set ID ───────────────────────────────────────────────────────
    public static String getAppSetId(Context context) {
        if (cachedAppSetId != null) return cachedAppSetId;
        try {
            Class<?> appSetClass = Class.forName("com.google.android.gms.appset.AppSet");
            Method getClient = appSetClass.getMethod("getClient", Context.class);
            Object client = getClient.invoke(null, context);
            Method getAppSetId = client.getClass().getMethod("getAppSetId");
            Object task = getAppSetId.invoke(client);

            CountDownLatch latch = new CountDownLatch(1);
            final String[] result = {null};

            Class<?> onSuccessClass = Class.forName(
                "com.google.android.gms.tasks.OnSuccessListener");
            java.lang.reflect.Proxy.newProxyInstance(
                onSuccessClass.getClassLoader(),
                new Class[]{onSuccessClass},
                (proxy, method, args) -> {
                    if (args != null && args.length > 0) {
                        try {
                            Method getId = args[0].getClass().getMethod("getId");
                            result[0] = (String) getId.invoke(args[0]);
                        } catch (Exception ignored) {}
                    }
                    latch.countDown();
                    return null;
                }
            );
            latch.await(2, TimeUnit.SECONDS);
            cachedAppSetId = result[0];
            return result[0];
        } catch (Exception e) { }
        return null;
    }

    // ─── Stable Device ID ─────────────────────────────────────────────────
    public static String getDeviceId(Context context) {
        try {
            String androidId = Settings.Secure.getString(
                context.getContentResolver(), Settings.Secure.ANDROID_ID);
            if (androidId != null && !androidId.equals("9774d56d682e549c")
                    && !androidId.equals("0000000000000000")) {
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

    // ─── Device Checksum (cksm_v3) ───────────────────────────────────────
    public static String getDeviceChecksum(Context context) {
        try {
            String raw = Build.BOARD       + "|" +
                         Build.BOOTLOADER  + "|" +
                         Build.BRAND       + "|" +
                         Build.DEVICE      + "|" +
                         Build.DISPLAY     + "|" +
                         Build.FINGERPRINT + "|" +
                         Build.HARDWARE    + "|" +
                         Build.HOST        + "|" +
                         Build.ID          + "|" +
                         Build.MANUFACTURER+ "|" +
                         Build.MODEL       + "|" +
                         Build.PRODUCT     + "|" +
                         Build.TAGS        + "|" +
                         Build.TYPE        + "|" +
                         Build.USER;
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] bytes = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++)
                sb.append(String.format("%02x", bytes[i]));
            return sb.toString();
        } catch (Exception e) { }
        return "";
    }

    // ─── Battery Level ────────────────────────────────────────────────────
    public static float getBatteryLevel(Context context) {
        try {
            BatteryManager bm = (BatteryManager)
                context.getSystemService(Context.BATTERY_SERVICE);
            if (bm != null) {
                int level = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY);
                return level;
            }
        } catch (Exception e) { }
        return -1f;
    }

    // ─── Disk Info ────────────────────────────────────────────────────────
    public static Map<String, Long> getDiskInfo() {
        Map<String, Long> disk = new HashMap<>();
        try {
            StatFs stat = new StatFs(Environment.getDataDirectory().getPath());
            long blockSize = stat.getBlockSizeLong();
            long total = stat.getBlockCountLong() * blockSize / (1024 * 1024);
            long free  = stat.getAvailableBlocksLong() * blockSize / (1024 * 1024);
            disk.put("total_mb", total);
            disk.put("free_mb", free);
        } catch (Exception e) { }
        return disk;
    }

    // ─── Disk String (AppsFlyer format: "free/total") ────────────────────
    public static String getDiskString() {
        try {
            StatFs stat = new StatFs(Environment.getDataDirectory().getPath());
            long blockSize = stat.getBlockSizeLong();
            long total = stat.getBlockCountLong() * blockSize / (1024 * 1024);
            long free  = stat.getAvailableBlocksLong() * blockSize / (1024 * 1024);
            return free + "/" + total;
        } catch (Exception e) { }
        return "";
    }

    // ─── Language ─────────────────────────────────────────────────────────
    public static String getLanguage(Context context) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                return context.getResources().getConfiguration()
                    .getLocales().get(0).getDisplayLanguage();
            } else {
                return context.getResources().getConfiguration()
                    .locale.getDisplayLanguage();
            }
        } catch (Exception e) { }
        return "unknown";
    }

    public static String getLanguageCode(Context context) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                return context.getResources().getConfiguration()
                    .getLocales().get(0).toString();
            } else {
                return context.getResources().getConfiguration().locale.toString();
            }
        } catch (Exception e) { }
        return "unknown";
    }

    // ─── Country from SIM ─────────────────────────────────────────────────
    public static String getCountry(Context context) {
        try {
            TelephonyManager tm = (TelephonyManager)
                context.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm != null) {
                String country = tm.getNetworkCountryIso();
                if (country != null && !country.isEmpty())
                    return country.toUpperCase();
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                return context.getResources().getConfiguration()
                    .getLocales().get(0).getCountry();
            }
        } catch (Exception e) { }
        return null;
    }

    // ─── Open Referrer ────────────────────────────────────────────────────
    public static String getOpenReferrer(Context context) {
        try {
            android.app.ActivityManager am = (android.app.ActivityManager)
                context.getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null) {
                List<android.app.ActivityManager.RunningTaskInfo> tasks =
                    am.getRunningTasks(1);
                if (tasks != null && !tasks.isEmpty()) {
                    android.content.ComponentName baseActivity =
                        tasks.get(0).baseActivity;
                    if (baseActivity != null) {
                        return "android-app://" + baseActivity.getPackageName();
                    }
                }
            }
        } catch (Exception e) { }
        return null;
    }

    // ─── CPU Architecture ─────────────────────────────────────────────────
    public static String getCpuArch() {
        try {
            return System.getProperty("os.arch", "");
        } catch (Exception e) { }
        return "";
    }

    public static String getCpuAbi2() {
        try {
            if (Build.SUPPORTED_ABIS.length > 1) {
                return Build.SUPPORTED_ABIS[1];
            }
        } catch (Exception e) { }
        return "";
    }

    // ─── App Version Code ─────────────────────────────────────────────────
    public static int getAppVersionCode(Context context) {
        try {
            PackageInfo pi = context.getPackageManager()
                .getPackageInfo(context.getPackageName(), 0);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                return (int) pi.getLongVersionCode();
            } else {
                return pi.versionCode;
            }
        } catch (Exception e) { }
        return 0;
    }

    // ─── Target SDK Version ───────────────────────────────────────────────
    public static int getTargetSdkVersion(Context context) {
        try {
            return context.getApplicationInfo().targetSdkVersion;
        } catch (Exception e) { }
        return 0;
    }

    // ─── Is Preinstalled ──────────────────────────────────────────────────
    public static boolean isPreinstalled(Context context) {
        try {
            int flags = context.getPackageManager()
                .getApplicationInfo(context.getPackageName(), 0).flags;
            return (flags & android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0;
        } catch (Exception e) { }
        return false;
    }

    // ─── Sensor List WITH VALUES ──────────────────────────────────────────
    public static List<Map<String, Object>> getSensorList(Context context) {
        List<Map<String, Object>> sensors = new ArrayList<>();
        try {
            SensorManager sm = (SensorManager)
                context.getSystemService(Context.SENSOR_SERVICE);
            if (sm == null) return sensors;

            CountDownLatch latch = new CountDownLatch(3);
            readSensorValues(sm, latch);
            latch.await(500, TimeUnit.MILLISECONDS);

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
                    float[] vals = getSensorValues(type);
                    if (vals != null) {
                        List<Float> vList = new ArrayList<>();
                        for (float v : vals) vList.add(v);
                        info.put("sVS", vList);
                        info.put("sVE", vList);
                    }
                    sensors.add(info);
                }
            }
        } catch (Exception e) { }
        return sensors;
    }

    private static void readSensorValues(SensorManager sm, CountDownLatch latch) {
        int[] types = {
            Sensor.TYPE_ACCELEROMETER,
            Sensor.TYPE_GYROSCOPE,
            Sensor.TYPE_MAGNETIC_FIELD
        };
        for (int type : types) {
            Sensor s = sm.getDefaultSensor(type);
            if (s != null) {
                sm.registerListener(new SensorEventListener() {
                    @Override
                    public void onSensorChanged(SensorEvent event) {
                        switch (event.sensor.getType()) {
                            case Sensor.TYPE_ACCELEROMETER:
                                lastAccelerometer = event.values.clone(); break;
                            case Sensor.TYPE_GYROSCOPE:
                                lastGyroscope = event.values.clone(); break;
                            case Sensor.TYPE_MAGNETIC_FIELD:
                                lastMagnetic = event.values.clone(); break;
                        }
                        sm.unregisterListener(this);
                        latch.countDown();
                    }
                    @Override public void onAccuracyChanged(Sensor s, int a) {}
                }, s, SensorManager.SENSOR_DELAY_FASTEST);
            } else {
                latch.countDown();
            }
        }
    }

    private static float[] getSensorValues(int type) {
        switch (type) {
            case Sensor.TYPE_ACCELEROMETER:  return lastAccelerometer;
            case Sensor.TYPE_GYROSCOPE:      return lastGyroscope;
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
                    return info.getType() == ConnectivityManager.TYPE_WIFI
                        ? "WIFI" : "CELLULAR";
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
                android.content.pm.InstallSourceInfo info =
                    pm.getInstallSourceInfo(context.getPackageName());
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

    // ─── IVC ──────────────────────────────────────────────────────────────
    public static boolean getIVC(Context context) {
        try {
            return "com.android.vending".equals(getInstallSource(context));
        } catch (Exception e) { return false; }
    }

    // ─── App Version Name ─────────────────────────────────────────────────
    public static String getAppVersion(Context context) {
        try {
            return context.getPackageManager()
                .getPackageInfo(context.getPackageName(), 0).versionName;
        } catch (Exception e) { return "unknown"; }
    }

    // ─── Screen Info ──────────────────────────────────────────────────────
    public static Map<String, Object> getScreenInfo(Context context) {
        Map<String, Object> screen = new HashMap<>();
        try {
            DisplayMetrics dm = new DisplayMetrics();
            WindowManager wm = (WindowManager)
                context.getSystemService(Context.WINDOW_SERVICE);
            if (wm != null) {
                wm.getDefaultDisplay().getMetrics(dm);
                screen.put("x_px", dm.widthPixels);
                screen.put("y_px", dm.heightPixels);
                screen.put("dpi",  dm.densityDpi);
                screen.put("xdp",  String.valueOf(dm.xdpi));
                screen.put("ydp",  String.valueOf(dm.ydpi));
                int size = context.getResources().getConfiguration().screenLayout
                    & android.content.res.Configuration.SCREENLAYOUT_SIZE_MASK;
                screen.put("size", String.valueOf(size));
            }
        } catch (Exception e) { }
        return screen;
    }

    // ─── HMAC-SHA256 ──────────────────────────────────────────────────────
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
        } catch (Exception e) { return ""; }
    }
}
