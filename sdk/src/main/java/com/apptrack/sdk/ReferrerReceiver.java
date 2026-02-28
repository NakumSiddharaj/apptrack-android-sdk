package com.apptrack.sdk;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import com.android.installreferrer.api.InstallReferrerClient;
import com.android.installreferrer.api.InstallReferrerStateListener;
import com.android.installreferrer.api.ReferrerDetails;

import java.net.URLDecoder;

public class ReferrerReceiver {
    private static final String TAG = "AppTrack.Referrer";

    public interface ReferrerCallback {
        void onResult(String clickid, String campaignId);
    }

    // ─── Read Play Store Referrer ─────────────────────────
    public static void readReferrer(Context context, ReferrerCallback callback) {
        InstallReferrerClient client = InstallReferrerClient.newBuilder(context).build();
        client.startConnection(new InstallReferrerStateListener() {
            @Override
            public void onInstallReferrerSetupFinished(int responseCode) {
                if (responseCode == InstallReferrerClient.InstallReferrerResponse.OK) {
                    try {
                        ReferrerDetails details = client.getInstallReferrer();
                        String referrer = details.getInstallReferrer();
                        Log.d(TAG, "Raw referrer: " + referrer);
                        if (referrer != null) {
                            String[] result = parseReferrer(referrer);
                            fireCallback(callback, result[0], result[1]);
                        } else {
                            fireCallback(callback, null, null);
                        }
                    } catch (Exception e) {
                        Log.e(TAG, "Referrer error: " + e.getMessage());
                        fireCallback(callback, null, null);
                    } finally {
                        try { client.endConnection(); } catch (Exception ignored) {}
                    }
                } else if (responseCode == InstallReferrerClient.InstallReferrerResponse.FEATURE_NOT_SUPPORTED) {
                    Log.d(TAG, "Referrer not supported on this device");
                    fireCallback(callback, null, null);
                    try { client.endConnection(); } catch (Exception ignored) {}
                } else {
                    Log.d(TAG, "Referrer not available: " + responseCode);
                    fireCallback(callback, null, null);
                    try { client.endConnection(); } catch (Exception ignored) {}
                }
            }

            @Override
            public void onInstallReferrerServiceDisconnected() {
                Log.d(TAG, "Referrer service disconnected");
                // Retry once after disconnect
                new Handler(Looper.getMainLooper()).postDelayed(() -> {
                    try {
                        client.startConnection(this);
                    } catch (Exception e) {
                        Log.e(TAG, "Retry failed: " + e.getMessage());
                        fireCallback(callback, null, null);
                    }
                }, 2000);
            }
        });
    }

    // ─── Fire callback on main thread ─────────────────────
    private static void fireCallback(ReferrerCallback callback, String clickid, String campaignId) {
        new Handler(Looper.getMainLooper()).post(() ->
            callback.onResult(clickid, campaignId)
        );
    }

    // ─── Parse referrer string ────────────────────────────
    private static String[] parseReferrer(String referrer) {
        String clickid    = null;
        String campaignId = null;
        try {
            String decoded = URLDecoder.decode(referrer, "UTF-8");
            String[] parts = decoded.split("&");
            for (String part : parts) {
                String[] kv = part.split("=", 2);
                if (kv.length == 2) {
                    if (kv[0].equals("at_click")) {
                        clickid = kv[1];
                    } else if (kv[0].equals("at_campaign")) {
                        campaignId = kv[1];
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Parse error: " + e.getMessage());
        }
        Log.d(TAG, "Parsed | clickid=" + clickid + " campaign=" + campaignId);
        return new String[]{clickid, campaignId};
    }
}
