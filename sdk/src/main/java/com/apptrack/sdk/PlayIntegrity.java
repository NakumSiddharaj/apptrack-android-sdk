package com.apptrack.sdk;

import android.content.Context;
import android.util.Log;

import java.lang.reflect.Method;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class PlayIntegrity {

    private static final String TAG = "AppTrack.Integrity";

    public interface IntegrityCallback {
        void onResult(String token, String error);
    }

    public static void getToken(Context context, String appPackageName, IntegrityCallback callback) {
        try {
            // com.google.android.play.core.integrity.IntegrityManagerFactory
            Class<?> factoryClass = Class.forName(
                "com.google.android.play.core.integrity.IntegrityManagerFactory");
            Method createMethod = factoryClass.getMethod("create", Context.class);
            Object integrityManager = createMethod.invoke(null, context);

            // IntegrityTokenRequest
            Class<?> requestBuilderClass = Class.forName(
                "com.google.android.play.core.integrity.IntegrityTokenRequest");
            Method builderMethod = requestBuilderClass.getMethod("builder");
            Object builder = builderMethod.invoke(null);

            // Set nonce
            long nonce = System.currentTimeMillis();
            Method setNonce = builder.getClass().getMethod("setNonce", String.class);
            setNonce.invoke(builder, "apptrack-" + nonce);

            Method buildMethod = builder.getClass().getMethod("build");
            Object request = buildMethod.invoke(builder);

            // Request token
            Method requestToken = integrityManager.getClass()
                .getMethod("requestIntegrityToken",
                    Class.forName("com.google.android.play.core.integrity.IntegrityTokenRequest"));
            Object task = requestToken.invoke(integrityManager, request);

            // Wait for result
            CountDownLatch latch = new CountDownLatch(1);
            final String[] result = {null};
            final String[] error  = {null};

            Class<?> onSuccessClass = Class.forName("com.google.android.gms.tasks.OnSuccessListener");
            Class<?> onFailureClass = Class.forName("com.google.android.gms.tasks.OnFailureListener");

            Method addOnSuccess = task.getClass().getMethod("addOnSuccessListener", onSuccessClass);
            Method addOnFailure = task.getClass().getMethod("addOnFailureListener", onFailureClass);

            addOnSuccess.invoke(task,
                java.lang.reflect.Proxy.newProxyInstance(
                    onSuccessClass.getClassLoader(),
                    new Class[]{onSuccessClass},
                    (proxy, method, args) -> {
                        try {
                            if (args != null && args.length > 0) {
                                Method getToken = args[0].getClass().getMethod("token");
                                result[0] = (String) getToken.invoke(args[0]);
                            }
                        } catch (Exception e) {
                            error[0] = e.getMessage();
                        }
                        latch.countDown();
                        return null;
                    }
                )
            );

            addOnFailure.invoke(task,
                java.lang.reflect.Proxy.newProxyInstance(
                    onFailureClass.getClassLoader(),
                    new Class[]{onFailureClass},
                    (proxy, method, args) -> {
                        error[0] = args != null && args.length > 0
                            ? args[0].toString() : "unknown";
                        latch.countDown();
                        return null;
                    }
                )
            );

            latch.await(5, TimeUnit.SECONDS);
            callback.onResult(result[0], error[0]);

        } catch (ClassNotFoundException e) {
            // Play Integrity library not available
            Log.d(TAG, "Play Integrity not available");
            callback.onResult(null, "not_available");
        } catch (Exception e) {
            Log.e(TAG, "Error: " + e.getMessage());
            callback.onResult(null, e.getMessage());
        }
    }
}
