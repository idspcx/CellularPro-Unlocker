package io.github.ldxm666.cellularpro;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.lang.reflect.Array;
import java.lang.reflect.Executable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

public class Main extends XposedModule {

    static final String TAG = "CProUnlock";
    static final String TARGET = "make.more.r2d2.play.cellular_pro";
    static final String EXT_DIR = "/sdcard/Android/data/" + TARGET + "/files";
    static final String DUMP_FILE = EXT_DIR + "/lsp_net.log";
    static final String PAYLOAD_FILE = EXT_DIR + "/payload.json";

    static final String CERT_B64 = "MIICxzCCAa+gAwIBAgIEFrQwGzANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDEwhKZXJzZXlIbzAgFw0xNDA4MTgwODM2NDlaGA8yMTEzMDcyNTA4MzY0OVowEzERMA8GA1UEAxMISmVyc2V5SG8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDD8kzu5Q7Iw5kg7S6ohHX6T/YgNXSoE6qufnRsC+asvyogSlx4NQCCSfXp4WUhn2oqSTpfwHuA3L4wU4ugY0kBkEmqt9f5Ll553KdO3p2fOkVZhjltZPs/vAT9iOv/FSZaGmvPaPRIkTjW4uXUL0nt+qH2Upwda/JZl6kJAgErKjMCE83TZsoTwGq2a9JiteesGIS9S9vjHLzvV5w+5+Nrn8r6baWuxLZGo8sP2T2DtoHlCg7NtPlc53t7Avrgs336wTpYniUHCG3PveW/AaMEddUyxje6GxBExVqTkHx4gtQysGHIXEDF9U6/rBDSYdKiFtpUO8uIk54Nt3xD0E5vAgMBAAGjITAfMB0GA1UdDgQWBBQgpnjRtpTU+sF3urgNAUKdVutwIjANBgkqhkiG9w0BAQsFAAOCAQEAsvNKBV7J7GX2pZ9/dHW3FcOckb04OTAHOrjS5BOx/1EJIQcXJHFH5RUFtNIfaltQKxbjmkGlvx3VB/vSrai8COPUMgB9eSYSOxnC8DnUusy60ekNF1O7I/pAxWAVoSC+/TyxCmE0oz9QonO9ZjpFvqvhLySHoSb97sEgta+iHcNuxQomD6EeAdXN/Afl0tCWcY6P1HaJhYVnUH+uuujyBIrwcnXOBktTdgYSzFcwPH1rCu0z2iZG+NqloR/BWrnAbfZUbrVgjnocTUvsAIFU9zO4516xjv43uzbAWGNthxSDTfblxkueMbZ9PeGPMyg/UMF8KuzsazrcXwmwxT5cSw==";

    static volatile Map<String, String> sStrings = new HashMap<String, String>();
    static int sStackN = 0;
    static volatile long sArmUntil = 0L;
    // 信令行缓存：直接从 TextView.setText 里攒，不碰 native
    static final java.util.ArrayList<String[]> sSig = new java.util.ArrayList<>();
    static String[] sSigPend = null;
    static android.app.Activity sAct = null;
    private static boolean sInit = false;
    private volatile SigningInfo sSigningInfo;

    @Override
    public void onPackageLoaded(XposedModuleInterface.PackageLoadedParam param) {
        if (!TARGET.equals(param.getPackageName())) {
            detach();
            return;
        }
        if (sInit) return;
        sInit = true;
        ClassLoader tmp;
        try {
            tmp = param.getDefaultClassLoader();
        } catch (Throwable t) {
            tmp = Main.class.getClassLoader();
        }
        final ClassLoader cl = tmp;
        log(Log.INFO, TAG, "loaded pkg=" + param.getPackageName() + " cl=" + cl);
        safe("flags", () -> forceMemberFlags(cl));
        safe("native", () -> nativePredicates(cl));
        safe("prefs", () -> hookPrefs(cl));
        safe("web", () -> hookWeb(cl));
        safe("cv", () -> hookCanvas(cl));
        safe("res", () -> resProbe(cl));
        safe("text", () -> textProbe(cl));
        safe("ge", () -> geProbe(cl));
        safe("exp", () -> exportProbe(cl));
        safe("entry", () -> entryUnlock(cl));
        // safe("fld", () -> fieldProbe(cl)); // 只在需要摊开字段时打开
        safe("cry", () -> cryptoProbe(cl));
        safe("tr-ge", () -> traceNative(cl, "A0B0.ge", true));
        safe("exp-bind", () -> exportBind(cl));
    safe("tr-mon", () -> traceNative(cl, "make.more.r2d2.cellular_pro.activity.MonitorActivity", false));
        safe("tr-sig", () -> traceNative(cl, "make.more.r2d2.cellular_pro.fragment.FragmentSignal", false));
    }

    interface Step { void run() throws Throwable; }

    private void safe(String name, Step s) {
        try {
            s.run();
        } catch (Throwable t) {
            log(Log.ERROR, TAG, name + " failed: " + t, t);
        }
    }

    private void out(String s) {
        log(Log.INFO, TAG, s);
    }

    // ---------------------------------------------------------------- cert

    private Object signingInfo() {
        if (sSigningInfo != null) return sSigningInfo;
        synchronized (this) {
            if (sSigningInfo != null) return sSigningInfo;
            try {
                byte[] der = android.util.Base64.decode(CERT_B64, android.util.Base64.DEFAULT);
                Signature[] sigs = new Signature[]{new Signature(der)};
                Class<?> sd = Class.forName("android.content.pm.SigningDetails");
                Object details;
                try {
                    java.lang.reflect.Constructor<?> ctor =
                            sd.getDeclaredConstructor(Signature[].class, int.class);
                    ctor.setAccessible(true);
                    details = ctor.newInstance(sigs, 3);
                } catch (Throwable t) {
                    java.lang.reflect.Constructor<?> ctor =
                            sd.getDeclaredConstructor(Signature[].class);
                    ctor.setAccessible(true);
                    details = ctor.newInstance((Object) sigs);
                }
                java.lang.reflect.Constructor<?> c2 = SigningInfo.class.getDeclaredConstructor(sd);
                c2.setAccessible(true);
                sSigningInfo = (SigningInfo) c2.newInstance(details);
                out("signing info built");
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "signingInfo: " + t, t);
            }
            return sSigningInfo;
        }
    }

    private void patchInfo(PackageInfo pi) {
        if (pi == null || !TARGET.equals(pi.packageName)) return;
        Object si = signingInfo();
        try {
            pi.signatures = new Signature[]{new Signature(android.util.Base64.decode(CERT_B64, android.util.Base64.DEFAULT))};
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "signatures: " + t);
        }
        if (si != null) {
            try {
                Field f = PackageInfo.class.getField("signingInfo");
                f.set(pi, si);
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "signingInfo field: " + t);
            }
        }
        out("patched PackageInfo " + pi.packageName);
    }

    private void hookPackageManager(ClassLoader cl) {
        String[] cls = {"android.app.ApplicationPackageManager", "android.content.pm.PackageManager"};
        int n = 0;
        for (String name : cls) {
            Class<?> c;
            try {
                c = Class.forName(name, false, cl);
            } catch (Throwable t) {
                continue;
            }
            for (Method m : c.getDeclaredMethods()) {
                String mn = m.getName();
                if (!mn.startsWith("getPackageInfo") && !mn.startsWith("getInstalledPackages")) continue;
                Class<?> rt = m.getReturnType();
                if (rt != PackageInfo.class && rt != PackageInfo[].class) continue;
                try {
                    hook(m).setId("cp-pm-" + name + "-" + mn + "-" + m.getParameterCount())
                            .intercept(chain -> {
                                Object r = chain.proceed();
                                try {
                                    if (r instanceof PackageInfo) {
                                        patchInfo((PackageInfo) r);
                                    } else if (r instanceof PackageInfo[]) {
                                        for (PackageInfo pi : (PackageInfo[]) r) patchInfo(pi);
                                    }
                                } catch (Throwable t) {
                                    log(Log.ERROR, TAG, "patch: " + t);
                                }
                                return r;
                            });
                    n++;
                } catch (Throwable t) {
                    log(Log.WARN, TAG, "pm hook " + mn + ": " + t);
                }
            }
        }
        out("pm hooks=" + n);
    }

    // -------------------------------------------------------------- okhttp

    static void append(String path, String text) {
        try {
            File f = new File(path);
            File d = f.getParentFile();
            if (d != null && !d.exists()) d.mkdirs();
            FileWriter w = new FileWriter(f, true);
            w.write(text);
            w.close();
        } catch (Throwable ignored) {
        }
    }

    static String readSmall(String path) {
        try {
            File f = new File(path);
            if (!f.exists()) return null;
            BufferedReader r = new BufferedReader(new FileReader(f));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) sb.append(line);
            r.close();
            return sb.toString();
        } catch (Throwable t) {
            return null;
        }
    }

    static Object call(Object target, String name, Class<?>[] types, Object[] args) throws Throwable {
        Method m = null;
        Class<?> c = target.getClass();
        while (c != null && m == null) {
            try {
                m = c.getDeclaredMethod(name, types);
            } catch (Throwable ignored) {
            }
            c = c.getSuperclass();
        }
        if (m == null) throw new NoSuchMethodException(name);
        m.setAccessible(true);
        return m.invoke(target, args);
    }

    static Object responseBody(ClassLoader cl, String s) throws Throwable {
        Class<?> rb = Class.forName("okhttp3.ResponseBody", false, cl);
        Class<?> mt = Class.forName("okhttp3.MediaType", false, cl);
        Object media = null;
        try {
            media = mt.getMethod("parse", String.class).invoke(null, "application/json; charset=utf-8");
        } catch (Throwable ignored) {
        }
        for (Method m : rb.getMethods()) {
            if (!m.getName().equals("create") || !Modifier.isStatic(m.getModifiers())) continue;
            Class<?>[] ps = m.getParameterTypes();
            if (ps.length == 2 && ps[1] == String.class) return m.invoke(null, media, s);
        }
        throw new NoSuchMethodException("ResponseBody.create");
    }

    private void hookOkHttp(ClassLoader cl) {
        String[] names = {"okhttp3.internal.http.CallServerInterceptor", "okhttp3.internal.http.RealInterceptorChain"};
        int n = 0;
        for (String name : names) {
            Class<?> c;
            try {
                c = Class.forName(name, false, cl);
            } catch (Throwable t) {
                continue;
            }
            for (Method m : c.getDeclaredMethods()) {
                String mn = m.getName();
                if (!mn.equals("intercept") && !mn.equals("proceed")) continue;
                if (m.getParameterCount() != 1) continue;
                try {
                    hook(m).setId("cp-net-" + mn).intercept(chain -> {
                        Object resp = chain.proceed();
                        if (resp == null) return null;
                        try {
                            Object req = call(resp, "request", new Class<?>[0], new Object[0]);
                            Object url = call(req, "url", new Class<?>[0], new Object[0]);
                            String u = String.valueOf(url);
                            if (u == null || !u.contains("cellularpro")) return resp;
                            String body = "";
                            String b64 = "";
                            try {
                                Object rb = call(resp, "body", new Class<?>[0], new Object[0]);
                                Object bs = call(rb, "bytes", new Class<?>[0], new Object[0]);
                                byte[] raw = (byte[]) bs;
                                b64 = android.util.Base64.encodeToString(raw, 2);
                                Object pb = call(resp, "peekBody", new Class<?>[]{long.class}, new Object[]{1048576L});
                                body = String.valueOf(call(pb, "string", new Class<?>[0], new Object[0]));
                            } catch (Throwable t) {
                                try {
                                    Object pb = call(resp, "peekBody", new Class<?>[]{long.class}, new Object[]{1048576L});
                                    body = String.valueOf(call(pb, "string", new Class<?>[0], new Object[0]));
                                } catch (Throwable t2) {
                                    body = "<body err " + t2 + ">";
                                }
                            }
                            append(DUMP_FILE, "URL " + u + "\n" + body + "\nB64 " + b64 + "\n----\n");
                            out("NET " + u + " len=" + body.length());
                            String repl = readSmall(PAYLOAD_FILE);
                            if (repl == null || repl.length() < 2) return resp;
                            Object nb = responseBody(cl, repl);
                            Object b = call(resp, "newBuilder", new Class<?>[0], new Object[0]);
                            call(b, "body", new Class<?>[]{Class.forName("okhttp3.ResponseBody", false, cl)}, new Object[]{nb});
                            out("NET swapped len=" + repl.length());
                            return call(b, "build", new Class<?>[0], new Object[0]);
                        } catch (Throwable t) {
                            log(Log.ERROR, TAG, "net: " + t, t);
                            return resp;
                        }
                    });
                    n++;
                } catch (Throwable t) {
                    log(Log.WARN, TAG, "net hook " + mn + ": " + t);
                }
            }
        }
        out("okhttp hooks=" + n);
    }

    // -------------------------------------------------------------- crypto

    static boolean isText(String s) {
        if (s == null || s.length() < 2) return false;
        int ok = 0;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch >= 32 && ch < 127) ok++;
        }
        return ok * 100 / s.length() > 85;
    }

    private void hookCrypto(ClassLoader cl) {
        Class<?> c;
        try {
            c = Class.forName("com.tozny.crypto.android.AesCbcWithIntegrity", false, cl);
        } catch (Throwable t) {
            out("crypto class missing");
            return;
        }
        int n = 0;
        for (final Method m : c.getDeclaredMethods()) {
            final String mn = m.getName();
            if (!mn.equals("decryptString") && !mn.equals("decrypt") && !mn.equals("encrypt")) continue;
            if (!Modifier.isStatic(m.getModifiers())) continue;
            try {
                hook(m).setId("cp-crypto-" + mn + "-" + m.getParameterCount()).intercept(chain -> {
                    Object r = chain.proceed();
                    try {
                        String s;
                        if (r instanceof byte[]) {
                            s = new String((byte[]) r, "UTF-8");
                        } else if (r != null && "encrypt".equals(mn)) {
                            s = String.valueOf(r);
                        } else {
                            s = String.valueOf(r);
                        }
                        String key = "";
                        String in = "";
                        try {
                            if (m.getParameterCount() >= 2) {
                                Object sk = chain.getArg(1);
                                Class<?> ac = Class.forName("com.tozny.crypto.android.AesCbcWithIntegrity", false, cl);
                                key = String.valueOf(ac.getMethod("keyString", Class.forName("com.tozny.crypto.android.AesCbcWithIntegrity$SecretKeys", false, cl)).invoke(null, sk));
                                in = String.valueOf(chain.getArg(0));
                                if (in.length() > 48) in = in.substring(0, 48);
                            }
                        } catch (Throwable ignored) {
                        }
                        if (isText(s)) append(DUMP_FILE, "DEC " + mn + "/" + m.getParameterCount() + " key=" + key + " in=" + in + "\n" + s + "\n----\n");
                    } catch (Throwable t) {
                        log(Log.ERROR, TAG, "crypto log: " + t);
                    }
                    return r;
                });
                n++;
            } catch (Throwable t) {
                log(Log.WARN, TAG, "crypto hook " + mn + ": " + t);
            }
        }
        out("crypto hooks=" + n);
    }
    // -------------------------------------------------------------- cipher

    // -------------------------------------------------------------- billing

    static Object okResult(ClassLoader cl) {
        try {
            Class<?> br = Class.forName("com.android.billingclient.api.BillingResult", false, cl);
            Object b = br.getMethod("newBuilder").invoke(null);
            b.getClass().getMethod("setResponseCode", int.class).invoke(b, 0);
            return b.getClass().getMethod("build").invoke(b);
        } catch (Throwable t) {
            return null;
        }
    }

    static Object fakePurchase(ClassLoader cl, String sku, long now) {
        try {
            String json = "{\"orderId\":\"GPA.3338-6736-3937-52287\","
                    + "\"packageName\":\"" + TARGET + "\","
                    + "\"productId\":\"" + sku + "\","
                    + "\"products\":[\"" + sku + "\"],"
                    + "\"productIds\":[\"" + sku + "\"],"
                    + "\"purchaseTime\":" + now + ","
                    + "\"purchaseState\":0,"
                    + "\"purchaseToken\":\"smith" + now + "aaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                    + "\"acknowledged\":true,"
                    + "\"autoRenewing\":true,"
                    + "\"quantity\":1,"
                    + "\"purchaseType\":0}";
            Class<?> pc = Class.forName("com.android.billingclient.api.Purchase", false, cl);
            return pc.getConstructor(String.class, String.class).newInstance(json, "smithsig");
        } catch (Throwable t) {
            append(DUMP_FILE, "BILL fake purchase err " + t + "\r\n");
            return null;
        }
    }

    static void post(Runnable r) {
        try {
            new android.os.Handler(android.os.Looper.getMainLooper()).post(r);
        } catch (Throwable t) {
            try {
                r.run();
            } catch (Throwable ignored) {
            }
        }
    }

    private void hookBilling(ClassLoader cl) {
        Class<?> impl;
        Class<?> brc;
        try {
            impl = Class.forName("com.android.billingclient.api.BillingClientImpl", false, cl);
            brc = Class.forName("com.android.billingclient.api.BillingResult", false, cl);
        } catch (Throwable t) {
            out("billing missing");
            return;
        }
        final Class<?> brClass = brc;
        int n = 0;

        for (Method m : impl.getDeclaredMethods()) {
            String mn = m.getName();
            try {
                if (mn.equals("queryPurchasesAsync") && m.getParameterCount() == 2) {
                    hook(m).setId("cp-bill-query").intercept(chain -> {
                        Object listener = chain.getArg(1);
                        long now = System.currentTimeMillis();
                        java.util.List<Object> list = new java.util.ArrayList<>();
                        Object p1 = fakePurchase(cl, "general_vip_month", now);
                        Object p2 = fakePurchase(cl, "senior_vip_month", now);
                        if (p1 != null) list.add(p1);
                        if (p2 != null) list.add(p2);
                        Object ok = okResult(cl);
                        append(DUMP_FILE, "BILL query -> fake list size=" + list.size() + "\n");
                        final Object l = listener;
                        final Object o = ok;
                        final java.util.List<Object> fl = list;
                        post(() -> {
                            try {
                                call(l, "onQueryPurchasesResponse", new Class<?>[]{brClass, java.util.List.class}, new Object[]{o, fl});
                            } catch (Throwable t) {
                                log(Log.ERROR, TAG, "bill cb: " + t, t);
                            }
                        });
                        return null;
                    });
                    n++;
                } else if (mn.equals("acknowledgePurchase") && m.getParameterCount() == 2) {
                    hook(m).setId("cp-bill-ack").intercept(chain -> {
                        Object listener = chain.getArg(1);
                        final Object l = listener;
                        final Object o = okResult(cl);
                        append(DUMP_FILE, "BILL ack -> OK\n");
                        post(() -> {
                            try {
                                call(l, "onAcknowledgePurchaseResponse", new Class<?>[]{brClass}, new Object[]{o});
                            } catch (Throwable t) {
                            }
                        });
                        return null;
                    });
                    n++;
                } else if (mn.equals("startConnection") && m.getParameterCount() == 1) {
                    hook(m).setId("cp-bill-conn").intercept(chain -> {
                        try {
                            chain.proceed();
                        } catch (Throwable ignored) {
                        }
                        Object listener = chain.getArg(0);
                        final Object l = listener;
                        final Object o = okResult(cl);
                        append(DUMP_FILE, "BILL startConnection -> OK\n");
                        post(() -> {
                            try {
                                call(l, "onBillingSetupFinished", new Class<?>[]{brClass}, new Object[]{o});
                            } catch (Throwable t) {
                            }
                        });
                        return null;
                    });
                    n++;
                } else if (mn.equals("isReady") && m.getParameterCount() == 0) {
                    hook(m).setId("cp-bill-ready").intercept(chain -> Boolean.TRUE);
                    n++;
                } else if (mn.equals("getConnectionState") && m.getParameterCount() == 0) {
                    hook(m).setId("cp-bill-state").intercept(chain -> 2);
                    n++;
                }
            } catch (Throwable t) {
                log(Log.WARN, TAG, "bill hook " + mn + ": " + t);
            }
        }
        out("billing hooks=" + n);
    }

    private void hookPrefs(ClassLoader cl) {
        Class<?> sp;
        try {
            sp = Class.forName("android.app.SharedPreferencesImpl", false, cl);
        } catch (Throwable t) {
            out("prefs impl missing");
            return;
        }
        int n = 0;
        for (String name : new String[]{"getString", "getBoolean", "getInt", "getLong"}) {
            for (Method m : sp.getDeclaredMethods()) {
                if (!m.getName().equals(name) || m.getParameterCount() != 2) continue;
                final String nm = name;
                try {
                    hook(m).setId("cp-prefs-" + name).intercept(chain -> {
                        Object r = chain.proceed();
                        try {
                            String k = String.valueOf(chain.getArg(0));
                            String v = String.valueOf(r);
                            if (v.length() > 140) v = v.substring(0, 140);
                            append(DUMP_FILE, "PREF " + nm + " " + k + " = " + v + "\n");
                        } catch (Throwable ignored) {
                        }
                        return r;
                    });
                    n++;
                } catch (Throwable t) {
                    log(Log.WARN, TAG, "prefs hook " + name + ": " + t);
                }
            }
        }
        out("prefs hooks=" + n);
        int pn = 0;
        try {
            Class<?> ed = Class.forName("android.app.SharedPreferencesImpl$EditorImpl", false, cl);
            for (Method m : ed.getDeclaredMethods()) {
                String nm = m.getName();
                if (!nm.startsWith("put") || m.getParameterCount() != 2) continue;
                final String fname = nm;
                try {
                    hook(m).setId("cp-prefput-" + nm).intercept(chain -> {
                        Object r = chain.proceed();
                        try {
                            String k = String.valueOf(chain.getArg(0));
                            String v = String.valueOf(chain.getArg(1));
                            if (v.length() > 160) v = v.substring(0, 160);
                            append(DUMP_FILE, "PUT " + fname + " " + k + " = " + v + "\n");
                        } catch (Throwable ignored) {
                        }
                        return r;
                    });
                    pn++;
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable t) {
            append(DUMP_FILE, "editor hook fail " + t + "\n");
        }
        append(DUMP_FILE, "prefs editor hooks=" + pn + "\n");
    }

    // 诊断: 记录 WebView 加载的地址, 用来判断信令导出按钮打开的是什么页面
    private void hookWeb(ClassLoader cl) {
        int n = 0;
        try {
            Class<?> wv = Class.forName("android.webkit.WebView", false, cl);
            for (Method m : wv.getDeclaredMethods()) {
                if (!"loadUrl".equals(m.getName())) continue;
                if (m.getParameterCount() < 1) continue;
                if (m.getParameterTypes()[0] != String.class) continue;
                try {
                    hook(m).setId("cp-web-" + m.getParameterCount()).intercept(chain -> {
                        try {
                            append(DUMP_FILE, "WEB loadUrl " + chain.getArg(0) + "\n");
                        } catch (Throwable ignored) {
                        }
                        return chain.proceed();
                    });
                    n++;
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable t) {
            append(DUMP_FILE, "web hook fail " + t + "\n");
        }
        append(DUMP_FILE, "web hooks=" + n + "\n");
    }

    // 诊断: 这个 app 的界面全是 canvas 画的, 把 drawText 的文字抓出来才能看见会员状态
    static final java.util.Set<String> sCvt = java.util.Collections.synchronizedSet(new java.util.HashSet<String>());

    private void hookCanvas(ClassLoader cl) {
        int n = 0;
        try {
            Class<?> cv = Class.forName("android.graphics.Canvas", false, cl);
            for (Method m : cv.getDeclaredMethods()) {
                if (!"drawText".equals(m.getName())) continue;
                Class<?>[] pt = m.getParameterTypes();
                if (pt.length < 1) continue;
                if (pt[0] == String.class) {
                    hook(m).setId("cp-cv-s").intercept(chain -> {
                        try {
                            if (true) logCvt(String.valueOf(chain.getArg(0)));
                        } catch (Throwable ignored) {
                        }
                        return chain.proceed();
                    });
                    n++;
                } else if (pt[0] == char[].class && pt.length >= 3) {
                    hook(m).setId("cp-cv-c").intercept(chain -> {
                        try {
                            if (true) {
                                char[] cs = (char[]) chain.getArg(0);
                                int st = ((Number) chain.getArg(1)).intValue();
                                int ln = ((Number) chain.getArg(2)).intValue();
                                if (st >= 0 && ln > 0 && st + ln <= cs.length) logCvt(new String(cs, st, ln));
                            }
                        } catch (Throwable ignored) {
                        }
                        return chain.proceed();
                    });
                    n++;
                }
            }
        } catch (Throwable t) {
            append(DUMP_FILE, "cv hook fail " + t + "\n");
        }
        append(DUMP_FILE, "canvas hooks=" + n + "\n");
    }

    private void logCvt(String s) {
        if (s == null) return;
        s = s.trim();
        if (s.length() < 2 || s.length() > 60) return;
        if (sCvt.size() > 400) return;
        if (!sCvt.add(s)) return;
        append(DUMP_FILE, "CVT " + s + "\n");
    }

    private void hookCipher(ClassLoader cl) {
        Class<?> c;
        try {
            c = Class.forName("javax.crypto.Cipher", false, cl);
        } catch (Throwable t) {
            out("cipher missing");
            return;
        }
        int n = 0;
        try {
            Method m = c.getDeclaredMethod("doFinal", byte[].class);
            hook(m).setId("cp-cipher-dofinal").intercept(chain -> {
                Object r = chain.proceed();
                try {
                    Object self = chain.getThisObject();
                    int mode = -1;
                    try {
                        Field fm = c.getDeclaredField("mode");
                        fm.setAccessible(true);
                        mode = fm.getInt(self);
                    } catch (Throwable ignored) {
                    }
                    if (r instanceof byte[] && mode == 2) {
                        byte[] b = (byte[]) r;
                        if (b.length > 1 && b.length < 60000) {
                            String s = new String(b, "UTF-8");
                            if (isText(s)) append(DUMP_FILE, "CIPHER dec\n" + s + "\n----\n");
                        }
                    }
                } catch (Throwable t) {
                    log(Log.ERROR, TAG, "cipher log: " + t);
                }
                return r;
            });
            n++;
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "cipher hook: " + t, t);
        }
        out("cipher hooks=" + n);
    }
    // --------------------------------------------------------------- flags

    private void forceMemberFlags(ClassLoader cl) {
        String[] names = {"A0B0.ka0", "A0B0.ge", "A0B0.pp1"};
        int n = 0;
        for (String name : names) {
            Class<?> c;
            try {
                c = Class.forName(name, false, cl);
            } catch (Throwable t) {
                continue;
            }
            for (Method m : c.getDeclaredMethods()) {
                if (m.getReturnType() != boolean.class) continue;
                if (m.getParameterCount() > 1) continue;
                if (Modifier.isStatic(m.getModifiers())) continue;
                if (Modifier.isNative(m.getModifiers())) continue;
                if (m.getParameterCount() == 1 && m.getParameterTypes()[0] != c) continue;
                try {
                    hook(m).setId("cp-flag-" + name + "-" + m.getName()).intercept(chain -> {
                        Object r = chain.proceed();
                        if (Boolean.TRUE.equals(r)) return r;
                        out("flag TRUE " + chain.getExecutable());
                        return Boolean.TRUE;
                    });
                    n++;
                } catch (Throwable ignored) {
                }
            }
        }
        out("flag hooks=" + n);
    }

    // ------------------------------------------------------ native predicates

    static final String FLAG_FILE = EXT_DIR + "/flags.txt";
    static final String FLAG_LOG = EXT_DIR + "/lsp_flags.log";
    static volatile long sFlagMtime = -2;
    static volatile Map<String, Boolean> sFlags = new HashMap<String, Boolean>();
    static volatile Map<String, Integer> sInts = new HashMap<String, Integer>();
    static final Map<String, Integer> sSeen = new HashMap<String, Integer>();
    static final String GATE = "ez,eh,em,#FragmentMember,#MemberActivity,#FragmentVip,#FragmentPay";
    static final int SEEN_MAX = 3;

    private void loadFlags() {
        File f = new File(FLAG_FILE);
        long mt = f.exists() ? f.lastModified() : 0;
        if (mt == sFlagMtime) return;
        sFlagMtime = mt;
        Map<String, Boolean> m = new HashMap<String, Boolean>();
        Map<String, Integer> mi = new HashMap<String, Integer>();
        Map<String, String> ms = new HashMap<String, String>();
        if (mt != 0) {
            try {
                BufferedReader r = new BufferedReader(new FileReader(f));
                String line;
                while ((line = r.readLine()) != null) {
                    line = line.trim();
                    if (line.length() == 0 || line.charAt(0) == '#') continue;
                    int eq = line.indexOf('=');
                    if (eq <= 0) continue;
                    String k = line.substring(0, eq).trim();
                    String v = line.substring(eq + 1).trim();
                    m.put(k, "1".equals(v));
                    ms.put(k, v);
                    try {
                        mi.put(k, Integer.valueOf(Integer.parseInt(v)));
                    } catch (Throwable ignored) {
                    }
                }
                r.close();
            } catch (Throwable ignored) {
            }
        }
        sFlags = m;
        sInts = mi;
        sStrings = ms;
        // 会员谓词不再默认强推：native 手里有自己的签发状态，Java 侧说谎会被一致性检查退进程。
        // 会员相关的入口改为逐个直接接管（导出、测试计划等）。
        synchronized (sSeen) {
            sSeen.clear();
        }
        append(FLAG_LOG, "flags reloaded: " + m + "\n");
    }

    private void note(String key, Object result) {
        boolean first;
        synchronized (sSeen) {
            Integer c = sSeen.get(key);
            first = c == null || c.intValue() < SEEN_MAX;
            sSeen.put(key, Integer.valueOf(c == null ? 1 : c.intValue() + 1));
        }
        if (!first) return;
        String caller = "?";
        StackTraceElement[] st = new Throwable().getStackTrace();
        for (int i = 2; i < st.length && i < 9; i++) {
            String cn = st[i].getClassName();
            if (!cn.startsWith("make.more.r2d2") && !cn.startsWith("android.")
                    && !cn.startsWith("java.") && !cn.startsWith("A0B0")) continue;
            caller = cn + "." + st[i].getMethodName() + ":" + st[i].getLineNumber();
            break;
        }
        append(FLAG_LOG, key + " -> " + result + "  from " + caller + "\n");
    }

    private void nativePredicates(ClassLoader cl) {
        String[] names = {"A0B0.ge",
                "make.more.r2d2.cellular_pro.fragment.FragmentLock",
                "make.more.r2d2.cellular_pro.fragment.ViewPagerFragment",
                "make.more.r2d2.cellular_pro.activity.AssistActivity",
                "make.more.r2d2.cellular_pro.activity.AboutActivity",
                "make.more.r2d2.cellular_pro.activity.MonitorActivity",
                "make.more.r2d2.cellular_pro.fragment.FragmentSignal"};
        loadFlags();
        append(FLAG_LOG, "---- process start ----\n");
        int n = 0;
        for (String cn : names) {
            Class<?> c;
            try {
                c = Class.forName(cn, false, cl);
            } catch (Throwable t) {
                append(FLAG_LOG, "missing " + cn + "\n");
                continue;
            }
            final String shortName = cn.substring(cn.lastIndexOf('.') + 1);
            for (final Method m : c.getDeclaredMethods()) {
                if (!Modifier.isNative(m.getModifiers())) continue;
                final Class<?> rt = m.getReturnType();
                if (rt != boolean.class && rt != int.class) continue;
                if (m.getParameterCount() != 0) continue;
                final String key = shortName + "." + m.getName();
                try {
                    hook(m).setId("cp-nat-" + key).intercept(chain -> {
                        loadFlags();
                        Object r = chain.proceed();
                        Object want;
                        if (rt == int.class) {
                            Integer iv = sInts.get(key);
                            if (iv == null) iv = sInts.get(m.getName());
                            want = iv;
                        } else {
                            Boolean bv = sFlags.get(key);
                            if (bv == null) bv = sFlags.get(m.getName());
                            want = bv;
                        }
                        if (want != null) {
                            String gate = sStrings.get(key + "@");
                            if (gate == null) gate = sStrings.get(m.getName() + "@");
                            if (gate != null) {
                                boolean deny = gate.startsWith("!");
                                String g = deny ? gate.substring(1) : gate;
                                boolean hit = "ARM".equals(g)
                                        ? System.currentTimeMillis() <= sArmUntil
                                        : hasFrame(g);
                                if (deny ? hit : !hit) {
                                    note(key + "[gate-skip " + gate + "]", r);
                                    return r;
                                }
                            }
                            note(key + "[forced " + want + "]", r);
                            return want;
                        }
                        note(key, r);
                        return r;
                    });
                    n++;
                } catch (Throwable t) {
                    append(FLAG_LOG, "hook fail " + key + ": " + t + "\n");
                }
            }
        }
        out("native predicate hooks=" + n);
        append(FLAG_LOG, "native predicate hooks=" + n + "\n");
    }


    // ------------------------------------------------------------- frame gate
    // 只在指定 Java 调用帧里强制返回值，避免全局强制把启动期自检也改掉（会秒退）。
    private static boolean hasFrame(String csv) {
        try {
            StackTraceElement[] st = new Throwable().getStackTrace();
            int n = Math.min(st.length, 14);
            for (int i = 0; i < n; i++) {
                String mn = st[i].getMethodName();
                for (String t : csv.split("[,; ]+")) {
                    if (t.length() == 0) continue;
                    if (t.startsWith("#")) {
                        if (st[i].getClassName().contains(t.substring(1))) return true;
                        continue;
                    }
                    if ("*".equals(t)) return true;
                    if (t.equals(mn)) return true;
                    if (st[i].getClassName().endsWith("." + t)) return true;
                }
            }
        } catch (Throwable ignore) {
        }
        return false;
    }
    // ------------------------------------------------------------- crypto probe
    // 会员记录在 prefs 里是 AES-GCM 密文；解开它才能看清会员字段长什么样。
    private static String printable(byte[] b) {
        if (b == null) return "null";
        int n = Math.min(b.length, 1800);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            int c = b[i] & 0xFF;
            if (c == 10 || c == 13) sb.append(' ');
            else if (c >= 32 && c < 127) sb.append((char) c);
            else sb.append('.');
        }
        return sb.toString();
    }

    private void cryptoProbe(ClassLoader cl) {
        int n = 0;
        try {
            Class<?> cip = Class.forName("javax.crypto.Cipher", false, cl);
            for (final Method m : cip.getDeclaredMethods()) {
                if (!m.getName().equals("doFinal")) continue;
                final Class<?>[] pt = m.getParameterTypes();
                if (pt.length != 1 || pt[0] != byte[].class) continue;
                hook(m).setId("cp-crypto").intercept(chain -> {
                    byte[] in = (byte[]) chain.getArg(0);
                    Object r = chain.proceed();
                    CipherHolder h = cipherState(chain.getThisObject());
                    String dir = h.mode == 2 ? "DEC" : (h.mode == 1 ? "ENC" : "?");
                    String plain = "DEC".equals(dir) ? printable((byte[]) r) : printable(in);
                    note("CRY " + dir + " alg=" + h.alg + " in=" + printable(in) + " => " + printable((byte[]) r), null);
                    if ("DEC".equals(dir)) {
                        lastPlain = plain;
                        Object out = forgeResponse(r);
                        if (out != null) return out;
                    }
                    return r;
                });
                n++;
            }
        } catch (Throwable t) {
            append(FLAG_LOG, "cryptoProbe failed " + t + "\n");
        }
        append(FLAG_LOG, "crypto probe hooks=" + n + "\n");
    }

    static volatile String lastPlain = "";

    // 服务端回的会员记录被写成 A100(非会员)；另外把下发配置里的自杀策略/反 hook 名单关掉，
    // 这样「伪会员」不会因为一致性自检直接退进程。
    private byte[] forgeResponse(Object plainObj) {
        if (!(plainObj instanceof byte[])) return null;
        String s;
        try {
            s = new String((byte[]) plainObj, "UTF-8");
        } catch (Throwable t) {
            return null;
        }
        String out = s;
        String mc = sStrings.get("mcode");
        if (mc == null || mc.length() == 0) mc = "A200";
        if (!"off".equalsIgnoreCase(mc)) {
            if (out.contains("\"code\":\"A100\"") || out.contains("\"code\": \"A100\"")) {
                out = out.replace("\"code\":\"A100\"", "\"code\":\"" + mc + "\"");
                out = out.replace("\"code\": \"A100\"", "\"code\": \"" + mc + "\"");
                note("FORGE code -> " + mc, null);
            }
        }
        out = forgeConfig(out);
        if (out.equals(s)) return null;
        try {
            return out.getBytes("UTF-8");
        } catch (Throwable t) {
            return null;
        }
    }

    // exit.policy / xpose_check / az 反 hook 名单：一律改成不动作
    private String forgeConfig(String s) {
        if (s == null || !s.contains("xpose_check")) return s;
        if (!"1".equals(sStrings.get("cfgforge"))) return s;  // 默认关闭：粗暴改服务端配置会弄坏功能
        String o = s;
        o = o.replace("\"policy\":1", "\"policy\":0");
        o = o.replace("\"policy\": 1", "\"policy\": 0");
        o = o.replace("\"online\":true", "\"online\":false");
        o = o.replaceAll("\"az\":\"[^\"]*\"", "\"az\":\"\"");
        o = o.replace("\"af\":1", "\"af\":0");
        if (!o.equals(s)) {
            note("FORGE config: exit/hook off", null);
        }
        return o;
    }
    static final class CipherHolder {
        int mode;
        String alg = "?";
    }

    private static CipherHolder cipherState(Object cipher) {
        CipherHolder h = new CipherHolder();
        if (cipher == null) return h;
        try {
            Field f = Class.forName("javax.crypto.Cipher").getDeclaredField("transformation");
            f.setAccessible(true);
            h.alg = String.valueOf(f.get(cipher));
        } catch (Throwable ignored) {
        }
        for (Class<?> k = cipher.getClass(); k != null; k = k.getSuperclass()) {
            try {
                Field f = k.getDeclaredField("opmode");
                f.setAccessible(true);
                Object v = f.get(cipher);
                if (v instanceof Integer) h.mode = (Integer) v;
                break;
            } catch (Throwable ignored) {
            }
        }
        return h;
    }
    // ------------------------------------------------------------- field dump
    // VM 的会员等级最终一定落在某个 Java 对象的字段里 —— 反射读一遍就把状态摊开了
    private void dumpFields(Object o, String tag, int depth) {
        if (o == null) return;
        Class<?> c = o.getClass();
        for (Class<?> k = c; k != null && k != Object.class; k = k.getSuperclass()) {
            Field[] fs;
            try {
                fs = k.getDeclaredFields();
            } catch (Throwable t) {
                continue;
            }
            for (Field f : fs) {
                String v;
                try {
                    f.setAccessible(true);
                    Object x = f.get(o);
                    v = String.valueOf(x);
                    if (v.length() > 70) v = v.substring(0, 70);
                    if (depth > 0 && x != null && !(x instanceof String) && !(x instanceof Number)
                            && !(x instanceof Boolean) && !x.getClass().isArray()) {
                        String cn = x.getClass().getName();
                        if (!cn.startsWith("java.") && !cn.startsWith("android.")) {
                            dumpFields(x, tag + "." + f.getName(), depth - 1);
                            v = v + " {nested}";
                        }
                    }
                } catch (Throwable t) {
                    v = "<" + t.getClass().getSimpleName() + ">";
                }
                note("F " + tag + "|" + k.getSimpleName() + "." + f.getName() + ":" + f.getType().getSimpleName() + " = " + v, null);
            }
        }
    }

    private void fieldProbe(ClassLoader cl) {
        int n = 0;
        try {
            Class<?> g = Class.forName("A0B0.ge", false, cl);
            for (final Method m : g.getDeclaredMethods()) {
                if (!Modifier.isNative(m.getModifiers()) || m.getParameterCount() != 0) continue;
                if (m.getReturnType() != g) continue;
                final String nm = m.getName();
                hook(m).setId("cp-fld-ge-" + nm).intercept(chain -> {
                    Object r = chain.proceed();
                    dumpFields(r, "ge." + nm, 0);
                    return r;
                });
                n++;
            }
        } catch (Throwable t) {
            append(FLAG_LOG, "fieldProbe ge failed " + t + "\n");
        }
        try {
            final Class<?> mon = Class.forName("make.more.r2d2.cellular_pro.activity.MonitorActivity", false, cl);
            for (final Method m : mon.getDeclaredMethods()) {
                if (m.getName().equals("onResume") && m.getParameterCount() == 0) {
                    hook(m).setId("cp-fld-mon").intercept(chain -> {
                        Object r = chain.proceed();
                        dumpFields(chain.getThisObject(), "mon", 1);
                        return r;
                    });
                    n++;
                }
            }
        } catch (Throwable t) {
            append(FLAG_LOG, "fieldProbe mon failed " + t + "\n");
        }
        append(FLAG_LOG, "field probe hooks=" + n + "\n");
    }
    // ------------------------------------------------------------- native trace
    // VM 的方法全是 native，Java 侧只能看见「进了哪个函数、参数是什么、回什么」
    // —— 这就是唯一的观测通道。只记不改。
    // ---------------------------------------------------------------- 信令导出
    private static boolean isClock(String s) {
        if (s.length() < 8 || s.length() > 13) return false;
        if (s.charAt(2) != ':' || s.charAt(5) != ':') return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == ':' || c == '.') continue;
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    private static void sigFlush() {
        String[] p = sSigPend;
        sSigPend = null;
        if (p == null || p[0] == null || p[2] == null || p[2].length() == 0) return;
        synchronized (sSig) {
            if (sSig.size() >= 5000) sSig.remove(0);
            sSig.add(p);
        }
    }

    private static void sigFeed(String s) {
        if (s == null || s.length() == 0 || s.length() > 512) return;
        if (isClock(s)) {
            sigFlush();
            sSigPend = new String[] { s, null, "" };
            return;
        }
        String[] p = sSigPend;
        if (p == null) return;
        if (p[1] == null) {
            if (s.length() <= 12 && s.indexOf(' ') < 0) p[1] = s;
            return;
        }
        if (p[2].length() == 0) {
            p[2] = s;
            sigFlush();
        }
    }

    private static android.content.Context appCtx() {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object a = at.getMethod("currentApplication").invoke(null);
            if (a instanceof android.content.Context) return (android.content.Context) a;
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static void toast(final String msg) {
        try {
            final android.content.Context c = appCtx();
            if (c == null) return;
            new android.os.Handler(android.os.Looper.getMainLooper()).post(new Runnable() {
                public void run() {
                    try {
                        android.widget.Toast.makeText(c, msg, android.widget.Toast.LENGTH_LONG).show();
                    } catch (Throwable ignored) {
                    }
                }
            });
        } catch (Throwable ignored) {
        }
    }

    private static String csv(String v) {
        if (v == null) return "";
        StringBuilder o = new StringBuilder(v.length());
        boolean sp = false;
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == '\r' || c == '\n' || c == '\t' || c == '\u2028' || c == '\u2029' || c == ' ') {
                if (!sp) {
                    o.append(' ');
                    sp = true;
                }
                continue;
            }
            o.append(c);
            sp = false;
        }
        String r = o.toString().trim();
        if (r.indexOf(',') >= 0 || r.indexOf('"') >= 0) {
            r = "\"" + r.replace("\"", "\"\"") + "\"";
        }
        return r;
    }

    // 直接把信令列表 adapter 里的全部条目取出来（比只看屏幕上的多得多）
    private static void rvWalk(android.view.View v, java.util.ArrayList<Object> items, int[] guard) {
        if (v == null || guard[0]++ > 4000) return;
        try {
            if (v.getClass().getName().startsWith("androidx.recyclerview.widget.RecyclerView")) {
                Object ad = v.getClass().getMethod("getAdapter").invoke(v);
                if (ad != null) {
                    int n = (Integer) ad.getClass().getMethod("getItemCount").invoke(ad);
                    java.lang.reflect.Method gi = null;
                    for (java.lang.reflect.Method m : ad.getClass().getMethods()) {
                        if (m.getName().equals("getItem") && m.getParameterCount() == 1) {
                            gi = m;
                            break;
                        }
                    }
                    if (gi != null && n > 0) {
                        for (int i = 0; i < n && i < 20000; i++) {
                            try {
                                items.add(gi.invoke(ad, i));
                            } catch (Throwable ignored) {
                            }
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        if (v instanceof android.view.ViewGroup) {
            android.view.ViewGroup vg = (android.view.ViewGroup) v;
            for (int i = 0; i < vg.getChildCount(); i++) rvWalk(vg.getChildAt(i), items, guard);
        }
    }

    private static java.util.ArrayList<String[]> rvRows(android.app.Activity a) {
        java.util.ArrayList<String[]> out = new java.util.ArrayList<>();
        try {
            java.util.ArrayList<Object> items = new java.util.ArrayList<>();
            rvWalk(a.getWindow().getDecorView(), items, new int[] { 0 });
            for (int i = 0; i < items.size(); i++) {
                Object it = items.get(i);
                if (it == null) continue;
                java.util.ArrayList<String> sv = new java.util.ArrayList<>();
                for (Class<?> c = it.getClass(); c != null && c != Object.class; c = c.getSuperclass()) {
                    java.lang.reflect.Field[] fs = c.getDeclaredFields();
                    for (int k = 0; k < fs.length; k++) {
                        try {
                            fs[k].setAccessible(true);
                            Object v = fs[k].get(it);
                            if (v instanceof String) sv.add((String) v);
                        } catch (Throwable ignored) {
                        }
                    }
                }
                String t = null, rat = null, msg = null;
                for (int k = 0; k < sv.size(); k++) {
                    String v = sv.get(k);
                    if (v.length() == 0) continue;
                    if (t == null && isClock(v)) {
                        t = v;
                        continue;
                    }
                    if (msg == null || v.length() > msg.length()) msg = v;
                }
                for (int k = 0; k < sv.size(); k++) {
                    String v = sv.get(k);
                    if (v.equals(t) || v.equals(msg) || v.length() > 10 || v.indexOf(' ') >= 0) continue;
                    rat = v;
                    break;
                }
                if (t != null && msg != null) out.add(new String[] { t, rat, msg });
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    // 导出按钮：不调 native，自己写文件，会员校验整段跳过
    private void exportSignalNative() {
        sigFlush();
        java.util.ArrayList<String[]> rows = new java.util.ArrayList<>();
        if (sAct != null) rows = rvRows(sAct);
        if (rows.isEmpty()) {
            synchronized (sSig) {
                for (int i = 0; i < sSig.size(); i++) rows.add(sSig.get(i));
            }
        }
        int n = rows.size();
        StringBuilder sb = new StringBuilder("\uFEFF时间,制式,消息\r\n");
        for (int i = 0; i < n; i++) {
            String[] r = rows.get(i);
            sb.append(csv(r[0])).append(',').append(csv(r[1])).append(',').append(csv(r[2])).append("\r\n");
        }
        if (n == 0) {
            toast("没有可导出的信令，先切到「信令」页");
            note("EXPORT 0 rows", null);
            return;
        }
        String stamp = new java.text.SimpleDateFormat("yyyyMMdd_HHmmss", java.util.Locale.US)
                .format(new java.util.Date());
        String name = "signaling_" + stamp + ".csv";
        java.io.File f = null;
        try {
            android.content.Context c = appCtx();
            java.io.File base = c == null ? null : c.getExternalFilesDir(null);
            if (base == null) base = c == null ? null : c.getFilesDir();
            if (base != null) {
                java.io.File dir = new java.io.File(base, "CellularPro/export");
                if (!dir.exists()) dir.mkdirs();
                f = new java.io.File(dir, name);
                java.io.FileOutputStream o = new java.io.FileOutputStream(f);
                o.write(sb.toString().getBytes("UTF-8"));
                o.close();
            }
        } catch (Throwable t) {
            note("EXPORT fail " + t, null);
        }
        if (f != null && f.exists()) {
            toast("已导出 " + n + " 条信令\n" + f.getAbsolutePath());
            note("EXPORT " + n + " rows -> " + f.getAbsolutePath(), null);
        } else {
            toast("导出失败，路径不可写");
        }
    }

    // ------------------------------------------------------- 导出 按钮接管
    // native 的导出分支里带会员校验，点了只会弹「仅对高级会员开放」。
    // 直接把监听器换掉：点击 = 模块自己写 CSV，完全不进 native。
    private void launch(String cls) {
        try {
            android.content.Context c = sAct != null ? sAct : appCtx();
            if (c == null) return;
            android.content.Intent i = new android.content.Intent();
            i.setClassName(c.getPackageName(), cls);
            if (!(c instanceof android.app.Activity)) i.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
            c.startActivity(i);
            note("LAUNCH " + cls, null);
        } catch (Throwable t) {
            note("LAUNCH fail " + t, null);
        }
    }

    private void exportBind(final ClassLoader cl) {
        try {
            final Class<?> mon = Class.forName("make.more.r2d2.cellular_pro.activity.MonitorActivity", false, cl);
            for (final Method m : mon.getDeclaredMethods()) {
                if (!m.getName().equals("onResume") || m.getParameterCount() != 0) continue;
                hook(m).setId("cp-exp-mon").intercept(chain -> {
                    Object r = chain.proceed();
                    try {
                        sAct = (android.app.Activity) chain.getThisObject();
                        bindExport((android.app.Activity) chain.getThisObject());
                    } catch (Throwable ignored) {
                    }
                    return r;
                });
            }
            append(FLAG_LOG, "export bind hook ready\n");
        } catch (Throwable t) {
            append(FLAG_LOG, "export bind fail " + t + "\n");
        }
    }

    private void bindExport(final android.app.Activity a) {
        try {
            final int id = a.getResources().getIdentifier("btn_export", "id", a.getPackageName());
            if (id == 0) return;
            final android.view.View v = a.findViewById(id);
            if (v == null) return;
            v.setOnClickListener(new android.view.View.OnClickListener() {
                public void onClick(android.view.View view) {
                    exportSignalNative();
                }
            });
            note("EXPORT listener bound", null);
        } catch (Throwable t) {
            note("EXPORT bind fail " + t, null);
        }
    }

    private void traceNative(ClassLoader cl, String cn, boolean skipZero) {
        Class<?> c;
        try {
            c = Class.forName(cn, false, cl);
        } catch (Throwable t) {
            append(FLAG_LOG, "trace missing " + cn + "\n");
            return;
        }
        final String shortName = cn.substring(cn.lastIndexOf('.') + 1);
        int n = 0;
        for (final Method m : c.getDeclaredMethods()) {
            if (!Modifier.isNative(m.getModifiers())) continue;
            final String nm = m.getName();
            final int pc = m.getParameterCount();
            if (skipZero && pc == 0) continue;
            try {
                hook(m).setId("cp-tr-" + shortName + "-" + nm).intercept(chain -> {
                    if (nm.equals("btn_export")) {
                        exportSignalNative();
                        return null;   // 整段 native 会员校验不执行
                    }
                    if (nm.equals("btn_task")) {
                        launch("make.more.r2d2.cellular_pro.test.activity.TestPlanActivity");
                        return null;   // 测试计划：直接开页面，跳过会员提示
                    }
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < pc; i++) {
                        Object a;
                        try {
                            a = chain.getArg(i);
                        } catch (Throwable t) {
                            a = "?";
                        }
                        if (i > 0) sb.append(',');
                        String s = String.valueOf(a);
                        if (s.length() > 48) s = s.substring(0, 48);
                        sb.append(s);
                    }
                    Object r = chain.proceed();
                    String rs = String.valueOf(r);
                    if (rs.length() > 60) rs = rs.substring(0, 60);
                    note(shortName + "." + nm + "(" + sb + ") -> " + rs, null);
                    return r;
                });
                n++;
            } catch (Throwable t) {
                append(FLAG_LOG, "trace fail " + shortName + "." + nm + ": " + t + "\n");
            }
        }
        append(FLAG_LOG, "trace " + shortName + " hooks=" + n + "\n");
    }
    // ------------------------------------------------------------- entry unlock
    // About 页里被 VM 判空的原生入口：直接拉起对应 Activity（这些页面本身完整可用）
    private void entryUnlock(ClassLoader cl) {
        String A = "make.more.r2d2.cellular_pro.activity.AboutActivity";
        unlock(cl, A, "task_test", "make.more.r2d2.cellular_pro.test.activity.AddTaskActivity");
        unlock(cl, A, "file_management", "make.more.r2d2.cellular_pro.activity.FileManageActivity");
        unlock(cl, A, "layout_play_back", "make.more.r2d2.cellular_pro.activity.FileSelectActivity");
        unlock(cl, "make.more.r2d2.cellular_pro.activity.MonitorActivity", "btn_task",
                "make.more.r2d2.cellular_pro.test.activity.AddTaskActivity");
    }

    private void unlock(ClassLoader cl, String className, String method, String targetName) {
        try {
            final Class<?> host = Class.forName(className, false, cl);
            final Class<?> target = Class.forName(targetName, false, cl);
            Method pick = null;
            for (Method x : host.getDeclaredMethods()) {
                if (x.getName().equals(method) && x.getParameterCount() == 0) { pick = x; break; }
            }
            if (pick == null) { append(FLAG_LOG, "unlock miss " + method + "\n"); return; }
            hook(pick).setId("cp-unlock-" + method).intercept(chain -> {
                Object self = chain.getThisObject();
                if (!(self instanceof android.app.Activity)) return chain.proceed();
                final android.app.Activity act = (android.app.Activity) self;
                act.runOnUiThread(() -> {
                    try {
                        android.content.Intent it = new android.content.Intent(act, target);
                        act.startActivity(it);
                        append(FLAG_LOG, "unlock " + method + " -> " + targetName + "\n");
                    } catch (Throwable t) {
                        append(FLAG_LOG, "unlock fail " + method + ": " + t + "\n");
                    }
                });
                return null;
            });
            append(FLAG_LOG, "unlock hooked " + method + " -> " + targetName + "\n");
        } catch (Throwable t) {
            append(FLAG_LOG, "unlock err " + method + ": " + t + "\n");
        }
    }
    // --------------------------------------------------------- toast probe
    // 诊断用：任何 Toast 都记下文本 + 调用栈，用来定位会员判定所在的 Java 方法
    private void toastProbe(ClassLoader cl) {
        int n = 0;
        try {
            final Class<?> toast = Class.forName("android.widget.Toast", false, cl);
            final Method show = toast.getDeclaredMethod("show");
            final Method getText = toast.getDeclaredMethod("getText");
            hook(show).setId("cp-toast-show").intercept(chain -> {
                try {
                    Object self = chain.getThisObject();
                    Object txt = self == null ? null : getText.invoke(self);
                    StringBuilder sb = new StringBuilder("TOAST '").append(txt).append('\'');
                    StackTraceElement[] st = new Throwable().getStackTrace();
                    for (int i = 0; i < st.length && i < 22; i++) {
                        sb.append("\n    at ").append(st[i]);
                    }
                    append(FLAG_LOG, sb.append('\n').toString());
                } catch (Throwable t) {
                    append(FLAG_LOG, "toast probe err " + t + "\n");
                }
                return chain.proceed();
            });
            n++;
            for (Method m : toast.getDeclaredMethods()) {
                if (!"makeText".equals(m.getName())) continue;
                hook(m).setId("cp-toast-make-" + m.getParameterCount()).intercept(chain -> {
                    try {
                        StringBuilder sb = new StringBuilder("MAKETEXT");
                        for (Object a : chain.getArgs()) {
                            sb.append(" | ").append(a instanceof CharSequence ? a : String.valueOf(a));
                        }
                        StackTraceElement[] st = new Throwable().getStackTrace();
                        for (int i = 0; i < st.length && i < 16; i++) {
                            sb.append("\n    at ").append(st[i]);
                        }
                        append(FLAG_LOG, sb.append('\n').toString());
                    } catch (Throwable ignored) {
                    }
                    return chain.proceed();
                });
                n++;
            }
        } catch (Throwable t) {
            append(FLAG_LOG, "toast probe failed " + t + "\n");
        }
        append(FLAG_LOG, "toast probe hooks=" + n + "\n");
    }

    // --------------------------------------------------------- res probe
    // 应用把 R 常量藏在加密数组里，静态看不到 caller —— 运行时按 id 记录谁在取什么串
    private void resProbe(ClassLoader cl) {
        int n = 0;
        try {
            Class<?> rc = Class.forName("android.content.res.Resources", false, cl);
            Method gs = rc.getDeclaredMethod("getString", int.class);
            hook(gs).setId("cp-res-getstring").intercept(chain -> {
                Object r = chain.proceed();
                try {
                    int id = ((Integer) chain.getArg(0)).intValue();
                    String s = String.valueOf(r);
                    if (s.length() > 70) s = s.substring(0, 70);
                    note("RES 0x" + Integer.toHexString(id) + " = " + s, null);
                } catch (Throwable ignored) {
                }
                return r;
            });
            n++;
        } catch (Throwable t) {
            append(FLAG_LOG, "res probe failed " + t + "\n");
        }
        append(FLAG_LOG, "res probe hooks=" + n + "\n");
    }

    // --------------------------------------------------------- text probe
    // 诊断用：那个蓝色提示条不是 Toast，是自绘 View —— 直接盯 TextView.setText
    private void textProbe(ClassLoader cl) {
        int n = 0;
        try {
            Class<?> tv = Class.forName("android.widget.TextView", false, cl);
            final Method setText = tv.getDeclaredMethod("setText", CharSequence.class);
            hook(setText).setId("cp-tv-settext").intercept(chain -> {
                try {
                    Object a = chain.getArgs().get(0);
                    if (a != null) {
                        String s = a.toString();
                        sigFeed(s);
                        if (s.contains("会员") || s.contains("高级")) {
                            StringBuilder sb = new StringBuilder("TEXT '" + s + "'");
                            StackTraceElement[] st = new Throwable().getStackTrace();
                            for (int i = 0; i < st.length && i < 26; i++) {
                                sb.append("\n    at ").append(st[i]);
                            }
                            append(FLAG_LOG, sb.append('\n').toString());
                        }
                    }
                } catch (Throwable ignored) {
                }
                return chain.proceed();
            });
            n++;
        } catch (Throwable t) {
            append(FLAG_LOG, "text probe failed " + t + "\n");
        }
        append(FLAG_LOG, "text probe hooks=" + n + "\n");
    }

    // --------------------------------------------------------- export probe
    // 诊断用：导出走的是原生 VM，Java 只看到 eb() 一票。这里盯文件写入与分享意图，
    // 判断「放行之后」到底有没有真的落盘。
    private void exportProbe(ClassLoader cl) {
        int n = 0;
        try {
            Class<?> fos = Class.forName("java.io.FileOutputStream", false, cl);
            java.lang.reflect.Constructor<?> c1 = fos.getDeclaredConstructor(String.class);
            hook(c1).setId("cp-fos-str").intercept(chain -> {
                try {
                    String p = String.valueOf(chain.getArg(0));
                    if (p.contains("export") || p.contains("signaling") || p.endsWith(".xls") || p.endsWith(".csv")) {
                        append(FLAG_LOG, "FOS " + p + "\n");
                    }
                } catch (Throwable ignored) {
                }
                return chain.proceed();
            });
            n++;
        } catch (Throwable t) {
            append(FLAG_LOG, "fos probe failed " + t + "\n");
        }
        try {
            Class<?> file = Class.forName("java.io.File", false, cl);
            java.lang.reflect.Constructor<?> c2 = file.getDeclaredConstructor(String.class);
            hook(c2).setId("cp-file-str").intercept(chain -> {
                try {
                    String p = String.valueOf(chain.getArg(0));
                    if (p.contains("export")) {
                        append(FLAG_LOG, "FILE " + p + "\n");
                    }
                } catch (Throwable ignored) {
                }
                return chain.proceed();
            });
            n++;
        } catch (Throwable t) {
            append(FLAG_LOG, "file probe failed " + t + "\n");
        }
        try {
            Class<?> act = Class.forName("android.app.Activity", false, cl);
            Method sa = act.getDeclaredMethod("startActivityForResult", android.content.Intent.class, int.class);
            hook(sa).setId("cp-sact").intercept(chain -> {
                try {
                    android.content.Intent i = (android.content.Intent) chain.getArg(0);
                    append(FLAG_LOG, "SACT " + (i == null ? "null" : i.getAction() + " " + i.getType()) + "\n");
                } catch (Throwable ignored) {
                }
                return chain.proceed();
            });
            n++;
        } catch (Throwable t) {
            append(FLAG_LOG, "sact probe failed " + t + "\n");
        }
        append(FLAG_LOG, "export probe hooks=" + n + "\n");
    }
    // ------------------------------------------------------------- ge probe
    // 诊断用：把 A0B0.ge 的所有原生入口都记一遍（含非布尔），点一次导出就能看出判定源
    private void geProbe(ClassLoader cl) {
        int n = 0;
        try {
            Class<?> c = Class.forName("A0B0.ge", false, cl);
            for (final Method m : c.getDeclaredMethods()) {
                if (!Modifier.isNative(m.getModifiers())) continue;
                if (m.getParameterCount() > 2) continue;
                final String key = "ge." + m.getName() + "/" + m.getReturnType().getSimpleName();
                try {
                    hook(m).setId("cp-ge-" + m.getName()).intercept(chain -> {
                        Object r;
                        try {
                            r = chain.proceed();
                        } catch (Throwable t) {
                            append(FLAG_LOG, "CALL " + key + " threw " + t + "\n");
                            throw t;
                        }
                        note("CALL " + key, r);
                        return r;
                    });
                    n++;
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable t) {
            append(FLAG_LOG, "ge probe failed " + t + "\n");
        }
        append(FLAG_LOG, "ge probe hooks=" + n + "\n");
    }

    // ---------------------------------------------------------------- dump

    private void dump(ClassLoader cl) {
        String[] names = {"A0B0.ka0", "A0B0.ge", "A0B0.pp1",
                "make.more.r2d2.cellular_pro.fragment.ViewPagerFragment",
                "make.more.r2d2.cellular_pro.fragment.FragmentLock"};
        for (String name : names) {
            try {
                Class<?> c = Class.forName(name, false, cl);
                StringBuilder sb = new StringBuilder();
                for (Method m : c.getDeclaredMethods()) {
                    sb.append(Modifier.isNative(m.getModifiers()) ? "N:" : "J:")
                            .append(m.getReturnType().getSimpleName()).append(' ')
                            .append(m.getName()).append('/').append(m.getParameterCount()).append(' ');
                }
                out("DUMP " + name + " " + sb);
            } catch (Throwable t) {
                out("DUMP " + name + " missing");
            }
        }
    }
}

