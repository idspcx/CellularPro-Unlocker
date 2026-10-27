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
        safe("entry", () -> entryUnlock(cl));
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
    static final Map<String, Integer> sSeen = new HashMap<String, Integer>();
    static final int SEEN_MAX = 3;

    private void loadFlags() {
        File f = new File(FLAG_FILE);
        long mt = f.exists() ? f.lastModified() : 0;
        if (mt == sFlagMtime) return;
        sFlagMtime = mt;
        Map<String, Boolean> m = new HashMap<String, Boolean>();
        if (mt != 0) {
            try {
                BufferedReader r = new BufferedReader(new FileReader(f));
                String line;
                while ((line = r.readLine()) != null) {
                    line = line.trim();
                    if (line.length() == 0 || line.charAt(0) == '#') continue;
                    int eq = line.indexOf('=');
                    if (eq <= 0) continue;
                    m.put(line.substring(0, eq).trim(), "1".equals(line.substring(eq + 1).trim()));
                }
                r.close();
            } catch (Throwable ignored) {
            }
        }
        sFlags = m;
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
                "make.more.r2d2.cellular_pro.activity.AboutActivity"};
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
                if (m.getReturnType() != boolean.class) continue;
                if (m.getParameterCount() != 0) continue;
                final String key = shortName + "." + m.getName();
                try {
                    hook(m).setId("cp-nat-" + key).intercept(chain -> {
                        loadFlags();
                        Boolean want = sFlags.get(key);
                        if (want == null) want = sFlags.get(m.getName());
                        Object r = chain.proceed();
                        if (want != null) {
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