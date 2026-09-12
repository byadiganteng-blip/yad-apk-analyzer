#!/usr/bin/env python3
# ============================================================
# APK DEEP ANALYZER
# Analisis mendalam: manifest, DEX, resources, native, security,
# dependencies, dead code, entry points, permission usage, dll.
# Output: report.txt, report.json, classes.csv, permissions.csv,
#         methods.csv, manifest.txt, strings.txt, native.csv,
#         security.txt, dependencies.txt, dead_code.txt
# Created by KARYADI, Coding by KARYADI
# ============================================================

import os, sys, zipfile, hashlib, json, csv, re, io
from datetime import datetime
from collections import Counter, defaultdict

# ---------- CONFIG ----------
APK_DIR    = os.environ.get("APK_DIR", "apk")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def P(name): return os.path.join(OUTPUT_DIR, name)

REPORT_TXT    = P("report.txt")
REPORT_JSON   = P("report.json")
CLASSES_CSV   = P("classes.csv")
METHODS_CSV   = P("methods.csv")
PERMS_CSV     = P("permissions.csv")
NATIVE_CSV    = P("native.csv")
MANIFEST_TXT  = P("manifest.txt")
STRINGS_TXT   = P("strings.txt")
SECURITY_TXT  = P("security.txt")
DEPS_TXT      = P("dependencies.txt")
DEADCODE_TXT  = P("dead_code.txt")
ENTRY_TXT     = P("entry_points.txt")
APK_INFO      = P("apk_info.txt")

report = []
data = {}

def log(m=""):
    print(m)
    report.append(str(m))

def section(t):
    log()
    log("=" * 78)
    log(f"  {t}")
    log("=" * 78)

def sub(t):
    log()
    log(f"── {t} " + "─" * (74 - len(t)))

# ---------- FIND APK ----------
apk_files = []
if os.path.exists(APK_DIR):
    for f in os.listdir(APK_DIR):
        if f.lower().endswith(".apk"):
            apk_files.append(os.path.join(APK_DIR, f))

if not apk_files:
    log(f"❌ Tidak ada APK di {APK_DIR}/")
    sys.exit(1)

APK_PATH = apk_files[0]
APK_NAME = os.path.basename(APK_PATH)
APK_SIZE = os.path.getsize(APK_PATH)

# ---------- HEADER ----------
log("=" * 78)
log("  APK DEEP ANALYZER")
log("  Created by KARYADI, Coding by KARYADI")
log("=" * 78)

section("1. INFORMASI DASAR")
log(f"  Nama        : {APK_NAME}")
log(f"  Ukuran      : {APK_SIZE:,} bytes ({APK_SIZE/1024/1024:.2f} MB)")
log(f"  Waktu       : {datetime.now().isoformat()}")

with open(APK_PATH, "rb") as f:
    content = f.read()
    md5    = hashlib.md5(content).hexdigest()
    sha1   = hashlib.sha1(content).hexdigest()
    sha256 = hashlib.sha256(content).hexdigest()

log(f"  MD5         : {md5}")
log(f"  SHA-1       : {sha1}")
log(f"  SHA-256     : {sha256}")

data["basic"] = {
    "name": APK_NAME, "size": APK_SIZE,
    "md5": md5, "sha1": sha1, "sha256": sha256,
    "analyzed_at": datetime.now().isoformat(),
}

with open(APK_INFO, "w") as f:
    f.write(f"Name: {APK_NAME}\n")
    f.write(f"Size: {APK_SIZE} bytes\n")
    f.write(f"MD5: {md5}\n")
    f.write(f"SHA1: {sha1}\n")
    f.write(f"SHA256: {sha256}\n")

# ---------- ZIP STRUCTURE ----------
section("2. STRUKTUR FILE DALAM APK")
z = zipfile.ZipFile(APK_PATH)
all_files = z.namelist()
log(f"  Total file: {len(all_files)}")

categories = {
    "DEX (bytecode)": [],
    "AndroidManifest": [],
    "Resources (res/)": [],
    "Assets": [],
    "Native (.so)": [],
    "META-INF (sign)": [],
    "Kotlin metadata": [],
    "Lain-lain": [],
}
for f in all_files:
    if f.endswith(".dex"): categories["DEX (bytecode)"].append(f)
    elif f == "AndroidManifest.xml": categories["AndroidManifest"].append(f)
    elif f.startswith("res/"): categories["Resources (res/)"].append(f)
    elif f.startswith("assets/"): categories["Assets"].append(f)
    elif f.endswith(".so"): categories["Native (.so)"].append(f)
    elif f.startswith("META-INF/"): categories["META-INF (sign)"].append(f)
    elif f.endswith(".kotlin_module"): categories["Kotlin metadata"].append(f)
    else: categories["Lain-lain"].append(f)

log()
for cat, files in categories.items():
    if files:
        total = sum(z.getinfo(f).file_size for f in files)
        log(f"  {cat:22s}: {len(files):5d} file | {total/1024:10.1f} KB")

data["structure"] = {k: {"count": len(v),
                         "size": sum(z.getinfo(f).file_size for f in v)}
                     for k, v in categories.items() if v}

# Simpan daftar file lengkap
with open(P("file_list.txt"), "w") as f:
    for name in all_files:
        try:
            size = z.getinfo(name).file_size
            f.write(f"{size:12d}  {name}\n")
        except:
            f.write(f"           ?  {name}\n")

# ---------- MANIFEST ----------
section("3. ANDROID MANIFEST (Deep)")
manifest_info = {}

try:
    from androguard.core.apk import APK as AG
    a = AG(APK_PATH)

    pkg          = a.get_package()
    version_name = a.get_androidversion_name()
    version_code = a.get_androidversion_code()
    min_sdk      = a.get_min_sdk_version()
    target_sdk   = a.get_target_sdk_version()
    main_act     = a.get_main_activity()

    log(f"  Package       : {pkg}")
    log(f"  Version name  : {version_name}")
    log(f"  Version code  : {version_code}")
    log(f"  Min SDK       : {min_sdk}")
    log(f"  Target SDK    : {target_sdk}")
    log(f"  Main Activity : {main_act}")

    manifest_info = {
        "package": pkg, "version_name": version_name,
        "version_code": version_code,
        "min_sdk": min_sdk, "target_sdk": target_sdk,
        "main_activity": main_act,
    }

    # ---- PERMISSIONS ----
    perms = sorted(a.get_permissions())
    DANGEROUS = {
        "android.permission.READ_SMS", "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS", "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS", "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION", "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG", "android.permission.CALL_PHONE",
        "android.permission.READ_PHONE_STATE", "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.BODY_SENSORS",
        "android.permission.GET_ACCOUNTS", "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR", "android.permission.POST_NOTIFICATIONS",
        "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.QUERY_ALL_PACKAGES", "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_PHONE_NUMBERS", "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.ACTIVITY_RECOGNITION", "android.permission.BLUETOOTH_SCAN",
        "android.permission.BLUETOOTH_CONNECT", "android.permission.UWB_RANGING",
    }
    SIGNATURE = {
        "android.permission.INSTALL_PACKAGES", "android.permission.DELETE_PACKAGES",
        "android.permission.WRITE_SECURE_SETTINGS", "android.permission.READ_LOGS",
        "android.permission.REBOOT", "android.permission.SHUTDOWN",
    }

    sub(f"Permissions ({len(perms)})")
    for p in perms:
        if p in SIGNATURE: flag = "SIGNATURE"
        elif p in DANGEROUS: flag = "DANGEROUS"
        else: flag = "normal"
        log(f"      [{flag:10s}] {p}")

    # Save permissions.csv
    with open(PERMS_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["permission", "level"])
        for p in perms:
            lvl = "SIGNATURE" if p in SIGNATURE else ("DANGEROUS" if p in DANGEROUS else "normal")
            w.writerow([p, lvl])

    manifest_info["permissions"] = perms

    # ---- COMPONENTS ----
    acts      = a.get_activities()
    services  = a.get_services()
    receivers = a.get_receivers()
    providers = a.get_providers()

    sub(f"Activities ({len(acts)})")
    for x in acts:
        # Cek apakah exported
        marker = ""
        if x == main_act: marker = " ⭐ LAUNCHER"
        log(f"      {x}{marker}")

    sub(f"Services ({len(services)})")
    for x in services: log(f"      {x}")

    sub(f"Receivers ({len(receivers)})")
    for x in receivers: log(f"      {x}")

    sub(f"Providers ({len(providers)})")
    for x in providers: log(f"      {x}")

    manifest_info.update({
        "activities": acts, "services": services,
        "receivers": receivers, "providers": providers,
    })

    # Simpan manifest.txt
    with open(MANIFEST_TXT, "w") as f:
        f.write(f"Package: {pkg}\n")
        f.write(f"Version: {version_name} ({version_code})\n")
        f.write(f"Min SDK: {min_sdk}\nTarget SDK: {target_sdk}\n")
        f.write(f"Main Activity: {main_act}\n\n")
        f.write("PERMISSIONS:\n")
        for p in perms: f.write(f"  {p}\n")
        f.write("\nACTIVITIES:\n")
        for x in acts: f.write(f"  {x}\n")
        f.write("\nSERVICES:\n")
        for x in services: f.write(f"  {x}\n")
        f.write("\nRECEIVERS:\n")
        for x in receivers: f.write(f"  {x}\n")
        f.write("\nPROVIDERS:\n")
        for x in providers: f.write(f"  {x}\n")

except Exception as e:
    log(f"  ❌ Manifest error: {e}")
    manifest_info = {"error": str(e)}

data["manifest"] = manifest_info

# ---------- DEX ----------
section("4. DEX DEEP ANALYSIS")
dex_info = {"classes": [], "total_methods": 0}

try:
    from androguard.core.dex import DEX

    dex_list = [f for f in all_files if f.endswith(".dex")]
    log(f"  Jumlah DEX: {len(dex_list)}")
    log()

    all_class_objs = []
    class_map = {}   # class_name -> obj
    method_set = set()

    for dex_name in dex_list:
        log(f"  ⏳ Parsing {dex_name} ...")
        dex_bytes = z.read(dex_name)
        try:
            dx = DEX(dex_bytes)
            for cls in dx.get_classes():
                name = cls.get_name()
                methods = [m.get_name() for m in cls.get_methods()]
                # Simpan semua method (bukan hanya 50)
                all_class_objs.append({
                    "class": name,
                    "methods_count": len(methods),
                    "methods": methods,
                    "dex": dex_name,
                    "super": cls.get_superclassname() if hasattr(cls, "get_superclassname") else "",
                    "interfaces": cls.get_interfaces() if hasattr(cls, "get_interfaces") else [],
                })
                class_map[name] = cls
                for m in methods:
                    method_set.add(f"{name}->{m}")
        except Exception as e:
            log(f"    ⚠️  {dex_name}: {e}")

    log()
    log(f"  📦 Total classes   : {len(all_class_objs)}")
    log(f"  🔧 Total methods   : {sum(c['methods_count'] for c in all_class_objs)}")

    dex_info["classes"] = all_class_objs
    dex_info["total_methods"] = sum(c["methods_count"] for c in all_class_objs)

    # Package counter
    pkg_counter = Counter()
    for c in all_class_objs:
        parts = c["class"].lstrip("L").split("/")
        if len(parts) >= 3:
            pkg_counter["/".join(parts[:3])] += 1

    sub("Top 15 Package")
    for pkg, cnt in pkg_counter.most_common(15):
        log(f"      {cnt:6d}  {pkg}")

    # Save classes.csv
    with open(CLASSES_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["class", "methods_count", "super", "dex"])
        for c in all_class_objs:
            w.writerow([c["class"], c["methods_count"], c["super"], c["dex"]])

    # Save methods.csv (semua method)
    with open(METHODS_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["class", "method"])
        for c in all_class_objs:
            for m in c["methods"]:
                w.writerow([c["class"], m])

    # ---- ANALYSIS: CLASS YANG DIPAKAI (referenced) ----
    sub("Dead Code Detection")

    # Class yang dideklarasikan
    declared_classes = set(c["class"] for c in all_class_objs)

    # Class yang dipakai di manifest
    used_in_manifest = set()
    for key in ("activities", "services", "receivers", "providers"):
        for name in manifest_info.get(key, []):
            # Convert com.example.Foo → Lcom/example/Foo;
            used_in_manifest.add("L" + name.replace(".", "/") + ";")

    # Class yang direferensikan sebagai string
    all_strings = set()
    for dex_name in dex_list:
        try:
            dex_bytes = z.read(dex_name)
            dx = DEX(dex_bytes)
            for s in dx.get_strings():
                all_strings.add(str(s))
        except: pass

    # Klasifikasi
    entry_points = set()
    dead_candidates = set()

    for c in all_class_objs:
        name = c["class"]
        # Simpel: kalau class dipakai di manifest, itu entry point
        if name in used_in_manifest:
            entry_points.add(name)
            continue
        # Kalau namanya tidak muncul di strings, mungkin dead code
        simple = name.lstrip("L").rstrip(";").split("/")[-1]
        if simple and not any(simple in s for s in all_strings if len(s) < 200):
            dead_candidates.add(name)

    log(f"  🎯 Entry points: {len(entry_points)}")
    log(f"  🧹 Dead code candidates: {len(dead_candidates)}")

    with open(DEADCODE_TXT, "w") as f:
        f.write(f"Entry Points ({len(entry_points)}):\n")
        for e in sorted(entry_points): f.write(f"  {e}\n")
        f.write(f"\n\nDead Code Candidates ({len(dead_candidates)}):\n")
        for d in sorted(dead_candidates): f.write(f"  {d}\n")

    # Save entry_points.txt
    with open(ENTRY_TXT, "w") as f:
        f.write(f"Entry Points ({len(entry_points)}):\n")
        for e in sorted(entry_points): f.write(f"  {e}\n")

    dex_info["entry_points"] = list(entry_points)
    dex_info["dead_candidates"] = list(dead_candidates)
    dex_info["top_packages"] = dict(pkg_counter.most_common(20))

except Exception as e:
    log(f"  ❌ DEX error: {e}")
    dex_info = {"error": str(e)}

data["dex"] = dex_info

# ---------- NATIVE LIBS ----------
section("5. NATIVE LIBRARIES")
native_info = {}
try:
    so_files = [f for f in all_files if f.endswith(".so")]
    log(f"  Total .so: {len(so_files)}")

    abi_counter = Counter()
    lib_names = set()
    for so in so_files:
        parts = so.split("/")
        if "lib" in parts:
            idx = parts.index("lib")
            if idx + 1 < len(parts):
                abi_counter[parts[idx + 1]] += 1
        lib_names.add(os.path.basename(so).replace("lib", "").replace(".so", ""))

    log()
    log("  Per ABI:")
    for abi, cnt in abi_counter.most_common():
        log(f"      {abi}: {cnt}")

    log()
    log("  Library names:")
    for l in sorted(lib_names):
        log(f"      - {l}")

    with open(NATIVE_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["library", "path"])
        for so in so_files:
            w.writerow([os.path.basename(so), so])

    native_info = {
        "total": len(so_files),
        "abis": dict(abi_counter),
        "libraries": sorted(lib_names),
    }
except Exception as e:
    log(f"  ❌ Native error: {e}")
    native_info = {"error": str(e)}

data["native"] = native_info

# ---------- RESOURCES ----------
section("6. RESOURCES (Deep)")
resource_info = {}
try:
    layouts = [f for f in all_files if "/layout/" in f and f.endswith(".xml")]
    drawables = [f for f in all_files if "/drawable" in f]
    strings_xml = [f for f in all_files if "strings.xml" in f]
    assets = [f for f in all_files if f.startswith("assets/")]
    raw = [f for f in all_files if "/raw/" in f]
    anim = [f for f in all_files if "/anim/" in f]
    menus = [f for f in all_files if "/menu/" in f]
    colors = [f for f in all_files if "/color" in f and f.endswith(".xml")]
    fonts = [f for f in all_files if "/font" in f]

    log(f"  Layout XML   : {len(layouts)}")
    log(f"  Drawables    : {len(drawables)}")
    log(f"  strings.xml  : {len(strings_xml)}")
    log(f"  Assets       : {len(assets)}")
    log(f"  Raw          : {len(raw)}")
    log(f"  Anim         : {len(anim)}")
    log(f"  Menu         : {len(menus)}")
    log(f"  Colors       : {len(colors)}")
    log(f"  Fonts        : {len(fonts)}")

    sub("Layouts")
    for l in sorted(layouts):
        log(f"      - {os.path.basename(l)}")

    sub("Assets")
    for a in sorted(assets)[:50]:
        try:
            size = z.getinfo(a).file_size
            log(f"      - {a} ({size:,} B)")
        except:
            log(f"      - {a}")

    # Baca strings.xml (kalau ada)
    sub("Strings.xml")
    try:
        for sx in strings_xml:
            try:
                sx_content = z.read(sx).decode("utf-8", errors="ignore")
                # Cari string tags
                matches = re.findall(r'<string name="([^"]+)">([^<]*)</string>', sx_content)
                log(f"      {sx}: {len(matches)} strings")
                with open(STRINGS_TXT, "a", encoding="utf-8") as f:
                    f.write(f"\n=== {sx} ===\n")
                    for name, val in matches:
                        f.write(f"{name} = {val}\n")
            except Exception as e:
                log(f"      ⚠️  {sx}: {e}")
    except: pass

    resource_info = {
        "layouts": len(layouts),
        "drawables": len(drawables),
        "assets": len(assets),
        "raw": len(raw),
        "anim": len(anim),
        "menus": len(menus),
        "fonts": len(fonts),
        "layout_list": [os.path.basename(l) for l in layouts],
    }

except Exception as e:
    log(f"  ❌ Resource error: {e}")
    resource_info = {"error": str(e)}

data["resources"] = resource_info

# ---------- SIGNATURE ----------
section("7. SIGNATURE")
sig_info = {}
try:
    from androguard.core.apk import APK as AG2
    a2 = AG2(APK_PATH)
    certs = a2.get_certificates()
    if certs:
        for cert in certs:
            log(f"  Subject    : {cert.subject.human_friendly}")
            log(f"  Issuer     : {cert.issuer.human_friendly}")
            log(f"  Serial     : {cert.serial_number}")
            log(f"  Valid from : {cert.not_valid_before}")
            log(f"  Valid to   : {cert.not_valid_after}")
            log(f"  SHA-1      : {cert.sha1_fingerprint}")
            log(f"  SHA-256    : {cert.sha256_fingerprint}")
            sig_info = {
                "subject": cert.subject.human_friendly,
                "issuer": cert.issuer.human_friendly,
                "serial": str(cert.serial_number),
                "sha1": cert.sha1_fingerprint,
                "sha256": cert.sha256_fingerprint,
            }
    else:
        log("  ⚠️  APK tidak ditandatangani")
        sig_info = {"error": "unsigned"}
except Exception as e:
    log(f"  ❌ Signature error: {e}")
    sig_info = {"error": str(e)}

data["signature"] = sig_info

# ---------- SECURITY ----------
section("8. SECURITY ANALYSIS")
security_issues = []
try:
    PATTERNS = {
        "GitHub Token": r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}',
        "Google API Key": r'AIza[A-Za-z0-9_\-]{35}',
        "AWS Access Key": r'AKIA[A-Z0-9]{16}',
        "AWS Secret Key": r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]',
        "Private Key": r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        "JWT": r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        "Firebase URL": r'https://[a-z0-9\-]+\.firebaseio\.com',
        "Slack Token": r'xox[baprs]-[0-9a-zA-Z]{10,}',
        "Stripe Key": r'sk_live_[0-9a-zA-Z]{24}',
        "Password": r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{6,})["\']',
    }

    sub("Scanning DEX for hardcoded secrets")
    for dex_name in [f for f in all_files if f.endswith(".dex")]:
        try:
            dex_bytes = z.read(dex_name)
            text = dex_bytes.decode("utf-8", errors="ignore")
            for name, pat in PATTERNS.items():
                matches = re.findall(pat, text)
                if matches:
                    issue = f"🔴 {name} di {dex_name}: {len(matches)} kali"
                    security_issues.append(issue)
                    log(f"      {issue}")
        except: pass

    sub("Scanning strings.xml")
    for sx in [f for f in all_files if "strings.xml" in f]:
        try:
            sx_content = z.read(sx).decode("utf-8", errors="ignore")
            for name, pat in PATTERNS.items():
                if re.search(pat, sx_content):
                    issue = f"🔴 {name} di {sx}"
                    security_issues.append(issue)
                    log(f"      {issue}")
        except: pass

    sub("Checking manifest flags")
    # Cek allowBackup
    try:
        manifest_text = z.read("AndroidManifest.xml").decode("utf-8", errors="ignore")
        if 'allowBackup="true"' in manifest_text or "allowBackup" in manifest_text:
            security_issues.append("🟡 allowBackup=true")
            log("      🟡 allowBackup=true — data bisa di-backup")

        if 'debuggable="true"' in manifest_text:
            security_issues.append("🔴 APK debuggable=true")
            log("      🔴 APK debuggable=true — tidak untuk produksi")

        if 'exported="true"' in manifest_text:
            security_issues.append("🟡 Ada komponen exported=true")
            log("      🟡 Ada komponen exported=true — cek apakah perlu")
    except: pass

    sub("Summary")
    if security_issues:
        log(f"      Total {len(security_issues)} isu ditemukan")
    else:
        log("      ✅ Tidak ada isu terdeteksi")

except Exception as e:
    log(f"  ❌ Security error: {e}")

with open(SECURITY_TXT, "w") as f:
    if security_issues:
        for i in security_issues: f.write(f"{i}\n")
    else:
        f.write("No issues detected\n")

data["security"] = {"issues": security_issues}

# ---------- DEPENDENCIES ----------
section("9. DEPENDENCIES (Heuristic)")
deps_detected = []
try:
    LIB_HINTS = {
        "okhttp":        "OkHttp (HTTP client)",
        "retrofit":      "Retrofit (REST client)",
        "gson":          "Gson (JSON)",
        "moshi":         "Moshi (JSON)",
        "jackson":       "Jackson (JSON)",
        "glide":         "Glide (image loader)",
        "picasso":       "Picasso (image loader)",
        "coil":          "Coil (image loader)",
        "fresco":        "Fresco (image loader)",
        "firebase":      "Firebase",
        "play-services": "Google Play Services",
        "ffmpeg":        "FFmpeg",
        "exoplayer":     "ExoPlayer",
        "media3":        "Media3",
        "kotlin":        "Kotlin stdlib",
        "kotlinx":       "Kotlin Coroutines / Serialization",
        "coroutines":    "Kotlin Coroutines",
        "material":      "Material Components",
        "androidx":      "AndroidX",
        "realm":         "Realm DB",
        "room":          "Room DB",
        "sqlite":        "SQLite",
        "jsoup":         "Jsoup (HTML parser)",
        "zxing":         "ZXing (QR code)",
        "lottie":        "Lottie (animation)",
        "butterknife":   "ButterKnife",
        "dagger":        "Dagger (DI)",
        "hilt":          "Hilt (DI)",
        "kodein":        "Kodein (DI)",
        "timber":        "Timber (logging)",
        "leakcanary":    "LeakCanary",
        "stetho":        "Stetho",
        "appintro":      "AppIntro",
        "photoView":     "PhotoView",
        "chart":         "MPAndroidChart",
        "admob":         "AdMob",
        "facebook":      "Facebook SDK",
        "crashlytics":   "Crashlytics",
        "sentry":        "Sentry",
        "amplitude":     "Amplitude",
        "mixpanel":      "Mixpanel",
    }
    all_names_lower = " ".join(all_files).lower()
    for hint, desc in LIB_HINTS.items():
        if hint.lower() in all_names_lower:
            deps_detected.append(desc)
            log(f"      ✅ {desc}")

    with open(DEPS_TXT, "w") as f:
        for d in deps_detected: f.write(f"{d}\n")
except Exception as e:
    log(f"  ❌ Deps error: {e}")

data["dependencies"] = deps_detected

# ---------- RINGKASAN ----------
section("10. RINGKASAN AKHIR")
log(f"  📱 APK            : {APK_NAME}")
log(f"  📦 Ukuran         : {APK_SIZE/1024/1024:.2f} MB")
log(f"  📄 Total file     : {len(all_files)}")
log(f"  🎬 Activities     : {len(manifest_info.get('activities', []))}")
log(f"  ⚙️  Services       : {len(manifest_info.get('services', []))}")
log(f"  📡 Receivers      : {len(manifest_info.get('receivers', []))}")
log(f"  📤 Providers      : {len(manifest_info.get('providers', []))}")
log(f"  🔐 Permissions    : {len(manifest_info.get('permissions', []))}")
log(f"  📦 Classes        : {dex_info.get('total_methods', 0) and len(dex_info.get('classes', [])) or 0}")
log(f"  🔧 Methods        : {dex_info.get('total_methods', 0)}")
log(f"  🔗 Native libs    : {native_info.get('total', 0)}")
log(f"  🎨 Layout XML     : {resource_info.get('layouts', 0)}")
log(f"  🖼️  Drawables      : {resource_info.get('drawables', 0)}")
log(f"  🚨 Security       : {len(security_issues)} isu")
log(f"  📚 Dependencies   : {len(deps_detected)} library")
log()
log("=" * 78)
log("  ✅ Analisis selesai")
log("  Created by KARYADI, Coding by KARYADI")
log("=" * 78)

# ---------- WRITE OUTPUTS ----------
with open(REPORT_TXT, "w", encoding="utf-8") as f:
    f.write("\n".join(report))

with open(REPORT_JSON, "w", encoding="utf-8") as f:
    # Convert set → list
    def json_safe(o):
        if isinstance(o, set): return list(o)
        if isinstance(o, dict): return {k: json_safe(v) for k, v in o.items()}
        if isinstance(o, list): return [json_safe(x) for x in o]
        return o
    json.dump(json_safe(data), f, indent=2, ensure_ascii=False)

print()
print("=" * 60)
print("📄 OUTPUT FILES:")
for f in [REPORT_TXT, REPORT_JSON, CLASSES_CSV, METHODS_CSV, PERMS_CSV,
          NATIVE_CSV, MANIFEST_TXT, STRINGS_TXT, SECURITY_TXT, DEPS_TXT,
          DEADCODE_TXT, ENTRY_TXT, APK_INFO]:
    if os.path.exists(f):
        print(f"   ✅ {f} ({os.path.getsize(f):,} bytes)")
print("=" * 60)
