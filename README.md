# Yad APK Analyzer

**Created by KARYADI, Coding by KARYADI**

Deep APK analysis via GitHub Actions. Hasil otomatis jadi artifact (ZIP + TXT + JSON + CSV).

## Fitur Analisis

- ✅ Basic info (hash MD5/SHA-1/SHA-256)
- ✅ Struktur lengkap file APK
- ✅ Manifest deep (permission, activity, service, receiver, provider)
- ✅ DEX analysis (semua class + method, top package)
- ✅ Dead code detection (class tidak terpakai)
- ✅ Entry points detection
- ✅ Native libraries (.so) per ABI
- ✅ Resources (layout, drawable, string, asset)
- ✅ Signature & certificate info
- ✅ Security scan (hardcoded token, API key, dll)
- ✅ Dependencies detection (25+ library populer)

## Cara Pakai

### Metode 1 — Upload APK via Web (Paling Mudah)

1. Buka repo ini di GitHub
2. Klik folder **`apk/`**
3. Klik **Add file** → **Upload files**
4. Drag & drop file `.apk` Anda
5. Klik **Commit changes**
6. Workflow **Analyze APK (Auto)** akan otomatis jalan
7. Tunggu ~2-5 menit
8. Buka tab **Actions** → klik run terbaru
9. Scroll bawah → download artifact:
   - `apk-analysis-zip` — bundle ZIP lengkap
   - `apk-analysis-files` — file individual

### Metode 2 — Manual Trigger

1. Buka tab **Actions**
2. Pilih **Analyze APK (Manual)** di sidebar
3. Klik **Run workflow**
4. (Opsional) isi `apk_url` dengan link download APK
5. Klik **Run workflow**

## Output Files

| File | Isi |
|------|-----|
| `report.txt` | Report lengkap format teks |
| `report.json` | Format JSON (untuk parsing) |
| `classes.csv` | Daftar class + method count + superclass |
| `methods.csv` | Semua method di semua class |
| `permissions.csv` | Permission + level (dangerous/normal/signature) |
| `native.csv` | Native libraries (.so) |
| `manifest.txt` | Info manifest lengkap |
| `strings.txt` | Semua string resources |
| `security.txt` | Isu keamanan |
| `dependencies.txt` | Library terdeteksi |
| `dead_code.txt` | Class kandidat dead code |
| `entry_points.txt` | Entry points (activity dari manifest) |
| `file_list.txt` | Semua file dalam APK |
| `apk_info.txt` | Hash APK |

## Credit

Created by KARYADI
Coding by KARYADI
