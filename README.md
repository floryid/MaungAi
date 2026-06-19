# MaungAi

MaungAi adalah aplikasi terminal berbasis Python untuk workflow reconnaissance dan vulnerability assessment yang bertahap, cepat, terstruktur, dan fokus pada target yang memang relevan. Tool ini dirancang untuk authorized testing seperti bug bounty, VDP, penetration test resmi, dan audit keamanan yang memiliki izin tertulis.

Repository GitHub:

- Repository page: `https://github.com/floryid/MaungAi`
- Git clone URL: `https://github.com/floryid/MaungAi.git`

## Preview Banner

Berikut contoh banner terminal `MaungAi` yang dipakai di aplikasi. Pada terminal Linux UTF-8, banner ini tampil dengan tema warna merah dan hijau.

```text
 ███╗   ███╗ █████╗ ██╗   ██╗███╗   ██╗ ██████╗      █████╗ ██╗
 ████╗ ████║██╔══██╗██║   ██║████╗  ██║██╔════╝     ██╔══██╗██║
 ██╔████╔██║███████║██║   ██║██╔██╗ ██║██║  ███╗    ███████║██║
 ██║╚██╔╝██║██╔══██║██║   ██║██║╚██╗██║██║   ██║    ██╔══██║██║
 ██║ ╚═╝ ██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝    ██║  ██║██║
 ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝     ╚═╝  ╚═╝╚═╝

         Recon • Discovery • Automation • Research
```

Catatan:

- Di terminal Linux UTF-8, banner tampil penuh dengan warna ANSI merah-hijau.
- Di terminal yang tidak mendukung Unicode dengan baik, `MaungAi` otomatis memakai fallback ASCII agar tetap terbaca.

## Ringkasan

MaungAi mengikuti alur kerja bug hunter modern:

1. Temukan aset
2. Validasi host hidup
3. Petakan endpoint
4. Prioritaskan parameter rawan
5. Jalankan automated checks
6. Lanjut verifikasi manual
7. Dokumentasikan hasil

Pendekatan ini lebih rapi dan efisien dibanding langsung menghajar semua target dengan satu command panjang.

## Kenapa MaungAi

- Fokus pada workflow terminal Linux yang sederhana tetapi powerful.
- Mengikuti alur modern: `recon -> validation -> discovery -> scanning`.
- Mengurangi noise dengan memproses host hidup dan endpoint relevan.
- Menyimpan hasil scan per target agar mudah di-review.
- Tetap bisa jalan meskipun sebagian tool eksternal belum terpasang.
- Mendukung preset scan `fast`, `balanced`, dan `deep`.
- Menyediakan report, execution plan, inventory, dan manual review queue.

## Fitur Utama

- UI terminal interaktif dengan menu yang jelas.
- Mode CLI non-interaktif untuk automasi atau scripting.
- Preset scan:
  - `fast` untuk triage cepat
  - `balanced` untuk workflow harian
  - `deep` untuk audit resmi yang lebih dalam
- Integrasi tool modern:
  - `subfinder` untuk subdomain discovery
  - `httpx` untuk validasi live host dan fingerprinting
  - `katana` untuk crawling endpoint
  - `gau` dan `waybackurls` untuk historical URLs
  - `gf` dan `uro` untuk parameter triage
  - `nuclei -as` untuk automated checks
- Output profesional per target:
  - `assets/`
  - `endpoints/`
  - `parameters/`
  - `findings/`
  - `raw/`
  - `logs/`
  - `reports/`
- Fallback internal Python jika tool tertentu belum tersedia.

## Filosofi Pipeline

### Asset Discovery

- Cari subdomain awal dan inventaris dasar.

### Live Host Validation

- Buang aset mati lebih awal.
- Simpan informasi teknologi untuk triage berikutnya.

### Endpoint Discovery

- Gabungkan crawling aktif dan historical URLs.
- Pisahkan endpoint API, JavaScript, dan endpoint penting.

### Parameter Analysis

- Prioritaskan parameter yang paling sering relevan untuk XSS, SQLi, SSRF, redirect, dan sink input lain.

### Automated Checks

- Jalankan scan template modern hanya pada target yang lebih relevan.

### Manual Review

- Fokus ke auth, authz, upload, business logic, akses API, dan validasi manual lain.

### Reporting

- Hasil akhir disusun dalam markdown dan JSON agar mudah dibaca atau diolah ulang.

## Kebutuhan Sistem

Target utama penggunaan adalah Linux.

### Minimum

- Linux modern seperti Ubuntu, Debian, Kali, Parrot, Arch, atau distro sejenis
- Python `>= 3.10`
- Git
- Go untuk install tool recon eksternal

### Tool eksternal yang didukung

- `subfinder`
- `httpx`
- `katana`
- `gau`
- `waybackurls`
- `gf`
- `uro`
- `nuclei`

## Instalasi Lengkap di Linux

### 1. Clone repository

```bash
git clone https://github.com/floryid/MaungAi.git
cd MaungAi
```

### 2. Buat virtual environment Python

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Update `pip` dan install package

```bash
pip install --upgrade pip
pip install -e .
```

Setelah langkah ini selesai, Anda bisa menjalankan command:

```bash
maungai
```

### 4. Install tool eksternal secara otomatis

Gunakan script installer bawaan:

```bash
chmod +x scripts/install_linux_tools.sh
./scripts/install_linux_tools.sh
```

Script ini akan membantu menginstall:

- `subfinder`
- `httpx`
- `katana`
- `gau`
- `waybackurls`
- `gf`
- `uro`
- `nuclei`

Script installer:

- Relative path: `scripts/install_linux_tools.sh`
- GitHub URL: `https://github.com/floryid/MaungAi/blob/main/scripts/install_linux_tools.sh`

### 5. Verifikasi instalasi tool

```bash
subfinder -version
httpx -version
katana -version
nuclei -version
```

Jika semua normal, maka lingkungan Linux Anda sudah siap.

## Menjalankan MaungAi

Ada dua cara utama:

### 1. Mode interaktif

Jalankan:

```bash
maungai
```

Atau:

```bash
python3 main.py
```

Mode ini cocok jika Anda ingin memilih target, profile, dan step langsung dari menu terminal.

### 2. Mode non-interaktif

Mode ini cocok untuk automasi, VPS, screen/tmux, atau cron/manual scripting.

Contoh:

```bash
python3 main.py --target example.com --scope "*.example.com" --profile balanced --full-pipeline
```

## Cara Pakai Lengkap

### A. Jalankan full pipeline

```bash
python3 main.py \
  --target example.com \
  --scope "*.example.com" \
  --profile balanced \
  --full-pipeline
```

Penjelasan:

- `--target` adalah domain utama
- `--scope` adalah scope yang Anda izinkan untuk diuji
- `--profile balanced` cocok untuk workflow standar
- `--full-pipeline` menjalankan semua tahap

### B. Jalankan per tahap

Jika ingin lebih terkontrol, jalankan satu per satu:

```bash
python3 main.py --target example.com --step assets
python3 main.py --target example.com --step live
python3 main.py --target example.com --step endpoints
python3 main.py --target example.com --step params
python3 main.py --target example.com --step scan
python3 main.py --target example.com --step manual
python3 main.py --target example.com --step report
```

### C. Simpan konfigurasi

```bash
python3 main.py \
  --target example.com \
  --scope "*.example.com" \
  --profile fast \
  --save-config
```

Output config akan tersimpan seperti:

```text
project/example.com/reports/maungai-config.json
```

### D. Gunakan config yang sudah disimpan

```bash
python3 main.py --config project/example.com/reports/maungai-config.json --full-pipeline
```

### E. Jalankan tanpa historical URLs

```bash
python3 main.py \
  --target example.com \
  --scope "*.example.com" \
  --profile fast \
  --no-history \
  --full-pipeline
```

Ini berguna jika Anda ingin scan lebih hemat request dan lebih fokus pada crawling aktif.

## Penjelasan Profile

### `fast`

Cocok untuk:

- triage cepat
- cek awal scope besar
- hemat request

Contoh:

```bash
python3 main.py --target example.com --scope "*.example.com" --profile fast --full-pipeline
```

### `balanced`

Cocok untuk:

- workflow default harian
- recon yang cukup lengkap
- hasil lebih stabil

Contoh:

```bash
python3 main.py --target example.com --scope "*.example.com" --profile balanced --full-pipeline
```

### `deep`

Cocok untuk:

- audit resmi
- scope lebih sempit
- eksplorasi lebih dalam

Contoh:

```bash
python3 main.py --target app.example.com --scope "app.example.com" --profile deep --full-pipeline
```

## Contoh Penggunaan Lengkap

### Contoh 1: Recon cepat untuk bug bounty

```bash
git clone https://github.com/floryid/MaungAi.git
cd MaungAi
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
chmod +x scripts/install_linux_tools.sh
./scripts/install_linux_tools.sh

python3 main.py \
  --target example.com \
  --scope "*.example.com" \
  --profile fast \
  --full-pipeline
```

Hasil utama yang akan Anda dapat:

- `project/example.com/assets/live.txt`
- `project/example.com/endpoints/urls.txt`
- `project/example.com/parameters/gf_xss.txt`
- `project/example.com/parameters/gf_sqli.txt`
- `project/example.com/parameters/gf_ssrf.txt`
- `project/example.com/reports/summary.md`

### Contoh 2: Jalankan bertahap untuk validasi manual

```bash
python3 main.py --target example.com --step assets
python3 main.py --target example.com --step live
python3 main.py --target example.com --step endpoints
python3 main.py --target example.com --step params
python3 main.py --target example.com --step report
```

Lalu review:

```bash
cat project/example.com/reports/summary.md
cat project/example.com/reports/manual-review.md
```

### Contoh 3: Workflow interaktif

```bash
maungai
```

Lalu di menu:

1. Pilih `t` untuk set target
2. Pilih `p` untuk set profile
3. Pilih `8` untuk menjalankan full pipeline
4. Pilih `7` untuk generate report
5. Buka hasil di folder `project/<target>/reports/`

## Opsi CLI

- `--target` domain utama, contoh `example.com`
- `--scope` scope target, contoh `"*.example.com"`
- `--workspace-root` root folder output, default `project`
- `--profile` preset scan: `fast`, `balanced`, `deep`
- `--timeout` timeout per command dalam detik
- `--config` load config JSON yang pernah disimpan
- `--save-config` simpan config lalu keluar
- `--no-history` matikan pengambilan URL historical
- `--step` jalankan satu tahap
- `--full-pipeline` jalankan semua tahap

## Struktur Output

Untuk target `example.com`, struktur output default:

```text
project/example.com/
├── assets/
│   ├── subdomains.txt
│   ├── live.txt
│   ├── technologies.txt
│   └── dns.txt
├── endpoints/
│   ├── urls.txt
│   ├── js.txt
│   ├── api.txt
│   └── interesting.txt
├── parameters/
│   ├── query.txt
│   ├── post.txt
│   ├── hidden.txt
│   ├── priority.txt
│   ├── gf_xss.txt
│   ├── gf_sqli.txt
│   └── gf_ssrf.txt
├── findings/
│   ├── info/
│   ├── low/
│   ├── medium/
│   └── high/
├── screenshots/
├── raw/
├── logs/
└── reports/
    ├── maungai-config.json
    ├── manual-review.md
    ├── execution-plan.md
    ├── inventory.md
    ├── summary.md
    └── summary.json
```

## File Hasil yang Paling Sering Dipakai

- `assets/live.txt` untuk daftar host hidup
- `endpoints/urls.txt` untuk seluruh URL unik
- `endpoints/interesting.txt` untuk endpoint prioritas
- `parameters/priority.txt` untuk parameter yang lebih menarik
- `findings/` untuk hasil severity otomatis
- `reports/manual-review.md` untuk checklist verifikasi manual
- `reports/summary.md` untuk ringkasan hasil

## Workflow Ideal

1. Set `target` dan `scope`
2. Pilih profile scan
3. Jalankan `assets`
4. Lanjut `live`
5. Jalankan `endpoints`
6. Review `params`
7. Jalankan `scan`
8. Gunakan `manual-review.md` untuk verifikasi
9. Simpan dan review `summary.md`

## Testing

Jalankan test bawaan:

```bash
python3 -m unittest discover -s tests -v
```

## Troubleshooting

### Command `maungai` tidak ditemukan

Pastikan Anda sudah menjalankan:

```bash
pip install -e .
```

dan virtual environment sedang aktif:

```bash
source .venv/bin/activate
```

### Tool eksternal tidak ditemukan

Jalankan:

```bash
./scripts/install_linux_tools.sh
```

atau install manual tool yang belum ada.

### Hasil scan kosong

Periksa:

- target benar
- scope benar
- host memang hidup
- tool seperti `httpx`, `katana`, `gau`, `nuclei` berhasil terpasang

### Terminal tidak menampilkan banner Unicode dengan baik

MaungAi sudah punya fallback ASCII, tetapi untuk hasil terbaik gunakan terminal Linux UTF-8.

## Catatan Keamanan

- Gunakan hanya pada aset yang masuk scope dan memiliki izin pengujian.
- Tool ini membantu otomasi workflow, bukan pengganti validasi manual.
- Hasil `nuclei`, `gf`, crawler, dan historical source tetap harus diverifikasi sebelum dijadikan temuan.
- Jangan gunakan pada target di luar program bug bounty, VDP, atau audit resmi.
