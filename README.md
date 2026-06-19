# MaungAi

MaungAi adalah aplikasi terminal berbasis Python untuk workflow reconnaissance dan vulnerability assessment yang bertahap, cepat, dan terstruktur pada pengujian resmi, bug bounty, VDP, dan audit yang memiliki izin.

Fokus utamanya adalah:

1. Temukan aset
2. Validasi host hidup
3. Petakan endpoint
4. Prioritaskan parameter rawan
5. Jalankan automated checks
6. Lanjutkan verifikasi manual
7. Dokumentasikan hasil dengan rapi

## Kenapa MaungAi

- Mudah dipakai dari terminal Linux.
- Mengikuti alur modern: `recon -> validation -> discovery -> scanning`.
- Lebih hemat request karena memproses host dan endpoint yang relevan.
- Menyimpan output per target agar hasil tidak berantakan.
- Tetap bisa jalan walau sebagian tool eksternal belum terpasang.
- Menyediakan preset scan `fast`, `balanced`, dan `deep`.

## Fitur Utama

- UI terminal interaktif dengan menu yang jelas.
- Preset scan:
  - `fast` untuk triage cepat
  - `balanced` untuk workflow harian
  - `deep` untuk audit resmi lebih dalam
- Struktur output profesional per target:
  - `assets/`
  - `endpoints/`
  - `parameters/`
  - `findings/info|low|medium|high/`
  - `screenshots/`
  - `raw/`
  - `logs/`
  - `reports/`
- Integrasi tool modern:
  - `subfinder` untuk subdomain discovery
  - `httpx` untuk validasi live host dan tech fingerprinting
  - `katana` untuk crawl endpoint
  - `gau` dan `waybackurls` untuk historical URLs
  - `gf` dan `uro` untuk parameter triage
  - `nuclei -as` untuk automated checks modern
- Fallback internal berbasis Python saat tool eksternal belum tersedia.
- Config snapshot, execution plan, inventory, dan summary report.
- Manual review queue untuk membantu validasi bug yang tidak terdeteksi otomatis.

## Filosofi Pipeline

### 1. Asset Discovery

- Cari subdomain dan inventaris DNS awal.

### 2. Live Host Validation

- Buang aset yang mati.
- Simpan teknologi dan respons awal untuk prioritas triage.

### 3. Endpoint Discovery

- Gabungkan crawling aktif dan historical URLs.
- Pisahkan JavaScript, API, dan endpoint menarik.

### 4. Parameter Analysis

- Fokus ke query yang punya nilai tinggi untuk XSS, SQLi, SSRF, redirect, dan sink input lain.

### 5. Automated Checks

- Jalankan `nuclei` hanya pada target yang lebih relevan.

### 6. Manual Review

- Validasi auth, authz, upload, business logic, dan area sensitif lain.

### 7. Reporting

- Hasil dirangkum ke format markdown dan JSON.

## Instalasi Linux

### 1. Clone project

```bash
git clone <repo-url> maungai
cd maungai
```

### 2. Install Python package

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

### 3. Install tool eksternal

```bash
chmod +x scripts/install_linux_tools.sh
./scripts/install_linux_tools.sh
```

Script installer ada di [install_linux_tools.sh](file:///d:/wamserver64/www/MaungAi/scripts/install_linux_tools.sh).

## Menjalankan App

### Mode interaktif

```bash
python3 main.py
```

Atau jika sudah di-install:

```bash
maungai
```

### Jalankan seluruh pipeline

```bash
python3 main.py --target example.com --scope "*.example.com" --profile balanced --full-pipeline
```

### Jalankan satu tahap

```bash
python3 main.py --target example.com --step assets
python3 main.py --target example.com --step live
python3 main.py --target example.com --step endpoints
python3 main.py --target example.com --step params
python3 main.py --target example.com --step scan
python3 main.py --target example.com --step manual
python3 main.py --target example.com --step report
```

### Simpan config

```bash
python3 main.py --target example.com --scope "*.example.com" --profile fast --save-config
```

### Load config lama

```bash
python3 main.py --config project/example.com/reports/maungai-config.json --full-pipeline
```

## Opsi CLI Penting

- `--target` domain utama
- `--scope` scope pengujian
- `--profile` preset scan: `fast`, `balanced`, `deep`
- `--timeout` timeout per command
- `--no-history` matikan `gau` dan `waybackurls`
- `--step` jalankan satu tahap
- `--full-pipeline` jalankan semua tahap
- `--config` load config JSON yang tersimpan
- `--save-config` simpan config snapshot lalu keluar

## Struktur Output

Untuk target `example.com`, output default akan dibuat di:

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

## Workflow Ideal

1. Set `target` dan `scope`
2. Pilih profile scan
3. Jalankan `Asset Discovery`
4. Lanjut `Live Host Validation`
5. Kumpulkan endpoint
6. Triage parameter
7. Jalankan `Automated Checks`
8. Review `manual-review.md`
9. Buka `summary.md` dan `inventory.md`

## Testing

Jalankan test bawaan:

```bash
python3 -m unittest discover -s tests -v
```

## Catatan Keamanan

- Gunakan hanya pada aset yang masuk scope dan memiliki izin pengujian.
- Tool ini membantu otomasi workflow, bukan pengganti validasi manual.
- Hasil `nuclei`, `gf`, crawler, dan historical source tetap harus diverifikasi sebelum dijadikan temuan.
- Jangan gunakan pada target di luar program bug bounty, VDP, atau audit resmi.
