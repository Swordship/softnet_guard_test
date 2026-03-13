# SoftNet-Guard — Setup & Run Guide
**Velalar College of Engineering and Technology | Department of IT**

---

## ✅ Quick Setup (5 minutes)

### Step 1 — Install Python dependencies
Open Command Prompt and run:
```
pip install flask scapy requests pandas scikit-learn
```

### Step 2 — (Optional but recommended) Install Npcap
Npcap allows live packet capture on Windows.
Download from: **https://npcap.com/**
- During install, check ✅ "Install Npcap in WinPcap API-compatible Mode"

---

## 🚀 Running the Project

### Option A — Demo Mode (works WITHOUT Npcap)
Best for showing your guide quickly. Uses real ARP scan + simulated traffic.
```
python main.py --simulate
```
Then open: **http://127.0.0.1:5000**

### Option B — Real Scan Only (no dashboard)
```
python main.py --scan
```

### Option C — Full System with Dashboard
```
python main.py
```
Then open: **http://127.0.0.1:5000**

### Option D — Live Packet Capture (needs Npcap + Admin rights)
Right-click Command Prompt → "Run as Administrator", then:
```
python main.py --capture
```

---

## 📁 Project Structure

```
softnet_guard/
│
├── main.py              ← Entry point (run this)
├── database.py          ← SQLite storage (Module 2 - Storage Layer)
├── device_scanner.py    ← ARP/Ping device discovery (Module 2 - Collection)
├── traffic_analyzer.py  ← Scapy packet capture (Module 2 - Processing)
├── app.py               ← Flask web dashboard (Module 4 preview)
├── requirements.txt     ← Python dependencies
│
└── templates/
    └── dashboard.html   ← Web UI
```

---

## 🗂️ Module Coverage

| Module | Component | File | Status |
|--------|-----------|------|--------|
| Module 1 | Domain Knowledge & Requirements | (PPT Slides) | ✅ Complete |
| Module 2 | Data Collection — Device Scanner | `device_scanner.py` | ✅ Complete |
| Module 2 | Data Collection — Traffic Analyzer | `traffic_analyzer.py` | ✅ Complete |
| Module 2 | Data Storage — SQLite | `database.py` | ✅ Complete |
| Module 4 | Web Dashboard (preview) | `app.py`, `dashboard.html` | ✅ Preview Ready |

---

## 🔍 What the Guide Will See

1. **Real device discovery** — the system scans your network and lists every device with IP, MAC, hostname, and vendor
2. **Traffic data** — packets counted per device with protocol breakdown
3. **Security alerts** — new device detection raises an alert automatically
4. **Live dashboard** — http://127.0.0.1:5000 shows all data in real-time

---

## ⚠️ Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: flask` | Run `pip install flask` |
| `Permission denied` on capture | Run CMD as Administrator |
| No devices shown | Use `--simulate` flag or check your network connection |
| Scapy error on Windows | Install Npcap from https://npcap.com/ |
