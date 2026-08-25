# Installation & Setup Guide 🛠️

This guide provides step-by-step instructions for installing and running **CryptoJackGuard** on your system.

---

## 📋 System Requirements

- **Operating System:** Windows 10 / 11 (64-bit recommended; core modules are cross-platform compatible with Linux / macOS).
- **Python Version:** Python 3.12 or higher.
- **Memory:** Minimum 2 GB RAM (4 GB+ recommended).
- **Hardware:** CPU with at least 2 cores. Dedicated NVIDIA GPU optional (supported via `GPUtil`).

---

## 🚀 Step-by-Step Installation

### Step 1: Clone the Repository
Clone the project repository from GitHub to your local workstation:

```powershell
git clone https://github.com/PubuduTerance/CryptoJackGuard.git
cd CryptoJackGuard
```

---

### Step 2: Create a Python Virtual Environment
It is best practice to run CryptoJackGuard inside an isolated Python virtual environment to avoid dependency conflicts:

```powershell
# Create virtual environment named '.venv'
python -m venv .venv
```

---

### Step 3: Activate the Virtual Environment

- **On Windows (PowerShell):**
  ```powershell
  .\.venv\Scripts\Activate.ps1
  ```
  *(If PowerShell gives a script execution policy error, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

- **On Windows (Command Prompt `cmd`):**
  ```cmd
  .venv\Scripts\activate.bat
  ```

- **On Linux / macOS:**
  ```bash
  source .venv/bin/activate
  ```

Once activated, your terminal prompt will be prefixed with `(.venv)`.

---

### Step 4: Upgrade pip & Install Dependencies
Install all required packages from `requirements.txt`:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### Included Packages:
- `psutil` — Real-time process and socket connection collection
- `scikit-learn`, `joblib`, `numpy`, `pandas` — Machine learning inference and model serialization
- `streamlit`, `streamlit-autorefresh`, `plotly` — Interactive web application dashboard
- `rich`, `typer` — Terminal formatting and CLI styling
- `GPUtil` — (Optional) NVIDIA GPU hardware monitoring

---

### Step 5: Verify the Installation
Run the automated test suite to confirm that all components and models are correctly installed:

```powershell
python -m unittest discover -s tests
```

Expected output:
```text
Ran 99 tests in 0.4s
OK
```

You are now ready to launch and use CryptoJackGuard! Refer to [USER_GUIDE.md](USER_GUIDE.md) for usage instructions.
