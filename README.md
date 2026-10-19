# VIT Campus CA Portal

A demo Public Key Infrastructure for the BCSE330L case study at VIT Vellore:

offline Root CA -> online Issuing CA -> Registration Authority (RA) -> end-entity X.509v3 certificates.

> Work in progress: the project is built phase by phase (see `git tag`).
> The full README (architecture, report-to-feature table, limitations) arrives in Phase 6.

## Quick start

Run these from the `campus-ca-portal` folder.

### 1. Virtual environment and dependencies

PowerShell:

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt

Git Bash:

    python -m venv .venv
    source .venv/Scripts/activate
    pip install -r requirements.txt

### 2. Create the database (safe to repeat)

    flask --app app init-db

### 3. Run the portal

    python run.py

Then open http://localhost:5000

### 4. Run the tests

    pytest
