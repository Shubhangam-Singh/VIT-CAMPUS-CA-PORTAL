"""UI checks: the setup-health banner, the home dashboard, the track page, navigation and error pages."""
import io

from cryptography.hazmat.primitives import serialization

from csr_factory import make_csr


def text(response):
    return response.get_data(as_text=True)


def test_banner_says_the_ca_is_missing(app, tmp_path):
    app.config["ISSUING_DIR"] = tmp_path / "no-ca-here"
    page = text(app.test_client().get("/"))
    assert "Setup needed: the CA does not exist yet." in page and "bootstrap_ca.py" in page


def test_banner_says_the_key_is_locked(app, demo_ca, monkeypatch):
    app.config["ISSUING_DIR"] = demo_ca.ca_dir / "issuing"
    monkeypatch.delenv("ISSUING_CA_PASS", raising=False)
    page = text(app.test_client().get("/admin/"))
    assert "The Issuing CA key is locked." in page and "Setup needed" not in page

    monkeypatch.setenv("ISSUING_CA_PASS", "set")
    page = text(app.test_client().get("/admin/"))
    assert "is locked" not in page and "Setup needed" not in page


def test_no_banner_when_the_ca_is_ready(ca_app):
    page = text(ca_app.test_client().get("/"))
    assert "Setup needed" not in page and "is locked" not in page


def test_home_shows_live_numbers(ca_app, keys):
    web = ca_app.test_client()
    web.post("/enroll?role=student", content_type="multipart/form-data", data={
        "role": "student", "template": "student_auth", "name": "Asha Rao", "email": "asha.rao@vit.ac.in",
        "reg_no": "21BCE0001",
        "csr_file": (io.BytesIO(make_csr(keys.rsa2048).public_bytes(serialization.Encoding.PEM)), "a.csr")})
    page = text(web.get("/"))
    assert 'kpi-value">1</span>\n  <span class="kpi-label">requests waiting for the RA' in page
    assert 'kpi-value">0</span>\n  <span class="kpi-label">certificates issued' in page


def test_track_page_and_lookup(app):
    web = app.test_client()
    page = text(web.get("/status"))
    assert "Track a request" in page and 'name="tracking_id"' in page
    assert web.get("/status?tracking_id=req-1").headers["Location"].endswith("/request/REQ-1")


def test_navigation_marks_the_current_page(app):
    page = text(app.test_client().get("/enroll"))
    assert 'href="/enroll" class="active"' in page
    assert 'href="/admin/" class=""' in page


def test_friendly_404_page(app):
    response = app.test_client().get("/no/such/page")
    assert response.status_code == 404
    page = text(response)
    assert "Page not found" in page and "Go to the home page" in page
