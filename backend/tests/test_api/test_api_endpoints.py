

def test_health_check(client):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_aws_connection_status(client):
    res = client.get("/api/v1/aws/connection-status")
    assert res.status_code == 200
    data = res.json()
    assert "mode" in data


def test_list_scans(client):
    res = client.get("/api/v1/scans")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 1
    assert len(data["items"]) >= 1


def test_get_scan_detail(client):
    scans_res = client.get("/api/v1/scans")
    first_scan_id = scans_res.json()["items"][0]["id"]

    res = client.get(f"/api/v1/scans/{first_scan_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == first_scan_id
    assert "findings" in data


def test_get_scan_findings_and_filters(client):
    scans_res = client.get("/api/v1/scans")
    first_scan_id = scans_res.json()["items"][0]["id"]

    # All findings
    res = client.get(f"/api/v1/scans/{first_scan_id}/findings")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] > 0

    # Filter by severity
    res_crit = client.get(f"/api/v1/scans/{first_scan_id}/findings?severity=CRITICAL")
    assert res_crit.status_code == 200
    for f in res_crit.json()["findings"]:
        assert f["severity"] == "CRITICAL"


def test_update_finding_status(client):
    scans_res = client.get("/api/v1/scans")
    first_scan_id = scans_res.json()["items"][0]["id"]
    findings_res = client.get(f"/api/v1/scans/{first_scan_id}/findings")
    first_finding_id = findings_res.json()["findings"][0]["id"]

    # Update status to ACKNOWLEDGED
    patch_res = client.patch(
        f"/api/v1/findings/{first_finding_id}/status",
        json={"status": "ACKNOWLEDGED"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "ACKNOWLEDGED"


def test_download_reports(client):
    scans_res = client.get("/api/v1/scans")
    first_scan_id = scans_res.json()["items"][0]["id"]

    # JSON report
    res_json = client.get(f"/api/v1/scans/{first_scan_id}/report.json")
    assert res_json.status_code == 200
    assert "application/json" in res_json.headers["content-type"]

    # CSV report
    res_csv = client.get(f"/api/v1/scans/{first_scan_id}/report.csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    assert "Finding ID" in res_csv.text

    # HTML report
    res_html = client.get(f"/api/v1/scans/{first_scan_id}/report.html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers["content-type"]
    assert "<html" in res_html.text


def test_demo_reset(client):
    res = client.post("/api/v1/demo/reset")
    assert res.status_code == 200
    data = res.json()
    assert data["scan_mode"] == "demo"
    assert data["findings_count"] >= 7
