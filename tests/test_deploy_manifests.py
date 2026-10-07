from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _api_deployment() -> dict:
    docs = list(yaml.safe_load_all((ROOT / "k8s" / "api.yaml").read_text(encoding="utf-8")))
    return next(d for d in docs if d and d.get("kind") == "Deployment")


def test_k8s_audit_path_is_writable_under_read_only_rootfs():
    pod = _api_deployment()["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True

    mounts = {m["name"]: m["mountPath"] for m in container["volumeMounts"]}
    volumes = {v["name"]: v for v in pod["volumes"]}
    assert mounts.get("audit-logs") == "/app/logs"
    assert "emptyDir" in volumes["audit-logs"] or "persistentVolumeClaim" in volumes["audit-logs"]

    env = {e["name"]: e.get("value") for e in container["env"]}
    assert env["AUDIT_OUTPUT_DESTINATION"] in {"stdout", "file"}
    assert env["AUDIT_LOG_PATH"].startswith("/app/logs/")


def test_compose_api_mounts_audit_dir():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    api = compose["services"]["api"]
    assert any(v.endswith(":/app/logs") for v in api["volumes"])
    assert api["environment"]["AUDIT_LOG_PATH"].startswith("/app/logs/")


def test_helm_mounts_audit_volume_and_defines_pvc():
    templates = ROOT / "helm" / "authinject-rag" / "templates"
    deployment = (templates / "deployment.yaml").read_text(encoding="utf-8")
    assert "readOnlyRootFilesystem: true" in deployment
    assert "mountPath: /app/logs" in deployment
    assert "AUDIT_OUTPUT_DESTINATION" in deployment
    assert "-audit-pvc" in (templates / "audit-pvc.yaml").read_text(encoding="utf-8")
