#!/usr/bin/env python3
"""Security gate: gộp báo cáo của các lớp kiểm tra -> quyết định BLOCK/WARN/IGNORE theo policy + ngoại lệ."""
import argparse, datetime as dt, json, re, sys
from pathlib import Path
import yaml

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


def load_json(p):
    try:
        return json.loads(Path(p).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return "MISSING"


def F(tool, layer, fid, sev, title, loc, fixable=True):
    sev = (sev or "UNKNOWN").upper()
    return dict(tool=tool, layer=layer, id=fid, severity=sev if sev in SEV else "UNKNOWN",
                title=(title or "")[:120], location=loc or "", fixable=fixable)


def parse_gitleaks(d, pol):
    return [F("gitleaks", "secrets", x.get("RuleID"), "CRITICAL", x.get("Description"),
              f"{x.get('File')}:{x.get('StartLine')}") for x in (d or [])]


def parse_semgrep(d, pol):
    m = pol["semgrep_severity_map"]
    return [F("semgrep", "sast", x["check_id"].split(".")[-1], m.get(x["extra"].get("severity"), "MEDIUM"),
              x["extra"].get("message"), f"{x['path']}:{x['start']['line']}") for x in d.get("results", [])]


def parse_trivy(d, layer):
    out = []
    for r in d.get("Results", []) or []:
        for v in r.get("Vulnerabilities", []) or []:
            out.append(F("trivy", layer, v["VulnerabilityID"], v.get("Severity"),
                         f"{v.get('PkgName')} {v.get('InstalledVersion')} - {v.get('Title', '')}",
                         r.get("Target"), fixable=bool(v.get("FixedVersion"))))
    return out


def parse_checkov(d, pol):
    ov = {i: s for s, ids in pol["checkov_severity_overrides"].items() for i in ids}
    blocks = d if isinstance(d, list) else [d]
    out = []
    for b in blocks:
        for c in (b.get("results", {}) or {}).get("failed_checks", []):
            cid = c["check_id"]
            out.append(F("checkov", "iac", cid, c.get("severity") or ov.get(cid, pol["checkov_default_severity"]),
                         c.get("check_name"), f"{c.get('file_path')} [{c.get('resource')}]"))
    return out


def parse_conftest(d, pol):
    out = []
    for f in d or []:
        for key, sev in (("failures", "HIGH"), ("warnings", "MEDIUM")):
            for m in f.get(key, []) or []:
                msg = m.get("msg", "")
                fid = msg.split(":")[0] if re.match(r"^[A-Z]{2,}\d+:", msg) else msg[:20]
                out.append(F("conftest", "policy", fid, sev, msg, f.get("filename")))
    return out


LAYERS = [  # (file, parser)
    ("gitleaks.json", parse_gitleaks), ("semgrep.json", parse_semgrep),
    ("trivy-fs.json", lambda d, p: parse_trivy(d, "sca")), ("checkov.json", parse_checkov),
    ("conftest.json", parse_conftest), ("trivy-image.json", lambda d, p: parse_trivy(d, "image")),
]


def check_exceptions(items, pol, today):
    valid, bad = [], []
    for e in items or []:
        if not isinstance(e, dict):
            bad.append(({"value": e}, "ngoại lệ phải là một object YAML")); continue
        # Scope bắt buộc để ngoại lệ không vô tình áp dụng cho toàn bộ repo.
        miss = [k for k in ("id", "scope", "owner", "reason", "created", "expires") if not e.get(k)]
        if miss:
            bad.append((e, f"thiếu trường: {', '.join(miss)}")); continue
        try:
            c = dt.date.fromisoformat(str(e["created"]))
            x = dt.date.fromisoformat(str(e["expires"]))
        except (TypeError, ValueError):
            bad.append((e, "created/expires phải có định dạng YYYY-MM-DD")); continue
        if c > today:
            bad.append((e, f"ngày tạo nằm trong tương lai ({c})"))
        elif x < c:
            bad.append((e, f"ngày hết hạn {x} trước ngày tạo {c}"))
        elif x < today:
            bad.append((e, f"ĐÃ HẾT HẠN {x}"))
        elif (x - c).days > pol["max_exception_days"]:
            bad.append((e, f"thời hạn > {pol['max_exception_days']} ngày"))
        else:
            valid.append(e)
    return valid, bad


def decide(f, pol, exc):
    # Secret không được miễn trừ: always_block_tools có ưu tiên cao nhất.
    if f["tool"] in pol["always_block_tools"]:
        return "BLOCK", None
    for e in exc:
        # Scope phải khớp chính xác target (ví dụ lab/vulnerable), không so khớp chuỗi con.
        if e["id"] == f["id"] and e["scope"].rstrip("/") == f.get("_scope", "").rstrip("/"):
            return "EXCEPTED", e
    if f["severity"] in pol["block_severities"]:
        if f["tool"] == "trivy" and not f["fixable"] and not pol["block_unfixed_vulns"]:
            return "WARN", None
        return "BLOCK", None
    return ("WARN" if f["severity"] in pol["warn_severities"] else "IGNORE"), None


def timings(rdir):
    ts = [json.loads(p.read_text()) for p in Path(rdir).glob("timing-*.json")]
    if not ts:
        return None
    total, wall = sum(t["seconds"] for t in ts), max(t["seconds"] for t in ts)
    return ts, total, wall


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--policy", default="gate/gate-policy.yaml")
    ap.add_argument("--exceptions", default="gate/exceptions.yaml")
    ap.add_argument("--out", default="gate-out")
    ap.add_argument("--expect", choices=["none", "block", "pass"], default="none")
    ap.add_argument("--today", default=None)
    a = ap.parse_args()
    pol = yaml.safe_load(Path(a.policy).read_text())
    today = dt.date.fromisoformat(a.today) if a.today else dt.date.today()
    exc, bad = check_exceptions((yaml.safe_load(Path(a.exceptions).read_text()) or {}).get("exceptions"), pol, today)
    rdir = Path(a.reports) / a.target

    findings, missing = [], []
    for fname, parser in LAYERS:
        d = load_json(rdir / fname)
        if d == "MISSING":
            missing.append(fname); continue
        findings += parser(d, pol)

    counts, blocking, warns, used = {}, [], [], []
    for f in findings:
        f["_scope"] = f"lab/{a.target}"
        dec, e = decide(f, pol, exc)
        f["decision"] = dec
        counts.setdefault(f["layer"], dict(BLOCK=0, WARN=0, EXCEPTED=0, IGNORE=0))[dec] += 1
        if dec == "BLOCK": blocking.append(f)
        if dec == "WARN": warns.append(f)
        if dec == "EXCEPTED": used.append((f, e))
    fail_closed = bool(missing) and pol["fail_closed"]
    blocked = bool(blocking) or fail_closed

    L = [f"### Security gate - `{a.target}`: {'BLOCKED' if blocked else 'PASSED'}", "",
         "| Lớp | Block | Warn | Excepted | Ignored |", "|---|---|---|---|---|"]
    for layer, c in sorted(counts.items()):
        L.append(f"| {layer} | {c['BLOCK']} | {c['WARN']} | {c['EXCEPTED']} | {c['IGNORE']} |")
    if missing:
        L += ["", f"Thiếu báo cáo: {', '.join(missing)} ({'fail-closed -> chặn' if fail_closed else 'bỏ qua'})"]
    if blocking:
        L += ["", "**Phát hiện chặn release (tối đa 25):**", "", "| Mức | Công cụ | ID | Vị trí | Mô tả |", "|---|---|---|---|---|"]
        for f in sorted(blocking, key=lambda x: SEV.index(x["severity"]))[:25]:
            L.append(f"| {f['severity']} | {f['tool']} | {f['id']} | `{f['location'][:60]}` | {f['title'][:70].replace('|', '/')} |")
    if used:
        L += ["", "**Ngoại lệ đang áp dụng:**"] + [f"- {f['id']} - owner {e['owner']}, hết hạn {e['expires']} ({e.get('ticket', '-')})" for f, e in used]
    if bad:
        L += ["", "**Ngoại lệ KHÔNG hợp lệ (bị bỏ qua):**"] + [f"- {e.get('id')} - {why}" for e, why in bad]
    t = timings(rdir)
    if t:
        ts, total, wall = t
        L += ["", "**Thời gian pipeline (giây):** " + ", ".join(f"{x['name']}={x['seconds']}" for x in sorted(ts, key=lambda x: x['name'])),
              f"- Tổng nếu chạy tuần tự: {total}s; thực tế song song (job dài nhất): {wall}s; tiết kiệm {total - wall}s"]
    summary = "\n".join(L) + "\n"

    out = Path(a.out) / a.target
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.md").write_text(summary)
    (out / "gate-report.json").write_text(json.dumps(dict(
        target=a.target, blocked=blocked, missing=missing, counts=counts, findings=findings,
        invalid_exceptions=[dict(exception=e, reason=w) for e, w in bad]), indent=2, default=str))
    print(summary)

    if a.expect == "block":
        # Phải có finding thực sự bị BLOCK và không được thiếu báo cáo scanner.
        ok = bool(blocking) and not missing
        why = ("thiếu báo cáo: " + ", ".join(missing)) if missing else "không có finding BLOCK nào"
        print("EXPECT block ->", "OK: finding thực sự đã bị chặn" if ok else f"FAIL: {why}")
    elif a.expect == "pass":
        # Bản fixed chỉ được xem là vượt khi tất cả báo cáo đều có mặt.
        ok = not blocked and not missing
        why = ("thiếu báo cáo: " + ", ".join(missing)) if missing else f"{len(blocking)} finding bị BLOCK"
        print("EXPECT pass ->", "OK: bản đã sửa vượt gate với đủ báo cáo" if ok else f"FAIL: {why}")
    else:
        ok = not blocked
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
