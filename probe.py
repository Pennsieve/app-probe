#!/usr/bin/env python3
"""app-probe: report what a Pennsieve app step can see about its runtime.

Modes (the MODE parameter):
  inspect  write report.json and report.md to OUTPUT_DIR, and a summary to stdout
  echo     copy INPUT_DIR to OUTPUT_DIR unchanged (a pass-through step); the
           report goes to stdout only, so the outputs stay a clean copy

Standard library only, so it runs on any Python 3.8+ image.

Secrets: a run's shared and user secrets are injected as environment variables
under names their owners choose, so secrets can't be recognised by name. Every
variable's name is reported, but a value is printed only when the name is on
SHOWN_VARIABLES or is one of this app's own parameters.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

# The app's own parameters (app.yml), with their defaults.
PARAMETERS = {
    "MODE": "inspect",
    "SLEEP_SECONDS": "0",
    "EXIT_CODE": "0",
    "LOG_LINES": "0",
    "WRITE_MB": "0",
    "NETWORK_CHECKS": "true",
    "HASH_MAX_MB": "64",
}

# Variables whose values are safe to print: set by the platform or the image,
# never secrets.
SHOWN_VARIABLES = {
    # platform: identity and environment
    "ENVIRONMENT", "REGION", "AWS_REGION", "AWS_DEFAULT_REGION",
    "COMPUTE_NODE_ID", "GPU_TIER", "DEPLOYMENT_MODE",
    "EXECUTION_RUN_ID", "WORKFLOW_INSTANCE_ID", "INTEGRATION_ID",
    "PENNSIEVE_API_HOST", "PENNSIEVE_API_HOST2",
    # platform: data
    "INPUT_DIR", "OUTPUT_DIR",
    "DATASET_ID", "ORGANIZATION_ID", "TARGET_TYPE",
    # platform: interactive sessions
    "SESSION_TYPE", "NOTEBOOK_ROOT", "LOGS_DIR", "ENVIRONMENTS_DIR",
    # platform: LLM steps (endpoints only; the proxy holds the real token)
    "LLM_GOVERNOR_FUNCTION_NAME", "ANTHROPIC_BASE_URL", "AWS_ENDPOINT_URL_LAMBDA",
    # ECS and GPU runtime
    "ECS_CONTAINER_METADATA_URI_V4", "ECS_CONTAINER_METADATA_URI",
    "ECS_AGENT_URI", "NVIDIA_VISIBLE_DEVICES", "NVIDIA_DRIVER_CAPABILITIES",
    # process and image
    "HOME", "TMPDIR", "PATH", "LANG", "LC_ALL", "PWD", "HOSTNAME",
    "PYTHON_VERSION", "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED",
}

# Variables known to hold credentials: reported as present or absent, never shown.
KNOWN_SECRETS = {
    "SESSION_TOKEN", "REFRESH_TOKEN", "CALLBACK_TOKEN", "RUN_DATA_TOKEN",
    "LLM_GOVERNOR_TOKEN", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
}

MAX_LISTED_FILES = 2000
MAX_HASHED_FILES = 200
HTTP_TIMEOUT = 5


def log(message: str) -> None:
    print(f"[app-probe] {message}", flush=True)


def param(name: str) -> str:
    return os.environ.get(name, PARAMETERS[name]).strip()


def param_int(name: str, low: int, high: int) -> int:
    raw = param(name)
    try:
        value = int(float(raw))
    except ValueError:
        log(f"{name}={raw!r} is not a number; using {PARAMETERS[name]}")
        value = int(PARAMETERS[name])
    return max(low, min(high, value))


def param_bool(name: str) -> bool:
    return param(name).lower() in ("1", "true", "yes", "on")


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def read_text(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


# --- environment -------------------------------------------------------------

def environment() -> dict:
    variables = []
    for name in sorted(os.environ):
        if name in PARAMETERS:
            kind, shown = "parameter", True
        elif name in SHOWN_VARIABLES:
            kind, shown = "platform", True
        elif name in KNOWN_SECRETS:
            kind, shown = "known-secret", False
        else:
            kind, shown = "other", False
        variables.append({
            "name": name,
            "kind": kind,
            "value": os.environ[name] if shown else None,
        })
    return {
        "variables": variables,
        "knownSecretsPresent": sorted(n for n in KNOWN_SECRETS if n in os.environ),
        "note": "values are shown only for platform variables and this app's parameters; "
                "others may be secrets and are listed by name only",
    }


# --- ECS task metadata ---------------------------------------------------------

def http_json(url: str, timeout: float = 2) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except (OSError, ValueError):
        return None


# App Store images are pushed as <hash>-<tag> (and <hash>-<tag>-soci for the
# SOCI index), e.g. ...:4101059555-v0.1.3.
APPSTORE_IMAGE_TAG = re.compile(r"^[0-9a-f]{6,}-(?P<tag>.+?)(?:-soci)?$")


def release_tag(image: str | None) -> str | None:
    """The release tag in an App Store image reference, when it carries one.

    Compute nodes often run a digest-pinned reference (repo@sha256:...), which
    has no tag; the image digest is the reliable identity then.
    """
    if not image:
        return None
    name = image.split("@", 1)[0].rsplit("/", 1)[-1]
    if ":" not in name:
        return None
    match = APPSTORE_IMAGE_TAG.match(name.split(":", 1)[1])
    return match.group("tag") if match else None


def ecs_metadata() -> dict | None:
    base = os.environ.get("ECS_CONTAINER_METADATA_URI_V4")
    if not base:
        return None
    container = http_json(base) or {}
    task = http_json(base + "/task") or {}
    if not container and not task:
        return {"reachable": False}
    family = task.get("Family", "")
    return {
        "reachable": True,
        "taskArn": task.get("TaskARN"),
        "family": family,
        "revision": task.get("Revision"),
        "launchType": task.get("LaunchType"),
        "availabilityZone": task.get("AvailabilityZone"),
        "cluster": task.get("Cluster"),
        "taskLimits": task.get("Limits"),
        "containers": [c.get("Name") for c in task.get("Containers", [])],
        "container": {
            "name": container.get("Name"),
            "image": container.get("Image"),
            "imageDigest": container.get("ImageID"),
            "releaseTag": release_tag(container.get("Image")),
            "limits": container.get("Limits"),
            "logStream": (container.get("LogOptions") or {}).get("awslogs-stream"),
        },
    }


# --- compute -------------------------------------------------------------------

def detect_compute(ecs: dict | None, gpu: dict) -> dict:
    input_dir = os.environ.get("INPUT_DIR", "")
    reasons = []
    if ecs and ecs.get("reachable"):
        launch = ecs.get("launchType")
        kind = "gpu" if (launch == "EC2" and gpu.get("present")) or os.environ.get("GPU_TIER") else "standard"
        reasons.append(f"ECS task metadata reachable (launch type {launch})")
    elif input_dir.startswith("/tmp"):
        kind = "lambda"
        reasons.append("INPUT_DIR is under /tmp, as the Lambda step runtime places it")
    elif input_dir == "/input":
        kind = "sample-runner"
        reasons.append("INPUT_DIR=/input, as the release sample runner sets it")
    elif os.environ.get("ECS_CONTAINER_METADATA_URI_V4"):
        kind = "ecs (metadata unreachable)"
        reasons.append("ECS_CONTAINER_METADATA_URI_V4 is set but did not answer")
    else:
        kind = "unknown (local?)"
        reasons.append("no ECS metadata and no platform INPUT_DIR layout")
    if os.environ.get("GPU_TIER"):
        reasons.append(f"GPU_TIER={os.environ['GPU_TIER']}")
    return {"type": kind, "reasons": reasons}


def cgroup_limits() -> dict:
    """The container's own cgroup limits. None means no limit at the container level;
    on Fargate the task's limits are enforced by a parent cgroup the container can't see."""
    cpu_cores = None
    cpu_max = read_text("/sys/fs/cgroup/cpu.max")  # cgroup v2: "<quota> <period>"
    if cpu_max:
        quota, _, period = cpu_max.partition(" ")
        if quota != "max" and period:
            cpu_cores = round(int(quota) / int(period), 2)
    else:  # cgroup v1
        quota = read_text("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
        period = read_text("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
        if quota and period and int(quota) > 0:
            cpu_cores = round(int(quota) / int(period), 2)
    memory_mib = None
    memory = read_text("/sys/fs/cgroup/memory.max") or read_text("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    # "max" (v2) or a value near 2**63 (v1) means unlimited.
    if memory and memory != "max" and int(memory) < 1 << 60:
        memory_mib = int(memory) // (1024 * 1024)
    return {"cpuQuotaCores": cpu_cores, "memoryLimitMiB": memory_mib}


def smallest(candidates: dict) -> tuple:
    """The smallest known limit and its name, ignoring unknown (None) ones."""
    known = {name: value for name, value in candidates.items() if value is not None}
    if not known:
        return None, None
    name = min(known, key=known.get)
    return known[name], name


LAMBDA_NOT_VISIBLE = "not visible on Lambda: set by the function's memory size, which the step runtime doesn't pass to the app"
# Lambda allocates CPU in proportion to memory: one vCPU's worth at 1769 MB, up to 6.
LAMBDA_MB_PER_VCPU = 1769


def lambda_resources() -> dict:
    """On Lambda the sandbox's MemTotal and core count are not the function's limits, and
    no cgroup shows them. The memory size is known only if AWS_LAMBDA_FUNCTION_MEMORY_SIZE
    reaches the app (the step runtime normally strips it)."""
    size = os.environ.get("AWS_LAMBDA_FUNCTION_MEMORY_SIZE")
    memory_mb = int(size) if size and size.isdigit() else None
    cpu = {"visibleCores": os.cpu_count(), "effectiveVcpu": None, "limitedBy": LAMBDA_NOT_VISIBLE}
    memory = {"hostTotalMiB": mem_total_mib(), "functionMemoryMB": memory_mb,
              "effectiveMiB": None, "limitedBy": LAMBDA_NOT_VISIBLE}
    if memory_mb:
        cpu["effectiveVcpu"] = round(min(6, memory_mb / LAMBDA_MB_PER_VCPU), 2)
        cpu["limitedBy"] = "Lambda's share for the function's memory size"
        memory["effectiveMiB"], memory["limitedBy"] = memory_mb, "function memory size"
    return {"cpu": cpu, "memory": memory}


def resources(ecs: dict | None, compute: str = "") -> dict:
    """CPU and memory as the step actually gets them. The host's figures (cores visible,
    MemTotal) describe the VM, not the step, so the effective value is the smallest limit."""
    if compute == "lambda":
        return lambda_resources()
    cgroup = cgroup_limits()
    ecs = ecs or {}
    task = ecs.get("taskLimits") or {}
    container = (ecs.get("container") or {}).get("limits") or {}
    try:
        affinity = len(os.sched_getaffinity(0))
    except AttributeError:
        affinity = None
    cpu = {
        "visibleCores": os.cpu_count(),
        "affinityCores": affinity,
        "cgroupQuotaCores": cgroup["cpuQuotaCores"],
        "taskVcpu": task.get("CPU"),
        # ECS container CPU units are a relative weight (1024 = 1 vCPU), not a cap.
        "containerCpuUnits": container.get("CPU"),
    }
    cpu["effectiveVcpu"], cpu["limitedBy"] = smallest({
        "visible cores": affinity or os.cpu_count(),
        "cgroup quota": cgroup["cpuQuotaCores"],
        "task limit": task.get("CPU"),
    })
    memory = {
        "hostTotalMiB": mem_total_mib(),
        "cgroupLimitMiB": cgroup["memoryLimitMiB"],
        "taskLimitMiB": task.get("Memory"),
        "containerLimitMiB": container.get("Memory"),
    }
    memory["effectiveMiB"], memory["limitedBy"] = smallest({
        "host total": memory["hostTotalMiB"],
        "cgroup limit": memory["cgroupLimitMiB"],
        "task limit": memory["taskLimitMiB"],
        "container limit": memory["containerLimitMiB"],
    })
    return {"cpu": cpu, "memory": memory}


def mem_total_mib() -> int | None:
    text = read_text("/proc/meminfo")
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) // 1024
    return None


def gpu_info() -> dict:
    smi = shutil.which("nvidia-smi")
    if not smi:
        return {"present": False, "note": "nvidia-smi not on PATH"}
    try:
        out = subprocess.run(
            [smi, "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=15,
        )
        gpus = [line.strip() for line in out.stdout.splitlines() if line.strip()]
        return {"present": bool(gpus), "gpus": gpus, "stderr": out.stderr.strip()[:500] or None}
    except (OSError, subprocess.SubprocessError) as e:
        return {"present": False, "error": str(e)}


def disk(paths: list[str]) -> list[dict]:
    result = []
    seen = set()
    for path in paths:
        if not path or path in seen:
            continue
        seen.add(path)
        try:
            usage = shutil.disk_usage(path)
            result.append({
                "path": path,
                "totalGiB": round(usage.total / 2**30, 2),
                "freeGiB": round(usage.free / 2**30, 2),
            })
        except OSError as e:
            result.append({"path": path, "error": e.strerror})
    return result


def system(ecs: dict | None) -> dict:
    uname = platform.uname()
    gpu = gpu_info()
    tmpdir = tempfile.gettempdir()
    compute = detect_compute(ecs, gpu)
    return {
        "compute": compute,
        "hostname": socket.gethostname(),
        "os": f"{uname.system} {uname.release}",
        "machine": uname.machine,
        "python": sys.version.split()[0],
        **resources(ecs, compute["type"]),
        "gpu": gpu,
        "disk": disk([os.environ.get("INPUT_DIR", ""), os.environ.get("OUTPUT_DIR", ""),
                      tmpdir, "/data", "/tmp", os.getcwd()]),
    }


# --- process identity --------------------------------------------------------

def writable(path: str | None) -> bool | None:
    if not path or not os.path.isdir(path):
        return None
    try:
        with tempfile.NamedTemporaryFile(dir=path, prefix=".app-probe-"):
            return True
    except OSError:
        return False


def process() -> dict:
    try:
        import pwd
        try:
            pw_name = pwd.getpwuid(os.getuid()).pw_name
        except KeyError:
            pw_name = None
    except ImportError:
        pw_name = None
    umask = os.umask(0)
    os.umask(umask)
    cwd = os.getcwd()
    tmpdir = tempfile.gettempdir()
    return {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "groups": os.getgroups(),
        "userName": pw_name,
        "passwdEntry": pw_name is not None,
        "cwd": cwd,
        "home": os.environ.get("HOME"),
        "umask": oct(umask),
        "argv": sys.argv,
        "writable": {
            "INPUT_DIR": writable(os.environ.get("INPUT_DIR")),
            "OUTPUT_DIR": writable(os.environ.get("OUTPUT_DIR")),
            "TMPDIR": writable(tmpdir),
            "HOME": writable(os.environ.get("HOME")),
            "cwd": writable(cwd),
        },
    }


# --- inputs ------------------------------------------------------------------

def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def inputs(hash_max_mb: int) -> dict:
    root = os.environ.get("INPUT_DIR")
    if not root:
        return {"inputDir": None, "note": "INPUT_DIR is not set"}
    if not os.path.isdir(root):
        return {"inputDir": root, "exists": False}
    files, total, count, hashed, truncated = [], 0, 0, 0, False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            count += 1
            try:
                st = os.lstat(path)
            except OSError as e:
                files.append({"path": rel, "error": e.strerror})
                continue
            total += st.st_size
            if len(files) >= MAX_LISTED_FILES:
                truncated = True
                continue
            entry = {"path": rel, "bytes": st.st_size}
            if os.path.islink(path):
                entry["symlinkTo"] = os.readlink(path)
            elif hashed < MAX_HASHED_FILES and st.st_size <= hash_max_mb * 2**20:
                try:
                    entry["sha256"] = sha256(path)
                    hashed += 1
                except OSError as e:
                    entry["error"] = e.strerror
            files.append(entry)
    top = sorted(os.listdir(root))
    return {
        "inputDir": root,
        "exists": True,
        "topLevel": [e + ("/" if os.path.isdir(os.path.join(root, e)) else "") for e in top],
        "fileCount": count,
        "totalBytes": total,
        "files": files,
        "truncated": truncated,
        "views": input_views(root),
        "note": "a port with placement: subfolder shows as its own top-level folder",
    }


VIEW_CRATE = os.path.join(".pennsieve", "view.json")


def input_views(root: str) -> list[dict]:
    """The dataset views staged as inputs: each has its crate at .pennsieve/view.json in
    its source's folder (INPUT_DIR itself, or a folder of it)."""
    candidates = [os.path.join(root, VIEW_CRATE)]
    try:
        candidates += [os.path.join(root, e, VIEW_CRATE) for e in sorted(os.listdir(root))
                       if e != ".pennsieve" and os.path.isdir(os.path.join(root, e))]
    except OSError:
        pass
    return [view_summary(root, path) for path in candidates if os.path.isfile(path)]


def view_summary(root: str, path: str) -> dict:
    summary = {"crate": os.path.relpath(path, root)}
    try:
        with open(path) as f:
            graph = json.load(f).get("@graph", [])
    except (OSError, ValueError, AttributeError) as e:
        summary["error"] = str(e)
        return summary
    by_id = {node.get("@id"): node for node in graph if isinstance(node, dict)}
    view = by_id.get("./", {})
    sources = []
    for ref in view.get("isBasedOn") or []:
        source = by_id.get(ref.get("@id"), {})
        ids = {by_id.get(i.get("@id"), {}).get("propertyID"): by_id.get(i.get("@id"), {}).get("value")
               for i in source.get("identifier") or []}
        sources.append({"type": source.get("views:sourceType"), "dataset": ids.get("pennsieve")})
    summary.update({
        "id": view.get("identifier"),
        "name": view.get("name"),
        "version": view.get("version"),
        "lifecycle": view.get("views:lifecycle"),
        "accessScope": view.get("views:accessScope"),
        "entryCount": view.get("views:entryCount"),
        "created": view.get("dateCreated"),
        "sources": sources,
    })
    return summary


# --- network -----------------------------------------------------------------

def check_url(label: str, url: str) -> dict:
    result = {"target": label, "url": url}
    host = urllib.parse.urlparse(url).hostname or ""
    try:
        addresses = sorted({a[4][0] for a in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
        result["dns"] = addresses[:4]
    except OSError as e:
        result["dns"] = None
        result["error"] = f"DNS: {e}"
        return result
    started = time.monotonic()
    try:
        request = urllib.request.Request(url, method="GET", headers={"User-Agent": "app-probe"})
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            result["httpStatus"] = response.status
    except urllib.error.HTTPError as e:
        result["httpStatus"] = e.code  # reachable; the status itself doesn't matter
    except (OSError, ValueError) as e:
        result["error"] = f"HTTPS: {getattr(e, 'reason', e)}"
    result["ms"] = int((time.monotonic() - started) * 1000)
    result["reachable"] = "httpStatus" in result
    return result


def check_tcp(label: str, url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    result = {"target": label, "url": url}
    try:
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT):
            result["reachable"] = True
    except OSError as e:
        result["reachable"] = False
        result["error"] = str(e)
    return result


def network() -> list[dict]:
    checks = []
    api = os.environ.get("PENNSIEVE_API_HOST")
    if api:
        checks.append(check_url("Pennsieve API", api if "://" in api else "https://" + api))
    region = os.environ.get("REGION") or os.environ.get("AWS_REGION") or "us-east-1"
    checks.append(check_url("AWS endpoint (STS)", f"https://sts.{region}.amazonaws.com/"))
    checks.append(check_url("public internet (pypi.org)", "https://pypi.org/simple/"))
    proxy = os.environ.get("ANTHROPIC_BASE_URL")
    if proxy:
        checks.append(check_tcp("LLM governor proxy", proxy))
    return checks


# --- actions -----------------------------------------------------------------

def echo_inputs() -> dict:
    src, dst = os.environ.get("INPUT_DIR"), os.environ.get("OUTPUT_DIR")
    if not src or not dst or not os.path.isdir(src):
        return {"copied": False, "reason": "INPUT_DIR or OUTPUT_DIR missing"}
    shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
    return {"copied": True, "from": src, "to": dst}


def write_filler(mb: int) -> dict | None:
    out = os.environ.get("OUTPUT_DIR")
    if mb <= 0 or not out:
        return None
    path = os.path.join(out, "app-probe-filler.bin")
    block = os.urandom(1 << 20)
    with open(path, "wb") as f:
        for _ in range(mb):
            f.write(block)
    return {"path": path, "megabytes": mb}


def emit_log_lines(n: int) -> None:
    for i in range(1, n + 1):
        print(f"[app-probe] log line {i}/{n}", flush=True)


def sleep(seconds: int) -> None:
    end = time.monotonic() + seconds
    while (left := end - time.monotonic()) > 0:
        log(f"sleeping, {int(left)}s left")
        time.sleep(min(30, left))


# --- report ------------------------------------------------------------------

def cpu_line(cpu: dict) -> str:
    value = f"**{cpu['effectiveVcpu']} vCPU**" if cpu["effectiveVcpu"] is not None else "**unknown**"
    details = [f"{cpu['visibleCores']} cores visible"]
    if "taskVcpu" in cpu:
        details += [f"task {cpu['taskVcpu'] or '-'}", f"cgroup quota {cpu['cgroupQuotaCores'] or 'none'}"]
    return f"- CPU: {value} ({cpu['limitedBy']}); {', '.join(details)}"


def memory_line(memory: dict) -> str:
    value = f"**{memory['effectiveMiB']} MiB**" if memory["effectiveMiB"] is not None else "**unknown**"
    details = [f"host {memory['hostTotalMiB'] or '-'} MiB"]
    if "taskLimitMiB" in memory:
        details += [f"task {memory['taskLimitMiB'] or '-'} MiB", f"cgroup limit {memory['cgroupLimitMiB'] or 'none'}"]
    return f"- Memory: {value} ({memory['limitedBy']}); {', '.join(details)}"


def markdown(report: dict) -> str:
    s, p = report["system"], report["process"]
    lines = [
        f"# app-probe report ({report['probe']['mode']})",
        "",
        f"- Started {report['probe']['startedAt']}",
        f"- Compute: **{s['compute']['type']}** ({'; '.join(s['compute']['reasons'])})",
        f"- Run `{os.environ.get('EXECUTION_RUN_ID', '-')}` on node `{os.environ.get('COMPUTE_NODE_ID', '-')}`, "
        f"environment `{os.environ.get('ENVIRONMENT', '-')}`, mode `{os.environ.get('DEPLOYMENT_MODE', '-')}`",
        cpu_line(s["cpu"]),
        memory_line(s["memory"]),
        f"- GPU: {', '.join(s['gpu'].get('gpus', [])) or 'none'}",
        f"- User {p['uid']}:{p['gid']} (passwd entry: {p['passwdEntry']}), cwd `{p['cwd']}`, "
        f"writable {json.dumps(p['writable'])}",
    ]
    ecs = report.get("ecs")
    if ecs and ecs.get("reachable"):
        c = ecs["container"]
        lines += [
            f"- ECS task `{ecs['taskArn']}` family `{ecs['family']}` ({ecs['launchType']}, {ecs['availabilityZone']})",
            f"- Image `{c['image']}` digest `{c['imageDigest']}`, release tag `{c['releaseTag'] or 'not in the image reference'}`",
            f"- Containers in the task: {', '.join(n for n in ecs['containers'] if n)}",
        ]
    lines += ["", "## Disk", ""]
    lines += [f"- `{d['path']}`: " + (f"{d['freeGiB']} of {d['totalGiB']} GiB free" if "error" not in d else d["error"])
              for d in s["disk"]]
    i = report["inputs"]
    lines += ["", "## Inputs", ""]
    if i.get("exists"):
        lines.append(f"`{i['inputDir']}`: {i['fileCount']} files, {i['totalBytes']} bytes; "
                     f"top level: {', '.join(i['topLevel']) or '(empty)'}")
        lines += [f"- `{f['path']}` {f.get('bytes', '?')} B {f.get('sha256', '')[:12]}" for f in i["files"][:50]]
        if len(i["files"]) > 50 or i["truncated"]:
            lines.append("- ... (full list in report.json)")
        for v in i.get("views", []):
            if "error" in v:
                lines.append(f"- View crate `{v['crate']}` could not be read: {v['error']}")
                continue
            sources = ", ".join(f"{s['type']} {s['dataset']}" for s in v["sources"]) or "-"
            lines.append(f"- View `{v['name']}` `{v['id']}` v{v['version']} ({v['lifecycle']}, "
                         f"{v['entryCount']} entries) from {sources}; crate `{v['crate']}`")
    else:
        lines.append(f"No input directory ({i.get('inputDir')}).")
    lines += ["", "## Network", ""]
    for n in report.get("network") or []:
        status = f"HTTP {n['httpStatus']} in {n.get('ms')} ms" if n.get("httpStatus") else (
            "reachable" if n.get("reachable") else n.get("error", "unreachable"))
        lines.append(f"- {n['target']}: {status}")
    if report.get("network") is None:
        lines.append("Skipped (NETWORK_CHECKS=false).")
    env = report["environment"]
    lines += ["", "## Environment", "",
              f"Known secrets present (values never shown): {', '.join(env['knownSecretsPresent']) or 'none'}", ""]
    lines += [f"- `{v['name']}`" + (f" = `{v['value']}`" if v["value"] is not None else f" ({v['kind']}, value hidden)")
              for v in env["variables"]]
    return "\n".join(lines) + "\n"


def main() -> int:
    started = time.monotonic()
    mode = param("MODE").lower()
    if mode not in ("inspect", "echo"):
        log(f"MODE={mode!r} is not inspect or echo; using inspect")
        mode = "inspect"
    log(f"app-probe, mode {mode}")

    ecs = ecs_metadata()
    report = {
        "probe": {"mode": mode, "startedAt": now()},
        "parameters": {name: param(name) for name in PARAMETERS},
        "system": system(ecs),
        "ecs": ecs,
        "process": process(),
        "inputs": inputs(param_int("HASH_MAX_MB", 0, 100_000)),
        "environment": environment(),
        "network": network() if param_bool("NETWORK_CHECKS") else None,
    }

    actions = {}
    if mode == "echo":
        actions["echo"] = echo_inputs()
    actions["filler"] = write_filler(param_int("WRITE_MB", 0, 100_000))
    emit_log_lines(param_int("LOG_LINES", 0, 10_000_000))
    sleep(param_int("SLEEP_SECONDS", 0, 7 * 24 * 3600))
    exit_code = param_int("EXIT_CODE", 0, 255)
    report["actions"] = actions
    report["probe"]["finishedAt"] = now()
    report["probe"]["seconds"] = round(time.monotonic() - started, 2)
    report["probe"]["exitCode"] = exit_code

    text = markdown(report)
    print(text, flush=True)
    out = os.environ.get("OUTPUT_DIR")
    if mode == "inspect" and out:
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, "report.json"), "w") as f:
            json.dump(report, f, indent=2, default=str)
        with open(os.path.join(out, "report.md"), "w") as f:
            f.write(text)
        log(f"wrote report.json and report.md to {out}")
    elif mode == "inspect":
        log("OUTPUT_DIR is not set; the report is in the log only")

    summary = {
        "compute": report["system"]["compute"]["type"],
        "run": os.environ.get("EXECUTION_RUN_ID"),
        "imageDigest": (ecs or {}).get("container", {}).get("imageDigest"),
        "releaseTag": (ecs or {}).get("container", {}).get("releaseTag"),
        "inputFiles": report["inputs"].get("fileCount"),
        "exitCode": exit_code,
    }
    print("APP_PROBE_SUMMARY " + json.dumps(summary), flush=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
