from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from protocol import Frame


MAX_TOOL_OUTPUT = 12000
AI_RESOURCE = "https://ai.azure.com"
BACKUP_DIR = ".cloud-upgrade/backup"


def backup_paths(project_root: Path) -> tuple[Path, Path]:
    backup_root = project_root / BACKUP_DIR
    return backup_root / "manifest.json", backup_root / "files"


def record_snapshot(project_root: Path, target: Path) -> None:
    """Back up a file before its first modification so --rollback can restore it."""
    relative = target.relative_to(Path(os.path.realpath(project_root))).as_posix()
    if relative.startswith(".cloud-upgrade/"):
        return
    manifest_path, files_dir = backup_paths(project_root)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {"entries": []}
    if any(entry["path"] == relative for entry in manifest["entries"]):
        return
    if target.exists():
        files_dir.mkdir(parents=True, exist_ok=True)
        backup_name = f"{len(manifest['entries'])}_{target.name}"
        shutil.copy2(target, files_dir / backup_name)
        manifest["entries"].append({"path": relative, "backup": backup_name})
    else:
        manifest["entries"].append({"path": relative, "backup": None})
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def rollback(project_root: Path) -> str:
    manifest_path, files_dir = backup_paths(project_root)
    if not manifest_path.exists():
        return "nothing to roll back (no backup manifest)"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    restored: list[str] = []
    for entry in reversed(manifest["entries"]):
        target = project_root / entry["path"]
        if entry["backup"] is None:
            if target.exists():
                target.unlink()
                restored.append(f"removed {entry['path']}")
        else:
            shutil.copy2(files_dir / entry["backup"], target)
            restored.append(f"restored {entry['path']}")
    shutil.rmtree(manifest_path.parent, ignore_errors=True)
    return "\n".join(restored) if restored else "nothing to roll back"


def resolve_project_path(project_root: Path, requested_path: str) -> Path:
    project_root = Path(os.path.realpath(project_root))
    candidate = Path(os.path.realpath(project_root / requested_path))
    if candidate != project_root and project_root not in candidate.parents:
        raise ValueError(f"path escapes project root: {requested_path}")
    return candidate


def read_file(project_root: Path, arguments: dict[str, Any]) -> str:
    path = resolve_project_path(project_root, str(arguments["path"]))
    start_line = int(arguments.get("startLine", 1))
    end_line = int(arguments.get("endLine", 240))
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[start_line - 1 : end_line])


def list_dir(project_root: Path, arguments: dict[str, Any]) -> str:
    path = resolve_project_path(project_root, str(arguments.get("path", ".")))
    entries = []
    for child in sorted(path.iterdir(), key=lambda item: item.name):
        entries.append(child.name + ("/" if child.is_dir() else ""))
    return "\n".join(entries)


def grep_search(project_root: Path, arguments: dict[str, Any]) -> str:
    pattern = str(arguments["query"])
    include = str(arguments.get("includePattern", "."))
    search_root = resolve_project_path(project_root, include)
    command = ["rg", "--line-number", "--no-heading", pattern, str(search_root)]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode not in (0, 1):
        raise RuntimeError(completed.stderr.strip() or f"rg exited with {completed.returncode}")
    return completed.stdout


def create_file(project_root: Path, arguments: dict[str, Any]) -> str:
    project_root = Path(os.path.realpath(project_root))
    path = resolve_project_path(project_root, str(arguments["path"]))
    if path.exists():
        raise FileExistsError(f"file already exists: {arguments['path']}")
    record_snapshot(project_root, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(arguments.get("content", "")), encoding="utf-8")
    return f"created {path.relative_to(project_root)}"


def replace_string_in_file(project_root: Path, arguments: dict[str, Any]) -> str:
    project_root = Path(os.path.realpath(project_root))
    path = resolve_project_path(project_root, str(arguments["path"]))
    old = str(arguments["old_str"])
    new = str(arguments["new_str"])
    content = path.read_text(encoding="utf-8", errors="replace")
    count = content.count(old)
    if count != 1:
        raise ValueError(f"old_str must appear exactly once, found {count}")
    record_snapshot(project_root, path)
    path.write_text(content.replace(old, new), encoding="utf-8")
    return f"updated {path.relative_to(project_root)}"


MVN_DENY_PATTERNS = ("exec:", "antrun:", "groovy:", "-Dexec.", "-Dmaven.ext.class.path")
GIT_ALLOWED_SUBCOMMANDS = {
    "status", "diff", "log", "show", "add", "commit", "checkout", "switch",
    "restore", "stash", "branch", "rev-parse", "init",
}
GIT_DENY_PREFIXES = ("-c", "--config", "--exec-path", "--upload-pack", "--receive-pack", "--ext-diff", "-C")


def validate_command(command: list[str]) -> None:
    """argv-level policy on top of the binary whitelist."""
    binary = command[0]
    if binary in {"mvn", "./mvnw", "mvnw"}:
        for arg in command[1:]:
            if any(pattern in arg for pattern in MVN_DENY_PATTERNS):
                raise PermissionError(f"maven argument not allowed: {arg}")
        return
    if binary == "git":
        for arg in command[1:]:
            if arg.startswith(GIT_DENY_PREFIXES):
                raise PermissionError(f"git option not allowed: {arg}")
        subcommands = [arg for arg in command[1:] if not arg.startswith("-")]
        if not subcommands or subcommands[0] not in GIT_ALLOWED_SUBCOMMANDS:
            raise PermissionError(f"git subcommand not allowed: {subcommands[0] if subcommands else '(none)'}")
        return


def run_command(project_root: Path, arguments: dict[str, Any]) -> str:
    command_text = str(arguments["command"])
    command = shlex.split(command_text)
    if not command:
        raise ValueError("command must not be empty")
    allowed = {"mvn", "./mvnw", "mvnw", "java", "javac", "git"}
    if command[0] not in allowed:
        raise PermissionError(f"command is not whitelisted: {command[0]}")
    validate_command(command)
    timeout = int(arguments.get("timeout", 180))
    completed = subprocess.run(command, cwd=project_root, check=False, capture_output=True, text=True, timeout=timeout)
    output = completed.stdout + completed.stderr
    return f"exit_code={completed.returncode}\n{output}"


def probe_environment(project_root: Path, arguments: dict[str, Any]) -> str:
    probes = [
        ["java", "-version"],
        ["javac", "-version"],
        ["mvn", "-version"],
    ]
    results = []
    for command in probes:
        try:
            completed = subprocess.run(command, cwd=project_root, check=False, capture_output=True, text=True, timeout=20)
            results.append(f"$ {' '.join(command)}\nexit_code={completed.returncode}\n{completed.stdout}{completed.stderr}".strip())
        except Exception as error:
            results.append(f"$ {' '.join(command)}\nerror={error}")
    return "\n\n".join(results)


def generate_sbom(project_root: Path, arguments: dict[str, Any]) -> str:
    """Generate a CycloneDX SBOM (Maven plugin) and store a compact fingerprint locally."""
    command = [
        "mvn", "-q", "-B",
        "org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom",
        "-DoutputFormat=json", "-DoutputName=bom",
    ]
    timeout = int(arguments.get("timeout", 300))
    completed = subprocess.run(command, cwd=project_root, check=False, capture_output=True, text=True, timeout=timeout)
    bom_path = project_root / "target" / "bom.json"
    if completed.returncode != 0 or not bom_path.exists():
        tail = (completed.stdout + completed.stderr)[-2000:]
        raise RuntimeError(f"sbom generation failed (exit_code={completed.returncode})\n{tail}")
    bom = json.loads(bom_path.read_text(encoding="utf-8"))
    components = sorted(
        f"{item.get('group', '')}:{item.get('name', '')}:{item.get('version', '')}"
        for item in bom.get("components", [])
    )
    fingerprint = {
        "project": project_root.name,
        "generated": time.strftime("%Y-%m-%d"),
        "component_count": len(components),
        "components": components,
    }
    out_dir = project_root / ".cloud-upgrade"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "sbom-fingerprint.json").write_text(json.dumps(fingerprint, indent=2), encoding="utf-8")
    return "\n".join([f"SBOM fingerprint for {project_root.name}: {len(components)} components", *components])


def ask_user(project_root: Path, arguments: dict[str, Any]) -> str:
    question = str(arguments.get("question", "Approve?"))
    default = str(arguments.get("default", "yes")).lower()
    if os.environ.get("CLOUD_UPGRADE_AUTO_APPROVE", "").lower() in {"1", "true", "yes"}:
        return f"approved by CLOUD_UPGRADE_AUTO_APPROVE for: {question}"
    answer = input(f"{question} [{default}] ").strip().lower() or default
    if answer not in {"y", "yes", "approve", "approved"}:
        raise RuntimeError(f"user did not approve: {answer}")
    return f"approved: {question}"


TOOLS = {
    "read_file": read_file,
    "list_dir": list_dir,
    "grep_search": grep_search,
    "create_file": create_file,
    "replace_string_in_file": replace_string_in_file,
    "run_command": run_command,
    "probe_environment": probe_environment,
    "generate_sbom": generate_sbom,
    "ask_user": ask_user,
}


def truncate_output(output: str) -> str:
    if len(output) <= MAX_TOOL_OUTPUT:
        return output
    return output[:MAX_TOOL_OUTPUT] + f"\n...[truncated {len(output) - MAX_TOOL_OUTPUT} chars]"


def extract_json_frame(text: str) -> Frame:
    decoder = json.JSONDecoder()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{", text)
        if not match:
            raise
        frame, _ = decoder.raw_decode(text[match.start() :])
        return frame


def resolve_endpoint(explicit: str | None) -> str:
    endpoint = explicit or os.environ.get("FOUNDRY_PROJECT_ENDPOINT") or os.environ.get("AZURE_AI_PROJECT_ENDPOINT")
    if endpoint:
        return endpoint.rstrip("/")
    completed = subprocess.run(  # optional one-time dev fallback, not a per-turn dependency
        ["azd", "env", "get-value", "AZURE_AI_PROJECT_ENDPOINT"], check=False, capture_output=True, text=True
    )
    if completed.returncode == 0 and completed.stdout.strip():
        return completed.stdout.strip().rstrip("/")
    raise SystemExit("project endpoint required: pass --endpoint or set FOUNDRY_PROJECT_ENDPOINT")


class ResponsesClient:
    """Minimal stdlib client for a hosted agent's OpenAI responses endpoint."""

    def __init__(self, endpoint: str, agent_name: str, correlation_id: str) -> None:
        self.url = f"{endpoint}/agents/{agent_name}/endpoint/protocols/openai/responses?api-version=v1"
        self.correlation_id = correlation_id
        self._token: str | None = None
        self._token_expiry = 0.0

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expiry - 300:
            return self._token
        completed = subprocess.run(
            ["az", "account", "get-access-token", "--resource", AI_RESOURCE, "-o", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(completed.stdout)
        self._token = payload["accessToken"]
        expires_on = payload.get("expires_on")
        self._token_expiry = float(expires_on) if expires_on else time.time() + 3300
        return self._token

    def send(self, frame: Frame, previous_response_id: str | None) -> tuple[Frame, str]:
        """POST one frame; return (response frame, response id for chaining)."""
        body: dict[str, Any] = {"input": json.dumps(frame), "stream": False}
        if previous_response_id:
            body["previous_response_id"] = previous_response_id
        request = urllib.request.Request(
            self.url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._get_token()}",
                "Content-Type": "application/json",
                "x-ms-client-request-id": self.correlation_id,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=600) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"agent endpoint returned HTTP {error.code}: {detail}") from error
        response_id = str(payload["id"])
        texts = [
            content.get("text", "")
            for item in payload.get("output", [])
            if item.get("type") == "message"
            for content in item.get("content", [])
        ]
        return extract_json_frame("\n".join(texts)), response_id


def load_state(state_file: Path | None) -> tuple[str | None, Frame | None]:
    if state_file is None or not state_file.exists():
        return None, None
    state = json.loads(state_file.read_text(encoding="utf-8"))
    return state.get("previous_response_id"), state.get("frame")


def save_state(state_file: Path | None, previous_response_id: str | None, frame: Frame) -> None:
    if state_file is None:
        return
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(
        json.dumps({"previous_response_id": previous_response_id, "frame": frame}, indent=2),
        encoding="utf-8",
    )


def run_tool(project_root: Path, frame: Frame) -> Frame:
    call_id = str(frame.get("call_id", "local-call"))
    name = str(frame["name"])
    arguments = frame.get("arguments", {})
    try:
        if name not in TOOLS:
            raise ValueError(f"unsupported tool: {name}")
        output = TOOLS[name](project_root, arguments)
        return {"type": "tool_result", "call_id": call_id, "output": truncate_output(output), "is_error": False}
    except Exception as error:
        return {"type": "tool_result", "call_id": call_id, "output": str(error), "is_error": True}


def prompt_user(question: str, options: list[str], default: str) -> str:
    """Render an ask_user frame in the terminal and return the chosen answer."""
    if os.environ.get("CLOUD_UPGRADE_AUTO_APPROVE", "").lower() in {"1", "true", "yes"}:
        answer = default or (options[0] if options else "yes")
        print(f"[ask_user] auto-approved: {answer}", flush=True)
        return answer
    print(f"\n{question}", flush=True)
    for index, option in enumerate(options, start=1):
        marker = " (default)" if option == default else ""
        print(f"  {index}. {option}{marker}", flush=True)
    raw = input("> ").strip()
    if not raw:
        return default or (options[0] if options else "")
    if raw.isdigit() and options and 1 <= int(raw) <= len(options):
        return options[int(raw) - 1]
    return raw


def run(project_root: Path, endpoint: str, agent_name: str, goal: str, max_turns: int, debug_frames: bool, state_file: Path | None) -> str:
    correlation_id = uuid.uuid4().hex
    client = ResponsesClient(endpoint, agent_name, correlation_id)
    previous_response_id, saved_frame = load_state(state_file)
    frame: Frame = saved_frame or {"type": "task", "goal": goal}
    started_at = time.monotonic()
    step = 0

    print(f"[start] project={project_root.name} agent={agent_name} correlation={correlation_id}", flush=True)
    if previous_response_id:
        print(f"[resume] previous_response={previous_response_id}", flush=True)

    for _ in range(max_turns):
        response_frame, previous_response_id = client.send(frame, previous_response_id)
        if debug_frames:
            print(f"[agent] {json.dumps(response_frame, ensure_ascii=False)}", flush=True)
        frame_type = response_frame.get("type")

        if frame_type == "tool_call":
            step += 1
            elapsed = time.monotonic() - started_at
            print(
                f"[step {step:02d} +{elapsed:05.1f}s] {response_frame.get('name')} "
                f"{json.dumps(response_frame.get('arguments', {}), ensure_ascii=False)}",
                flush=True,
            )
            frame = run_tool(project_root, response_frame)
            save_state(state_file, previous_response_id, frame)
            continue
        if frame_type == "progress":
            elapsed = time.monotonic() - started_at
            print(f"[{response_frame.get('phase', 'progress')} +{elapsed:05.1f}s] {response_frame.get('text', '')}", flush=True)
            frame = {"type": "ack"}
            save_state(state_file, previous_response_id, frame)
            continue
        if frame_type == "ask_user":
            answer = prompt_user(
                str(response_frame.get("question", "Approve?")),
                [str(option) for option in response_frame.get("options", [])],
                str(response_frame.get("default", "")),
            )
            frame = {"type": "user_answer", "answer": answer}
            save_state(state_file, previous_response_id, frame)
            continue
        if frame_type == "done":
            elapsed = time.monotonic() - started_at
            print(f"[done +{elapsed:05.1f}s] completed in {step} tool steps", flush=True)
            if state_file is not None and state_file.exists():
                state_file.unlink()
            return str(response_frame.get("summary", ""))
        if frame_type == "error":
            hint = " (run again with --rollback to restore modified files)" if (project_root / BACKUP_DIR).exists() else ""
            raise RuntimeError(str(response_frame.get("message", "agent returned an error")) + hint)

        raise RuntimeError(f"unexpected frame type: {frame_type}")

    raise RuntimeError(f"tool loop did not finish within {max_turns} turns")


def main() -> None:
    parser = argparse.ArgumentParser(description="Thin client for the Cloud Java Upgrade Agent.")
    parser.add_argument("project", type=Path, help="Local Java project root")
    parser.add_argument("--agent", default="java-upgrade-cloud", help="Foundry hosted agent name")
    parser.add_argument("--endpoint", help="Foundry project endpoint (default: FOUNDRY_PROJECT_ENDPOINT / AZURE_AI_PROJECT_ENDPOINT)")
    parser.add_argument("--goal", default="Read pom.xml and summarize the Maven project technology stack.")
    parser.add_argument("--max-turns", type=int, default=4)
    parser.add_argument("--debug-frames", action="store_true", help="Print raw JSON frames returned by the hosted agent")
    parser.add_argument("--state-file", type=Path, help="Persist response chain state for resume after interruption")
    parser.add_argument("--rollback", action="store_true", help="Restore files modified by the last run and exit")
    args = parser.parse_args()

    project_root = args.project.resolve()
    if args.rollback:
        print(rollback(project_root), flush=True)
        return
    endpoint = resolve_endpoint(args.endpoint)
    state_file = args.state_file.resolve() if args.state_file else None
    summary = run(project_root, endpoint, args.agent, args.goal, args.max_turns, args.debug_frames, state_file)
    print(summary, flush=True)


if __name__ == "__main__":
    main()