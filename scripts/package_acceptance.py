#!/usr/bin/env python3
"""FOSS-440: exercise real .crate archives via an ephemeral loopback Cargo registry.

No source workspace manifest is changed, no public registry is contacted for
the candidate packages, no authentication token is read, and no package is uploaded.
Third-party published dependencies are resolved normally from crates.io.
"""
from __future__ import annotations

import functools
import hashlib
import http.server
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
import threading
import tomllib

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = ("pqc-kit", "cryptopolicy")
VERSION = "0.1.0"
CRATES_IO_INDEX = "https://github.com/rust-lang/crates.io-index"
REQUIRED_FILES = {
    "pqc-kit": {"Cargo.toml", "src/lib.rs", "data/catalog-v1.json"},
    "cryptopolicy": {"Cargo.toml", "src/lib.rs", "src/evaluator.rs"},
}
MAX_ARCHIVE_MEMBER_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 20 * 1024 * 1024


class AcceptanceFailure(RuntimeError):
    """A candidate artifact or local-registry test did not meet the contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceFailure(message)


def assert_source_is_unpublishable(source: Path = ROOT) -> None:
    workspace = tomllib.loads((source / "Cargo.toml").read_text())
    members = workspace["workspace"]["members"]
    require(set(CANDIDATES).issubset({Path(m).name for m in members}), "missing candidate workspace member")
    for member in members:
        manifest = tomllib.loads((source / member / "Cargo.toml").read_text())
        require(manifest["package"].get("publish") is False, "source package has publishing enabled: " + member)
    core = tomllib.loads((source / "crates/cryptopolicy/Cargo.toml").read_text())
    dependency = core["dependencies"]["pqc-kit"]
    require(dependency.get("version") == "=0.1.0" and dependency.get("path") == "../pqc-kit",
            "unexpected candidate dependency version or source")


def index_path(crate: str) -> Path:
    require(crate.isascii() and crate.replace("-", "").isalnum() and crate == crate.lower(),
            "invalid registry crate name")
    if len(crate) == 1:
        return Path("1", crate)
    if len(crate) == 2:
        return Path("2", crate)
    if len(crate) == 3:
        return Path("3", crate[0], crate)
    return Path(crate[:2], crate[2:4], crate)


def validate_archive(archive: Path, name: str) -> tuple[dict, str]:
    prefix = name + "-" + VERSION + "/"
    found: set[str] = set()
    total = 0
    manifest_bytes = None
    with tarfile.open(archive, mode="r:gz") as tf:
        for entry in tf:
            require(entry.isfile() or entry.isdir(), "unsupported package member type: " + entry.name)
            require(entry.name.startswith(prefix), "unexpected package prefix")
            relative = entry.name[len(prefix):]
            parts = PurePosixPath(relative).parts
            require(bool(parts) and all(p not in (".", "..") for p in parts), "unsafe package member path")
            require(not relative.startswith("/") and not relative.startswith(".git/"), "unsafe package member")
            require("target" not in parts and ".env" not in parts, "build output or environment included")
            require(entry.size <= MAX_ARCHIVE_MEMBER_BYTES, "oversized package member")
            total += entry.size
            require(total <= MAX_ARCHIVE_TOTAL_BYTES, "oversized package")
            if entry.isfile():
                found.add(relative)
                if relative == "Cargo.toml":
                    data = tf.extractfile(entry)
                    require(data is not None, "missing manifest stream")
                    manifest_bytes = data.read()
    require(REQUIRED_FILES[name].issubset(found), "missing essential package files: " + name)
    require(manifest_bytes is not None, "missing packaged manifest")
    manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
    require(manifest["package"]["name"] == name, "mismatched package name")
    require(manifest["package"]["version"] == VERSION, "mismatched package version")
    require(manifest["package"].get("rust-version") == "1.85", "unapproved MSRV")
    for dep in manifest.get("dependencies", {}).values():
        if isinstance(dep, dict):
            require("path" not in dep and "git" not in dep, "path or git dependency leaked into archive")
    return manifest, hashlib.sha256(archive.read_bytes()).hexdigest()


def index_record(name: str, manifest: dict, digest: str) -> dict:
    deps = []
    for dependency, spec in sorted(manifest.get("dependencies", {}).items()):
        spec = {"version": spec} if isinstance(spec, str) else spec
        require(isinstance(spec, dict) and "version" in spec, "unversioned package dependency")
        require("path" not in spec and "git" not in spec, "unpackaged dependency source")
        deps.append({
            "name": dependency,
            "req": spec["version"],
            "features": spec.get("features", []),
            "optional": spec.get("optional", False),
            "default_features": spec.get("default-features", True),
            "target": None,
            "kind": "normal",
            "registry": None if dependency in CANDIDATES else CRATES_IO_INDEX,
        })
    return {
        "name": name,
        "vers": VERSION,
        "deps": deps,
        "cksum": digest,
        "features": {},
        "yanked": False,
        "links": None,
        "rust_version": "1.85",
    }


def install_archive(registry: Path, archive: Path, name: str) -> str:
    manifest, digest = validate_archive(archive, name)
    index_file = registry / "index" / index_path(name)
    index_file.parent.mkdir(parents=True, exist_ok=True)
    index_file.write_text(json.dumps(index_record(name, manifest, digest), sort_keys=True) + "\n")
    download = registry / "crates" / name / VERSION / "download"
    download.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(archive, download)
    return digest


def command(args: list[str], *, cwd: Path, env: dict[str, str]) -> None:
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=cwd, env=env, check=True, timeout=360)


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        pass


def run_acceptance(source: Path = ROOT) -> None:
    assert_source_is_unpublishable(source)
    with tempfile.TemporaryDirectory(prefix="cryptopolicy-package-") as temporary:
        home = Path(temporary)
        stage = home / "staged-source"
        shutil.copytree(source, stage, ignore=shutil.ignore_patterns(".git", "target", "__pycache__", ".venv"))
        # Only disposable staging manifests are adjusted to allow Cargo to form
        # genuine .crate archives. The repository remains publish=false.
        for name in CANDIDATES:
            manifest = stage / "crates" / name / "Cargo.toml"
            data = manifest.read_text()
            require(data.count("publish = false") == 1, "staging publish gate is ambiguous")
            manifest.write_text(data.replace("publish = false", 'publish = ["preview"]'))
        registry = home / "registry"
        (registry / "index").mkdir(parents=True)
        handler = functools.partial(QuietHandler, directory=str(registry))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            port = server.server_address[1]
            origin = "http://127.0.0.1:" + str(port)
            (registry / "index" / "config.json").write_text(json.dumps({
                "dl": origin + "/crates/{crate}/{version}/download",
                "api": origin + "/unused-no-publishing-api",
            }))
            option = 'registries.preview.index="sparse+' + origin + '/index/"'
            cargo = ["cargo", "--config", option]
            env = dict(os.environ)
            env["CARGO_TARGET_DIR"] = str(home / "cargo-target")
            # No release credentials or publish commands are used.
            for name in CANDIDATES:
                args = cargo + ["package", "-p", name, "--manifest-path", str(stage / "Cargo.toml"),
                                "--registry", "preview", "--no-verify", "--allow-dirty"]
                command(args, cwd=stage, env=env)
                artifact = home / "cargo-target" / "package" / (name + "-" + VERSION + ".crate")
                require(artifact.is_file(), "Cargo did not create a crate archive: " + name)
                first = install_archive(registry, artifact, name)
                command(args, cwd=stage, env=env)
                second = hashlib.sha256(artifact.read_bytes()).hexdigest()
                require(first == second, "package archive is not reproducible: " + name)
                print("PACKAGED", name, VERSION, "sha256=" + first, flush=True)

            consumer = home / "independent-consumer"
            shutil.copytree(source / "acceptance" / "fresh-consumer", consumer,
                            ignore=shutil.ignore_patterns("target", "Cargo.lock"))
            consumer_manifest = consumer / "Cargo.toml"
            current = consumer_manifest.read_text()
            start = next((line for line in current.splitlines()
                          if line.startswith("cryptopolicy = { git = ")), None)
            require(start is not None, "expected pinned Git preview dependency")
            consumer_manifest.write_text(current.replace(
                start, 'cryptopolicy = { version = "=0.1.0", registry = "preview" }'
            ))
            dependency = tomllib.loads(consumer_manifest.read_text())["dependencies"]["cryptopolicy"]
            require("git" not in dependency and "path" not in dependency,
                    "consumer must request a versioned local-registry artifact")
            command(cargo + ["generate-lockfile", "--manifest-path", str(consumer_manifest)],
                    cwd=consumer, env=env)
            lock = tomllib.loads((consumer / "Cargo.lock").read_text())
            for name in CANDIDATES:
                entries = [p for p in lock["package"] if p["name"] == name]
                print("LOCK SOURCE", name, [(e.get("version"), e.get("source")) for e in entries], flush=True)
                require(len(entries) == 1 and
                        entries[0].get("source", "") == "sparse+" + origin + "/index/",
                        "consumer did not resolve local registry package: " + name)
            command(cargo + ["run", "--locked", "--manifest-path", str(consumer_manifest)],
                    cwd=consumer, env=env)
            print("PASS external consumer resolved both .crate artifacts by registry version", flush=True)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)
    assert_source_is_unpublishable(source)


if __name__ == "__main__":
    run_acceptance()
