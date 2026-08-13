from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from urllib.parse import urlsplit

LOOPBACK_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def run(command: Sequence[str], *, capture: bool = False) -> str:
    completed = subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    return completed.stdout.strip() if capture else ""


def request(url: str, *, timeout: float = 5.0) -> tuple[int, dict[str, str], bytes]:
    if urlsplit(url).hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("container runtime probe only permits loopback URLs")
    try:
        with LOOPBACK_OPENER.open(url, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers.items()), error.read()


def wait_for(url: str, *, timeout: float = 60.0) -> tuple[dict[str, str], bytes]:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            status, headers, body = request(url)
            if status == 200:
                return headers, body
            last_error = RuntimeError(f"unexpected HTTP status {status}")
        except (OSError, urllib.error.URLError) as error:
            last_error = error
        time.sleep(0.25)
    raise RuntimeError(f"container endpoint did not become ready: {url}: {last_error}")


def published_port(container: str, port: int) -> int:
    value = run(["docker", "port", container, f"{port}/tcp"], capture=True)
    return int(value.rsplit(":", 1)[1])


def remove_container(name: str) -> None:
    subprocess.run(
        ["docker", "rm", "--force", name],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def container_logs(name: str) -> str:
    completed = subprocess.run(
        ["docker", "logs", name],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return completed.stdout[-8_000:]


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and exercise hardened runtime images")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--backend-image", default="industryshadow-backend:smoke")
    parser.add_argument("--web-image", default="industryshadow-web:smoke")
    arguments = parser.parse_args()
    suffix = str(os.getpid())
    network = f"industryshadow-runtime-smoke-{suffix}"
    backend = f"industryshadow-backend-smoke-{suffix}"
    web = f"industryshadow-web-smoke-{suffix}"
    build_digest = "sha256:" + "a" * 64

    if arguments.build:
        run(
            [
                "docker",
                "build",
                "-f",
                "deploy/compose/Dockerfile.backend",
                "-t",
                arguments.backend_image,
                ".",
            ]
        )
        run(
            [
                "docker",
                "build",
                "-f",
                "deploy/compose/Dockerfile.web",
                "-t",
                arguments.web_image,
                ".",
            ]
        )

    run(["docker", "network", "create", network], capture=True)
    try:
        run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                backend,
                "--network",
                network,
                "--network-alias",
                "control-api",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m",
                "--tmpfs",
                "/app/.runtime:rw,noexec,nosuid,size=256m,mode=1777",
                "--publish",
                "127.0.0.1::8000",
                "--env",
                "SHADOW_ENVIRONMENT=development",
                "--env",
                f"SHADOW_BUILD_DIGEST={build_digest}",
                arguments.backend_image,
            ],
            capture=True,
        )
        backend_port = published_port(backend, 8000)
        wait_for(f"http://127.0.0.1:{backend_port}/api/v1/health/live")
        status, _, body = request(f"http://127.0.0.1:{backend_port}/api/v1/version")
        if status != 200 or json.loads(body)["build_digest"] != build_digest:
            raise RuntimeError("backend version endpoint is not bound to the candidate digest")
        status, _, body = request(f"http://127.0.0.1:{backend_port}/openapi.json")
        paths = json.loads(body).get("paths", {})
        operation_count = sum(
            method.lower() in {"get", "post", "patch", "put", "delete"}
            for operations in paths.values()
            for method in operations
        )
        if status != 200 or operation_count != 89:
            raise RuntimeError("backend OpenAPI contract is incomplete")
        if run(["docker", "exec", backend, "id", "-u"], capture=True) == "0":
            raise RuntimeError("backend image runs as root")

        run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                web,
                "--network",
                network,
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m",
                "--publish",
                "127.0.0.1::8080",
                arguments.web_image,
            ],
            capture=True,
        )
        web_port = published_port(web, 8080)
        headers, body = wait_for(f"http://127.0.0.1:{web_port}/")
        if b'<div id="app"></div>' not in body:
            raise RuntimeError("web image did not serve the application shell")
        for name in (
            "Content-Security-Policy",
            "Permissions-Policy",
            "Referrer-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
        ):
            if name not in headers:
                raise RuntimeError(f"web image is missing security header: {name}")
        status, _, _ = request(f"http://127.0.0.1:{web_port}/assets/hidden.js.map")
        if status != 404:
            raise RuntimeError("web image exposed a source map path")
        if run(["docker", "exec", web, "id", "-u"], capture=True) == "0":
            raise RuntimeError("web image runs as root")
    except Exception as error:
        raise RuntimeError(
            f"{error}\nbackend logs:\n{container_logs(backend)}"
            f"\nweb logs:\n{container_logs(web)}"
        ) from error
    finally:
        remove_container(web)
        remove_container(backend)
        subprocess.run(
            ["docker", "network", "rm", network],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    print(
        "Backend and web images passed non-root, read-only runtime, health, OpenAPI, "
        "candidate-digest, security-header, and source-map denial checks."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
