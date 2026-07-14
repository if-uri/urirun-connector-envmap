# Author: Tom Sapletta · Part of the ifURI solution.
"""urirun-connector-envmap — MAPA środowiska w ograniczonej pamięci (`envmap://`).

Reverse+verify wymagają stanu-przed (dla inverse) i stanu-po (dla verify). Kopiowanie gigabajtów
jest niemożliwe — pamięć nas ogranicza. Rozwiązanie wynika z modelu CECH: nie trzymaj OBIEKTÓW,
trzymaj **odciski cech (fingerprints)** i **referencje do snapshotów**. Gigabajty danych opisujesz
kilobajtami hashy (drzewo Merkle); duże pliki próbkujesz (head+tail+size), nie czytasz w całości.

  * ``envmap://target/query/fingerprint`` — mapa cech targetu (per-plik hash) + root Merkle. Bounded.
  * ``envmap://target/query/diff``        — różnica dwóch map: added/removed/changed (dla verify + delta-inverse)
  * ``envmap://snapshot/command/take``    — referencja stanu-przed do cofnięcia (git-commit / manifest), NIE kopia

Inverse przy skali = przywróć TYLKO zmienione (delta) z referencji (git/CoW/DB-savepoint), nie
całość. Verify przy skali = porównaj root-hashe, nie czytaj całości. Read-only fingerprint/diff;
snapshot mutuje store → isolated.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import urirun

CONNECTOR_ID = "envmap"
conn = urirun.connector(CONNECTOR_ID, scheme="envmap")

_SAMPLE = 65536  # duże pliki: hashuj head+tail po 64KB (bounded), nie całość
_STORE_ENV = "URIRUN_ENVMAP_STORE"


def _ok(**kw: Any) -> dict[str, Any]:
    return urirun.ok(connector=CONNECTOR_ID, **kw)


def _fail(msg: str, action: str) -> dict[str, Any]:
    return urirun.fail(msg, connector=CONNECTOR_ID, action=action)


def _file_fp(p: Path) -> str:
    """Odcisk pliku bez czytania całości: rozmiar + head/tail (próbkowanie dla GB-plików)."""
    try:
        sz = p.stat().st_size
    except OSError:
        return "err"
    h = hashlib.sha1()
    h.update(str(sz).encode())
    try:
        with p.open("rb") as f:
            h.update(f.read(_SAMPLE))
            if sz > 2 * _SAMPLE:
                f.seek(-_SAMPLE, os.SEEK_END)
                h.update(f.read(_SAMPLE))
    except OSError:
        return "err"
    return f"{sz}:{h.hexdigest()[:16]}"


def fingerprint(target: str, max_files: int = 20000) -> dict[str, Any]:
    """Mapa cech targetu: {ścieżka→odcisk} + root Merkle. Pamięć = O(liczba plików), nie O(bajty)."""
    base = Path(os.path.expanduser(target))
    files: dict[str, str] = {}
    total = 0
    if base.is_file():
        files[base.name] = _file_fp(base)
    else:
        for p in sorted(base.rglob("*")):
            if p.is_file() and ".git" not in p.parts:
                files[str(p.relative_to(base))] = _file_fp(p)
                total += 1
                if total >= max_files:
                    break
    root = hashlib.sha1("|".join(f"{k}={v}" for k, v in sorted(files.items())).encode()).hexdigest()
    return {"target": str(base), "root": root, "count": len(files), "files": files}


def diff(before: dict, after: dict) -> dict[str, Any]:
    """Różnica dwóch map cech — dla verify (czy zmiana zaszła) i delta-inverse (co przywrócić)."""
    fb, fa = (before or {}).get("files", {}), (after or {}).get("files", {})
    added = [k for k in fa if k not in fb]
    removed = [k for k in fb if k not in fa]
    changed = [k for k in fa if k in fb and fa[k] != fb[k]]
    return {"added": added, "removed": removed, "changed": changed,
            "identical": (before or {}).get("root") == (after or {}).get("root"),
            "delta_count": len(added) + len(removed) + len(changed)}


def _store() -> Path:
    p = Path(os.environ.get(_STORE_ENV) or "~/.urirun/host-dashboard/envmap-snapshots.json").expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def snapshot(target: str, label: str = "") -> dict[str, Any]:
    """Referencja stanu-przed do cofnięcia. Preferuj git-commit (0 kopii); fallback: manifest cech."""
    base = Path(os.path.expanduser(target))
    ref = {"target": str(base), "label": label, "at": time.time()}
    git_root = base if (base / ".git").is_dir() else next(
        (par for par in [base, *base.parents] if (par / ".git").is_dir()), None)
    if git_root:
        import subprocess
        try:
            rev = subprocess.run(["git", "-C", str(git_root), "rev-parse", "HEAD"],
                                 capture_output=True, text=True, timeout=10)
            ref.update(kind="git", git_root=str(git_root), commit=(rev.stdout or "").strip(),
                       inverse="git -C <root> reset --hard <commit> (przywraca cechy, 0 kopii)")
            return _ok(action="envmap-snapshot", **ref)
        except Exception:  # noqa: BLE001
            pass
    fp = fingerprint(target)
    data = _load()
    key = f"{base.name}-{int(ref['at'])}"
    data[key] = {"ref": ref, "fingerprint": {"root": fp["root"], "count": fp["count"]}}
    _store().write_text(json.dumps(data, indent=1), encoding="utf-8")
    ref.update(kind="fingerprint", id=key, root=fp["root"],
               inverse="przywróć delta z backupu/CoW-snapshot wg diff (nie całość)")
    return _ok(action="envmap-snapshot", **ref)


def _load() -> dict:
    f = _store()
    if not f.is_file():
        return {}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


@conn.handler("target/query/fingerprint", isolated=False,
              meta={"label": "Mapa cech targetu (Merkle root + per-plik odcisk) — bounded memory"})
def target_query_fingerprint(target: str = ".", max_files: int = 20000) -> dict[str, Any]:
    try:
        return _ok(action="envmap-fingerprint", **fingerprint(target, int(max_files)))
    except Exception as exc:  # noqa: BLE001
        return _fail(str(exc), "envmap-fingerprint")


@conn.handler("target/query/diff", isolated=False,
              meta={"label": "Różnica map cech: added/removed/changed (verify + delta-inverse)"})
def target_query_diff(before: dict | None = None, after: dict | None = None) -> dict[str, Any]:
    try:
        return _ok(action="envmap-diff", **diff(before or {}, after or {}))
    except Exception as exc:  # noqa: BLE001
        return _fail(str(exc), "envmap-diff")


@conn.handler("snapshot/command/take", isolated=True,
              meta={"label": "Referencja stanu do cofnięcia (git-commit / manifest) — NIE kopia GB",
                    "reversible": True,
                    "inverse": [{"technique": "git-reset", "feature": "tree-state",
                                 "how": "git reset --hard <commit> — odtwarza cechy drzewa, 0 kopii"},
                                {"technique": "delta-restore", "feature": "changed-files",
                                 "how": "przywróć tylko zmienione pliki wg diff z CoW-snapshotu"}]})
def snapshot_command_take(target: str = ".", label: str = "") -> dict[str, Any]:
    try:
        return snapshot(target, label)
    except Exception as exc:  # noqa: BLE001
        return _fail(str(exc), "envmap-snapshot")


def urirun_bindings() -> dict[str, Any]:
    return conn.bindings()


def connector_manifest() -> dict[str, Any]:
    return urirun.load_manifest(__package__) or {"id": CONNECTOR_ID}


def main(argv: list[str] | None = None) -> int:
    return conn.cli(argv, manifest_prose=urirun.load_manifest(__package__))


if __name__ == "__main__":
    raise SystemExit(main())
