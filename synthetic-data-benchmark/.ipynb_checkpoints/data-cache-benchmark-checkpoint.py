#!/usr/bin/env python3
"""
data_cache_bench.py

Standalone lightweight fingerprint + cache benchmark for S3 and Pelican sources.

Fingerprint = SHA-256( canonical_JSON( spec_fields + remote_source_metadata ) )
Including remote metadata (etag, size, last_modified) means the key changes
when the remote data changes, even when the spec hasn't — the core goal.

Usage:
    python data_cache_bench.py <spec.yml> [options]

Options:
    --cache-dir PATH        Cache root (default: ./floability-data-cache)
    --download-on-miss      Download and build cache entry on miss
    --profile NAME          Profile to use (default: spec's default_profile)
    --output PATH           Write JSON report to file (default: stdout)
    --no-anonymous          Use AWS credential chain instead of anonymous S3
    --verbose
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import yaml


# ──────────────────────────────────────────────────────────────────────────────
# Spec loading
# ──────────────────────────────────────────────────────────────────────────────

def load_and_validate_spec(
    spec_path: Path, profile_name: Optional[str] = None
) -> Tuple[str, Dict[str, Any]]:
    """Load YAML and return (profile_name, profile_dict).
    Mirrors data_handler.load_and_validate_spec; stripped to essentials.
    """
    with spec_path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    profiles = raw.get("data_profiles") or raw.get("profiles")
    if not profiles or not isinstance(profiles, dict):
        raise ValueError("Spec missing 'data_profiles' mapping")

    if profile_name:
        if profile_name not in profiles:
            raise ValueError(f"Profile '{profile_name}' not found in spec")
        return profile_name, profiles[profile_name]

    default = raw.get("default_profile") or next(iter(profiles))
    profile = profiles.get(default)
    if profile is None:
        raise ValueError(f"Default profile '{default}' not found")
    return default, profile


def _infer_source_type(source: str) -> str:
    if source.startswith("s3://"):
        return "s3"
    if source.startswith(("pelican://", "osdf://")):
        return "pelican"
    if source.startswith(("http://", "https://")):
        return "http"
    return "fs"


def _normalize_data_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Unify target_path → target_location, infer source_type, set name.
    Mirrors data_handler._normalize_data_item.
    """
    it = dict(item)
    if not it.get("target_location") and it.get("target_path"):
        it["target_location"] = it["target_path"]
    if not it.get("name"):
        tloc = str(it.get("target_location") or "")
        it["name"] = Path(tloc).name if tloc else "<unnamed>"
    if not it.get("source_type"):
        if it.get("sources"):
            it["source_type"] = "multi"
        else:
            src = str(it.get("source", "") or "")
            if src.startswith("backpack://"):
                it["source_type"] = "backpack"
                it["source"] = src[len("backpack://"):]
            else:
                it["source_type"] = _infer_source_type(src)
    if isinstance(it.get("sources"), list):
        norm = []
        for s in it["sources"]:
            s = dict(s)
            if not s.get("source_type"):
                s["source_type"] = _infer_source_type(str(s.get("source", "") or ""))
            norm.append(s)
        it["sources"] = norm
    return it


# ──────────────────────────────────────────────────────────────────────────────
# S3 metadata helpers
# ──────────────────────────────────────────────────────────────────────────────

def _s3_client(anonymous: bool = True):
    """Anonymous by default for public HPC buckets; override with --no-anonymous."""
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config
    if anonymous:
        return boto3.client("s3", config=Config(signature_version=UNSIGNED))
    return boto3.client("s3")


def _parse_s3_uri(uri: str) -> Tuple[str, str]:
    if not uri.startswith("s3://"):
        raise ValueError(f"Not an S3 URI: {uri}")
    bucket, _, key = uri[5:].partition("/")
    return bucket, key


def s3_file_metadata(uri: str, anonymous: bool = True) -> Dict[str, Any]:
    """Single HEAD request — returns etag, size, last_modified. No data transfer."""
    t0 = time.perf_counter()
    bucket, key = _parse_s3_uri(uri)
    try:
        resp = _s3_client(anonymous).head_object(Bucket=bucket, Key=key)
        lm = resp.get("LastModified")
        return {
            "ok": True,
            "object_type": "file",
            "etag": resp.get("ETag", "").strip('"'),
            "size": resp.get("ContentLength"),
            "last_modified": lm.isoformat() if lm else None,
            "fetch_ms": (time.perf_counter() - t0) * 1000,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "fetch_ms": (time.perf_counter() - t0) * 1000}


def s3_list_objects(uri: str, anonymous: bool = True) -> List[Dict[str, Any]]:
    """Paginated listing of all objects under a prefix — returns rel_path + metadata only.
    Mirrors data_handler.s3_list_objects; stripped to fingerprint-relevant fields.
    """
    bucket, prefix = _parse_s3_uri(uri)
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    paginator = _s3_client(anonymous).get_paginator("list_objects_v2")
    results = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/"):
                continue  # skip directory marker objects
            rel = key[len(prefix):] if key.startswith(prefix) else key
            lm = obj.get("LastModified")
            results.append({
                "rel_path": rel,
                "etag": obj.get("ETag", "").strip('"'),
                "size": obj.get("Size"),
                "last_modified": lm.isoformat() if lm else None,
            })
    return results


def s3_dir_metadata(uri: str, anonymous: bool = True) -> Dict[str, Any]:
    """List all objects under a prefix and aggregate into a single metadata dict.
    S3 has no real directory object — listing is the only way to detect any change.
    """
    t0 = time.perf_counter()
    try:
        files = s3_list_objects(uri, anonymous)
        files.sort(key=lambda f: f["rel_path"])  # deterministic order for stable hash
        return {
            "ok": True,
            "object_type": "directory",
            "file_count": len(files),
            "total_size": sum(f["size"] or 0 for f in files),
            "files": files,
            "fetch_ms": (time.perf_counter() - t0) * 1000,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "fetch_ms": (time.perf_counter() - t0) * 1000}


def _is_s3_directory(uri: str, anonymous: bool = True) -> bool:
    """True if the URI is a prefix with multiple objects (not a single exact-match key)."""
    if uri.endswith("/"):
        return True
    try:
        bucket, prefix = _parse_s3_uri(uri)
        resp = _s3_client(anonymous).list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=2)
        contents = resp.get("Contents", [])
        if len(contents) == 1 and contents[0]["Key"] == prefix:
            return False  # exact single key match → file
        return len(contents) > 0
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Pelican metadata helpers
# ──────────────────────────────────────────────────────────────────────────────

def _pelican_fs_and_path(url: str):
    """Parse pelican:// or osdf:// into (PelicanFileSystem, path).
    Mirrors _get_fs_and_path from pelican_file_utils.
    """
    from pelicanfs.core import PelicanFileSystem
    u = urlparse(url)
    if u.scheme == "osdf":
        director, path = "pelican://osg-htc.org", u.path or "/"
    elif u.scheme == "pelican":
        director, path = f"pelican://{u.netloc}", u.path or "/"
    else:
        raise ValueError(f"Expected pelican:// or osdf://, got: {url}")
    return PelicanFileSystem(director), path


def _extract_pelican_extra(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Best-effort extraction of etag and last_modified from fsspec info dict.
    PelicanFS may or may not surface these depending on the backing HTTP server.
    If absent the fingerprint falls back to size-only — acceptable degradation.
    """
    result = {}
    for key in ("etag", "ETag", "e_tag"):
        if raw.get(key):
            result["etag"] = str(raw[key]).strip('"')
            break
    for key in ("last_modified", "LastModified", "modified"):
        if raw.get(key):
            val = raw[key]
            result["last_modified"] = val.isoformat() if hasattr(val, "isoformat") else str(val)
            break
    return result


def pelican_file_metadata(url: str) -> Dict[str, Any]:
    """fs.info() for a single Pelican object — no body download.
    Mirrors pelican_file_utils.pelican_file_metadata.
    """
    t0 = time.perf_counter()
    try:
        fs, path = _pelican_fs_and_path(url)
        raw = fs.info(path)
        extra = _extract_pelican_extra(raw)
        return {
            "ok": True,
            "object_type": "file",
            "size": raw.get("size"),
            "etag": extra.get("etag"),          # None if server doesn't expose it
            "last_modified": extra.get("last_modified"),
            "fetch_ms": (time.perf_counter() - t0) * 1000,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "fetch_ms": (time.perf_counter() - t0) * 1000}


def pelican_list_directory(url: str) -> List[Dict[str, Any]]:
    """Recursive walk collecting per-file metadata from a Pelican directory.
    Mirrors pelican_file_utils.pelican_list_directory but includes etag/last_modified.
    Parent-dir mtime is unreliable on HTTP servers (content changes don't propagate
    upward), so per-file metadata is the only robust change signal.
    """
    fs, base_path = _pelican_fs_and_path(url)
    if not base_path.endswith("/"):
        base_path += "/"
    files = []
    for dirpath, dirnames, filenames in fs.walk(base_path):
        dirnames.sort()   # sort for deterministic traversal
        filenames.sort()
        for fname in filenames:
            fpath = f"{dirpath.rstrip('/')}/{fname}"
            try:
                raw = fs.info(fpath)
                extra = _extract_pelican_extra(raw)
                rel = fpath[len(base_path):] if fpath.startswith(base_path) else fpath
                files.append({
                    "rel_path": rel,
                    "size": raw.get("size"),
                    "etag": extra.get("etag"),
                    "last_modified": extra.get("last_modified"),
                })
            except Exception:
                pass  # skip inaccessible files; don't abort the walk
    return files


def pelican_dir_metadata(url: str) -> Dict[str, Any]:
    """Walk a Pelican directory and aggregate per-file metadata.
    Mirrors s3_dir_metadata in structure so fingerprint logic is source-agnostic.
    """
    t0 = time.perf_counter()
    try:
        files = pelican_list_directory(url)
        files.sort(key=lambda f: f["rel_path"])  # deterministic order
        return {
            "ok": True,
            "object_type": "directory",
            "file_count": len(files),
            "total_size": sum(f["size"] or 0 for f in files),
            "files": files,
            "fetch_ms": (time.perf_counter() - t0) * 1000,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "fetch_ms": (time.perf_counter() - t0) * 1000}


# ──────────────────────────────────────────────────────────────────────────────
# Fingerprint
# ──────────────────────────────────────────────────────────────────────────────

def _create_artifact_spec(item: Dict[str, Any]) -> Dict[str, Any]:
    """Extract normalized spec fields that identify data content.
    Target path deliberately excluded: same data at different locations = same cache entry.
    Mirrors data_handler._create_artifact_spec; no backpack path resolution needed here.
    """
    spec: Dict[str, Any] = {}
    stype = item.get("source_type", "")
    spec["source_type"] = stype

    if stype == "multi":
        # All sources included so any change to the fallback list invalidates the key
        spec["sources"] = sorted(
            [{"source_type": s.get("source_type", ""), "source": s.get("source", "")}
             for s in item.get("sources", [])],
            key=lambda s: (s["source_type"], s["source"]),
        )
    else:
        spec["source"] = item.get("source", "")

    if item.get("name"):
        spec["name"] = item["name"]
    if item.get("expected_size") is not None:
        spec["expected_size"] = item["expected_size"]
    # Declared checksum: a spec-level integrity change should also bust the cache
    checksum = item.get("checksum") or (item.get("verification") or {}).get("checksum")
    if checksum:
        spec["checksum"] = str(checksum).strip().lower()

    return dict(sorted(spec.items()))  # sorted for canonical serialization


def _normalize_source_meta(meta: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only stable, non-None fields from source metadata for hash input.
    Strips fetch_ms and any None values so missing optional fields (e.g. etag on
    Pelican servers that don't expose it) don't produce a different hash each run.
    """
    if meta.get("object_type") == "directory":
        # Per-file entries: drop None values so absent etag/last_modified are stable
        files = [
            {k: v for k, v in f.items() if v is not None}
            for f in meta.get("files", [])
        ]
        return {
            "object_type": "directory",
            "file_count": meta.get("file_count"),
            "total_size": meta.get("total_size"),
            "files": sorted(files, key=lambda f: f.get("rel_path", "")),
        }
    # File: include only the fields that reliably signal a content change
    return {k: v for k, v in {
        "object_type": "file",
        "etag":          meta.get("etag"),
        "size":          meta.get("size"),
        "last_modified": meta.get("last_modified"),
    }.items() if v is not None}


def _compute_cache_key(artifact_spec: Dict[str, Any], source_meta: Dict[str, Any]) -> str:
    """SHA-256 of canonical JSON( spec_fields + normalized_source_metadata ).
    The inclusion of source_meta is the key difference from data_handler._compute_cache_key:
    the fingerprint changes when remote data changes even if the spec is unchanged.
    """
    combined = {
        "spec":        artifact_spec,
        "source_meta": _normalize_source_meta(source_meta),
    }
    canonical = json.dumps(combined, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _fetch_source_metadata(item: Dict[str, Any], anonymous: bool) -> Dict[str, Any]:
    """Dispatch to the right metadata fetch based on source_type.
    For multi-source, tries each S3/Pelican source in spec order; returns first success.
    fetch_ms covers all API calls made (HEAD + optional list for directory detection).
    """
    stype = item.get("source_type")
    source = item.get("source", "")

    if stype == "s3":
        # Try HEAD first; if it looks like a directory prefix, do a full listing
        if source.endswith("/") or _is_s3_directory(source, anonymous):
            return s3_dir_metadata(source, anonymous)
        return s3_file_metadata(source, anonymous)

    elif stype == "pelican":
        try:
            fs, path = _pelican_fs_and_path(source)
            info = fs.info(path)
            if info.get("type") == "directory" or source.endswith("/"):
                return pelican_dir_metadata(source)
            return pelican_file_metadata(source)
        except Exception as e:
            return {"ok": False, "error": str(e), "fetch_ms": 0.0}

    elif stype == "multi":
        for s in item.get("sources", []):
            if s.get("source_type") not in ("s3", "pelican"):
                continue
            meta = _fetch_source_metadata(
                {"source_type": s["source_type"], "source": s.get("source", "")}, anonymous
            )
            if meta.get("ok"):
                meta["used_source"] = s.get("source")
                return meta
        return {"ok": False, "error": "No reachable S3/Pelican source in multi", "fetch_ms": 0.0}

    return {"ok": False, "error": f"source_type '{stype}' not supported", "fetch_ms": 0.0}


# ──────────────────────────────────────────────────────────────────────────────
# Cache infrastructure  (mirrors data_handler cache functions)
# ──────────────────────────────────────────────────────────────────────────────

def _get_cache_dir(cache_base: Path, cache_key: str) -> Path:
    """Cache entry lives at <cache_base>/<cache_key>/."""
    return cache_base / cache_key


def _acquire_cache_lock(cache_dir: Path, timeout: int = 300) -> bool:
    """Atomically create .build.lock; spin-wait up to timeout seconds.
    Mirrors data_handler._acquire_cache_lock.
    """
    lock = cache_dir / ".build.lock"
    cache_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    while True:
        try:
            lock.touch(exist_ok=False)
            lock.write_text(str(os.getpid()))
            return True
        except FileExistsError:
            if time.time() - t0 > timeout:
                return False
            time.sleep(1)


def _release_cache_lock(cache_dir: Path) -> None:
    (cache_dir / ".build.lock").unlink(missing_ok=True)


def _write_cache_metadata(
    cache_dir: Path,
    cache_key: str,
    artifact_spec: Dict[str, Any],
    source_meta: Dict[str, Any],
) -> None:
    """Write .meta.json to the cache entry. Mirrors data_handler._write_cache_metadata."""
    meta = {
        "cache_key":     cache_key,
        "artifact_spec": artifact_spec,
        # Normalized source_meta stored for diagnostics; not re-read for validation
        "source_meta":   _normalize_source_meta(source_meta),
        "created_at":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with (cache_dir / ".meta.json").open("w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, sort_keys=True)


def _read_cache_metadata(cache_dir: Path) -> Optional[Dict[str, Any]]:
    """Read .meta.json; return None on missing or corrupt file.
    Mirrors data_handler._read_cache_metadata.
    """
    meta_file = cache_dir / ".meta.json"
    if not meta_file.exists():
        return None
    try:
        with meta_file.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _lookup_cache_entry(
    cache_dir: Path, cache_key: str, verbose: bool = False
) -> bool:
    """True if a valid, unlocked cache entry exists for this key.
    Validation: dir exists, no lock, .meta.json readable, key matches, cached_data/ present.
    Mirrors data_handler._lookup_cache_entry; no fingerprint re-validation needed
    because the key itself already encodes source metadata.
    """
    if not cache_dir.exists():
        if verbose:
            print(f"[cache] miss — dir absent")
        return False
    if (cache_dir / ".build.lock").exists():
        if verbose:
            print(f"[cache] miss — build in progress")
        return False
    meta = _read_cache_metadata(cache_dir)
    if not meta:
        if verbose:
            print(f"[cache] miss — missing/corrupt .meta.json")
        return False
    if meta.get("cache_key") != cache_key:
        # Shouldn't happen with SHA-256 keys but guard against corruption
        if verbose:
            print(f"[cache] miss — key mismatch")
        return False
    if not (cache_dir / "cached_data").exists():
        if verbose:
            print(f"[cache] miss — cached_data/ absent")
        return False
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Download helpers
# ──────────────────────────────────────────────────────────────────────────────

def _s3_file_download(uri: str, dest: Path, anonymous: bool, verbose: bool) -> None:
    bucket, key = _parse_s3_uri(uri)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    if verbose:
        print(f"[s3] {uri} -> {dest}")
    resp = _s3_client(anonymous).get_object(Bucket=bucket, Key=key)
    with open(tmp, "wb") as f:
        f.write(resp["Body"].read())
    tmp.replace(dest)  # atomic rename


def _s3_dir_download(uri: str, dest: Path, anonymous: bool, verbose: bool) -> None:
    bucket, prefix = _parse_s3_uri(uri)
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    dest.mkdir(parents=True, exist_ok=True)
    client = _s3_client(anonymous)
    for obj in s3_list_objects(uri, anonymous):
        local = dest / obj["rel_path"]
        local.parent.mkdir(parents=True, exist_ok=True)
        resp = client.get_object(Bucket=bucket, Key=prefix + obj["rel_path"])
        with open(local, "wb") as f:
            f.write(resp["Body"].read())
        if verbose:
            print(f"[s3] -> {obj['rel_path']}")


def _download_to_cache(
    item: Dict[str, Any], cache_file: Path, anonymous: bool, verbose: bool
) -> bool:
    """Route download to the right backend. Mirrors data_handler._download_to_cache."""
    stype = item.get("source_type")
    source = item.get("source", "")
    try:
        if stype == "s3":
            if source.endswith("/") or _is_s3_directory(source, anonymous):
                _s3_dir_download(source, cache_file, anonymous, verbose)
            else:
                _s3_file_download(source, cache_file, anonymous, verbose)
            return cache_file.exists()

        elif stype == "pelican":
            fs, path = _pelican_fs_and_path(source)
            info = fs.info(path)
            if info.get("type") == "directory" or source.endswith("/"):
                cache_file.mkdir(parents=True, exist_ok=True)
                if not path.endswith("/"):
                    path += "/"
                for dirpath, _, filenames in fs.walk(path):
                    for fname in sorted(filenames):
                        fpath = f"{dirpath.rstrip('/')}/{fname}"
                        rel = fpath[len(path):] if fpath.startswith(path) else fname
                        dest = cache_file / rel
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        with fs.open(fpath, "rb") as src, open(dest, "wb") as out:
                            out.write(src.read())
            else:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                with fs.open(path, "rb") as src, open(cache_file, "wb") as out:
                    out.write(src.read())
            return cache_file.exists()

        elif stype == "multi":
            # First available S3/Pelican source wins
            for s in item.get("sources", []):
                if s.get("source_type") not in ("s3", "pelican"):
                    continue
                if _download_to_cache(
                    {"source_type": s["source_type"], "source": s.get("source", "")},
                    cache_file, anonymous, verbose,
                ):
                    return True
            return False

    except Exception as e:
        if verbose:
            print(f"[cache] download error: {e}")
        return False
    return False


def _build_cache_entry(
    item: Dict[str, Any],
    cache_dir: Path,
    cache_key: str,
    artifact_spec: Dict[str, Any],
    source_meta: Dict[str, Any],
    anonymous: bool,
    verbose: bool,
) -> Tuple[bool, float]:
    """Download data into cache_dir/cached_data/ and write .meta.json.
    Returns (success, download_ms). Mirrors data_handler._build_cache_entry.
    """
    if not _acquire_cache_lock(cache_dir):
        return False, 0.0
    t0 = time.perf_counter()
    try:
        target_location = item.get("target_location") or item.get("target_path", "data")
        cache_file = cache_dir / "cached_data" / target_location
        cache_file.parent.mkdir(parents=True, exist_ok=True)

        if not _download_to_cache(item, cache_file, anonymous, verbose):
            return False, (time.perf_counter() - t0) * 1000

        download_ms = (time.perf_counter() - t0) * 1000
        _write_cache_metadata(cache_dir, cache_key, artifact_spec, source_meta)
        if verbose:
            print(f"[cache] entry built in {download_ms:.0f} ms: {cache_dir.name[:16]}...")
        return True, download_ms

    except Exception as e:
        if verbose:
            print(f"[cache] build error: {e}")
        return False, (time.perf_counter() - t0) * 1000
    finally:
        _release_cache_lock(cache_dir)


# ──────────────────────────────────────────────────────────────────────────────
# Benchmark runner
# ──────────────────────────────────────────────────────────────────────────────

def _metadata_only_report(
    spec_path: Path,
    profile_name: Optional[str] = None,
    anonymous: bool = True,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Fetch and return remote metadata for all items. Debug mode — no fingerprint/cache."""
    pname, profile = load_and_validate_spec(spec_path, profile_name)
    items = [_normalize_data_item(i) for i in (profile.get("data") or [])]

    if verbose:
        print(f"[metadata-only] spec={spec_path}  profile={pname}  items={len(items)}")

    results = []
    for item in items:
        name = item.get("name", "<unnamed>")
        stype = item.get("source_type", "")
        source = item.get("source", "")

        # Skip non-S3/Pelican
        effective_types = {stype}
        if stype == "multi":
            effective_types = {s.get("source_type") for s in item.get("sources", [])}
        if not effective_types.intersection({"s3", "pelican"}):
            results.append({
                "name": name,
                "source_type": stype,
                "source": source or "[multi]",
                "metadata": None,
                "error": f"Skipped: no S3/Pelican source (types: {effective_types})",
                "fetch_ms": None,
            })
            continue

        if verbose:
            print(f"[metadata-only] '{name}' — fetching...")

        meta = _fetch_source_metadata(item, anonymous)
        fetch_ms = meta.pop("fetch_ms", None)

        if not meta.get("ok"):
            results.append({
                "name": name,
                "source_type": stype,
                "source": source or "[multi]",
                "metadata": None,
                "error": meta.get("error"),
                "fetch_ms": fetch_ms,
            })
        else:
            meta.pop("ok", None)  # remove 'ok' flag from output
            results.append({
                "name": name,
                "source_type": stype,
                "source": source or "[multi]",
                "metadata": meta,
                "error": None,
                "fetch_ms": round(fetch_ms or 0, 2),
            })

    return {
        "spec":    str(spec_path),
        "profile": pname,
        "mode":    "metadata-only",
        "items":   results,
    }

def _bench_item(
    item: Dict[str, Any],
    cache_base: Path,
    download_on_miss: bool,
    anonymous: bool,
    verbose: bool,
) -> Dict[str, Any]:
    """Full cycle for one item: metadata fetch → fingerprint → cache lookup → optional download."""
    name = item.get("name", "<unnamed>")
    stype = item.get("source_type", "")

    result: Dict[str, Any] = {
        "name": name,
        "source_type": stype,
        "source": item.get("source") or "[multi]",
        "fingerprint": None,
        "cache_hit": None,
        "timings": {
            "metadata_fetch_ms":    None,
            "fingerprint_compute_ms": None,
            "total_lookup_ms":      None,  # metadata + fingerprint — cost of a cache hit
            "download_ms":          None,  # populated only when download actually runs
        },
        "source_meta_summary": None,
        "error": None,
    }

    # Skip anything that isn't (or doesn't contain) an S3/Pelican source
    effective_types = {stype}
    if stype == "multi":
        effective_types = {s.get("source_type") for s in item.get("sources", [])}
    if not effective_types.intersection({"s3", "pelican"}):
        result["error"] = f"Skipped: no S3/Pelican source (types: {effective_types})"
        return result

    # 1. Remote metadata fetch — the main I/O cost; must happen before fingerprint
    if verbose:
        print(f"[bench] '{name}' — fetching source metadata...")
    source_meta = _fetch_source_metadata(item, anonymous)
    result["timings"]["metadata_fetch_ms"] = round(source_meta.get("fetch_ms", 0.0), 2)

    if not source_meta.get("ok"):
        result["error"] = f"Metadata fetch failed: {source_meta.get('error')}"
        return result

    # Compact summary for output — omit the per-file list to keep JSON readable
    result["source_meta_summary"] = {
        k: source_meta[k]
        for k in ("object_type", "size", "file_count", "total_size")
        if k in source_meta
    }
    if source_meta.get("used_source"):
        result["source_meta_summary"]["used_source"] = source_meta["used_source"]

    # 2. Fingerprint — cheap CPU work once metadata is in hand
    t_fp = time.perf_counter()
    artifact_spec = _create_artifact_spec(item)
    cache_key = _compute_cache_key(artifact_spec, source_meta)
    fp_ms = (time.perf_counter() - t_fp) * 1000

    result["fingerprint"] = cache_key
    result["timings"]["fingerprint_compute_ms"] = round(fp_ms, 2)
    result["timings"]["total_lookup_ms"] = round(
        result["timings"]["metadata_fetch_ms"] + fp_ms, 2
    )

    # 3. Cache lookup — local FS only, zero network
    cache_dir = _get_cache_dir(cache_base, cache_key)
    hit = _lookup_cache_entry(cache_dir, cache_key, verbose)
    result["cache_hit"] = hit

    if verbose:
        status = "HIT " if hit else "MISS"
        print(
            f"[bench] '{name}' — {status} "
            f"(meta={result['timings']['metadata_fetch_ms']:.1f} ms  "
            f"fp={fp_ms:.2f} ms  "
            f"total={result['timings']['total_lookup_ms']:.1f} ms)"
        )

    # 4. Download on miss — only when explicitly requested
    if not hit and download_on_miss:
        if verbose:
            print(f"[bench] '{name}' — downloading...")
        ok, dl_ms = _build_cache_entry(
            item, cache_dir, cache_key, artifact_spec, source_meta, anonymous, verbose
        )
        result["timings"]["download_ms"] = round(dl_ms, 2)
        if not ok:
            result["error"] = "Cache build failed"

    return result


def run_benchmark(
    spec_path: Path,
    cache_base: Path,
    profile_name: Optional[str] = None,
    download_on_miss: bool = False,
    anonymous: bool = True,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Run the full benchmark for all items in the selected spec profile."""
    pname, profile = load_and_validate_spec(spec_path, profile_name)
    items = [_normalize_data_item(i) for i in (profile.get("data") or [])]

    cache_base.mkdir(parents=True, exist_ok=True)
    if verbose:
        print(f"[bench] spec={spec_path}  profile={pname}  items={len(items)}")

    results = [
        _bench_item(item, cache_base, download_on_miss, anonymous, verbose)
        for item in items
    ]

    valid = [r for r in results if r["error"] is None]
    return {
        "spec":      str(spec_path),
        "profile":   pname,
        "cache_dir": str(cache_base),
        "items":     results,
        "summary": {
            "total":               len(results),
            "skipped_or_errored":  len(results) - len(valid),
            "cache_hits":          sum(1 for r in valid if r["cache_hit"]),
            "cache_misses":        sum(1 for r in valid if not r["cache_hit"]),
            "downloaded":          sum(1 for r in valid if r["timings"]["download_ms"] is not None),
            "total_metadata_fetch_ms": round(
                sum(r["timings"]["metadata_fetch_ms"] or 0 for r in valid), 2
            ),
            "total_fingerprint_ms": round(
                sum(r["timings"]["fingerprint_compute_ms"] or 0 for r in valid), 2
            ),
            "total_download_ms": round(
                sum(r["timings"]["download_ms"] or 0 for r in valid
                    if r["timings"]["download_ms"]), 2
            ),
        },
    }


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(
        description="Lightweight cache fingerprint + lookup benchmark for S3 and Pelican."
    )
    p.add_argument("spec", help="Path to data spec YAML")
    p.add_argument("--cache-dir", default="./floability-data-cache",
                   help="Cache root directory (default: ./floability-data-cache)")
    p.add_argument("--download-on-miss", action="store_true",
                   help="Download and build a cache entry on miss")
    p.add_argument("--metadata-only", action="store_true",
                   help="Fetch and print remote metadata only (debug); skip fingerprint + cache lookup")
    p.add_argument("--profile", default=None,
                   help="Profile name (default: spec's default_profile)")
    p.add_argument("--output", default=None,
                   help="Write JSON report to file (default: stdout)")
    p.add_argument("--no-anonymous", action="store_true",
                   help="Use AWS credential chain instead of anonymous S3 access")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    spec_path = Path(args.spec)
    if not spec_path.is_file():
        print(f"error: spec not found: {spec_path}", file=sys.stderr)
        sys.exit(1)

    try:
        # Metadata-only mode: fetch and print, skip fingerprint/cache
        if args.metadata_only:
            report = _metadata_only_report(
                spec_path=spec_path,
                profile_name=args.profile,
                anonymous=not args.no_anonymous,
                verbose=args.verbose,
            )
        else:
            report = run_benchmark(
                spec_path=spec_path,
                cache_base=Path(args.cache_dir),
                profile_name=args.profile,
                download_on_miss=args.download_on_miss,
                anonymous=not args.no_anonymous,
                verbose=args.verbose,
            )
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        if args.verbose:
            print(f"[bench] report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()

