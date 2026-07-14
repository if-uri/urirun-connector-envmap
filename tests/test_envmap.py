from __future__ import annotations
from urirun_connector_envmap import core

def test_bindings():
    b=core.urirun_bindings()["bindings"]
    for r in ("envmap://host/target/query/fingerprint","envmap://host/target/query/diff","envmap://host/snapshot/command/take"):
        assert r in b

def test_fingerprint_bounded_and_diff(tmp_path):
    (tmp_path/"a.txt").write_text("hello")
    (tmp_path/"b.txt").write_text("world")
    m1=core.fingerprint(str(tmp_path))
    assert m1["count"]==2 and len(m1["root"])==40
    # zmiana jednego pliku → diff wykrywa changed, root się różni
    (tmp_path/"a.txt").write_text("HELLO CHANGED")
    m2=core.fingerprint(str(tmp_path))
    d=core.diff(m1,m2)
    assert d["changed"]==["a.txt"] and d["identical"] is False and d["delta_count"]==1

def test_identical_maps(tmp_path):
    (tmp_path/"x").write_text("same")
    a=core.fingerprint(str(tmp_path)); b=core.fingerprint(str(tmp_path))
    assert core.diff(a,b)["identical"] is True

def test_large_file_sampled_not_full_read(tmp_path):
    big=tmp_path/"big.bin"; big.write_bytes(b"\x00"*(300*1024))  # 300KB
    fp=core._file_fp(big)  # nie czyta całości — head+tail
    assert fp.startswith(str(300*1024)+":")

def test_snapshot_returns_reference_not_copy(tmp_path):
    (tmp_path/"f").write_text("data")
    r=core.snapshot(str(tmp_path),label="test")
    assert r["ok"] and r["kind"] in ("git","fingerprint") and "inverse" in r
