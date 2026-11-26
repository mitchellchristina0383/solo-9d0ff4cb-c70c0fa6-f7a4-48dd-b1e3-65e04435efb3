"""核心功能自测：符号化、整批退回、幂等重传、快照交错、重启持久化。"""
from __future__ import annotations

import io
import os
import threading
import time
from pathlib import Path

import httpx
import pytest
from elftools.elf.elffile import ELFFile

from app.elftools_ext import inspect_blob
from app.storage import BatchRejected, Store

FIX = Path(__file__).resolve().parent / "fixtures" / "built"
BUILD_ID_A = "a" * 40
BUILD_ID_B = "b" * 40
BUILD_ID_C = "c" * 40


def read_fixture(name: str) -> bytes:
    return (FIX / name).read_bytes()


def func_address(elf_path: Path, func: str) -> int:
    """从符号表取函数起始地址（固件均为 no-pie 可执行文件）。"""
    with open(elf_path, "rb") as fh:
        elf = ELFFile(fh)
        for section in elf.iter_sections():
            if section["sh_type"] != "SHT_SYMTAB":
                continue
            for sym in section.iter_symbols():
                if sym.name == func and sym["st_info"]["type"] == "STT_FUNC":
                    return sym["st_value"]
    raise AssertionError(f"符号 {func} 未在 {elf_path} 中找到")


# ---------------------------------------------------------------------------
# 1. ELF 校验
# ---------------------------------------------------------------------------
def test_inspect_valid_elf_reads_build_id():
    bid, has_dwarf = inspect_blob(read_fixture("demo-aaaa.elf"))
    assert bid == BUILD_ID_A
    assert has_dwarf is True


@pytest.mark.parametrize(
    "name, fragment",
    [
        ("no-buildid.elf", "Build ID"),
        ("stripped-cccc.elf", "调试信息"),
        ("not-elf.bin", "合法 ELF"),
    ],
)
def test_inspect_rejects_bad_files(name, fragment):
    from app.elftools_ext import ELFValidationError

    with pytest.raises(ELFValidationError) as exc:
        inspect_blob(read_fixture(name))
    assert fragment in str(exc.value)


# ---------------------------------------------------------------------------
# 2. 批量发布：整批退回 / 幂等
# ---------------------------------------------------------------------------
def test_batch_rejected_entirely_when_one_file_bad(store, data_dir):
    good = read_fixture("demo-aaaa.elf")
    bad = read_fixture("no-buildid.elf")
    with pytest.raises(BatchRejected) as exc:
        store.publish_batch([("good.elf", good), ("bad.elf", bad)])
    assert any("bad.elf" in e for e in exc.value.errors)
    # 整批退回：无数据库记录、无落盘文件
    assert store.list_build_ids() == []
    assert os.listdir(os.path.join(data_dir, "elfs")) == []
    assert store.symbol_version == 0


def test_batch_rejected_on_same_buildid_different_content_within_batch(store):
    with pytest.raises(BatchRejected) as exc:
        store.publish_batch(
            [
                ("demo.elf", read_fixture("demo-aaaa.elf")),
                ("conflict.elf", read_fixture("demo-aaaa-CONFLICT.elf")),
            ]
        )
    assert any("内容不同" in e for e in exc.value.errors)
    assert store.list_build_ids() == []


def test_batch_rejected_on_conflict_with_already_published(store):
    store.publish_batch([("demo.elf", read_fixture("demo-aaaa.elf"))])
    assert store.symbol_version == 1
    with pytest.raises(BatchRejected):
        store.publish_batch([("conflict.elf", read_fixture("demo-aaaa-CONFLICT.elf"))])
    # 已发布内容不受影响，版本不前进
    assert store.symbol_version == 1
    assert [b["build_id"] for b in store.list_build_ids()] == [BUILD_ID_A]


def test_identical_reupload_is_success_and_idempotent(store):
    blob = read_fixture("demo-aaaa.elf")
    first = store.publish_batch([("demo.elf", blob)])
    assert first["new_build_ids"] == [BUILD_ID_A]
    second = store.publish_batch([("demo-copy.elf", blob)])
    assert second["redundant"] == 1
    assert second["new_build_ids"] == []
    # 版本不因重复上传前进
    assert second["symbol_version"] == 1


def test_second_meaningful_batch_advances_version(store):
    store.publish_batch([("demo.elf", read_fixture("demo-aaaa.elf"))])
    result = store.publish_batch([("other.elf", read_fixture("other-bbbb.elf"))])
    assert result["symbol_version"] == 2
    assert result["new_build_ids"] == [BUILD_ID_B]


def test_identical_files_within_one_batch_are_deduped_not_rejected(store):
    blob = read_fixture("demo-aaaa.elf")
    result = store.publish_batch([("a.elf", blob), ("b.elf", blob), ("c.elf", blob)])
    assert result["accepted"] == 3
    assert result["new_build_ids"] == [BUILD_ID_A]
    assert result["redundant"] == 2  # 同批内两个完全相同的重复文件
    assert store.symbol_version == 1


def test_empty_batch_is_rejected(store):
    with pytest.raises(BatchRejected):
        store.publish_batch([])


# ---------------------------------------------------------------------------
# 3. 符号化：未解析保留原地址，补传后再查
# ---------------------------------------------------------------------------
def test_unresolved_frame_keeps_address_then_resolved_after_upload(store):
    addr = func_address(FIX / "demo-aaaa.elf", "crash_here")
    report_id = store.create_report(
        [{"build_id": BUILD_ID_A, "address": hex(addr)}]
    )

    before = store.resolve_report(report_id)
    assert before["resolved_count"] == 0
    frame = before["frames"][0]
    assert frame["status"] == "unresolved"
    assert frame["address"] == hex(addr)  # 原地址保留
    assert frame["reason"] == "build_id_not_published_at_snapshot"
    assert frame["function"] is None

    store.publish_batch([("demo.elf", read_fixture("demo-aaaa.elf"))])
    after = store.resolve_report(report_id)  # 同一报告号再查
    assert after["resolved_count"] == 1
    f = after["frames"][0]
    assert f["function"] == "crash_here"
    assert f["source_file"].endswith("demo.c")
    assert f["source_line"] is not None
    assert f["status"] == "resolved"


def test_symbolize_function_and_line_including_inner_call(store):
    store.publish_batch([("demo.elf", read_fixture("demo-aaaa.elf"))])
    helper = func_address(FIX / "demo-aaaa.elf", "helper_add")
    crash = func_address(FIX / "demo-aaaa.elf", "crash_here")
    report_id = store.create_report(
        [
            {"build_id": BUILD_ID_A, "address": hex(helper)},
            {"build_id": BUILD_ID_A, "address": hex(crash)},
            {"build_id": None, "address": "0xdeadbeef"},  # 缺 Build ID 的帧
        ]
    )
    result = store.resolve_report(report_id)
    assert result["frames"][0]["function"] == "helper_add"
    assert result["frames"][0]["source_line"] == 3  # helper_add 中 int s = a + b;
    assert result["frames"][1]["function"] == "crash_here"
    assert result["frames"][2]["status"] == "unresolved"
    assert result["frames"][2]["reason"] == "frame_missing_build_id"
    assert result["frames"][2]["address"] == "0xdeadbeef"


def test_unknown_address_stays_unresolved(store):
    store.publish_batch([("demo.elf", read_fixture("demo-aaaa.elf"))])
    report_id = store.create_report([{"build_id": BUILD_ID_A, "address": "0x10"}])
    result = store.resolve_report(report_id)
    assert result["frames"][0]["status"] == "unresolved"
    assert result["frames"][0]["reason"] == "address_not_found_in_elf"


def test_decimal_address_and_uppercase_build_id(store):
    """地址支持十进制字符串；Build ID 大小写不敏感（统一小写匹配）。"""
    store.publish_batch([("demo.elf", read_fixture("demo-aaaa.elf"))])
    addr = func_address(FIX / "demo-aaaa.elf", "crash_here")
    report_id = store.create_report(
        [{"build_id": BUILD_ID_A.upper(), "address": str(addr)}]
    )
    frame = store.resolve_report(report_id)["frames"][0]
    assert frame["status"] == "resolved"
    assert frame["function"] == "crash_here"


def test_dwarf4_and_dwarf5_source_paths(store):
    """DWARF v4/v5 行表目录索引规则不同，两者都应还原出完整源码路径。"""
    for elf_name, bid in (
        ("demo-aaaa.elf", BUILD_ID_A),
        ("demo-dwarf4-aaaa.elf", "add4aaaa" * 5),
    ):
        store.publish_batch([(elf_name, read_fixture(elf_name))])
        addr = func_address(FIX / elf_name, "helper_add")
        rid = store.create_report([{"build_id": bid, "address": hex(addr)}])
        frame = store.resolve_report(rid)["frames"][0]
        assert frame["function"] == "helper_add"
        assert frame["source_file"].endswith("demo.c")
        assert "/" in frame["source_file"]  # 含目录前缀而非裸文件名


# ---------------------------------------------------------------------------
# 4. 快照语义：查栈与发布交错
# ---------------------------------------------------------------------------
def test_snapshot_isolation_during_interleaved_publish(store, monkeypatch):
    addr = func_address(FIX / "demo-aaaa.elf", "crash_here")
    report_id = store.create_report([{"build_id": BUILD_ID_A, "address": hex(addr)}])

    versions_seen: list[int] = []
    orig_snapshot = store.snapshot_paths
    barrier = threading.Event()

    def spy_snapshot(version):
        # 模拟解析进行中：另一个线程发布新批次
        versions_seen.append(version)
        if not barrier.is_set():
            barrier.set()
            time.sleep(0.2)
        return orig_snapshot(version)

    monkeypatch.setattr(store, "snapshot_paths", spy_snapshot)

    def publish_later():
        barrier.wait(timeout=5)
        store.publish_batch([("demo.elf", read_fixture("demo-aaaa.elf"))])

    t = threading.Thread(target=publish_later)
    t.start()
    # 解析开始时版本为 0，即便期间发布了版本 1，本次结果仍按快照 0
    result = store.resolve_report(report_id)
    t.join()
    assert result["snapshot_symbol_version"] == 0
    assert result["frames"][0]["status"] == "unresolved"
    # 再查一次即可看到新版本
    again = store.resolve_report(report_id)
    assert again["snapshot_symbol_version"] == 1
    assert again["frames"][0]["function"] == "crash_here"


def test_concurrent_publish_and_query_through_http(data_dir):
    """HTTP 层交错：真实 uvicorn 服务上，查询进行中发布批次，查询保持旧快照。"""
    import socket
    import uvicorn
    from app.main import app

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(50):  # 等服务就绪
            try:
                httpx.get(f"{base}/health", timeout=1)
                break
            except httpx.HTTPError:
                time.sleep(0.1)

        addr = func_address(FIX / "demo-aaaa.elf", "crash_here")
        report_id = httpx.post(
            f"{base}/reports",
            json={"frames": [{"build_id": BUILD_ID_A, "address": hex(addr)}]},
            timeout=10,
        ).json()["report_id"]

        from app.main import get_store

        store = get_store()
        orig = store.snapshot_paths
        entered = threading.Event()

        def slow_snapshot(version):
            entered.set()
            time.sleep(0.5)
            return orig(version)

        store.snapshot_paths = slow_snapshot
        query_holder: dict = {}

        def do_query():
            query_holder["r"] = httpx.get(f"{base}/reports/{report_id}", timeout=15)

        tq = threading.Thread(target=do_query)
        tq.start()
        assert entered.wait(5)
        with open(FIX / "demo-aaaa.elf", "rb") as fh:
            up = httpx.post(
                f"{base}/symbols/batch",
                files=[("files", ("demo.elf", fh.read(), "application/octet-stream"))],
                timeout=15,
            )
        assert up.status_code == 200
        tq.join()
        store.snapshot_paths = orig

        body = query_holder["r"].json()
        assert body["snapshot_symbol_version"] == 0
        assert body["frames"][0]["status"] == "unresolved"
        final = httpx.get(f"{base}/reports/{report_id}", timeout=10).json()
        assert final["snapshot_symbol_version"] == 1
        assert final["frames"][0]["function"] == "crash_here"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


# ---------------------------------------------------------------------------
# 5. 重启持久化
# ---------------------------------------------------------------------------
def test_state_survives_restart(data_dir):
    addr = func_address(FIX / "demo-aaaa.elf", "crash_here")
    s1 = Store(data_dir=data_dir)
    report_id = s1.create_report([{"build_id": BUILD_ID_A, "address": hex(addr)}])
    s1.publish_batch([("demo.elf", read_fixture("demo-aaaa.elf"))])
    s1.close()

    # 模拟进程重启：全新 Store 打开同一数据目录
    s2 = Store(data_dir=data_dir)
    try:
        assert s2.symbol_version == 1
        result = s2.resolve_report(report_id)
        assert result["frames"][0]["function"] == "crash_here"
        assert result["frames"][0]["source_file"].endswith("demo.c")
        # 重启后重复上传同一文件仍为幂等成功
        again = s2.publish_batch([("demo.elf", read_fixture("demo-aaaa.elf"))])
        assert again["redundant"] == 1
    finally:
        s2.close()


def test_restart_drops_elf_row_when_content_file_missing(data_dir):
    s1 = Store(data_dir=data_dir)
    s1.publish_batch([("demo.elf", read_fixture("demo-aaaa.elf"))])
    # 人为删掉内容文件，模拟磁盘损坏
    for name in os.listdir(os.path.join(data_dir, "elfs")):
        os.remove(os.path.join(data_dir, "elfs", name))
    s1.close()

    s2 = Store(data_dir=data_dir)
    try:
        assert s2.list_build_ids() == []  # 悬挂映射在启动核对时清除
    finally:
        s2.close()


# ---------------------------------------------------------------------------
# 6. HTTP 接口细节
# ---------------------------------------------------------------------------
def test_http_batch_validation_errors_and_health(client):
    c, _store = client
    h = c.get("/health")
    assert h.status_code == 200
    assert h.json()["symbol_version"] == 0

    bad = read_fixture("no-buildid.elf")
    r = c.post(
        "/symbols/batch",
        files=[("files", ("bad.elf", bad, "application/octet-stream"))],
    )
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["message"] == "整批退回"
    assert any("bad.elf" in e for e in detail["errors"])

    r404 = c.get("/reports/99999")
    assert r404.status_code == 404


def test_http_full_flow_two_batches(client):
    c, _store = client
    helper = func_address(FIX / "demo-aaaa.elf", "helper_add")
    other_addr = func_address(FIX / "other-bbbb.elf", "other_func")
    r = c.post(
        "/reports",
        json={
            "frames": [
                {"build_id": BUILD_ID_A, "address": hex(helper)},
                {"build_id": BUILD_ID_B, "address": hex(other_addr)},
            ]
        },
    )
    assert r.status_code == 201
    report_id = r.json()["report_id"]
    assert r.json()["resolved_count"] == 0

    with open(FIX / "demo-aaaa.elf", "rb") as fh:
        b1 = c.post(
            "/symbols/batch",
            files=[("files", ("demo.elf", fh.read(), "application/octet-stream"))],
        )
    assert b1.json()["symbol_version"] == 1

    mid = c.get(f"/reports/{report_id}").json()
    assert mid["resolved_count"] == 1
    assert mid["frames"][0]["function"] == "helper_add"
    assert mid["frames"][1]["status"] == "unresolved"

    with open(FIX / "other-bbbb.elf", "rb") as fh:
        b2 = c.post(
            "/symbols/batch",
            files=[("files", ("other.elf", fh.read(), "application/octet-stream"))],
        )
    assert b2.json()["symbol_version"] == 2

    final = c.get(f"/reports/{report_id}").json()
    assert final["resolved_count"] == 2
    assert final["frames"][1]["function"] == "other_func"
    # 函数入口地址落在 DWARF 行表的函数声明行（第 1 行），与 addr2line 行为一致
    assert final["frames"][1]["source_line"] == 1


# ---------------------------------------------------------------------------
# 7. 只登记上报：立即回执、失败不留半份、重启后按号查栈
# ---------------------------------------------------------------------------
def test_register_only_ack_has_no_resolution_and_frames_are_queryable(client):
    c, _store = client
    addr = func_address(FIX / "demo-aaaa.elf", "crash_here")
    r = c.post(
        "/reports?register_only=true",
        json={
            "frames": [
                {"build_id": BUILD_ID_A, "address": hex(addr)},
                {"build_id": None, "address": "0xdeadbeef"},
            ]
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert set(body) == {"report_id", "created_at", "frame_count"}
    assert body["frame_count"] == 2  # 全部原始帧都已入库

    # 值班员凭原入口按号查栈；未发布符号时帧原样保留
    q = c.get(f"/reports/{body['report_id']}")
    assert q.status_code == 200
    frames = q.json()["frames"]
    assert [f["address"] for f in frames] == [hex(addr), "0xdeadbeef"]
    assert frames[0]["reason"] == "build_id_not_published_at_snapshot"
    raw = c.get(f"/reports/{body['report_id']}/raw").json()
    assert [f["address"] for f in raw["frames"]] == [hex(addr), "0xdeadbeef"]


def test_register_only_completes_while_all_resolve_slots_busy_and_queue_waiting(client):
    """解析满额且已有查栈在排队时，只登记仍能立即回执，不占解析名额。"""
    c, store = client
    store.publish_batch([("demo.elf", read_fixture("demo-aaaa.elf"))])
    addr = func_address(FIX / "demo-aaaa.elf", "crash_here")
    rid = store.create_report([{"build_id": BUILD_ID_A, "address": hex(addr)}])
    store.limiter._limit = 1

    entered = threading.Event()
    release = threading.Event()
    orig_resolve = store._resolve_report_unbounded

    def blocked_resolve(report_id, snapshot_version=None):
        entered.set()
        assert release.wait(10)
        return orig_resolve(report_id, snapshot_version)

    store._resolve_report_unbounded = blocked_resolve
    try:
        results: dict = {}

        def do_query():
            results["r"] = c.get(f"/reports/{rid}", timeout=20)

        holder = threading.Thread(target=do_query, daemon=True)
        holder.start()
        assert entered.wait(5)  # 唯一名额已被一次查栈占住

        # 再发一次查栈，令其排在名额后面等待
        waiting_before = store.limiter.stats()["waiting"]
        queued = threading.Thread(target=do_query, daemon=True)
        queued.start()
        deadline = time.monotonic() + 5
        while store.limiter.stats()["waiting"] <= waiting_before and time.monotonic() < deadline:
            time.sleep(0.01)
        assert store.limiter.stats()["waiting"] >= 1  # 确认有查栈在排队

        started = time.monotonic()
        r = c.post(
            "/reports?register_only=true",
            json={"frames": [{"build_id": BUILD_ID_A, "address": hex(addr)}]},
            timeout=5,
        )
        elapsed = time.monotonic() - started
        assert r.status_code == 201
        assert set(r.json()) == {"report_id", "created_at", "frame_count"}
        assert elapsed < 2.0  # 无需等解析腾出名额

        release.set()
        holder.join(20)
        queued.join(20)
        assert results["r"].status_code == 200
        # 回执的报告号仍可正常按号查栈
        assert c.get(f"/reports/{r.json()['report_id']}").json()["frame_count"] == 1
    finally:
        store._resolve_report_unbounded = orig_resolve
        release.set()


def test_register_only_write_failure_rolls_back_without_half_report(client):
    """帧写入触发数据库错误时整体回滚：不留下报告头，也不消耗报告号。"""
    c, store = client
    first = c.post("/reports?register_only=true", json={"frames": [{"address": "0x1"}]})
    assert first.status_code == 201

    # 用真实触发器让 frames 写入失败，验证事务回滚而非测试桩
    with store._db_lock, store._conn:
        store._conn.execute(
            "CREATE TRIGGER reject_frames BEFORE INSERT ON frames"
            " BEGIN SELECT RAISE(ABORT, 'injected write failure'); END"
        )
    try:
        bad = c.post(
            "/reports?register_only=true",
            json={"frames": [{"address": "0x2"}, {"address": "0x3"}]},
        )
    finally:
        with store._db_lock, store._conn:
            store._conn.execute("DROP TRIGGER reject_frames")

    assert bad.status_code == 503
    assert "登记失败" in bad.json()["detail"]
    with store._db_lock:
        report_rows = store._conn.execute("SELECT COUNT(*) n FROM reports").fetchone()["n"]
        frame_rows = store._conn.execute("SELECT COUNT(*) n FROM frames").fetchone()["n"]
    assert report_rows == 1  # 没有留下缺帧的报告头
    assert frame_rows == 1
    assert c.get(f"/reports/{first.json()['report_id']}").json()["frame_count"] == 1


def test_register_only_report_survives_restart_and_resolves_after_upload(data_dir):
    """只登记的报告重启后仍可按号查栈，补传符号后能解析。"""
    from fastapi.testclient import TestClient

    from app import main as main_module
    from app.storage import Store as StoreCls

    addr = func_address(FIX / "demo-aaaa.elf", "crash_here")

    s1 = StoreCls(data_dir=data_dir)
    main_module._store = s1
    with TestClient(main_module.app) as c1:
        rid = c1.post(
            "/reports?register_only=true",
            json={"frames": [{"build_id": BUILD_ID_A, "address": hex(addr)}]},
        ).json()["report_id"]
    main_module._store = None

    # 模拟重启：全新 Store + 全新应用实例，凭原报告号查询
    s2 = StoreCls(data_dir=data_dir)
    main_module._store = s2
    try:
        with TestClient(main_module.app) as c2:
            before = c2.get(f"/reports/{rid}")
            assert before.status_code == 200
            assert before.json()["frames"][0]["address"] == hex(addr)
            assert before.json()["frames"][0]["status"] == "unresolved"

            up = c2.post(
                "/symbols/batch",
                files=[
                    ("files", ("demo.elf", read_fixture("demo-aaaa.elf"), "application/octet-stream"))
                ],
            )
            assert up.status_code == 200
            after = c2.get(f"/reports/{rid}").json()
            assert after["frames"][0]["function"] == "crash_here"
    finally:
        main_module._store = None


def test_resolve_limit_is_configurable_from_env(monkeypatch, tmp_path):
    from app.config import resolve_concurrency
    from app.storage import Store as StoreCls

    monkeypatch.setenv("SYMBOL_RESOLVE_LIMIT", "2")
    assert resolve_concurrency() == 2
    s = StoreCls(data_dir=str(tmp_path / "d"))
    try:
        assert s.limiter.limit == 2
    finally:
        s.close()

    monkeypatch.setenv("SYMBOL_RESOLVE_LIMIT", "0")
    with pytest.raises(ValueError):
        resolve_concurrency()
    monkeypatch.setenv("SYMBOL_RESOLVE_LIMIT", "abc")
    with pytest.raises(ValueError):
        resolve_concurrency()


def test_default_submit_and_query_share_the_same_limit(client):
    """默认上报的同步解析与按号查栈共用同一上限：限额 1 时不会并发解析。"""
    c, store = client
    store.publish_batch([("demo.elf", read_fixture("demo-aaaa.elf"))])
    store.limiter._limit = 1
    addr = func_address(FIX / "demo-aaaa.elf", "crash_here")
    rid = store.create_report([{"build_id": BUILD_ID_A, "address": hex(addr)}])

    active_seen: list[int] = []
    orig = store._resolve_report_unbounded

    def observing(report_id, snapshot_version=None):
        active_seen.append(store.limiter.stats()["active"])
        time.sleep(0.2)
        return orig(report_id, snapshot_version)

    store._resolve_report_unbounded = observing
    try:
        statuses: list[int] = []

        def submit():
            statuses.append(
                c.post(
                    "/reports",
                    json={"frames": [{"build_id": BUILD_ID_A, "address": hex(addr)}]},
                    timeout=15,
                ).status_code
            )

        t = threading.Thread(target=submit)
        t.start()
        time.sleep(0.05)
        t0 = time.monotonic()
        q = c.get(f"/reports/{rid}", timeout=15)
        query_elapsed = time.monotonic() - t0
        t.join(20)
    finally:
        store._resolve_report_unbounded = orig

    assert q.status_code == 200 and q.json()["frames"][0]["function"] == "crash_here"
    assert statuses == [201]
    assert active_seen and max(active_seen) == 1  # 从未超过上限
    assert query_elapsed >= 0.2  # 后到的查栈排队等待名额
    assert store.limiter.stats()["active"] == 0
