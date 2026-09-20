"""样本分装谱系测试。

覆盖：
* 首次分装前设置初始数量 / 单位（精确十进制），子样本由批次产生不能单独设置；
* 单一事务校验：编号批次内 / 全局唯一、单位一致、分装量为正、合计不超余量；
* 成功后创建子样本、扣减父样本余量、批次与明细不可变并带 SHA-256 快照；
* 乐观锁：重复提交 / 过期版本 / 并发同版本提交返回 409 且无部分记录；
* 十进制精确求和（0.1 + 0.2）；
* 从子样本继续分装形成多级树，谱系来源链与批次详情正确；
* 禁止删除已有后代的样本；叶子子样本删除后批次仍可查（明细置空引用）；
* 批次详情接口与快照完整性校验。
"""
from __future__ import annotations

import os
import tempfile
import threading

_tmp = tempfile.mkdtemp(prefix="audit-aliquot-tests-")
os.environ["AUDIT_DB_PATH"] = os.path.join(_tmp, "test_aliquot.db")
os.environ["ATTACHMENT_DIR"] = os.path.join(_tmp, "att")

import itertools

import pytest
from fastapi.testclient import TestClient

from app.db import get_connection, init_db
from app.main import app


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


_seq = itertools.count(1)


@pytest.fixture()
def root(client):
    """新建一个未设置数量的父样本。"""
    code = f"UT-ALI-{next(_seq):03d}"
    s = client.post(
        "/api/samples",
        json={"code": code, "name": "分装测试父样本", "description": ""},
    ).json()
    return s


def _init(client, sid, qty="100", unit="mL", version=1):
    return client.put(
        f"/api/samples/{sid}/initial-quantity",
        json={"initial_qty": qty, "unit": unit, "expected_version": version},
    )


def _split(client, sid, children, version, operator="制备人", note=""):
    return client.post(
        f"/api/samples/{sid}/aliquots",
        json={
            "expected_version": version,
            "operator": operator,
            "note": note,
            "children": children,
        },
    )


def _detail(client, sid):
    return client.get(f"/api/samples/{sid}").json()


# ---------- 初始数量 / 单位 ----------

def test_set_initial_quantity_and_version(client, root):
    sid = root["id"]
    assert root["initial_qty"] is None
    assert root["version"] == 1

    r = _init(client, sid, "100.000", "mL")
    assert r.status_code == 200
    body = r.json()
    assert body["initial_qty"] == "100"          # 规范化去掉尾零
    assert body["remaining_qty"] == "100"
    assert body["unit"] == "mL"
    assert body["version"] == 2

    # 版本过期（重复提交）-> 409
    stale = _init(client, sid, "200", "mL", version=1)
    assert stale.status_code == 409


def test_initial_quantity_must_be_positive(client, root):
    sid = root["id"]
    r = _init(client, sid, "0", "mL")
    assert r.status_code == 422
    r = _init(client, sid, "-1", "mL")
    assert r.status_code == 422
    r = _init(client, sid, "abc", "mL")
    assert r.status_code == 422


def test_cannot_initialize_child_sample(client, root):
    sid = root["id"]
    _init(client, sid)
    r = _split(
        client, sid,
        [{"code": f"{root['code']}-K", "name": "子", "qty": "10"}],
        version=2,
    )
    assert r.status_code == 201
    child_id = r.json()["child_ids"][0]
    # 子样本的数量 / 单位已在分装时确定，不能单独设置
    bad = _init(client, child_id, "50", "mL")
    assert bad.status_code == 409


def test_initial_quantity_frozen_after_first_batch(client, root):
    sid = root["id"]
    _init(client, sid, "100", "mL")
    _split(client, sid, [{"code": f"{root['code']}-K", "name": "子", "qty": "10"}], 2)
    # 已分装 -> 初始量固化（即使携带新版本）
    d = _detail(client, sid)
    r = _init(client, sid, "200", "mL", version=d["sample"]["version"])
    assert r.status_code == 409
    assert d["sample"]["initial_qty"] == "100"


# ---------- 分装校验 ----------

def test_aliquot_requires_initial_quantity(client, root):
    r = _split(
        client, root["id"],
        [{"code": f"{root['code']}-K", "name": "子", "qty": "10"}],
        version=1,
    )
    assert r.status_code == 400


def test_aliquot_success_creates_children_and_batch(client, root):
    sid = root["id"]
    _init(client, sid, "100", "mL")
    r = _split(
        client, sid,
        [
            {"code": f"{root['code']}-A", "name": "子A", "qty": "30",
             "description": "送检", "unit": "mL"},
            {"code": f"{root['code']}-B", "name": "子B", "qty": "20.5"},
        ],
        version=2, note="首次分装",
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert len(body["child_ids"]) == 2
    assert body["parent"]["remaining_qty"] == "49.5"
    assert body["parent"]["version"] == 3

    batch = body["batch"]
    assert batch["total_qty"] == "50.5"
    assert batch["parent_remaining_before"] == "100"
    assert batch["parent_remaining_after"] == "49.5"
    assert batch["parent_version_before"] == 2
    assert batch["batch_no"].startswith("B-")
    assert [it["qty"] for it in batch["items"]] == ["30", "20.5"]
    assert all(it["unit"] == "mL" for it in batch["items"])

    # 子样本自身视图：初始量 = 分装量、单位继承
    for cid, qty in zip(body["child_ids"], ["30", "20.5"]):
        d = _detail(client, cid)
        assert d["sample"]["initial_qty"] == qty
        assert d["sample"]["remaining_qty"] == qty
        assert d["sample"]["unit"] == "mL"
        assert d["sample"]["parent_id"] == sid


def test_decimal_exact_sum(client, root):
    sid = root["id"]
    _init(client, sid, "1", "mL")
    r = _split(
        client, sid,
        [
            {"code": f"{root['code']}-A", "name": "子A", "qty": "0.1"},
            {"code": f"{root['code']}-B", "name": "子B", "qty": "0.2"},
        ],
        version=2,
    )
    assert r.status_code == 201
    assert r.json()["batch"]["total_qty"] == "0.3"  # 精确十进制，非浮点 0.30000000004
    assert r.json()["parent"]["remaining_qty"] == "0.7"

    # 余量恰好用完允许（合计 == 余量）
    r2 = _split(
        client, sid,
        [
            {"code": f"{root['code']}-C", "name": "子C", "qty": "0.4"},
            {"code": f"{root['code']}-D", "name": "子D", "qty": "0.3"},
        ],
        version=3,
    )
    assert r2.status_code == 201
    assert r2.json()["parent"]["remaining_qty"] == "0"


def test_qty_must_be_positive(client, root):
    sid = root["id"]
    _init(client, sid)
    r = _split(
        client, sid,
        [{"code": f"{root['code']}-Z", "name": "子", "qty": "0"}],
        version=2,
    )
    assert r.status_code == 422
    r = _split(
        client, sid,
        [{"code": f"{root['code']}-Z", "name": "子", "qty": "-5"}],
        version=2,
    )
    assert r.status_code == 422


def test_unit_mismatch_rejected(client, root):
    sid = root["id"]
    _init(client, sid, "100", "mL")
    r = _split(
        client, sid,
        [{"code": f"{root['code']}-L", "name": "子", "qty": "10", "unit": "L"}],
        version=2,
    )
    assert r.status_code == 400
    assert "单位" in r.json()["detail"]
    # 失败后父样本不变
    d = _detail(client, sid)
    assert d["sample"]["remaining_qty"] == "100"
    assert d["sample"]["version"] == 2


def test_total_cannot_exceed_remaining(client, root):
    sid = root["id"]
    _init(client, sid, "10", "mL")
    r = _split(
        client, sid,
        [
            {"code": f"{root['code']}-A", "name": "A", "qty": "6"},
            {"code": f"{root['code']}-B", "name": "B", "qty": "5"},
        ],
        version=2,
    )
    assert r.status_code == 400
    assert "余量" in r.json()["detail"]
    # 无部分记录：两个子样本都不存在
    codes = {s["code"] for s in client.get("/api/samples").json()}
    assert f"{root['code']}-A" not in codes
    assert f"{root['code']}-B" not in codes
    # 没有批次落库
    d = _detail(client, sid)
    assert d["lineage"]["total_batches"] == 0


def test_duplicate_code_within_batch_conflicts(client, root):
    sid = root["id"]
    _init(client, sid)
    code = f"{root['code']}-DUP"
    r = _split(
        client, sid,
        [{"code": code, "name": "A", "qty": "1"},
         {"code": code, "name": "B", "qty": "1"}],
        version=2,
    )
    assert r.status_code == 409


def test_duplicate_code_globally_conflicts(client, root):
    sid = root["id"]
    _init(client, sid)
    existing = client.post(
        "/api/samples", json={"code": f"{root['code']}-EXIST", "name": "别的样本"}
    ).json()
    assert existing["code"]
    r = _split(
        client, sid,
        [{"code": f"{root['code']}-EXIST", "name": "子", "qty": "1"}],
        version=2,
    )
    assert r.status_code == 409


def test_stale_version_resubmit_conflicts_and_no_partial_records(client, root):
    sid = root["id"]
    _init(client, sid, "100", "mL")
    payload_children = [
        {"code": f"{root['code']}-A", "name": "A", "qty": "10"},
        {"code": f"{root['code']}-B", "name": "B", "qty": "10"},
    ]
    first = _split(client, sid, payload_children, version=2)
    assert first.status_code == 201
    first_batch = first.json()["batch"]["id"]

    # 完全相同的请求重放 -> 版本冲突 409
    replay = _split(client, sid, payload_children, version=2)
    assert replay.status_code == 409

    # 重放未产生任何子样本 / 批次
    d = _detail(client, sid)
    assert d["lineage"]["total_batches"] == 1
    assert d["lineage"]["root"]["children"] and len(d["lineage"]["root"]["children"]) == 2
    assert d["sample"]["remaining_qty"] == "80"
    assert d["sample"]["version"] == 3
    # 批次明细仍然只有第一次的两条
    batch = client.get(f"/api/aliquot-batches/{first_batch}").json()
    assert batch["item_count"] == 2


def test_concurrent_same_version_only_one_wins(client, root):
    sid = root["id"]
    _init(client, sid, "100", "mL")
    results: list[tuple[int, int]] = []

    def worker(i: int):
        r = _split(
            client, sid,
            [{"code": f"{root['code']}-T{i}", "name": f"子{i}", "qty": "30"}],
            version=2,
        )
        results.append((i, r.status_code))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    success = [r for r in results if r[1] == 201]
    assert len(success) == 1
    d = _detail(client, sid)
    assert d["sample"]["remaining_qty"] == "70"
    assert d["sample"]["version"] == 3
    assert d["lineage"]["total_batches"] == 1
    assert len(d["lineage"]["root"]["children"]) == 1


# ---------- 多级谱系 ----------

def _three_level_tree(client, root):
    sid = root["id"]
    _init(client, sid, "100", "mL")
    r1 = _split(
        client, sid,
        [{"code": f"{root['code']}-A", "name": "A", "qty": "30"},
         {"code": f"{root['code']}-B", "name": "B", "qty": "30"}],
        version=2,
    )
    child_a = r1.json()["child_ids"][0]
    r2 = _split(
        client, child_a,
        [{"code": f"{root['code']}-A1", "name": "A1", "qty": "10"},
         {"code": f"{root['code']}-A2", "name": "A2", "qty": "15"}],
        version=1,
    )
    assert r2.status_code == 201
    return sid, child_a, r2.json()["child_ids"]


def test_aliquot_from_child_and_lineage_tree(client, root):
    sid, child_a, grandkids = _three_level_tree(client, root)

    # 从孙样本视角看谱系：根仍是原始父样本，来源链为 根 -> 子A -> 孙
    g = grandkids[0]
    lin = client.get(f"/api/samples/{g}/lineage").json()
    assert lin["current_id"] == g
    assert [o["id"] for o in lin["origin_chain"]] == [sid, child_a, g]
    assert lin["total_samples"] == 5
    assert lin["total_batches"] == 2

    def codes(node):
        return node["code"], [codes(c) for c in node["children"]]

    tree = codes(lin["root"])
    assert tree[0] == root["code"]
    a_branch = [c for c in tree[1] if c[0].endswith("-A")][0]
    assert {c[0] for c in a_branch[1]} == {f"{root['code']}-A1", f"{root['code']}-A2"}

    # 节点携带来源批次 / 批次记录与剩余量
    a_node = lin["root"]["children"][0]
    assert a_node["remaining_qty"] == "5"
    assert a_node["aliquot_in"]["qty"] == "30"
    assert len(a_node["batches_out"]) == 1

    # 子样本 A 继续分装时单位仍必须与谱系一致
    bad = _split(
        client, child_a,
        [{"code": f"{root['code']}-AX", "name": "AX", "qty": "1", "unit": "mg"}],
        version=2,
    )
    assert bad.status_code == 400


def test_delete_protection(client, root):
    sid, child_a, grandkids = _three_level_tree(client, root)
    # 根 / 中间节点有后代 -> 409
    assert client.delete(f"/api/samples/{sid}").status_code == 409
    assert client.delete(f"/api/samples/{child_a}").status_code == 409

    # 叶子孙样本可以删除
    g = grandkids[0]
    assert client.delete(f"/api/samples/{g}").status_code == 204
    # 删后子 A 仍有一个后代（A2），依旧禁止删除
    assert client.delete(f"/api/samples/{child_a}").status_code == 409
    # 子 B 是叶子，可删除
    b = [
        s for s in client.get("/api/samples").json()
        if s["code"] == f"{root['code']}-B"
    ][0]
    assert client.delete(f"/api/samples/{b['id']}").status_code == 204


# ---------- 批次详情（不可变） ----------

def test_batch_detail_and_immutability(client, root):
    sid = root["id"]
    _init(client, sid, "100", "mL")
    r = _split(
        client, sid,
        [{"code": f"{root['code']}-A", "name": "A", "qty": "30",
          "description": "备注"}],
        version=2, note="批次备注",
    )
    batch_id = r.json()["batch"]["id"]
    d = client.get(f"/api/aliquot-batches/{batch_id}")
    assert d.status_code == 200
    body = d.json()
    assert body["integrity_ok"] is True
    assert body["operator"] == "制备人"
    assert body["note"] == "批次备注"
    assert body["parent_sample"]["id"] == sid
    assert body["items"][0]["description"] == "备注"
    assert body["items"][0]["child_id"] is not None
    assert len(body["digest"]) == 64

    # 叶子子样本删除后：批次详情仍完整，明细的 child_id 置空但编号保留
    child_id = body["items"][0]["child_id"]
    assert client.delete(f"/api/samples/{child_id}").status_code == 204
    after = client.get(f"/api/aliquot-batches/{batch_id}").json()
    assert after["item_count"] == 1
    assert after["items"][0]["child_id"] is None
    assert after["items"][0]["code"] == f"{root['code']}-A"
    assert after["integrity_ok"] is True

    # 不存在的批次 -> 404
    assert client.get("/api/aliquot-batches/99999999").status_code == 404


def test_batch_cascade_with_root(client, root):
    sid = root["id"]
    _init(client, sid, "100", "mL")
    r = _split(
        client, sid,
        [{"code": f"{root['code']}-A", "name": "A", "qty": "30"}],
        version=2,
    )
    batch_id = r.json()["batch"]["id"]
    child_id = r.json()["child_ids"][0]
    # 叶子删除后根也可删除，批次随根级联清除
    client.delete(f"/api/samples/{child_id}")
    assert client.delete(f"/api/samples/{sid}").status_code == 204
    assert client.get(f"/api/aliquot-batches/{batch_id}").status_code == 404


def test_batch_snapshot_tamper_detected(client, root):
    sid = root["id"]
    _init(client, sid, "100", "mL")
    r = _split(
        client, sid,
        [{"code": f"{root['code']}-A", "name": "A", "qty": "30"}],
        version=2,
    )
    batch_id = r.json()["batch"]["id"]
    # 直接篡改库内不可变快照（模拟存储层异常），详情接口必须识别
    with get_connection() as conn:
        conn.execute(
            "UPDATE aliquot_batches SET snapshot = '{}' WHERE id = ?", (batch_id,)
        )
    body = client.get(f"/api/aliquot-batches/{batch_id}").json()
    assert body["integrity_ok"] is False
