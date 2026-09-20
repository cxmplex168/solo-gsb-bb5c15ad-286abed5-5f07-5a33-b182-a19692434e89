"""样本分装谱系（aliquot lineage）。

每个样本在**首次分装前**需设置初始数量与单位（精确十进制，以文本规范化后
存入 SQLite）；设置后可从当前样本发起一次分装，一次批次可拆出多个子样本。

一次分装在**单一写事务**（路由层 ``BEGIN IMMEDIATE``）内完成全部校验与写入：

* 父样本版本乐观锁：请求必须携带 ``expected_version``，与库内不一致
  （重复提交 / 并发变更）一律 **409**，不产生任何部分记录；
* 子样本编号在本批次内不重复、与全库样本编号不冲突（唯一约束兜底）-> 409；
* 单位一致：子样本若显式给出单位，必须与父样本一致 -> 400；
* 分装量为正十进制（请求模型先行校验，事务内再次防御性校验）；
* 分装量合计为精确十进制求和，不得超过父样本当前可用余量 -> 400。

校验全部通过后才：创建子样本（``parent_id`` 指回父样本，初始量 / 余量即本次
分装量）、扣减父样本余量并递增版本、写入**不可变**批次（``aliquot_batches``）
与逐子样本批次明细（``aliquot_items``，含批次快照 SHA-256）。批次表只提供
读取接口，应用层不存在任何修改 / 删除路径。

支持从子样本继续分装，从而形成任意深度的父子树；删除样本时若其仍有任何
后代（递归）则以 409 拒绝。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Optional
from sqlite3 import Connection

MAX_QTY_DIGITS = 28
MAX_CHILDREN_PER_BATCH = 200


class AliquotError(Exception):
    """分装业务校验失败，由路由层转换为 HTTPException。"""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# ---------- 十进制工具 ----------

def parse_qty(value: Any, field: str = "数量") -> Decimal:
    """把入参解析为有限、为正的 Decimal；非法 / 非正 / 位数超限抛 ValueError。"""
    if isinstance(value, Decimal):
        d = value
    else:
        try:
            d = Decimal(str(value).strip())
        except (InvalidOperation, AttributeError, ValueError):
            raise ValueError(f"{field}不是合法的十进制数字")
    if not d.is_finite():
        raise ValueError(f"{field}必须是有限数字")
    if d <= 0:
        raise ValueError(f"{field}必须大于 0")
    if len(d.as_tuple().digits) > MAX_QTY_DIGITS:
        raise ValueError(f"{field}有效数字不能超过 {MAX_QTY_DIGITS} 位")
    return d


def canon_qty(d: Decimal) -> str:
    """规范化为无指数、无多余尾零的纯文本（0.10 -> 0.5 等精确比较 / 存储用）。"""
    return format(d.normalize(), "f")


def qty_text(d: Decimal) -> str:
    return canon_qty(d)


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------- 读取视图 ----------

def _sample_node(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "code": row["code"],
        "name": row["name"],
        "description": row["description"],
        "parent_id": row["parent_id"],
        "initial_qty": row["initial_qty"],
        "remaining_qty": row["remaining_qty"],
        "unit": row["unit"],
        "version": row["version"],
        "created_at": row["created_at"],
    }


def get_sample_row(conn: Connection, sample_id: int) -> Optional[Any]:
    return conn.execute("SELECT * FROM samples WHERE id = ?", (sample_id,)).fetchone()


def has_descendants(conn: Connection, sample_id: int) -> bool:
    """递归判断样本是否仍有任何后代（子 / 孙 …）。"""
    row = conn.execute(
        """
        WITH RECURSIVE descendants(id) AS (
            SELECT id FROM samples WHERE parent_id = ?
            UNION ALL
            SELECT s.id FROM samples s JOIN descendants d ON s.parent_id = d.id
        )
        SELECT COUNT(*) FROM descendants
        """,
        (sample_id,),
    ).fetchone()
    return row[0] > 0


def has_outgoing_batches(conn: Connection, sample_id: int) -> bool:
    return conn.execute(
        "SELECT 1 FROM aliquot_batches WHERE parent_sample_id = ? LIMIT 1",
        (sample_id,),
    ).fetchone() is not None


def _batch_digest(snapshot: dict[str, Any]) -> str:
    raw = json.dumps(snapshot, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _batch_item_view(row: Any) -> dict[str, Any]:
    return {
        "line_no": row["line_no"],
        "child_id": row["child_sample_id"],
        "code": row["code"],
        "name": row["name"],
        "description": row["description"],
        "qty": row["qty"],
        "unit": row["unit"],
    }


def _batch_summary(conn: Connection, row: Any, items: list[Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "batch_no": row["batch_no"],
        "parent_sample_id": row["parent_sample_id"],
        "operator": row["operator"],
        "note": row["note"],
        "created_at": row["created_at"],
        "parent_initial_qty": row["parent_initial_qty"],
        "parent_remaining_before": row["parent_remaining_before"],
        "parent_remaining_after": row["parent_remaining_after"],
        "parent_version_before": row["parent_version_before"],
        "total_qty": row["total_qty"],
        "item_count": len(items),
        "items": [_batch_item_view(i) for i in items],
    }


def get_batch_detail(conn: Connection, batch_id: int) -> dict[str, Any]:
    """批次详情：不可变批次头 + 明细 + 快照完整性现场校验。"""
    batch = conn.execute(
        "SELECT * FROM aliquot_batches WHERE id = ?", (batch_id,)
    ).fetchone()
    if batch is None:
        raise AliquotError("分装批次不存在", status_code=404)

    items = conn.execute(
        "SELECT * FROM aliquot_items WHERE batch_id = ? ORDER BY line_no, id",
        (batch_id,),
    ).fetchall()
    parent = get_sample_row(conn, batch["parent_sample_id"])
    snapshot = json.loads(batch["snapshot"])
    integrity_ok = _batch_digest(snapshot) == batch["digest"]

    return {
        "id": batch["id"],
        "batch_no": batch["batch_no"],
        "operator": batch["operator"],
        "note": batch["note"],
        "created_at": batch["created_at"],
        "parent_sample": (
            {
                "id": parent["id"],
                "code": parent["code"],
                "name": parent["name"],
                "unit": parent["unit"],
            }
            if parent is not None
            else None
        ),
        "parent_initial_qty": batch["parent_initial_qty"],
        "parent_remaining_before": batch["parent_remaining_before"],
        "parent_remaining_after": batch["parent_remaining_after"],
        "parent_version_before": batch["parent_version_before"],
        "total_qty": batch["total_qty"],
        "item_count": len(items),
        "items": [_batch_item_view(i) for i in items],
        "digest": batch["digest"],
        "integrity_ok": integrity_ok,
    }


# ---------- 首次分装前：设置初始数量 / 单位 ----------

def set_initial_quantity(
    conn: Connection,
    sample_id: int,
    initial_qty: Decimal,
    unit: str,
    expected_version: int,
) -> dict[str, Any]:
    """在调用方已开启的写事务内设置（或首次分装前修正）初始数量与单位。

    * 子样本的数量由分装批次确定，不允许单独设置 -> 409；
    * 已发起过分装的父样本，初始数量固化不可修改 -> 409；
    * expected_version 与当前版本不一致（并发变更）-> 409。
    """
    sample = get_sample_row(conn, sample_id)
    if sample is None:
        raise AliquotError("样本不存在", status_code=404)
    if sample["parent_id"] is not None:
        raise AliquotError(
            "该样本由分装批次产生，初始数量与单位在分装时已确定，不能单独设置",
            status_code=409,
        )
    if sample["version"] != expected_version:
        raise AliquotError(
            f"样本版本已过期（当前 v{sample['version']}，请求基于 v{expected_version}），"
            "请刷新详情后重试",
            status_code=409,
        )
    if has_outgoing_batches(conn, sample_id):
        raise AliquotError(
            "该样本已发起过分装，初始数量与单位已固化，不能修改",
            status_code=409,
        )

    text = canon_qty(initial_qty)
    conn.execute(
        "UPDATE samples SET initial_qty = ?, remaining_qty = ?, unit = ?, "
        "version = version + 1 WHERE id = ?",
        (text, text, unit, sample_id),
    )
    return _sample_node(get_sample_row(conn, sample_id))


# ---------- 发起分装（单一事务） ----------

def create_aliquot_batch(
    conn: Connection,
    parent_id: int,
    operator: str,
    note: str,
    children: list[dict[str, Any]],
    expected_version: int,
) -> dict[str, Any]:
    """在调用方已开启的写事务（BEGIN IMMEDIATE）内校验并落库一次分装。

    任一步失败抛 :class:`AliquotError`，由路由整体 ROLLBACK，不存在部分写入。
    返回 ``{"batch": 批次详情, "parent": 父样本最新视图}``。
    """
    parent = get_sample_row(conn, parent_id)
    if parent is None:
        raise AliquotError("父样本不存在", status_code=404)

    # 1) 乐观锁：重复提交 / 并发变更一律 409
    if parent["version"] != expected_version:
        raise AliquotError(
            f"父样本版本已过期（当前 v{parent['version']}，请求基于 v{expected_version}），"
            "可能已被他人分装或修改，请刷新详情后重试",
            status_code=409,
        )

    # 2) 必须先设置初始数量 / 单位
    if parent["initial_qty"] is None or parent["remaining_qty"] is None or not parent["unit"]:
        raise AliquotError("请先为父样本设置初始数量与单位，再发起分装")

    if not children:
        raise AliquotError("本次分装至少需要一个子样本")
    if len(children) > MAX_CHILDREN_PER_BATCH:
        raise AliquotError(f"单次分装最多 {MAX_CHILDREN_PER_BATCH} 个子样本")

    unit = parent["unit"]

    # 3) 分装量解析（精确十进制）与单位一致
    parsed_children: list[dict[str, Any]] = []
    seen_codes: set[str] = set()
    total = Decimal("0")
    for idx, ch in enumerate(children, start=1):
        code = ch["code"].strip()
        name = ch["name"].strip()
        description = (ch.get("description") or "").strip()
        try:
            qty = parse_qty(ch["qty"], f"第 {idx} 个子样本分装量")
        except ValueError as exc:
            raise AliquotError(str(exc))
        child_unit = (ch.get("unit") or "").strip() or unit
        if child_unit != unit:
            raise AliquotError(
                f"子样本 {code} 的单位（{child_unit}）与父样本单位（{unit}）不一致，"
                "同一分装谱系必须使用相同单位"
            )
        if code in seen_codes:
            raise AliquotError(f"子样本编号 {code} 在本次分装中重复", status_code=409)
        seen_codes.add(code)
        total += qty
        parsed_children.append(
            {
                "code": code,
                "name": name,
                "description": description,
                "qty": qty,
                "qty_text": canon_qty(qty),
                "unit": unit,
            }
        )

    # 4) 编号全局唯一（唯一约束兜底，见下方 IntegrityError 处理）
    placeholders = ",".join("?" * len(seen_codes))
    existing = conn.execute(
        f"SELECT code FROM samples WHERE code IN ({placeholders})",
        tuple(seen_codes),
    ).fetchall()
    if existing:
        codes = "、".join(r["code"] for r in existing)
        raise AliquotError(f"样本编号 {codes} 已存在，分装失败", status_code=409)

    # 5) 合计不得超过可用余量（精确十进制比较）
    remaining_before = Decimal(parent["remaining_qty"])
    initial_qty = parent["initial_qty"]
    if total > remaining_before:
        raise AliquotError(
            f"分装量合计 {canon_qty(total)} {unit} 超过父样本可用余量 "
            f"{canon_qty(remaining_before)} {unit}，请调整各子样本分装量",
        )
    remaining_after = remaining_before - total
    version_before = parent["version"]
    now = _now()

    # 6) 编号、单位、数量全部校验通过后才开始写入 -----------------------------

    today = datetime.now().strftime("%Y%m%d")
    seq = conn.execute(
        "SELECT COUNT(*) FROM aliquot_batches WHERE batch_no LIKE ?",
        (f"B-{today}-%",),
    ).fetchone()[0] + 1
    batch_no = f"B-{today}-{seq:04d}"

    child_ids: list[int] = []
    item_payload: list[dict[str, Any]] = []
    for line_no, ch in enumerate(parsed_children, start=1):
        cur = conn.execute(
            "INSERT INTO samples (code, name, description, created_at, parent_id, "
            "initial_qty, remaining_qty, unit, version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (
                ch["code"], ch["name"], ch["description"], now, parent_id,
                ch["qty_text"], ch["qty_text"], ch["unit"],
            ),
        )
        child_id = cur.lastrowid
        child_ids.append(child_id)
        item_payload.append({**ch, "child_id": child_id, "line_no": line_no})

    # 扣减父样本余量并递增版本（WHERE 携带版本，双重防止并发覆盖）
    cur = conn.execute(
        "UPDATE samples SET remaining_qty = ?, version = version + 1 "
        "WHERE id = ? AND version = ?",
        (canon_qty(remaining_after), parent_id, expected_version),
    )
    if cur.rowcount != 1:
        # 理论上已被开头版本检查拦截；兜底抛错由路由回滚
        raise AliquotError(
            "父样本在提交期间被并发修改，请刷新后重试", status_code=409
        )

    snapshot = {
        "batch_no": batch_no,
        "parent_sample_id": parent_id,
        "parent_code": parent["code"],
        "operator": operator,
        "note": note,
        "created_at": now,
        "unit": unit,
        "parent_initial_qty": initial_qty,
        "parent_remaining_before": canon_qty(remaining_before),
        "parent_remaining_after": canon_qty(remaining_after),
        "parent_version_before": version_before,
        "total_qty": canon_qty(total),
        "items": [
            {
                "line_no": p["line_no"],
                "child_sample_id": p["child_id"],
                "code": p["code"],
                "name": p["name"],
                "description": p["description"],
                "qty": p["qty_text"],
                "unit": p["unit"],
            }
            for p in item_payload
        ],
    }
    digest = _batch_digest(snapshot)

    bcur = conn.execute(
        "INSERT INTO aliquot_batches (batch_no, parent_sample_id, operator, note, "
        "created_at, parent_initial_qty, parent_remaining_before, "
        "parent_remaining_after, parent_version_before, total_qty, snapshot, digest) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            batch_no, parent_id, operator, note, now,
            initial_qty, canon_qty(remaining_before), canon_qty(remaining_after),
            version_before, canon_qty(total),
            json.dumps(snapshot, ensure_ascii=False, sort_keys=True), digest,
        ),
    )
    batch_id = bcur.lastrowid
    for p in item_payload:
        conn.execute(
            "INSERT INTO aliquot_items (batch_id, child_sample_id, line_no, code, "
            "name, description, qty, unit, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                batch_id, p["child_id"], p["line_no"], p["code"], p["name"],
                p["description"], p["qty_text"], p["unit"], now,
            ),
        )

    return {
        "batch": get_batch_detail(conn, batch_id),
        "parent": _sample_node(get_sample_row(conn, parent_id)),
        "child_ids": child_ids,
    }


# ---------- 谱系树 ----------

def build_lineage(conn: Connection, sample_id: int) -> dict[str, Any]:
    """以当前样本的根祖先为根，返回整棵分装父子树及根 -> 当前样本的来源链。

    未设置数量、未发生分装的独立样本返回仅含自身的单层树。
    """
    current = get_sample_row(conn, sample_id)
    if current is None:
        raise AliquotError("样本不存在", status_code=404)

    # 沿 parent_id 上溯找根（深度通常很小，Python 循环即可）
    root_id = sample_id
    chain_map = {sample_id: current}
    guard = 0
    while chain_map[root_id]["parent_id"] is not None:
        pid = chain_map[root_id]["parent_id"]
        prow = get_sample_row(conn, pid)
        if prow is None:  # 数据异常兜底
            break
        chain_map[pid] = prow
        root_id = pid
        guard += 1
        if guard > 10000:
            raise AliquotError("谱系层级过深，存在环路")

    # 从根递归取全部后代
    rows = conn.execute(
        """
        WITH RECURSIVE tree(id, depth) AS (
            SELECT id, 0 FROM samples WHERE id = ?
            UNION ALL
            SELECT s.id, t.depth + 1 FROM samples s JOIN tree t ON s.parent_id = t.id
        )
        SELECT s.*, t.depth FROM samples s JOIN tree t ON s.id = t.id
        ORDER BY t.depth, s.id
        """,
        (root_id,),
    ).fetchall()
    by_id = {r["id"]: _sample_node(r) | {"depth": r["depth"]} for r in rows}

    # 取整棵树涉及的批次与明细（子样本删除后 child_sample_id 可能为 NULL，
    # 不可变批次行仍保留）
    subtree_ids = list(by_id)
    ph = ",".join("?" * len(subtree_ids))
    batches = conn.execute(
        f"SELECT * FROM aliquot_batches WHERE parent_sample_id IN ({ph}) ORDER BY id",
        tuple(subtree_ids),
    ).fetchall()
    items_by_batch: dict[int, list[Any]] = {}
    batch_ids = [b["id"] for b in batches]
    if batch_ids:
        bph = ",".join("?" * len(batch_ids))
        for it in conn.execute(
            f"SELECT * FROM aliquot_items WHERE batch_id IN ({bph}) ORDER BY line_no, id",
            tuple(batch_ids),
        ).fetchall():
            items_by_batch.setdefault(it["batch_id"], []).append(it)

    batches_out_by_parent: dict[int, list[dict[str, Any]]] = {}
    aliquot_in_by_child: dict[int, dict[str, Any]] = {}
    for b in batches:
        items = items_by_batch.get(b["id"], [])
        summary = _batch_summary(conn, b, items)
        batches_out_by_parent.setdefault(b["parent_sample_id"], []).append(summary)
        for it in items:
            if it["child_sample_id"] is not None:
                aliquot_in_by_child[it["child_sample_id"]] = {
                    "batch_id": b["id"],
                    "batch_no": b["batch_no"],
                    "parent_sample_id": b["parent_sample_id"],
                    "operator": b["operator"],
                    "created_at": b["created_at"],
                    "qty": it["qty"],
                    "unit": it["unit"],
                }

    # 组装树
    nodes_by_id: dict[int, dict[str, Any]] = {}
    for sid, node in by_id.items():
        nodes_by_id[sid] = {
            **node,
            "initialized": node["initial_qty"] is not None,
            "aliquot_in": aliquot_in_by_child.get(sid),
            "batches_out": batches_out_by_parent.get(sid, []),
            "children": [],
        }
    root_node: Optional[dict[str, Any]] = None
    for sid, node in nodes_by_id.items():
        parent_id = node["parent_id"]
        if parent_id is not None and parent_id in nodes_by_id and parent_id != sid:
            nodes_by_id[parent_id]["children"].append(node)
        if sid == root_id:
            root_node = node

    # 来源链：根 -> 当前样本
    origin_chain: list[dict[str, Any]] = []
    cur_id: Optional[int] = sample_id
    while cur_id is not None:
        n = nodes_by_id.get(cur_id)
        if n is None:
            break
        origin_chain.append(
            {"id": n["id"], "code": n["code"], "name": n["name"]}
        )
        cur_id = n["parent_id"] if n["parent_id"] in nodes_by_id else None
    origin_chain.reverse()

    return {
        "root": root_node,
        "origin_chain": origin_chain,
        "current_id": sample_id,
        "total_samples": len(nodes_by_id),
        "total_batches": len(batches),
    }
