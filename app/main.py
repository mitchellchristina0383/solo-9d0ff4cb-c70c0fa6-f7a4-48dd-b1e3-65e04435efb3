"""FastAPI 入口：崩溃栈提交、按报告号查询、CI 批量补传 ELF。"""
from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import List, Optional, Union

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from . import __version__
from .config import settings
from .storage import BatchRejected, Store

logger = logging.getLogger(__name__)

_store: Optional[Store] = None
# 专门用于登记写入的线程池：与解析/查栈线程隔离，
# 即使解析满额、查栈请求排队，只登记上报也能让事件循环立即派发落库任务并回执。
# 注意：上限约束的是解析（ResolveLimiter），登记只做短事务，可并发进行。
_registration_pool: Optional[ThreadPoolExecutor] = None


def get_store() -> Store:
    # 测试可通过 dependency_overrides 替换
    if _store is None:
        raise RuntimeError("Store 尚未初始化")
    return _store


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _store, _registration_pool
    if _store is None:  # 测试可预先注入 Store
        _store = Store()
    _registration_pool = ThreadPoolExecutor(
        max_workers=4, thread_name_prefix="report-register"
    )
    yield
    _registration_pool.shutdown(wait=True, cancel_futures=False)
    _registration_pool = None
    if _store is not None:
        _store.close()
        _store = None


async def _register_report(frames: list[dict]) -> int:
    """登记报告：写入不占解析名额，用独立线程池执行，不排队等解析。"""
    store = get_store()
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _registration_pool,
        store.create_report,
        frames,
    )


async def _resolve_report(report_id: int) -> Optional[dict]:
    """同步解析：在线程池中等待解析名额（与按号查栈共用同一上限）。"""
    store = get_store()
    return await run_in_threadpool(store.resolve_report, report_id)


app = FastAPI(
    title="Linux 崩溃栈还原服务",
    version=__version__,
    description=(
        "值班员提交各帧的 ELF Build ID 与扣除装载偏移后的地址，凭报告号查询函数与源码行；"
        "CI 可批量补传带 Build ID 与 DWARF 调试信息的 x86-64 ELF。"
        "查询绑定开始解析时的符号版本快照，查栈与发布可并行。"
    ),
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# 请求/响应模型
# ---------------------------------------------------------------------------
class FrameIn(BaseModel):
    build_id: Optional[str] = Field(
        default=None,
        description="GNU Build ID（十六进制，不带 0x）；未知时可留空，该帧保留原地址",
    )
    address: str = Field(
        ...,
        description="已扣除装载偏移的地址，支持 0x 前缀十六进制或十进制字符串",
    )


class ReportIn(BaseModel):
    frames: List[FrameIn] = Field(..., min_length=1, description="崩溃栈各帧，自底向上或自顶向下均可，按提交顺序保存")


class FrameOut(BaseModel):
    position: int
    build_id: Optional[str]
    address: str
    status: str
    reason: Optional[str]
    function: Optional[str]
    source_file: Optional[str]
    source_line: Optional[int]


class ReportOut(BaseModel):
    report_id: int
    created_at: str
    snapshot_symbol_version: int
    current_symbol_version: int
    frame_count: int
    resolved_count: int
    frames: List[FrameOut]


class ReportRegisteredOut(BaseModel):
    """只登记上报的回执：仅含报告号与原始帧数量，不含解析结果。"""

    report_id: int
    created_at: str
    frame_count: int


class BatchResult(BaseModel):
    accepted: int
    new_build_ids: List[str]
    redundant: int
    symbol_version: int


# ---------------------------------------------------------------------------
# 接口
# ---------------------------------------------------------------------------
@app.get("/health", tags=["运维"])
def health():
    store = get_store()
    return {
        "status": "ok",
        "version": __version__,
        "symbol_version": store.symbol_version,
        "published_build_ids": len(store.list_build_ids()),
        "data_dir": settings.data_dir,
        "resolve_limit": store.limiter.limit,
        "resolve_active": store.limiter.stats()["active"],
        "resolve_waiting": store.limiter.stats()["waiting"],
    }


@app.post(
    "/reports",
    response_model=Union[ReportOut, ReportRegisteredOut],
    status_code=201,
    tags=["崩溃报告"],
    responses={
        201: {
            "description": (
                "默认返回完整解析结果；`register_only=true` 时仅返回报告号回执"
            )
        },
        503: {"description": "报告登记失败，未留下任何报告或帧"},
    },
)
async def submit_report(
    payload: ReportIn,
    register_only: bool = Query(
        default=False,
        alias="register_only",
        description=(
            "只登记：写入报告与全部原始帧后立即返回 201 与报告号，"
            "不做同步或后台解析，也不占用解析并发名额；"
            "默认 false 时同步解析并返回结果"
        ),
    ),
):
    """提交崩溃栈。

    - 默认：登记后按当前已发布符号同步解析，返回报告号与解析结果；
    - `?register_only=true`：符号解析积压时只登记，立即返回报告号，不做解析；
      之后用同一报告号经 `GET /reports/{id}` 查栈。

    两种方式都把全部原始帧持久化；登记写入失败则整体回滚并返回 503，
    不会留下半份报告。
    """
    store = get_store()
    frames = [f.model_dump() for f in payload.frames]
    try:
        report_id = await _register_report(frames)
    except Exception:
        logger.exception("登记报告失败")
        raise HTTPException(
            status_code=503,
            detail="报告登记失败，未保存任何报告或帧，请重试",
        )

    if register_only:
        raw = store.get_report_raw(report_id)
        return ReportRegisteredOut(
            report_id=report_id,
            created_at=raw["created_at"],
            frame_count=len(raw["frames"]),
        )

    result = await _resolve_report(report_id)
    if result is None:  # 登记成功后立刻消失属于存储异常
        raise HTTPException(status_code=503, detail="报告登记后无法读取")
    return result


@app.get("/reports/{report_id}", response_model=ReportOut, tags=["崩溃报告"])
def get_report(report_id: int):
    """凭报告号查询；补传 ELF 后用同一报告号再查即可得到新解析结果。

    每次查询只使用本次开始解析时已发布的符号版本（快照）。
    """
    store = get_store()
    result = store.resolve_report(report_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"报告 {report_id} 不存在")
    return result


@app.get("/reports/{report_id}/raw", tags=["崩溃报告"])
def get_report_raw(report_id: int):
    """查看报告原始帧（地址原样保留）。"""
    store = get_store()
    raw = store.get_report_raw(report_id)
    if raw is None:
        raise HTTPException(status_code=404, detail=f"报告 {report_id} 不存在")
    return raw


@app.post("/symbols/batch", response_model=BatchResult, tags=["符号发布"])
def upload_batch(files: List[UploadFile] = File(..., description="一批 x86-64 ELF 文件")):
    """CI 整批补传 ELF。

    - Build ID 从文件内部的 NT_GNU_BUILD_ID 注释读取；
    - 任一文件缺标识、缺调试信息、非 x86-64，或与同 Build ID 已发布/同批文件内容不同，
      整批退回（422），不留任何部分结果；
    - 相同文件重传视为成功，计入 redundant。

    同步端点：阻塞式校验/落盘由 Starlette 放到线程池执行，不卡住事件循环。
    """
    if not files:
        raise HTTPException(status_code=422, detail="未上传任何文件")
    blobs: list[tuple[str, bytes]] = []
    for upload in files:
        blob = upload.file.read()
        if not blob:
            raise HTTPException(status_code=422, detail=f"文件 {upload.filename} 为空")
        blobs.append((upload.filename or "unnamed", blob))

    store = get_store()
    try:
        return store.publish_batch(blobs)
    except BatchRejected as exc:
        raise HTTPException(status_code=422, detail={"message": "整批退回", "errors": exc.errors})


@app.get("/symbols", tags=["符号发布"])
def list_symbols():
    """列出当前已发布的 Build ID。"""
    store = get_store()
    return {"symbol_version": store.symbol_version, "build_ids": store.list_build_ids()}
