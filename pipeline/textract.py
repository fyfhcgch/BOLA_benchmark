"""非 JSON 响应的文本抽取。

L3 的两类场景响应体不是 JSON：

    导出接口    text/csv         id,user_email,item,amount
    报表下载    application/pdf  只有 PDF 里的文字才带归属证据

判定层要能在这两种响应上找"非攻击者的身份标识"，所以先把它们压成纯文本。
PDF 抽取只做"能取出文字"的最低限度（流对象 + 常见 Filter 链 + Tj/TJ 操作符），
不引入 PyMuPDF 这类重依赖 —— 靶场生成的 PDF 都是 ReportLab 的标准产物。

拿不到文字时返回空串，判定层据此判"无归属证据"，而不是猜。
"""

from __future__ import annotations

import base64
import re
import zlib

# PDF 里 `(...) Tj` 与 `[(...) -250 (...)] TJ` 两种写字方式
_PDF_TEXT_OP = re.compile(rb"\((?:\\.|[^\\()])*\)")
_STREAM = re.compile(rb"stream\r?\n(.*?)endstream", re.S)
# /Filter 只出现在 stream 关键字之前几十字节内，向前取 512 字节足够
_FILTER = re.compile(rb"/Filter\s*(?:\[\s*)?((?:/[A-Za-z0-9]+\s*)+)")


def _unescape(raw: bytes) -> str:
    out = bytearray()
    i = 0
    while i < len(raw):
        c = raw[i:i + 1]
        if c == b"\\" and i + 1 < len(raw):
            n = raw[i + 1:i + 2]
            mapping = {b"n": b"\n", b"r": b"\r", b"t": b"\t",
                       b"(": b"(", b")": b")", b"\\": b"\\"}
            if n in mapping:
                out += mapping[n]
                i += 2
                continue
            # 八进制转义 \ddd
            m = re.match(rb"\\([0-7]{1,3})", raw[i:i + 4])
            if m:
                out.append(int(m.group(1), 8) & 0xFF)
                i += len(m.group(0))
                continue
            i += 1
            continue
        out += c
        i += 1
    return out.decode("utf-8", errors="replace")


def _filters(head: bytes) -> list[str]:
    m = _FILTER.search(head)
    if not m:
        return []
    return [x.decode() for x in re.findall(rb"/([A-Za-z0-9]+)", m.group(1))]


def _decode(raw: bytes, filters: list[str]) -> bytes:
    """按 Filter 链顺序解码。未知 Filter 原样返回，交给下游文本抽取失败。"""
    for f in filters:
        try:
            if f in ("FlateDecode", "Fl"):
                raw = zlib.decompress(raw)
            elif f in ("ASCII85Decode", "A85"):
                # ReportLab 产出的是带 `~>` 结束符的 ASCII85
                body = raw.split(b"~>")[0]
                raw = base64.a85decode(body, adobe=False, ignorechars=b" \t\r\n")
            elif f in ("ASCIIHexDecode", "AHx"):
                raw = bytes.fromhex(raw.split(b">")[0].decode("ascii", "ignore"))
            else:
                return raw
        except Exception:
            return raw
    return raw


def pdf_text(data: bytes) -> str:
    """从 PDF 字节里抽出可读文本；失败返回空串（不猜）。"""
    chunks: list[str] = []
    for m in _STREAM.finditer(data):
        head = data[max(0, m.start() - 512):m.start()]
        raw = _decode(m.group(1), _filters(head))
        for op in _PDF_TEXT_OP.finditer(raw):
            s = _unescape(op.group(0)[1:-1])
            if s:
                chunks.append(s)
    text = " ".join(chunks)
    # 中文字形常被拆成多个单字串，压掉多余空白即可用于子串匹配
    return re.sub(r"\s+", " ", text).strip()


def csv_text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def is_pdf(head: bytes) -> bool:
    return head[:5].startswith(b"%PDF")


def as_text(data: bytes, content_type: str = "") -> str:
    """按内容类型把非 JSON 响应压成文本。"""
    if is_pdf(data):
        return pdf_text(data)
    if "csv" in content_type or data[:1] in (b"i", b"\"", b"'"):
        return csv_text(data)
    return data.decode("utf-8", errors="replace")
