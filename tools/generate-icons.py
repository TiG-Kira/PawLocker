#!/usr/bin/env python3
"""生成 PawLocker 的 Windows 图标（.ico）。

为什么要自己画而不是找现成素材：
两端（Windows / Android）需要同一套品牌图形，且要能进版本库、能复现。
把形状写死在脚本里，改一次颜色或比例就重跑一遍，不必依赖设计文件。

图形含义：**肉垫（爪）中间挖出钥匙孔**——爪印是「手机侧的口令」，
钥匙孔是「要开的那把锁」，两者合成同一个形状，正好对应这个项目在做的事。

用法：
    python tools/generate-icons.py

产物：
    windowsApp/icons/pawlocker.ico        多尺寸（16/24/32/48/64/128/256）
    windowsApp/icons/pawlocker-1024.png   源图，便于以后微调或给别的平台用
"""

from __future__ import annotations

import sys
from pathlib import Path

# 只依赖 Pillow。刻意不引入 numpy：这个脚本的价值在于「clone 下来就能跑」，
# 为了两次数组运算把依赖翻倍不划算——渐变改用画线、求差改用 ImageChops。
try:
    from PIL import Image, ImageChops, ImageDraw
except ImportError as exc:  # pragma: no cover - 环境问题，不是逻辑问题
    sys.exit(f"需要 Pillow：{exc}")

# ——————————————————————————————————————————————————————————————
# 画布与调色
# ——————————————————————————————————————————————————————————————

# 渲染尺寸。所有形状坐标都写在这个 1024 空间里，输出时再缩到目标尺寸。
# 用 4 倍于最大图标尺寸（256）的缓冲，是因为 Pillow 不做矢量级抗锯齿——
# 先画大再缩小，是让椭圆和圆角边缘干净的最省事办法。
CANVAS = 1024

# 对角渐变，左上到右下。不用纯色是因为纯深色图标在深色任务栏上会「陷进去」，
# 只剩一个白爪子浮着；带一点色彩过渡才立得住。
COLOR_A = (63, 94, 255)    # #3F5EFF 靛蓝
COLOR_B = (132, 61, 245)   # #843DF5 紫

# 圆角方形的留白与圆角半径。半径取边长的 ~24%（232/944），接近 squircle 观感，
# 比正圆角更「系统图标」一点。
PADDING = 40
CORNER_RADIUS = 232

# 爪印整体上移。几何居中会让它看起来偏下——爪子的「重量」集中在肉垫上。
# 这一版的图形 y 跨度 [212, 810]，中心 511，已经在中线上，所以不再偏移。
Y_SHIFT = 0


def diagonal_gradient(size: int) -> Image.Image:
    """对角渐变底。

    沿 x+y=const 逐条画线。步长取 2*size，让相邻两条线在斜向上只隔半个像素，
    不会留下栅格缝隙。
    """
    grad = Image.new("RGB", (size, size))
    draw = ImageDraw.Draw(grad)
    last = size - 1
    steps = 2 * size
    for i in range(steps):
        t = i / (steps - 1)
        color = tuple(
            int(a + (b - a) * t) for a, b in zip(COLOR_A, COLOR_B)
        )
        draw.line(
            [
                (max(0, i - last), min(i, last)),
                (min(i, last), max(0, i - last)),
            ],
            fill=color,
        )
    return grad


def ellipse_layer(size: int, w: int, h: int, angle: float) -> Image.Image:
    """画一个可旋转的实心椭圆，返回 L 通道图层。

    Pillow 的 ellipse 不能旋转，所以每枚趾垫单独画一层再转。
    图层边长留到 1.8 倍，保证旋转后仍在框内（45° 时对角线最长）。
    """
    box = int(max(w, h) * 1.8)
    layer = Image.new("L", (box, box), 0)
    left, top = (box - w) // 2, (box - h) // 2
    ImageDraw.Draw(layer).ellipse([left, top, left + w, top + h], fill=255)
    if angle:
        layer = layer.rotate(angle, resample=Image.BICUBIC, expand=False)
    return layer


def stamped(mask: Image.Image, w: int, h: int, cx: float, cy: float, angle: float = 0.0) -> None:
    """把一枚椭圆贴到遮罩上（就地修改）。"""
    layer = ellipse_layer(CANVAS, w, h, angle)
    half = layer.width / 2
    mask.paste(layer, (int(cx - half), int(cy - half)), layer)


def paw_mask() -> Image.Image:
    """爪印遮罩：4 枚趾垫 + 1 个肉垫，肉垫里挖出钥匙孔。

    比例是这一版反复调出来的，几个数字都有理由：

    | 部位 | 尺寸 | 依据 |
    |---|---|---|
    | 肉垫 | 425 × 328 | 宽高比 1.3，再圆就变成「脸」而不是肉垫 |
    | 趾垫 | 172 × 213 | 竖长椭圆，宽约为肉垫的 40% |
    | 图形总宽 | 709 | 占圆角内容区（944）的 75%，再大就顶边 |

    第一版把肉垫做成 390 × 300（1.3 看着没问题，但配合过小的趾垫），
    渲染出来读起来是一张脸：四枚趾垫像头发、肉垫像脸、钥匙孔像鼻子。
    根因不是某一处尺寸，是**肉垫占整体太宽、趾垫太散**。缩肉垫、放大并收紧趾垫后才立住。
    """

    def y(v: float) -> float:
        return v + Y_SHIFT

    mask = Image.new("L", (CANVAS, CANVAS), 0)

    # 趾垫：中间两枚高、外侧两枚低并向外倾。
    # 外倾是关键——全都竖直排会看起来像一排鸡蛋，不像爪子。
    # 倾角也别贪大：外趾倾到 30° 以上，其水平投影会盖住中间两枚，
    # 五枚糊成一团。30° 是「看得出外张」和「彼此不重叠」的平衡点。
    #
    # 位置同样是调出来的。第一版各部件排得开，渲染出来是「五个独立的白球」，
    # 没有爪印的紧凑感。现在的间距（相邻趾垫中心距 ~160-182，与肉垫间隙 ~11）
    # 让它们挨着但不融合——真爪印本来就是这样。
    for cx, cy, angle in (
        (272, 405, -30.0),
        (432, 318, -11.0),
        (592, 318, 11.0),
        (752, 405, 30.0),
    ):
        stamped(mask, 172, 213, cx, y(cy), angle)

    # 肉垫。宽高比 1.47（440×300）——比「看着合理」的 1.3 更扁。
    # 1.3 渲染出来是颗鸡蛋；真实的爪垫是被踩扁的，底部宽、整体扁。
    stamped(mask, 440, 300, 512, y(660))

    # 钥匙孔：负空间。圆在上、柄向下——这是「钥匙孔」和「圆点加方块」的区别。
    #
    # 柄的**顶边取在圆心高度**（633）而不是圆的底部（693）：从圆心开始收窄，
    # 圆与柄的相接处才是平滑的。若从圆底起画，两者之间会多出一对「肩」，
    # 形状立刻变成水滴。
    hole = Image.new("L", (CANVAS, CANVAS), 0)
    hd = ImageDraw.Draw(hole)
    hd.ellipse([452, y(573), 572, y(693)], fill=255)
    hd.polygon(
        [(462, y(633)), (562, y(633)), (546, y(743)), (478, y(743))],
        fill=255,
    )

    # 用相减而不是往 mask 里画 0：钥匙孔只能和大肉垫求差，
    # 直接填 0 会连带擦掉与之相交的趾垫。
    return ImageChops.subtract(mask, hole)


def render(size: int = CANVAS) -> Image.Image:
    """渲染一张 RGBA 图，尺寸为 [size]。"""
    scale = size / CANVAS
    grad = diagonal_gradient(size)

    paw = paw_mask()
    if size != CANVAS:
        paw = paw.resize((size, size), Image.LANCZOS)

    # 白爪印贴在渐变上（而不是压成纯白块——钥匙孔要能透出渐变）
    body = Image.composite(Image.new("RGB", (size, size), (255, 255, 255)), grad, paw)

    # 圆角方形裁切
    shape = Image.new("L", (size, size), 0)
    pad = int(PADDING * scale)
    ImageDraw.Draw(shape).rounded_rectangle(
        [pad, pad, size - pad - 1, size - pad - 1],
        radius=int(CORNER_RADIUS * scale),
        fill=255,
    )

    out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    out.paste(body, (0, 0), shape)
    return out


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    out_dir = root / "windowsApp" / "icons"
    out_dir.mkdir(parents=True, exist_ok=True)

    master = render(CANVAS)
    master.save(out_dir / "pawlocker-1024.png")

    # 交给 Pillow 生成多尺寸 ICO。它内部会从最大边逐档 LANCZOS 缩放，
    # 并且小尺寸用 BMP 编码、256 用 PNG 编码——这个兼容性处理不值得自己重写。
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    master.resize((256, 256), Image.LANCZOS).save(
        out_dir / "pawlocker.ico", format="ICO", sizes=sizes
    )

    ico = out_dir / "pawlocker.ico"
    print(f"已写出 {ico}  ({ico.stat().st_size} 字节)")
    print(f"已写出 {out_dir / 'pawlocker-1024.png'}")


if __name__ == "__main__":
    main()
