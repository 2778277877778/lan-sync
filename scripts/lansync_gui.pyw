#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lan-sync 图形界面入口：双击运行，或打包成窗口版 exe。

带命令行参数时（例如 GUI 内部启动后台服务）转发给标准 CLI，行为与 lansync.py 完全一致。
"""

import sys

from lansync import gui, main

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()
    else:
        gui()
