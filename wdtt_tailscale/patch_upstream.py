"""Fail-closed patch: external wdttd MUST NOT modify Linux main route table.

This project is a HAOS client. The parent upstream OpenWrt implementation
installs bypass routes for TURN, VK and DNS even when routing_mode=external;
those routes must be handled by the HAOS normal route instead.
"""
from __future__ import annotations
import pathlib
import re
import sys


def patch(path: pathlib.Path) -> None:
    src = path.read_text(encoding='utf-8')
    matcher = re.compile(
        r'(\tvar routes \[\]string\n)'
        r'(\tgw, uplinkDev := gatewayForUplink\(uplinkIface\)\n.*?)'
        r'(?=\t// full —|\tif mode == ModeFull \{)',
        re.DOTALL,
    )
    def fix(match: re.Match[str]) -> str:
        # Keep the OpenWrt implementation intact for full/selective modes,
        # but leave main table completely untouched in external mode.
        statements = match.group(2)
        return match.group(1) + '\tif mode != ModeExternal {\n' + ''.join('\t'+s for s in statements.splitlines(keepends=True)) + '\t}\n'
    changed, count = matcher.subn(fix, src)
    if count != 2:
        raise SystemExit(f'FAIL CLOSED: expected exactly 2 upstream bypass route sections, found {count}')
    if changed.count('if mode != ModeExternal {') != 2:
        raise SystemExit('FAIL CLOSED: unguarded routing code')
    path.write_text(changed, encoding='utf-8')

if __name__ == '__main__':
    patch(pathlib.Path(sys.argv[1]))
