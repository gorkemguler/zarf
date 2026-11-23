#!/usr/bin/env python3
"""Build a spec-compliant Debian .deb package using only the Python standard library."""

import io
import os
import sys
import tarfile
import time


def add_bytes_to_tar(tf: tarfile.TarFile, arcname: str, data: bytes, mode: int, mtime: int):
    ti = tarfile.TarInfo(name=arcname)
    ti.size = len(data)
    ti.mode = mode
    ti.uid = 0
    ti.gid = 0
    ti.uname = "root"
    ti.gname = "root"
    ti.mtime = mtime
    tf.addfile(ti, io.BytesIO(data))


def add_dir_to_tar(tf: tarfile.TarFile, arcname: str, mtime: int):
    ti = tarfile.TarInfo(name=arcname)
    ti.type = tarfile.DIRTYPE
    ti.mode = 0o755
    ti.uid = 0
    ti.gid = 0
    ti.uname = "root"
    ti.gname = "root"
    ti.mtime = mtime
    tf.addfile(ti)


def write_ar_member(out: io.BufferedWriter, name: str, data: bytes, mtime: int):
    # GNU ar header is 60 ASCII bytes:
    # name(16), mtime(12), uid(6), gid(6), mode(8), size(10), fmag(2)
    header = (
        f"{name:<16}"
        f"{mtime:<12}"
        f"{0:<6}"
        f"{0:<6}"
        f"{'100644':<8}"
        f"{len(data):<10}"
        "`\n"
    ).encode("ascii")
    assert len(header) == 60, f"bad ar header len: {len(header)}"
    out.write(header)
    out.write(data)
    if len(data) % 2 == 1:
        out.write(b"\n")


def main():
    if len(sys.argv) != 7:
        print(
            "Usage: make_deb.py <version> <deb_arch> <binary_path> <desktop_path> <icon_svg_path> <out_deb>",
            file=sys.stderr,
        )
        sys.exit(1)

    version, arch, bin_path, desktop_path, icon_path, out_deb = sys.argv[1:7]
    mtime = int(time.time())

    with open(bin_path, "rb") as f:
        bin_data = f.read()
    with open(desktop_path, "rb") as f:
        desktop_data = f.read()
    with open(icon_path, "rb") as f:
        icon_data = f.read()

    # Build data.tar.gz
    data_buf = io.BytesIO()
    with tarfile.open(fileobj=data_buf, mode="w:gz") as tf:
        for d in [
            "./usr",
            "./usr/local",
            "./usr/local/bin",
            "./usr/share",
            "./usr/share/applications",
            "./usr/share/icons",
            "./usr/share/icons/hicolor",
            "./usr/share/icons/hicolor/scalable",
            "./usr/share/icons/hicolor/scalable/apps",
        ]:
            add_dir_to_tar(tf, d, mtime)
        add_bytes_to_tar(tf, "./usr/local/bin/zarf", bin_data, 0o755, mtime)
        add_bytes_to_tar(tf, "./usr/share/applications/zarf.desktop", desktop_data, 0o644, mtime)
        add_bytes_to_tar(tf, "./usr/share/icons/hicolor/scalable/apps/zarf.svg", icon_data, 0o644, mtime)
    data_tar_gz = data_buf.getvalue()

    installed_kb = max(1, (len(bin_data) + len(desktop_data) + len(icon_data)) // 1024)
    control_text = (
        f"Package: zarf\n"
        f"Version: {version}\n"
        f"Section: utils\n"
        f"Priority: optional\n"
        f"Architecture: {arch}\n"
        f"Installed-Size: {installed_kb}\n"
        f"Maintainer: Gorkem Guler <94464662+gorkemguler@users.noreply.github.com>\n"
        f"Homepage: https://github.com/gorkemguler/zarf\n"
        f"Description: Offline .eml phishing autopsy and email forensics tool\n"
        f" Single-binary zero-dependency Go CLI and embedded localhost Web UI for\n"
        f" 100% offline email forensics: SMTP hop graphs, RFC 6376 DKIM body-hash\n"
        f" verification, HTML smuggling detection, Punycode/homoglyph URL inspection,\n"
        f" static attachment analysis, and STIX 2.1 / Markdown / Takedown exports.\n"
    ).encode("utf-8")

    # Build control.tar.gz
    ctrl_buf = io.BytesIO()
    with tarfile.open(fileobj=ctrl_buf, mode="w:gz") as tf:
        add_bytes_to_tar(tf, "./control", control_text, 0o644, mtime)
    ctrl_tar_gz = ctrl_buf.getvalue()

    os.makedirs(os.path.dirname(os.path.abspath(out_deb)), exist_ok=True)
    with open(out_deb, "wb") as out:
        out.write(b"!<arch>\n")
        write_ar_member(out, "debian-binary", b"2.0\n", mtime)
        write_ar_member(out, "control.tar.gz", ctrl_tar_gz, mtime)
        write_ar_member(out, "data.tar.gz", data_tar_gz, mtime)

    print(f"built {out_deb} ({os.path.getsize(out_deb)} bytes)")


if __name__ == "__main__":
    main()
