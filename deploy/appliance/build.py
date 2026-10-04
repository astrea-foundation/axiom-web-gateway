"""Build a disk whose complete executable root lives in a measured UKI.

The UKI is Secure Boot signed, but its candidate metadata is not a release trust
document. Publishing trust documents is a separate release-authority operation
using a qualified Azure firmware/boot profile.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import pefile


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def file_digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def copy_binary(binary, root):
    target = root / binary.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, target)
    dependencies = subprocess.check_output(["ldd", binary], text=True)
    for line in dependencies.splitlines():
        for value in re.findall(r"(/[\w./+-]+)", line):
            if Path(value).is_file():
                dest = root / value.lstrip("/")
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(value, dest)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", default="/output")
    parser.add_argument("--secure-boot-key", required=True)
    parser.add_argument("--secure-boot-certificate", required=True)
    parser.add_argument("--epoch", required=True, type=int)
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    root = output / "root"
    if root.exists():
        raise SystemExit("output root already exists; use a new empty output directory")
    for directory in ["bin", "usr/bin", "etc/axiom-gateway", "proc", "sys", "dev", "run", "tmp", "lib"]:
        (root / directory).mkdir(parents=True, exist_ok=True)
    # Keep only the runtime and its dynamic dependencies. No package manager,
    # cloud agents, executable disk mounts or an administrative network service.
    copy_binary("/usr/local/bin/axiom-web-gateway", root)
    copy_binary("/usr/bin/setpriv", root)
    copy_binary("/usr/sbin/modprobe", root)
    shutil.copy2("/bin/busybox", root / "bin/busybox")
    for name in ["sh", "mount", "mkdir", "ip", "udhcpc", "modprobe", "chown", "chmod", "reboot"]:
        (root / "bin" / name).symlink_to("busybox")
    for name in ["init", "dhcp"]:
        dest = root / ("init" if name == "init" else "etc/axiom-gateway/dhcp")
        shutil.copy2(Path("/build-tools") / name, dest)
        dest.chmod(0o755)
    shutil.copy2(args.config, root / "etc/axiom-gateway/config.json")
    (root / "etc/resolv.conf").write_text("nameserver 168.63.129.16\n")
    shutil.copytree("/etc/ssl", root / "etc/ssl")
    (root / "etc/passwd").write_text("gateway:x:10001:10001:gateway:/nonexistent:/bin/false\n")
    (root / "etc/group").write_text("gateway:x:10001:\n")
    kernel = sorted(Path("/boot").glob("vmlinuz-*-amd64"))[-1]
    release = kernel.name.removeprefix("vmlinuz-")
    module_root = root / "lib/modules" / release
    module_root.mkdir(parents=True)
    for metadata in ["modules.builtin", "modules.builtin.modinfo", "modules.order"]:
        shutil.copy2(Path("/lib/modules") / release / metadata, module_root / metadata)
    for driver in ["hv_vmbus", "hv_netvsc", "tpm_crb", "tpm_tis"]:
        dependencies = subprocess.check_output(["modprobe", "-S", release, "--show-depends", driver], text=True)
        for line in dependencies.splitlines():
            if line.startswith("insmod "):
                source = Path(line.split()[1])
                dest = root / str(source).lstrip("/")
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, dest)
    run("depmod", "-b", str(root), release)
    for path in sorted(root.rglob("*"), reverse=True):
        os.utime(path, (args.epoch, args.epoch), follow_symlinks=False)
    # newc records sorted paths, fixed ownership and timestamps.
    files = [".", *sorted(str(p.relative_to(root)) for p in root.rglob("*"))]
    initrd = output / "initrd"
    with initrd.open("wb") as target:
        run("cpio", "--null", "-o", "--format=newc", "--owner=0:0", "--reproducible", input=b"\0".join(p.encode() for p in files) + b"\0", cwd=root, stdout=target)
    osrel = output / "os-release"
    osrel.write_text('ID=axiom-gateway\nNAME="Axiom Web Gateway"\nVERSION_ID=1\n')
    cmdline = output / "cmdline"
    cmdline.write_text("quiet loglevel=0 console=null rd.shell=0 panic=5 oops=panic module.sig_enforce=1 lockdown=confidentiality\n")
    uki = output / "gateway.efi"
    sections = ["--linux=" + str(kernel), "--initrd=" + str(initrd), "--os-release=@" + str(osrel), "--cmdline=@" + str(cmdline)]
    run("ukify", "build", *sections, "--secureboot-private-key=" + args.secure_boot_key,
        "--secureboot-certificate=" + args.secure_boot_certificate, "--output=" + str(uki))
    pe_output = subprocess.check_output(["pesign", "--hash", "--in", str(uki), "--digest_type", "sha256"], text=True)
    pe_digest = re.search(r"\b([a-fA-F0-9]{64})\b", pe_output)
    if not pe_digest:
        raise SystemExit("PE/COFF image digest unavailable")
    # systemd-stub extends these exact embedded sections into PCR11. No
    # systemd userspace phase service runs, so there are no additional extends.
    # Extract actual PE sections: ukify also adds .uname and merged .sbat, and
    # padding/NUL normalization must match the bytes the stub will measure.
    measured = {".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat", ".pcrpkey", ".dtb", ".ucode", ".hwids", ".dtbauto", ".profile"}
    command = ["/usr/lib/systemd/systemd-measure", "calculate", "--bank=sha256", "--phase=", "--json=short"]
    pe = pefile.PE(str(uki))
    for section in pe.sections:
        name = section.Name.rstrip(b"\0").decode("ascii")
        if name in measured:
            path = output / ("section" + name)
            path.write_bytes(section.get_data()[:section.Misc_VirtualSize])
            command.append("--" + name[1:] + "=" + str(path))
    measurement = subprocess.check_output(command, text=True)
    (output / "pcr11.json").write_text(measurement)
    disk = output / "gateway.raw"
    with disk.open("wb") as handle: handle.truncate(1024 * 1024 * 1024)
    run("sgdisk", "--clear", "--new=1:2048:0", "--typecode=1:EF00", str(disk))
    esp = output / "esp.fat"
    with esp.open("wb") as handle: handle.truncate(1024 * 1024 * 1024 - 1048576 - 1048576)
    run("mkfs.vfat", "-F", "32", str(esp))
    run("mmd", "-i", str(esp), "::EFI", "::EFI/BOOT")
    run("mcopy", "-i", str(esp), str(uki), "::EFI/BOOT/BOOTX64.EFI")
    with disk.open("r+b") as target, esp.open("rb") as source:
        target.seek(1048576); shutil.copyfileobj(source, target)
    run("qemu-img", "convert", "-f", "raw", "-O", "vpc", "-o", "subformat=fixed,force_size=on", str(disk), str(output / "gateway.vhd"))
    receipt = {"schema_version": 1, "appliance_sha256": file_digest(output / "gateway.vhd"),
               "uki_sha256": file_digest(uki), "uki_pe_sha256": pe_digest[1].lower(), "pcr11": json.loads(measurement),
               "secure_boot_certificate_sha256": file_digest(args.secure_boot_certificate)}
    (output / "candidate.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
