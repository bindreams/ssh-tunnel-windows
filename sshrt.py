import ctypes
import sys
from argparse import ArgumentParser
import subprocess
import base64
import colorama
from colorama import Fore, Style
from pathlib import Path
import shutil
import os
from zipfile import ZipFile
import yaml
import sys
import re
import sys
import hashlib

isadmin = ctypes.windll.shell32.IsUserAnAdmin() != 0
dir = Path(__file__).parent
bindir = dir / "bin"
tempdir = dir / "temp"


def run(command, **kwargs):
    kwargs["check"] = kwargs.get("check", True)
    if isinstance(command, list):
        display_command = " ".join([str(x) for x in command])
    else:
        display_command = command
    print(f"{Fore.WHITE}{Style.BRIGHT}+ {display_command}")

    try:
        return subprocess.run(command, **kwargs)
    except subprocess.CalledProcessError:
        print(f"sshtunnel failed while running: {display_command}")
        raise


def pwsh(command: str):
    print(f"{Fore.WHITE}{Style.BRIGHT}+ {command}")
    command_with_erroraction = f"$ErrorActionPreference = \"Stop\"; {command}"
    encoded_command = base64.b64encode(command_with_erroraction.encode("UTF-16LE"))
    try:
        return subprocess.run(["powershell.exe", "-EncodedCommand", encoded_command], check=True)
    except subprocess.CalledProcessError:
        print(f"sshtunnel failed while running: {command}")
        raise


def pwsh_query(command: str):
    print(f"{Fore.WHITE}{Style.BRIGHT}+ {command}")
    command_with_erroraction = f"$ErrorActionPreference = \"Stop\"; {command}"
    encoded_command = base64.b64encode(command_with_erroraction.encode("UTF-16LE"))
    try:
        return subprocess.run(["powershell.exe", "-EncodedCommand", encoded_command], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print(f"sshtunnel failed while running: {command}")
        raise


def filehash(path):
    # BUF_SIZE is totally arbitrary, change for your app!
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    sha256 = hashlib.sha256()

    with open(path, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)

    return sha256.hexdigest()


def log(message):
    print(f"{Fore.CYAN}{Style.BRIGHT}# {message}")


def error(message):
    print(f"{Fore.RED}{Style.BRIGHT}# {message}")


SID_ADMINISTRATORS = "S-1-5-32-544"
SID_SYSTEM = "S-1-5-18"
SID_NETWORK_SERVICE = "S-1-5-20"
sudo = [bindir / "PsExec64.exe", "-nobanner", "-accepteula", "-s"]


def setpermissions(path, *, sids=[SID_SYSTEM, SID_ADMINISTRATORS]):
    run(sudo + ["takeown", "/A", "/F", path])  # Administrators own this
    run(sudo + ["icacls.exe", path, "/reset"])
    run(sudo + ["icacls.exe", path, "/inheritance:r"])

    # Set correct permissions
    for sid in sids:
        run(sudo + ["icacls.exe", path, "/inheritance:r", "/grant", f"*{sid}:F"])


def ensurefile(path, *, directory=False, sids=[SID_SYSTEM, SID_ADMINISTRATORS]):
    """Ensure that a file exists and has permissions set."""
    path = Path(path)
    if path.exists():
        if path.is_file() and directory == True:
            raise RuntimeError("Path \"path\" exists but is not a file.")
        elif not path.is_file() and directory == False:
            raise RuntimeError("Path \"path\" exists but is not a directory.")
    elif directory == False:
        path.touch()
    else:
        path.mkdir(exist_ok=True)

    setpermissions(path, sids=sids)


def fix_permissions(path):
    path = Path(path)

    try:
        setpermissions(path, sids=[SID_SYSTEM, SID_NETWORK_SERVICE, SID_ADMINISTRATORS])
    except subprocess.CalledProcessError:
        return 1
    except RuntimeError:
        return 2


def winsw_fingerprint(path):
    hash = filehash(path)
    version = pwsh_query(f"(Get-Item '{path}').VersionInfo.FileVersion").stdout.decode().strip()
    return hash, version


def install(tunnel_name):
    programdata = os.getenv("ProgramData")
    servicesdir = Path(f"{programdata}/SshReverseTunnel/services")
    service_exe = servicesdir / f"{tunnel_name}.exe"
    service_yaml = servicesdir / f"{tunnel_name}.yml"

    try:
        with open(dir / "service-template.yml") as f:
            template_str = f.read()

        config_str, _ = re.subn("\${TunnelName}", tunnel_name, template_str)
        config = yaml.safe_load(config_str)

        service_exists_query = pwsh_query(f"Get-Service -Name {config['id']}")
        if service_exists_query.returncode == 0:
            error(f"Service {config['id']} already exists. Re-run this command with --force to remove it.")
            raise RuntimeError

        log("Running the test command")
        try:
            run("psexec -u \"NT AUTHORITY\\NETWORK SERVICE\" -nobanner -accepteula "
                f"{config['executable']} {config['testArguments']}", shell=True)
        except subprocess.CalledProcessError:
            error("Service test failed.")
            raise RuntimeError

        log(f"Installing SSH tunnel \"{tunnel_name}\"")
        # WinSW requires us to rename it to <tunnel_name>.exe an to place it alongside the yaml file.
        # To not duplicate executables we will scan the services directory and create a hardlink if an executable
        # already exists.
        target_fingerprint = winsw_fingerprint(bindir / "WinSW.exe")
        programdata = os.getenv("ProgramData")
        servicesdir = Path(f"{programdata}/SshReverseTunnel/services")
        service_exe = servicesdir / f"{tunnel_name}.exe"

        for exe in servicesdir.glob("*.exe"):
            if winsw_fingerprint(exe) == target_fingerprint:
                service_exe.hardlink_to(exe)
                break
        else:
            # We can't create a hard link to our WinSW because it might not be on the same disk.
            shutil.copy(bindir / "WinSW.exe", service_exe)
        setpermissions(service_exe, sids=[SID_SYSTEM, SID_NETWORK_SERVICE, SID_ADMINISTRATORS])

        with open(service_yaml, "w", encoding="utf-8") as f:
            yaml.dump(config, f)
        setpermissions(service_yaml, sids=[SID_SYSTEM, SID_NETWORK_SERVICE, SID_ADMINISTRATORS])

        run(f"{service_exe} install")

    except subprocess.CalledProcessError:
        service_yaml.unlink(missing_ok=True)
        service_exe.unlink(missing_ok=True)
        return 1
    except RuntimeError:
        service_yaml.unlink(missing_ok=True)
        service_exe.unlink(missing_ok=True)
        return 2


def bootstrap(entry_shell=None):
    try:
        log("Installing system OpenSSH")
        pwsh("Add-WindowsCapability -Online -Name OpenSSH.Client")
        pwsh("Add-WindowsCapability -Online -Name OpenSSH.Server")

        firewall_rule_query = pwsh_query("(Get-NetFirewallRule -Name \"OpenSSH-Server-In-TCP\").Enabled")
        if firewall_rule_query.returncode != 0:
            log("Adding firewall rule for OpenSSH")
            pwsh("New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22")
        elif not firewall_rule_query.stdout.startswith(b"True"):
            log("Enabling firewall rule for OpenSSH")
            pwsh("Enable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP'")

        entry_shell_exists_query = pwsh_query("(Get-ItemProperty -Path \"HKLM:\\SOFTWARE\\OpenSSH\").DefaultShell")
        entry_shell_exists_query_stdout = entry_shell_exists_query.stdout.decode().strip()
        if entry_shell_exists_query.returncode == 0 and entry_shell_exists_query_stdout != "" and entry_shell is None:
            log(f"Entry shell for SSH sessions already configured to \"{entry_shell_exists_query_stdout}\"")
        else:
            if entry_shell is None:
                default_shell_query = pwsh_query("Get-Command pwsh.exe")
                if default_shell_query.returncode == 0:
                    entry_shell = "pwsh.exe"
                else:
                    entry_shell = "powershell.exe"

            log(f"Setting entry shell for SSH sessions to \"{entry_shell}\"")
            entry_shell_path_query = pwsh_query(f"(Get-Command {entry_shell}).Path")
            if entry_shell_path_query.returncode != 0:
                error(f"Could not resolve full path for entry shell \"{entry_shell}\"")
                raise RuntimeError
            entry_shell_path = entry_shell_path_query.stdout.decode().strip()
            pwsh(
                f"New-ItemProperty -Path \"HKLM:\\SOFTWARE\\OpenSSH\" -Name DefaultShell -Value \"{entry_shell_path}\" -PropertyType String -Force")

        log("Downloading dependencies")
        if bindir.exists():
            shutil.rmtree(bindir)
        if tempdir.exists():
            shutil.rmtree(tempdir)
        bindir.mkdir(parents=True, exist_ok=True)
        tempdir.mkdir(parents=True, exist_ok=True)

        run(["curl", "-L", "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe", "-o", bindir / "WinSW.exe"])
        run(["curl", "-L", "https://download.sysinternals.com/files/PSTools.zip", "-o", tempdir / "PSTools.zip"])
        with ZipFile(tempdir / "PSTools.zip", "r") as zf:
            zf.extract("PsExec64.exe", bindir)
        (tempdir / "PSTools.zip").unlink()

        programdata = os.getenv("ProgramData")

        log("Generating host SSH keys")
        run(sudo + ["ssh-keygen", "-A"])
        for hostkey in Path(f"{programdata}/ssh").glob("ssh_host_*"):
            setpermissions(hostkey)

        log("Creating necessary files")
        ensurefile(f"{programdata}\\ssh\\administrators_authorized_keys")
        ensurefile(f"{programdata}\\ssh\\ssh_known_hosts", sids=[SID_SYSTEM, SID_ADMINISTRATORS, SID_NETWORK_SERVICE])

        ensurefile(f"{programdata}\\SshReverseTunnel", directory=True)
        ensurefile(f"{programdata}\\SshReverseTunnel\\services", directory=True,
                   sids=[SID_SYSTEM, SID_ADMINISTRATORS, SID_NETWORK_SERVICE])
        ensurefile(f"{programdata}\\SshReverseTunnel\\logs", directory=True,
                   sids=[SID_SYSTEM, SID_ADMINISTRATORS, SID_NETWORK_SERVICE])
        ensurefile(f"{programdata}\\SshReverseTunnel\\config", sids=[
                   SID_SYSTEM, SID_ADMINISTRATORS, SID_NETWORK_SERVICE])
        ensurefile(f"{programdata}\\SshReverseTunnel\\config.d", directory=True,
                   sids=[SID_SYSTEM, SID_ADMINISTRATORS, SID_NETWORK_SERVICE])

        log("Starting OpenSSH Server")
        pwsh("Start-Service -Name sshd")
        pwsh("Set-Service -Name sshd -StartupType Automatic")

    except subprocess.CalledProcessError:
        return 1
    except RuntimeError:
        return 2


def cli():
    parser = ArgumentParser("ssh-tunnel")
    subparsers = parser.add_subparsers(dest="command")

    bootstrap = subparsers.add_parser("bootstrap")
    bootstrap.add_argument("--entry-shell")

    install = subparsers.add_parser("install")
    install.add_argument("tunnel_name")

    fix_permissions = subparsers.add_parser("fix-permissions")
    fix_permissions.add_argument("path")

    return parser


def main():
    colorama.init(autoreset=True)

    if not isadmin:
        print("Please restart me from an admin shell.")
        return 1

    args = cli().parse_args()
    if args.command == "bootstrap":
        return bootstrap(entry_shell=args.entry_shell)
    if args.command == "install":
        return install(tunnel_name=args.tunnel_name)
    if args.command == "fix-permissions":
        return fix_permissions(path=args.path)


if __name__ == "__main__":
    sys.exit(main())
