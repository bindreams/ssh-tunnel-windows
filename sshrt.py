import base64
import ctypes
import hashlib
import os
import re
import shutil
import subprocess
import sys
from argparse import ArgumentParser
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import colorama
import yaml
from colorama import Fore, Style

# Static data ==========================================================================================================
dirs = SimpleNamespace()
dirs.repo = Path(__file__).parent
dirs.programdata = Path(os.getenv("ProgramData", "C:/ProgramData"))
dirs.root = dirs.programdata / "SshReverseTunnel"
dirs.ssh = dirs.programdata / "ssh"
dirs.configs = dirs.root / "config.d"
dirs.services = dirs.root / "services"
dirs.logs = dirs.root / "logs"
dirs.temp = dirs.repo / "temp"
dirs.bin = dirs.repo / "bin"

files = SimpleNamespace()
files.winsw = dirs.bin / "WinSW.exe"
files.psexec = dirs.bin / "PsExec64.exe"
files.authorized_keys = dirs.ssh / "administrators_authorized_keys"
files.known_hosts = dirs.ssh / "ssh_known_hosts"
files.config = dirs.root / "config"

sids = SimpleNamespace()
sids.administrators = "S-1-5-32-544"
sids.system = "S-1-5-18"
sids.network_service = "S-1-5-20"

default_config = b"""
Host *
\tBatchMode            yes
\tIdentitiesOnly       yes
\tExitOnForwardFailure yes
\tTCPKeepAlive         yes
\tServerAliveInterval  10
\tServerAliveCountMax  3

Include __PROGRAMDATA__/SshReverseTunnel/config.d/*
""".lstrip()

# Run shell commands ===================================================================================================
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
        error(f"Script failed while running: {display_command}")
        raise


def sudo(command, **kwargs):
    """Run a command as `NT AUTHORITY\SYSTEM`."""
    return run([files.psexec, "-nobanner", "-accepteula", "-s"] + command, **kwargs)


def pwsh(command: str):
    print(f"{Fore.WHITE}{Style.BRIGHT}+ {command}")
    command_with_erroraction = f"$ErrorActionPreference = \"Stop\"\n{command}"
    encoded_command = base64.b64encode(command_with_erroraction.encode("UTF-16LE"))
    try:
        return subprocess.run(["powershell.exe", "-EncodedCommand", encoded_command], check=True)
    except subprocess.CalledProcessError:
        error(f"Script failed while running: {command}")
        raise


def pwsh_query(command: str):
    """Same as pwsh() but does not throw on error and pipes stdout/stderr to inspect after."""
    print(f"{Fore.WHITE}{Style.BRIGHT}+ {command}")
    command_with_erroraction = f"$ErrorActionPreference = \"Stop\"\n{command}"
    encoded_command = base64.b64encode(command_with_erroraction.encode("UTF-16LE"))
    try:
        return subprocess.run(
            ["powershell.exe", "-EncodedCommand", encoded_command],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except subprocess.CalledProcessError:
        error(f"Script failed while running: {command}")
        raise


# Report messages ======================================================================================================
def msg(message, color):
    # Add "# " before each line
    message = "\n".join(f"# {s}" for s in message.split("\n"))
    print(f"{color}{Style.BRIGHT}{message}")


def log(message):
    msg(message, color=Fore.CYAN)


def error(message):
    msg(message, color=Fore.RED)


# Utility functions ====================================================================================================
def filehash(path):
    BUF_SIZE = 65536  # Recommended as a good default for Windows
    sha256 = hashlib.sha256()

    with open(path, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)

    return sha256.hexdigest()


def setpermissions(path, *, extrasids=None):
    if isinstance(extrasids, str):
        extrasids = {extrasids}
    extrasids = extrasids or set()
    extrasids |= {sids.system, sids.administrators}  # Always add SYSTEM and Administrators to the list

    path = Path(path)

    sudo(["takeown", "/A", "/F", path])  # Administrators group own this
    run(["icacls.exe", path, "/reset"])

    # Set correct permissions
    permissions = "F"
    if path.is_dir():
        permissions = "(OI)(CI)F"

    command = ["icacls.exe", path, "/inheritance:r"]
    for sid in extrasids:
        command += ["/grant", f"*{sid}:{permissions}"]

    run(command)


def ensurefile(path, *, contents: bytes = None, directory=False, extrasids=None):
    """Ensure that a file exists and has permissions set."""
    path = Path(path)
    if path.exists():
        if path.is_file() and directory == True:
            raise RuntimeError("Path \"path\" exists but is not a file.")
        elif not path.is_file() and directory == False:
            raise RuntimeError("Path \"path\" exists but is not a directory.")
    elif directory == False:
        if contents is not None:
            with open(path, "wb") as f:
                f.write(contents)
        else:
            path.touch()
    else:
        if contents is not None:
            raise ValueError("cannot specify contents together with directory=True")

        path.mkdir()

    setpermissions(path, extrasids=extrasids)


def ensuredir(path, *, extrasids=None):
    return ensurefile(path, directory=True, extrasids=extrasids)


def winsw_fingerprint(path):
    hash = filehash(path)
    version = pwsh_query(f"(Get-Item '{path}').VersionInfo.FileVersion").stdout.decode().strip()
    return hash, version


# Command-line commands ================================================================================================
def fix_permissions(path):
    try:
        setpermissions(path, extrasids=sids.network_service)
    except subprocess.CalledProcessError:
        return 1
    except RuntimeError:
        return 2


def install(tunnel_name):
    service_exe = dirs.services / f"{tunnel_name}.exe"
    service_yaml = dirs.services / f"{tunnel_name}.yml"

    try:
        with open(dirs.repo / "service-template.yml") as f:
            template_str = f.read()

        config_str, _ = re.subn("\${TunnelName}", tunnel_name, template_str)
        config = yaml.safe_load(config_str)

        service_exists_query = pwsh_query(f"Get-Service -Name {config['id']}")
        if service_exists_query.returncode == 0:
            error(
                f"Service {config['id']} already exists. You can delete it manually by running:\n"
                f"  sc stop {config['id']}\n"
                f"  sc delete {config['id']}"
            )
            raise RuntimeError

        log("Running the test command")
        try:
            run(f"{files.psexec} -u \"NT AUTHORITY\\NETWORK SERVICE\" -nobanner -accepteula "
                f"{config['executable']} {config['testArguments']}", shell=True)
        except subprocess.CalledProcessError:
            error("Service test failed.")
            raise RuntimeError

        log(f"Installing SSH tunnel \"{tunnel_name}\"")
        # WinSW requires us to rename it to <tunnel_name>.exe an to place it alongside the yaml file.
        # To not duplicate executables we will scan the services directory and create a hardlink if an executable
        # already exists.
        target_fingerprint = winsw_fingerprint(dirs.bin / "WinSW.exe")
        service_exe.unlink(missing_ok=True)  # Remove service exe if it was left out by a broken service removal

        for exe in dirs.services.glob("*.exe"):
            if winsw_fingerprint(exe) == target_fingerprint:
                service_exe.hardlink_to(exe)
                break
        else:
            # We can't create a hard link to our WinSW because it might not be on the same disk.
            shutil.copy(dirs.bin / "WinSW.exe", service_exe)
        setpermissions(service_exe, extrasids=sids.network_service)

        with open(service_yaml, "w", encoding="utf-8") as f:
            yaml.dump(config, f)
        setpermissions(service_yaml, extrasids=sids.network_service)

        run([service_exe, "install"])

    except subprocess.CalledProcessError:
        return 1
    except RuntimeError:
        return 2


def bootstrap(entry_shell=None):
    try:
        log("Installing system OpenSSH")
        pwsh("Add-WindowsCapability -Online -Name OpenSSH.Client")
        pwsh("Add-WindowsCapability -Online -Name OpenSSH.Server")

        firewall_rule_query = pwsh_query("(Get-NetFirewallRule -Name \"OpenSSH-Server-In-TCP\").Enabled")
        if firewall_rule_query.returncode != 0:
            log("Adding firewall rule for OpenSSH")
            pwsh("New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True"
                 " -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22")
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
                "New-ItemProperty"
                " -Path \"HKLM:\\SOFTWARE\\OpenSSH\""
                " -Name DefaultShell"
                f" -Value \"{entry_shell_path}\""
                " -PropertyType String"
                " -Force"
            )

        log("Downloading dependencies")
        if dirs.bin.exists():
            shutil.rmtree(dirs.bin)
        if dirs.temp.exists():
            shutil.rmtree(dirs.temp)
        dirs.bin.mkdir()
        dirs.temp.mkdir()

        run(["curl", "-L", "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe", "-o", files.winsw])
        run(["curl", "-L", "https://download.sysinternals.com/files/PSTools.zip", "-o", dirs.temp / "PSTools.zip"])
        with ZipFile(dirs.temp / "PSTools.zip", "r") as zf:
            with zf.open("PsExec64.exe", "r") as src, open(files.psexec, "wb") as dst:
                shutil.copyfileobj(src, dst)
        shutil.rmtree(dirs.temp)

        log("Generating host SSH keys")
        sudo(["ssh-keygen", "-A"])
        for hostkey in dirs.ssh.glob("ssh_host_*"):
            setpermissions(hostkey)

        log("Creating necessary files")
        ensurefile(files.authorized_keys)
        ensurefile(files.known_hosts, extrasids=sids.network_service)

        ensuredir(dirs.root)
        ensuredir(dirs.services, extrasids=sids.network_service)
        ensuredir(dirs.logs, extrasids=sids.network_service)
        ensuredir(dirs.configs, extrasids=sids.network_service)
        ensurefile(files.config, extrasids=sids.network_service, contents=default_config)

        log("Starting OpenSSH Server")
        pwsh("Start-Service -Name sshd")
        pwsh("Set-Service -Name sshd -StartupType Automatic")

    except subprocess.CalledProcessError:
        return 1
    except RuntimeError:
        return 2


# ======================================================================================================================
def cli():
    parser = ArgumentParser("ssh-tunnel")
    subparsers = parser.add_subparsers(dest="command")

    bootstrap = subparsers.add_parser("bootstrap")
    bootstrap.add_argument(
        "--entry-shell",
        help="entry shell for incoming SSH connections (default: keep current or set latest powershell)")

    install = subparsers.add_parser("install")
    install.add_argument("tunnel_name", help="SSH tunnel name, same as \"Host\" field in config, unique on this system")

    fix_permissions = subparsers.add_parser("fix-permissions")
    fix_permissions.add_argument("path")

    return parser


def main():
    colorama.init(autoreset=True)
    args = cli().parse_args()

    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Please restart me from an admin shell.")
        return 1

    if args.command == "bootstrap":
        return bootstrap(entry_shell=args.entry_shell)
    if args.command == "install":
        return install(tunnel_name=args.tunnel_name)
    if args.command == "fix-permissions":
        return fix_permissions(path=args.path)


if __name__ == "__main__":
    sys.exit(main())
