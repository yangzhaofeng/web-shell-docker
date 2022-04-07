import base64
import OpenSSL
import os
import time
import fcntl
import signal
import tempfile
import hashlib
import atexit
import subprocess
from datetime import datetime
import threading
import select
import sys

tmp_path = "/dev/shm/hackergame"
conn_interval = int(os.environ["challenge_conn_interval"])
token_timeout = int(os.environ["challenge_token_timeout"])
challenge_timeout = int(os.environ["challenge_timeout"])
cpus_limit = os.environ["challenge_cpus_limit"]
pids_limit = int(os.environ["challenge_pids_limit"])
mem_limit = os.environ["challenge_mem_limit"]
challenge_docker_name = os.environ["challenge_docker_name"]
read_only = 0 if os.environ.get("challenge_read_only") == "0" else 1

with open("cert.pem") as f:
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())


def validate(token):
    try:
        id, sig = token.split(":", 1)
        sig = base64.b64decode(sig, validate=True)
        OpenSSL.crypto.verify(cert, sig, id.encode(), "sha256")
        return id
    except Exception:
        return None


def try_login(id):
    os.makedirs(tmp_path, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(tmp_path, id), os.O_CREAT | os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)
    with os.fdopen(fd, "r+") as f:
        data = f.read()
        now = int(time.time())
        if data:
            last_login, balance = data.split()
            last_login = int(last_login)
            balance = int(balance)
            last_login_str = (
                datetime.fromtimestamp(last_login).isoformat().replace("T", " ")
            )
            balance += now - last_login
            if balance > conn_interval * 3:
                balance = conn_interval * 3
        else:
            balance = conn_interval * 3
        if conn_interval > balance:
            print(
                f"Player connection rate limit exceeded, please try again after {conn_interval-balance} seconds. "
                f"连接过于频繁，超出服务器限制，请等待 {conn_interval-balance} 秒后重试。"
            )
            return False
        balance -= conn_interval
        f.seek(0)
        f.truncate()
        f.write(str(now) + " " + str(balance))
        return True


def check_token():
    signal.alarm(token_timeout)
    token = input("Please input your token: ").strip()
    id = validate(token)
    if not id:
        print("Invalid token")
        exit(-1)
    if not try_login(id):
        exit(-1)
    signal.alarm(0)
    return token, id


def cleanup():
    if child_docker_id:
        subprocess.run(
            f"docker rm -f {child_docker_id}",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

def create_docker(id):
    cmd = (
        f"docker create --init --rm -i --network none "
        f"--pids-limit {pids_limit} -m {mem_limit} --memory-swap {mem_limit} --cpus {cpus_limit} "
        f"-e hackergame_token=$hackergame_token "
    )

    if read_only:
        cmd += "--read-only "

    if challenge_docker_name.endswith("_challenge"):
        name_prefix = challenge_docker_name[:-10]
    else:
        name_prefix = challenge_docker_name

    timestr = datetime.now().strftime("%m%d_%H%M%S_%f")[:-3]
    child_docker_name = f"{name_prefix}_u{id}_{timestr}"
    cmd += f'--name "{child_docker_name}" '

    with open("/etc/hostname") as f:
        hostname = f.read().strip()
    with open("/proc/self/mountinfo") as f:
        for part in f.read().split('/'):
            if len(part) == 64 and part.startswith(hostname):
                docker_id = part
                break
        else:
            raise ValueError('Docker ID not found')
    prefix = f"/var/lib/docker/containers/{docker_id}/mounts/shm/"

    cmd += challenge_docker_name

    return subprocess.check_output(cmd, shell=True).decode().strip()


def run_docker(child_docker_id):
    cmd = f"timeout -s 9 --foreground {challenge_timeout} docker start -i {child_docker_id}"
    subprocess.run(cmd, shell=True)


def clean_on_socket_close():
    p = select.poll()
    p.register(sys.stdin, select.POLLHUP | select.POLLERR | select.POLLRDHUP)
    p.poll()
    cleanup()


if __name__ == "__main__":
    child_docker_id = None
    atexit.register(cleanup)
    t = threading.Thread(target=clean_on_socket_close, daemon=True)
    t.start()

    token, id = check_token()
    os.environ["hackergame_token"] = token
    child_docker_id = create_docker(id)
    run_docker(child_docker_id)
