"""Real X11 and PipeWire integration; only called inside the disposable container."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

assert Path('/.dockerenv').exists() and os.environ.get('FRANKENSTEIN_DISPOSABLE') == '1'
assert os.getuid() != 0


def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, timeout=15, check=check)


def wait(predicate, description):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.1)
    raise AssertionError('timeout: ' + description)


def windows(name):
    return run('xdotool', 'search', '--onlyvisible', '--class', name, check=False).stdout.splitlines()


with tempfile.TemporaryDirectory(prefix='frankenstein-session-') as runtime:
    os.environ['XDG_RUNTIME_DIR'] = runtime
    os.environ['DISPLAY'] = ':93'
    children = []
    logs = []

    def start(*args):
        logfile = open(Path(runtime) / (str(len(children)) + '.log'), 'w+')
        logs.append(logfile)
        child = subprocess.Popen(args, stdout=logfile, stderr=subprocess.STDOUT)
        children.append(child)
        return child

    try:
        start('Xvfb', ':93', '-screen', '0', '1280x800x24', '-nolisten', 'tcp')
        wait(lambda: run('xdotool', 'getdisplaygeometry', check=False).returncode == 0, 'X server')
        # Exercise the installed .xinitrc -> public entrypoint -> Openbox chain.
        session = start(str(Path.home() / '.xinitrc'))
        wait(lambda: 'Openbox' in run('wmctrl', '-m', check=False).stdout, 'window manager')
        run('xdotool', 'key', '--clearmodifiers', 'super+Return')
        window = wait(lambda: windows('XTerm'), 'terminal shortcut')[0]
        run('xdotool', 'windowactivate', '--sync', window)
        run('xdotool', 'key', '--clearmodifiers', 'super+Up')
        wait(lambda: '_NET_WM_STATE_MAXIMIZED_VERT' in run('xprop', '-id', window, '_NET_WM_STATE').stdout, 'maximize')
        run('xdotool', 'key', '--clearmodifiers', 'super+2')
        wait(lambda: run('xdotool', 'get_desktop').stdout.strip() == '1', 'workspace shortcut')
        run('xdotool', 'key', '--clearmodifiers', 'super+1')
        run('xdotool', 'windowactivate', '--sync', window)
        run('xdotool', 'key', '--clearmodifiers', 'alt+F4')
        wait(lambda: not windows('XTerm'), 'close shortcut')
        run('xdotool', 'key', '--clearmodifiers', 'super+space')
        wait(lambda: windows('Rofi'), 'launcher shortcut')
        run('xdotool', 'key', 'Escape')
        run('xdotool', 'key', '--clearmodifiers', 'super+e')
        wait(lambda: windows('Thunar'), 'file manager shortcut')

        start('pipewire')
        wait(lambda: (Path(runtime) / 'pipewire-0').exists(), 'PipeWire socket')
        start('wireplumber')
        start('pipewire-pulse')
        wait(lambda: run('pactl', 'info', check=False).returncode == 0, 'Pulse compatibility socket')
        run('pactl', 'load-module', 'module-null-sink', 'sink_name=proof_sink')
        run('pactl', 'load-module', 'module-remap-source', 'master=proof_sink.monitor', 'source_name=proof_source')

        def node_id(name):
            nodes = json.loads(run('pw-dump').stdout)
            return next((str(node['id']) for node in nodes if node.get('info', {}).get('props', {}).get('node.name') == name), None)

        for command, name in (('vol', 'proof_sink'), ('mic', 'proof_source')):
            identifier = wait(lambda: node_id(name), name)
            run('wpctl', 'set-default', identifier)
            wait(lambda: run(command, 'status', check=False).returncode == 0, 'default audio device')
            run(command, '50')
            assert 'Volume: 0.50' in run(command).stdout
            run(command, 'mute')
            run(command, 'mute')
            assert '[MUTED]' in run(command).stdout
            run(command, '80')
            assert 'Volume: 0.80 [MUTED]' in run(command).stdout
            run(command, 'unmute')
            assert '[MUTED]' not in run(command).stdout
            assert run(command, '101', check=False).returncode == 2
        run('openbox', '--exit')
        assert session.wait(timeout=10) == 0
        for logfile in logs:
            logfile.flush()
            logfile.seek(0)
            assert 'cannot load font' not in logfile.read()
        print('NATIVE_X11_AUDIO_PROOF=PASS')
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for logfile in logs:
            logfile.seek(0)
            print(logfile.read())
            logfile.close()
