import importlib.util
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import patch


class ConsoleFraming(unittest.TestCase):
    def test_command_receipt_survives_guest_and_host_newline_translation(self):
        spec = importlib.util.spec_from_file_location('live_vm', Path(__file__).with_name('live-vm.py'))
        module = importlib.util.module_from_spec(spec)
        with patch.dict('sys.modules', {'pexpect': SimpleNamespace()}):
            spec.loader.exec_module(module)
        for ending in ('\n', '\r\n', '\r\r\n'):
            for code in (0, 1):
                with self.subTest(ending=repr(ending), code=code):
                    class Serial:
                        def sendline(self, text):
                            self.sent = text

                        def expect(self, pattern, timeout):
                            token = re.search('[0-9a-f]{24}', self.sent).group()
                            output = self.sent + ending + token + ':' + str(code) + ending
                            self.match = re.search(pattern, output)
                            if self.match is None:
                                raise AssertionError('receipt did not match real serial framing')
                    vm = module.VM.__new__(module.VM)
                    vm.child = Serial()
                    if code:
                        with self.assertRaises(RuntimeError):
                            vm.command('false')
                    else:
                        vm.command('true')
