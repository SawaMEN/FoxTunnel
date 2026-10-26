import pathlib
import shutil
import tempfile
import unittest

from test_unified_archive import prepare, VERSION, COMMIT
import unified_release_notes as notes


class UnifiedNotesTests(unittest.TestCase):
    def test_both_native_archives_verified_before_listing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            out=root/'published';out.mkdir()
            for arch in ('amd64','arm64'):
                work=root/arch;work.mkdir()
                archive=prepare(work,arch);shutil.copyfile(archive,out/archive.name)
            result=notes.render(out,VERSION,COMMIT)
            self.assertIn('ARM64: a single NSS-enabled CLI and the complete verified Necko runtime.',result)
            self.assertIn('linux_arm64.tar.gz',result)
            with self.assertRaises(ValueError):notes.render(out,VERSION,'b'*40)
            arm=out/'foxtunnel_0.0.0-ci_linux_arm64.tar.gz'
            arm.rename(out/'foxtunnel_0.0.0-ci_linux_arm64_nss.tar.gz')
            with self.assertRaises(ValueError):notes.render(out,VERSION,COMMIT)


if __name__=='__main__':unittest.main()
