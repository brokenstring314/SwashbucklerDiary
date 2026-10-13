using SwashbucklerDiary.Rcl.Services;
using System.IO.Compression;
using static SwashbucklerDiary.Rcl.Tests.TestHelpers;

namespace SwashbucklerDiary.Rcl.Tests
{
    /// <summary>The local backup/restore path used by LocalBackupsPage.</summary>
    public class BackupEncryptionServiceTests
    {
        [Fact]
        public async Task LocalBackup_EncryptThenDetectThenDecrypt_RestoresIdenticalZip()
        {
            using var dir = new TempDir();
            var service = new TestBackupEncryptionService(dir.Path, true);
            string zipPath = Path.Combine(dir.Path, "SwashbucklerDiaryBackup.zip");
            byte[] zip = CreateBackupLikeZip();
            File.WriteAllBytes(zipPath, zip);

            Assert.False(await service.IsEncryptedFileAsync(zipPath));
            string encrypted = await service.EncryptFileAsync(zipPath, Password);
            Assert.True(await service.IsEncryptedFileAsync(encrypted));
            Assert.StartsWith(dir.CryptoTempFolder, encrypted);

            string decrypted = await service.DecryptFileAsync(encrypted, Password);
            Assert.Equal(zip, File.ReadAllBytes(decrypted));
            using (var archive = ZipFile.OpenRead(decrypted))
            {
                Assert.Contains(archive.Entries, e => e.FullName.EndsWith(".db3"));
            }

            service.DeleteTempFile(encrypted);
            service.DeleteTempFile(decrypted);
            Assert.Empty(dir.LeftoverCryptoTempFiles());
        }

        [Fact]
        public async Task DecryptFile_Failure_LeavesNoPartialPlaintext()
        {
            using var dir = new TempDir();
            var service = new TestBackupEncryptionService(dir.Path, true);
            string zipPath = Path.Combine(dir.Path, "b.zip");
            File.WriteAllBytes(zipPath, CreateBackupLikeZip(3 * 1024 * 1024));
            string encrypted = await service.EncryptFileAsync(zipPath, Password);
            string movedEncrypted = Path.Combine(dir.Path, "b.encrypted.zip");
            File.Move(encrypted, movedEncrypted);

            await Assert.ThrowsAsync<BackupPasswordIncorrectException>(() => service.DecryptFileAsync(movedEncrypted, "nope nope"));
            Assert.Empty(dir.LeftoverCryptoTempFiles());

            // Corrupt the last chunk: chunks 0..2 authenticate and are written before the failure; they must be deleted.
            byte[] bytes = File.ReadAllBytes(movedEncrypted);
            bytes[^5] ^= 0xFF;
            File.WriteAllBytes(movedEncrypted, bytes);
            await Assert.ThrowsAsync<BackupCorruptedException>(() => service.DecryptFileAsync(movedEncrypted, Password));
            Assert.Empty(dir.LeftoverCryptoTempFiles());
        }

        [Fact]
        public async Task OldPlaintextLocalBackup_IsNotDetectedAsEncrypted()
        {
            using var dir = new TempDir();
            var service = new TestBackupEncryptionService(dir.Path, true);
            string zipPath = Path.Combine(dir.Path, "old.zip");
            File.WriteAllBytes(zipPath, CreateBackupLikeZip());
            Assert.False(await service.IsEncryptedFileAsync(zipPath));

            string empty = Path.Combine(dir.Path, "empty.zip");
            File.WriteAllBytes(empty, []);
            Assert.False(await service.IsEncryptedFileAsync(empty));
        }

        [Theory]
        [InlineData("SwashbucklerDiaryBackup_1_v1.zip", "SwashbucklerDiaryBackup_1_v1.encrypted.zip")]
        [InlineData("dir/a.ZIP", "dir/a.encrypted.zip")]
        [InlineData("a.encrypted.zip", "a.encrypted.zip")]
        [InlineData("noext", "noext.encrypted.zip")]
        public void EncryptedFileName(string input, string expected)
        {
            using var dir = new TempDir();
            var service = new TestBackupEncryptionService(dir.Path, true);
            Assert.Equal(expected, service.GetEncryptedFileName(input));
            Assert.True(service.IsEncryptedFileName(expected));
            Assert.EndsWith(".zip", expected);
        }

        [Fact]
        public void Password_IsOnlyHeldInMemoryUntilCleared()
        {
            using var dir = new TempDir();
            var service = new TestBackupEncryptionService(dir.Path, true);
            Assert.Null(service.Password);
            service.SetPassword(Password);
            Assert.Equal(Password, service.Password);
            service.ClearPassword();
            Assert.Null(service.Password);
            Assert.Throws<ArgumentException>(() => service.SetPassword(""));
        }

        [Fact]
        public void BackupEncryption_Setting_DefaultsOff_AndIsExcludedFromBackupSettings()
        {
            Assert.False(new Setting().BackupEncryption);
            var field = typeof(DiaryFileManager).GetField("excludedSettings",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
            var excluded = (List<string>)field.GetValue(null)!;
            Assert.Contains(nameof(Setting.BackupEncryption), excluded);
        }

        [Fact]
        public void IsSupported_OnThisPlatform()
        {
            Assert.True(BackupCrypto.IsSupported);
        }
    }
}
