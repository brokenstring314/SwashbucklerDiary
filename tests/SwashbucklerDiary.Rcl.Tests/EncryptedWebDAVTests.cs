using SwashbucklerDiary.Rcl.Services;
using System.IO.Compression;
using System.Text;
using static SwashbucklerDiary.Rcl.Tests.TestHelpers;

namespace SwashbucklerDiary.Rcl.Tests
{
    public class EncryptedWebDAVTests
    {
        private const string Folder = "SwashbucklerDiary";
        private const string BackupName = Folder + "/SwashbucklerDiaryBackup_20261013120000_v1.50.0.zip";

        private static (EncryptedWebDAV webDav, FakeWebDAV inner, TestBackupEncryptionService service) Create(TempDir dir, bool enabled)
        {
            var inner = new FakeWebDAV();
            var service = new TestBackupEncryptionService(dir.Path, enabled);
            return (new EncryptedWebDAV(inner, service), inner, service);
        }

        private static async Task<byte[]> ReadAll(Stream s)
        {
            using var ms = new MemoryStream();
            await s.CopyToAsync(ms);
            return ms.ToArray();
        }

        [Fact]
        public async Task Disabled_UploadIsPassThrough()
        {
            using var dir = new TempDir();
            var (webDav, inner, _) = Create(dir, enabled: false);
            byte[] zip = CreateBackupLikeZip();

            await webDav.UploadAsync(BackupName, new MemoryStream(zip));

            Assert.Equal([BackupName], inner.Files.Keys);
            Assert.Equal(zip, inner.Files[BackupName]);
            Assert.Empty(dir.LeftoverCryptoTempFiles());
        }

        [Fact]
        public async Task Enabled_UploadsOnlyCiphertext_UnderEncryptedName()
        {
            using var dir = new TempDir();
            var (webDav, inner, service) = Create(dir, enabled: true);
            byte[] zip = CreateBackupLikeZip();
            service.SetPassword(Password);

            await webDav.UploadAsync(BackupName, new NonSeekableStream(new MemoryStream(zip)));

            string expectedName = Folder + "/SwashbucklerDiaryBackup_20261013120000_v1.50.0.encrypted.zip";
            Assert.Equal([expectedName], inner.Files.Keys);
            byte[] uploaded = inner.Files[expectedName];
            Assert.True(BackupCrypto.HasEncryptedMagic(uploaded));
            Assert.False(BackupCrypto.HasZipMagic(uploaded));
            Assert.False(Contains(uploaded, Encoding.UTF8.GetBytes("diary secret text")));
            Assert.False(Contains(uploaded, Encoding.UTF8.GetBytes("SwashbucklerDiary.db3")));
            Assert.Equal(zip, Decrypt(uploaded));
            Assert.Empty(dir.LeftoverCryptoTempFiles());

            // still listed by the existing *.zip filter
            var list = await webDav.GetZipFileListAsync(Folder);
            Assert.Single(list);
            Assert.True(service.IsEncryptedFileName(list[0].Name));
        }

        [Fact]
        public async Task Enabled_WithoutPassword_RefusesToUpload()
        {
            using var dir = new TempDir();
            var (webDav, inner, _) = Create(dir, enabled: true);

            await Assert.ThrowsAsync<BackupPasswordRequiredException>(() => webDav.UploadAsync(BackupName, new MemoryStream(CreateBackupLikeZip())));

            Assert.Empty(inner.Files);
            Assert.Empty(dir.LeftoverCryptoTempFiles());
        }

        [Fact]
        public async Task Enabled_NonZipFiles_AreNotTouched()
        {
            using var dir = new TempDir();
            var (webDav, inner, service) = Create(dir, enabled: true);
            service.SetPassword(Password);
            byte[] json = Encoding.UTF8.GetBytes("{\"manifest\":1}");

            await webDav.UploadAsync(Folder + "/manifest.json", new MemoryStream(json));
            Assert.Equal(json, inner.Files[Folder + "/manifest.json"]);
            using var s = await webDav.DownloadAsync(Folder + "/manifest.json");
            Assert.Equal(json, await ReadAll(s));
        }

        [Theory]
        [InlineData(false, false)]
        [InlineData(true, false)]
        [InlineData(true, true)]
        public async Task OldPlaintextBackup_DownloadsUnchanged_WhateverTheSetting(bool enabled, bool passwordSet)
        {
            using var dir = new TempDir();
            var (webDav, inner, service) = Create(dir, enabled);
            if (passwordSet)
            {
                service.SetPassword(Password);
            }

            byte[] zip = CreateBackupLikeZip();
            inner.Files[BackupName] = zip;

            using (var s = await webDav.DownloadAsync(BackupName))
            {
                Assert.Equal(zip, await ReadAll(s));
            }

            Assert.Empty(dir.LeftoverCryptoTempFiles());
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)] // the setting was turned off after the encrypted backup was made
        public async Task EncryptedBackup_RoundTripsThroughDecorator_AndExtractsLikeImportDB(bool enabledAtRestore)
        {
            using var dir = new TempDir();
            var (webDav, inner, service) = Create(dir, enabled: true);
            byte[] zip = CreateBackupLikeZip(2 * 1024 * 1024 + 5);
            service.SetPassword(Password);
            await webDav.UploadAsync(BackupName, new MemoryStream(zip));
            service.ClearPassword();
            service.IsEnabled = enabledAtRestore;

            string remoteName = inner.Files.Keys.Single();

            // No password yet: the page catches this and prompts.
            await Assert.ThrowsAsync<BackupPasswordRequiredException>(() => webDav.DownloadAsync(remoteName));
            Assert.Empty(dir.LeftoverCryptoTempFiles());

            service.SetPassword(Password);
            byte[] restored;
            using (var s = await webDav.DownloadAsync(remoteName))
            {
                // Same steps as DiaryFileManager.ImportDBAsync(Stream): copy to a temp file, then ZipFile.ExtractToDirectory.
                string tempZip = await new TestAppFileSystem(dir.Path).CreateTempFileAsync(Guid.NewGuid().ToString("N") + ".zip", s);
                string outDir = Path.Combine(dir.Path, "DB");
                ZipFile.ExtractToDirectory(tempZip, outDir);
                Assert.Single(Directory.GetFiles(outDir, "*.db3"));
                Assert.Contains("diary secret text", File.ReadAllText(Path.Combine(outDir, "SwashbucklerDiary.db3")));
                Assert.True(File.Exists(Path.Combine(outDir, "version.json")));
                Assert.True(File.Exists(Path.Combine(outDir, "settings.json")));
                restored = File.ReadAllBytes(tempZip);
                File.Delete(tempZip);
            }

            Assert.Equal(zip, restored);
            Assert.Empty(dir.LeftoverCryptoTempFiles()); // DeleteOnClose removed the decrypted temp file
        }

        [Fact]
        public async Task EncryptedBackup_WrongPassword_ThrowsAndLeavesNoTempFiles()
        {
            using var dir = new TempDir();
            var (webDav, inner, service) = Create(dir, enabled: true);
            service.SetPassword(Password);
            await webDav.UploadAsync(BackupName, new MemoryStream(CreateBackupLikeZip()));

            service.SetPassword("wrong password");
            await Assert.ThrowsAsync<BackupPasswordIncorrectException>(() => webDav.DownloadAsync(inner.Files.Keys.Single()));
            Assert.Empty(dir.LeftoverCryptoTempFiles());
        }

        [Fact]
        public async Task EncryptedBackup_TamperedOnServer_ThrowsCorrupted_AndLeavesNoTempFiles()
        {
            using var dir = new TempDir();
            var (webDav, inner, service) = Create(dir, enabled: true);
            service.SetPassword(Password);
            await webDav.UploadAsync(BackupName, new MemoryStream(CreateBackupLikeZip(3 * 1024 * 1024)));
            string name = inner.Files.Keys.Single();
            inner.Files[name][^100] ^= 1; // last chunk

            await Assert.ThrowsAsync<BackupCorruptedException>(() => webDav.DownloadAsync(name));
            Assert.Empty(dir.LeftoverCryptoTempFiles());

            inner.Files[name] = inner.Files[name][..^1]; // and truncated
            await Assert.ThrowsAsync<BackupCorruptedException>(() => webDav.DownloadAsync(name));
            Assert.Empty(dir.LeftoverCryptoTempFiles());
        }

        [Fact]
        public async Task RandomNonZipData_PassesThroughUnchanged()
        {
            using var dir = new TempDir();
            var (webDav, inner, _) = Create(dir, enabled: true);
            byte[] junk = RandomBytes(5000);
            junk[0] = (byte)'X';
            inner.Files[BackupName] = junk;
            using var s = await webDav.DownloadAsync(BackupName);
            // Not our format: handed to ImportDBAsync exactly as before (which fails on it exactly as before).
            Assert.Equal(junk, await ReadAll(s));
        }
    }
}
