using SwashbucklerDiary.Rcl.Services;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace SwashbucklerDiary.Rcl.Tests
{
    internal static class TestHelpers
    {
        public const string Password = "correct horse battery staple";

        public const int FastIterations = BackupCrypto.MinIterations;

        public static byte[] RandomBytes(int length)
        {
            var bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }

        public static byte[] Encrypt(byte[] plain, string password = Password, int chunkSize = BackupCrypto.DefaultChunkSize)
        {
            using var input = new MemoryStream(plain);
            using var output = new MemoryStream();
            BackupCrypto.Encrypt(input, output, password, FastIterations, chunkSize);
            return output.ToArray();
        }

        public static byte[] Decrypt(byte[] cipher, string password = Password)
        {
            using var input = new MemoryStream(cipher);
            using var output = new MemoryStream();
            BackupCrypto.Decrypt(input, output, password);
            return output.ToArray();
        }

        /// <summary>A zip shaped like DiaryFileManager.ExportDBAsync output (db3 + version.json + settings.json + a media file).</summary>
        public static byte[] CreateBackupLikeZip(int mediaSize = 300_000)
        {
            using var ms = new MemoryStream();
            using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, true))
            {
                Add(zip, "SwashbucklerDiary.db3", Encoding.UTF8.GetBytes("SQLite format 3\0 diary secret text 今天的日记"));
                Add(zip, "version.json", Encoding.UTF8.GetBytes("{\"Version\":\"1.50.0\",\"FileSuffix\":\".db3\"}"));
                Add(zip, "settings.json", Encoding.UTF8.GetBytes("{\"NickName\":\"tester\"}"));
                Add(zip, "appdata/Image/photo.jpg", RandomBytes(mediaSize));
            }

            return ms.ToArray();
        }

        private static void Add(ZipArchive zip, string name, byte[] content)
        {
            using var s = zip.CreateEntry(name).Open();
            s.Write(content);
        }

        public static bool Contains(byte[] haystack, byte[] needle)
            => haystack.AsSpan().IndexOf(needle) >= 0;
    }

    /// <summary>Stream wrapper that hides CanSeek, like an HTTP response stream.</summary>
    internal sealed class NonSeekableStream(Stream inner) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => inner.CanWrite;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush();
        // Return short reads on purpose to exercise the read loops.
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, Math.Min(count, 7919));
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
        protected override void Dispose(bool disposing)
        {
            if (disposing) inner.Dispose();
            base.Dispose(disposing);
        }
    }

    internal sealed class TestAppFileSystem(string root) : SwashbucklerDiary.Rcl.Essentials.AppFileSystem
    {
        public override string AppDataDirectory { get; } = Path.Combine(root, "appdata");
        public override string CacheDirectory { get; } = Path.Combine(root, "cache");
    }

    internal sealed class TestBackupEncryptionService(string root, bool enabled)
        : BackupEncryptionService(null!, new TestAppFileSystem(root))
    {
        public bool IsEnabled { get; set; } = enabled;

        public override bool Enabled => IsSupported && IsEnabled;

        protected override int Iterations => TestHelpers.FastIterations;
    }

    internal sealed class TempDir : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sbd-tests-" + Guid.NewGuid().ToString("N"));

        public TempDir() => Directory.CreateDirectory(Path);

        public string CryptoTempFolder => System.IO.Path.Combine(Path, "cache", "BackupEncryption");

        public string[] LeftoverCryptoTempFiles()
            => Directory.Exists(CryptoTempFolder) ? Directory.GetFiles(CryptoTempFolder) : [];

        public void Dispose()
        {
            try { Directory.Delete(Path, true); } catch { }
        }
    }

    /// <summary>In-memory WebDAV server standing in for the real client.</summary>
    internal sealed class FakeWebDAV : IWebDAV
    {
        public Dictionary<string, byte[]> Files { get; } = [];

        public bool Initialized { get; set; } = true;

        public Task Set(string? baseAddress, string? userName, string? password) => Task.CompletedTask;

        public Task<Stream> DownloadAsync(string destFileName)
            => Task.FromResult<Stream>(new NonSeekableStream(new MemoryStream(Files[destFileName])));

        public async Task UploadAsync(string destFileName, Stream stream)
        {
            using var ms = new MemoryStream();
            await stream.CopyToAsync(ms);
            Files[destFileName] = ms.ToArray();
        }

        public Task<List<WebDAVFileInfo>> GetZipFileListAsync(string folderName)
            => Task.FromResult(Files.Keys.Where(k => k.EndsWith(".zip")).Select(k => new WebDAVFileInfo { Name = System.IO.Path.GetFileName(k) }).ToList());
    }
}
