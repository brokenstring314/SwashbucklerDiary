namespace SwashbucklerDiary.Rcl.Services
{
    /// <summary>
    /// Decorator around <see cref="IWebDAV"/> that encrypts backup archives (*.zip) before upload when backup
    /// encryption is enabled, and transparently decrypts encrypted archives on download.
    /// <list type="bullet">
    /// <item>Only names ending in ".zip" are touched; any other file passes through unchanged.</item>
    /// <item>Upload: when enabled, the archive is encrypted into a temp file and uploaded as "*.encrypted.zip".
    /// The plaintext stream itself is never sent. Without a password set, <see cref="BackupPasswordRequiredException"/> is thrown.</item>
    /// <item>Download: detection is by magic header, independent of the current setting and of the file name, so old
    /// plaintext backups keep working. Encrypted data without a password set throws <see cref="BackupPasswordRequiredException"/>.</item>
    /// </list>
    /// Temp files are opened with <see cref="FileOptions.DeleteOnClose"/>, so they disappear when the returned stream is disposed.
    /// </summary>
    public class EncryptedWebDAV : IWebDAV
    {
        private const int bufferSize = 81920;

        private readonly IWebDAV _inner;

        private readonly IBackupEncryptionService _backupEncryptionService;

        public EncryptedWebDAV(IWebDAV inner, IBackupEncryptionService backupEncryptionService)
        {
            _inner = inner;
            _backupEncryptionService = backupEncryptionService;
        }

        public bool Initialized
        {
            get => _inner.Initialized;
            // Only the inner client changes its own state (in Set); nothing sets this from outside.
            set { }
        }

        public Task Set(string? baseAddress, string? userName, string? password)
            => _inner.Set(baseAddress, userName, password);

        public Task<List<WebDAVFileInfo>> GetZipFileListAsync(string folderName)
            => _inner.GetZipFileListAsync(folderName);

        public async Task UploadAsync(string destFileName, Stream stream)
        {
            if (!IsBackupArchive(destFileName) || !_backupEncryptionService.Enabled)
            {
                await _inner.UploadAsync(destFileName, stream).ConfigureAwait(false);
                return;
            }

            string password = _backupEncryptionService.Password ?? throw new BackupPasswordRequiredException();

            await using var encrypted = CreateTempStream();
            await BackupCrypto.EncryptAsync(stream, encrypted, password).ConfigureAwait(false);
            encrypted.Position = 0;
            await _inner.UploadAsync(_backupEncryptionService.GetEncryptedFileName(destFileName), encrypted).ConfigureAwait(false);
        }

        public async Task<Stream> DownloadAsync(string destFileName)
        {
            if (!IsBackupArchive(destFileName))
            {
                return await _inner.DownloadAsync(destFileName).ConfigureAwait(false);
            }

            // Buffer to an app-private temp file: the network stream is not seekable and the header must be inspected.
            FileStream downloaded = CreateTempStream();
            try
            {
                await using (var remote = await _inner.DownloadAsync(destFileName).ConfigureAwait(false))
                {
                    await remote.CopyToAsync(downloaded).ConfigureAwait(false);
                }

                downloaded.Position = 0;
                if (!BackupCrypto.IsEncrypted(downloaded))
                {
                    // Old plaintext backup: hand it over unchanged.
                    return downloaded;
                }

                string password = _backupEncryptionService.Password ?? throw new BackupPasswordRequiredException();
                FileStream decrypted = CreateTempStream();
                try
                {
                    await BackupCrypto.DecryptAsync(downloaded, decrypted, password).ConfigureAwait(false);
                    decrypted.Position = 0;
                }
                catch
                {
                    await decrypted.DisposeAsync().ConfigureAwait(false);
                    throw;
                }

                await downloaded.DisposeAsync().ConfigureAwait(false);
                return decrypted;
            }
            catch
            {
                await downloaded.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        private static bool IsBackupArchive(string fileName)
            => fileName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase);

        private FileStream CreateTempStream()
            => new(_backupEncryptionService.CreateTempFilePath(), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None,
                bufferSize, FileOptions.DeleteOnClose | FileOptions.Asynchronous);
    }
}
