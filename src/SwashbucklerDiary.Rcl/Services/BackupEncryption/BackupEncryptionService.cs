using SwashbucklerDiary.Rcl.Essentials;

namespace SwashbucklerDiary.Rcl.Services
{
    public class BackupEncryptionService : IBackupEncryptionService
    {
        public const string EncryptedFileSuffix = ".encrypted.zip";

        private const string tempFolderName = "BackupEncryption";

        private readonly ISettingService _settingService;

        private readonly IAppFileSystem _appFileSystem;

        private volatile string? _password;

        public BackupEncryptionService(ISettingService settingService, IAppFileSystem appFileSystem)
        {
            _settingService = settingService;
            _appFileSystem = appFileSystem;
        }

        /// <summary>KDF iterations for new backups. Overridable for tests only.</summary>
        protected virtual int Iterations => BackupCrypto.DefaultIterations;

        public virtual bool IsSupported => BackupCrypto.IsSupported;

        public virtual bool Enabled => IsSupported && _settingService.Get(s => s.BackupEncryption);

        public string? Password => _password;

        public void SetPassword(string password)
        {
            ArgumentException.ThrowIfNullOrEmpty(password);
            _password = password;
        }

        public void ClearPassword() => _password = null;

        public async Task<string> EncryptFileAsync(string sourcePath, string password)
        {
            string destPath = CreateTempFilePath();
            try
            {
                await Task.Run(() =>
                {
                    using var input = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                    using var output = new FileStream(destPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                    BackupCrypto.Encrypt(input, output, password, Iterations);
                }).ConfigureAwait(false);
                return destPath;
            }
            catch
            {
                DeleteTempFile(destPath);
                throw;
            }
        }

        public async Task<string> DecryptFileAsync(string sourcePath, string password)
        {
            string destPath = CreateTempFilePath();
            try
            {
                await Task.Run(() =>
                {
                    using var input = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                    using var output = new FileStream(destPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                    BackupCrypto.Decrypt(input, output, password);
                }).ConfigureAwait(false);
                return destPath;
            }
            catch
            {
                // Partially decrypted (authenticated) plaintext must not stay on disk.
                DeleteTempFile(destPath);
                throw;
            }
        }

        public Task<bool> IsEncryptedFileAsync(string path)
            => Task.Run(() => BackupCrypto.IsEncryptedFile(path));

        public string GetEncryptedFileName(string fileName)
        {
            if (IsEncryptedFileName(fileName))
            {
                return fileName;
            }

            if (fileName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                fileName = fileName[..^4];
            }

            return fileName + EncryptedFileSuffix;
        }

        public bool IsEncryptedFileName(string fileName)
            => fileName.EndsWith(EncryptedFileSuffix, StringComparison.OrdinalIgnoreCase);

        public string CreateTempFilePath()
        {
            string folder = Path.Combine(_appFileSystem.CacheDirectory, tempFolderName);
            Directory.CreateDirectory(folder);
            return Path.Combine(folder, Guid.NewGuid().ToString("N") + ".tmp");
        }

        public void DeleteTempFile(string? path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return;
            }

            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    /// <summary>
    /// Used by the Web heads (Blazor Server / WebAssembly): the feature is hidden there. In WASM AES-GCM is unavailable;
    /// in Blazor Server the "device" is the server and the file is handed to the browser asynchronously, so client-side
    /// "encrypt before it leaves the device" cannot be honoured. Encrypted backups are still detected and rejected with a clear message.
    /// </summary>
    public class UnsupportedBackupEncryptionService : BackupEncryptionService
    {
        public UnsupportedBackupEncryptionService(ISettingService settingService, IAppFileSystem appFileSystem)
            : base(settingService, appFileSystem)
        {
        }

        public override bool IsSupported => false;
    }
}
