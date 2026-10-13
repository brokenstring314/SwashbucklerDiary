namespace SwashbucklerDiary.Rcl.Services
{
    /// <summary>
    /// Optional encryption of backups before they leave the device. The password is never persisted: the UI asks
    /// for it at backup/restore time and only holds it (via <see cref="SetPassword"/>) for the duration of one operation.
    /// </summary>
    public interface IBackupEncryptionService
    {
        /// <summary>False on platforms without AES-GCM (browser WebAssembly); the UI hides the feature there.</summary>
        bool IsSupported { get; }

        /// <summary>The user setting <c>BackupEncryption</c> is on and the platform supports it.</summary>
        bool Enabled { get; }

        /// <summary>Password for the operation in progress, or null.</summary>
        string? Password { get; }

        void SetPassword(string password);

        void ClearPassword();

        /// <summary>Encrypts <paramref name="sourcePath"/> into a new temp file and returns its path.</summary>
        Task<string> EncryptFileAsync(string sourcePath, string password);

        /// <summary>Decrypts <paramref name="sourcePath"/> into a new temp file and returns its path. Nothing is left behind on failure.</summary>
        Task<string> DecryptFileAsync(string sourcePath, string password);

        /// <summary>Detects the encrypted format by its magic header (independent of file name and current setting).</summary>
        Task<bool> IsEncryptedFileAsync(string path);

        /// <summary>"name.zip" -> "name.encrypted.zip" (keeps the .zip suffix so existing pickers/filters still list it).</summary>
        string GetEncryptedFileName(string fileName);

        bool IsEncryptedFileName(string fileName);

        /// <summary>A fresh path inside the app's private cache folder for crypto temp files.</summary>
        string CreateTempFilePath();

        void DeleteTempFile(string? path);
    }
}
