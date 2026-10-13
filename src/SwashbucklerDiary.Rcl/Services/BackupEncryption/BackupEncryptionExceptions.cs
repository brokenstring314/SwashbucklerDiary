namespace SwashbucklerDiary.Rcl.Services
{
    /// <summary>Base type for all encrypted-backup errors.</summary>
    public class BackupEncryptionException : Exception
    {
        public BackupEncryptionException(string message) : base(message)
        {
        }

        public BackupEncryptionException(string message, Exception? innerException) : base(message, innerException)
        {
        }
    }

    /// <summary>The password is wrong (or the header was modified; the two cannot be told apart).</summary>
    public class BackupPasswordIncorrectException : BackupEncryptionException
    {
        public BackupPasswordIncorrectException() : base("The backup password is incorrect.")
        {
        }
    }

    /// <summary>The ciphertext is truncated, extended or modified.</summary>
    public class BackupCorruptedException : BackupEncryptionException
    {
        public BackupCorruptedException(string message, Exception? innerException = null) : base(message, innerException)
        {
        }
    }

    /// <summary>The file was written by a newer, unknown format version.</summary>
    public class BackupUnsupportedVersionException : BackupEncryptionException
    {
        public BackupUnsupportedVersionException(byte version) : base($"Unsupported encrypted backup format version {version}.")
        {
            Version = version;
        }

        public byte Version { get; }
    }

    /// <summary>Decrypt was called on data that is not an encrypted backup.</summary>
    public class BackupNotEncryptedException : BackupEncryptionException
    {
        public BackupNotEncryptedException() : base("The data is not an encrypted backup.")
        {
        }
    }

    /// <summary>An encrypted backup was found (or encryption is enabled) but no password was supplied.</summary>
    public class BackupPasswordRequiredException : BackupEncryptionException
    {
        public BackupPasswordRequiredException() : base("A backup password is required.")
        {
        }
    }

    /// <summary>AES-GCM is unavailable on this platform (e.g. browser WebAssembly).</summary>
    public class BackupEncryptionNotSupportedException : BackupEncryptionException
    {
        public BackupEncryptionNotSupportedException() : base("Encrypted backups are not supported on the current platform.")
        {
        }
    }
}
