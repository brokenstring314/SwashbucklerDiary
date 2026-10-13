using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace SwashbucklerDiary.Rcl.Services
{
    /// <summary>
    /// Streaming password-based encryption for backup files.
    /// <para>
    /// File format (version 1, all integers big-endian):
    /// <code>
    /// offset size  field
    /// 0      6     magic "SBDENC"
    /// 6      1     format version (1)
    /// 7      1     KDF id (1 = PBKDF2-HMAC-SHA256)
    /// 8      4     KDF iterations (uint32)
    /// 12     4     plaintext chunk size in bytes (uint32)
    /// 16     16    salt (random)
    /// 32     12    base nonce (random)
    /// 44     32    header MAC = HMAC-SHA256(macKey, bytes 0..43)
    /// 76     ...   chunks: AES-256-GCM ciphertext (chunkSize bytes, last chunk 0..chunkSize bytes) followed by a 16-byte tag
    /// </code>
    /// Keys: PBKDF2-HMAC-SHA256(password (UTF-8, NFC), salt, iterations) -> 64 bytes = encKey(32) || macKey(32).
    /// Chunk i nonce = baseNonce XOR (0x00000000 || uint64_be(i)).
    /// Chunk i AAD = header(76 bytes) || uint64_be(i) || finalFlag(1 byte: 1 for the last chunk, else 0).
    /// There is always at least one chunk (an empty input produces one empty final chunk), so truncation at a chunk
    /// boundary, chunk reordering, appended data and header tampering are all detected.
    /// </para>
    /// </summary>
    public static class BackupCrypto
    {
        public static readonly byte[] Magic = "SBDENC"u8.ToArray();

        public const byte FormatVersion = 1;

        public const byte KdfPbkdf2Sha256 = 1;

        public const int DefaultIterations = 600_000;

        public const int MinIterations = 100_000;

        public const int MaxIterations = 10_000_000;

        public const int DefaultChunkSize = 1024 * 1024;

        public const int MinChunkSize = 1024;

        public const int MaxChunkSize = 16 * 1024 * 1024;

        public const int SaltSize = 16;

        public const int NonceSize = 12;

        public const int TagSize = 16;

        public const int MacSize = 32;

        private const int KeySize = 32;

        // magic(6) + version(1) + kdf(1) + iterations(4) + chunkSize(4) + salt(16) + nonce(12)
        private const int HeaderBodySize = 6 + 1 + 1 + 4 + 4 + SaltSize + NonceSize;

        public const int HeaderSize = HeaderBodySize + MacSize;

        /// <summary>
        /// AES-GCM is not available in browser WebAssembly. The feature must be hidden there.
        /// </summary>
        [UnsupportedOSPlatformGuard("browser")]
        public static bool IsSupported => !OperatingSystem.IsBrowser() && AesGcm.IsSupported;

        /// <summary>True when the span starts with the encrypted-backup magic bytes.</summary>
        public static bool HasEncryptedMagic(ReadOnlySpan<byte> start)
            => start.Length >= Magic.Length && start[..Magic.Length].SequenceEqual(Magic);

        /// <summary>True when the span starts like a zip file ("PK").</summary>
        public static bool HasZipMagic(ReadOnlySpan<byte> start)
            => start.Length >= 2 && start[0] == (byte)'P' && start[1] == (byte)'K';

        /// <summary>
        /// Checks whether the stream starts with the encrypted-backup magic. Seekable streams are restored to their
        /// original position; non-seekable streams are consumed, so callers should buffer them first.
        /// </summary>
        public static bool IsEncrypted(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);

            long position = stream.CanSeek ? stream.Position : 0;
            Span<byte> buffer = stackalloc byte[6];
            int read = ReadAtMost(stream, buffer);
            if (stream.CanSeek)
            {
                stream.Position = position;
            }

            return HasEncryptedMagic(buffer[..read]);
        }

        public static bool IsEncryptedFile(string path)
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return IsEncrypted(stream);
        }

        public static void Encrypt(Stream input, Stream output, string password,
            int iterations = DefaultIterations, int chunkSize = DefaultChunkSize)
        {
            ArgumentNullException.ThrowIfNull(input);
            ArgumentNullException.ThrowIfNull(output);
            ValidatePassword(password);
            ArgumentOutOfRangeException.ThrowIfLessThan(iterations, MinIterations);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(iterations, MaxIterations);
            ArgumentOutOfRangeException.ThrowIfLessThan(chunkSize, MinChunkSize);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(chunkSize, MaxChunkSize);
            if (!IsSupported)
            {
                throw new BackupEncryptionNotSupportedException();
            }

            byte[] header = new byte[HeaderSize];
            Magic.CopyTo(header, 0);
            header[6] = FormatVersion;
            header[7] = KdfPbkdf2Sha256;
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8, 4), (uint)iterations);
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12, 4), (uint)chunkSize);
            RandomNumberGenerator.Fill(header.AsSpan(16, SaltSize));
            RandomNumberGenerator.Fill(header.AsSpan(32, NonceSize));

            byte[] keys = DeriveKeys(password, header.AsSpan(16, SaltSize), iterations);
            try
            {
                HMACSHA256.HashData(keys.AsSpan(KeySize, KeySize), header.AsSpan(0, HeaderBodySize), header.AsSpan(HeaderBodySize, MacSize));
                output.Write(header);

                using var aes = new AesGcm(keys.AsSpan(0, KeySize), TagSize);
                byte[] baseNonce = header.AsSpan(32, NonceSize).ToArray();
                byte[] current = new byte[chunkSize];
                byte[] next = new byte[chunkSize];
                byte[] cipher = new byte[chunkSize];
                byte[] tag = new byte[TagSize];
                byte[] nonce = new byte[NonceSize];
                byte[] aad = new byte[HeaderSize + 8 + 1];
                header.CopyTo(aad, 0);

                try
                {
                    // Read ahead one chunk so we know which chunk is the final one.
                    int currentLength = ReadAtMost(input, current);
                    ulong index = 0;
                    while (true)
                    {
                        int nextLength = currentLength == chunkSize ? ReadAtMost(input, next) : 0;
                        bool isFinal = nextLength == 0;

                        BuildNonce(baseNonce, index, nonce);
                        BuildAad(aad, index, isFinal);
                        aes.Encrypt(nonce, current.AsSpan(0, currentLength), cipher.AsSpan(0, currentLength), tag, aad);
                        output.Write(cipher, 0, currentLength);
                        output.Write(tag);

                        if (isFinal)
                        {
                            break;
                        }

                        checked { index++; }
                        (current, next) = (next, current);
                        currentLength = nextLength;
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(current);
                    CryptographicOperations.ZeroMemory(next);
                }

                output.Flush();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keys);
            }
        }

        /// <summary>
        /// Decrypts an encrypted backup. Plaintext is only written after its chunk has been authenticated, but if a
        /// later chunk fails, earlier chunks have already been written: callers must discard the output on any exception.
        /// </summary>
        /// <exception cref="BackupNotEncryptedException">The input does not start with the magic bytes.</exception>
        /// <exception cref="BackupPasswordIncorrectException">Wrong password, or the header was modified.</exception>
        /// <exception cref="BackupCorruptedException">The data after the header is truncated, extended or modified.</exception>
        public static void Decrypt(Stream input, Stream output, string password)
        {
            ArgumentNullException.ThrowIfNull(input);
            ArgumentNullException.ThrowIfNull(output);
            ValidatePassword(password);
            if (!IsSupported)
            {
                throw new BackupEncryptionNotSupportedException();
            }

            byte[] header = new byte[HeaderSize];
            int headerRead = ReadAtMost(input, header);
            if (!HasEncryptedMagic(header.AsSpan(0, headerRead)))
            {
                throw new BackupNotEncryptedException();
            }

            if (headerRead < HeaderSize)
            {
                throw new BackupCorruptedException("The encrypted backup header is truncated.");
            }

            if (header[6] != FormatVersion)
            {
                throw new BackupUnsupportedVersionException(header[6]);
            }

            if (header[7] != KdfPbkdf2Sha256)
            {
                throw new BackupCorruptedException("Unknown key derivation function.");
            }

            uint iterations = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(8, 4));
            uint chunkSizeRaw = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(12, 4));
            // Bounds checks stop a crafted header from forcing huge allocations or near-endless key derivation.
            if (iterations < MinIterations || iterations > MaxIterations
                || chunkSizeRaw < MinChunkSize || chunkSizeRaw > MaxChunkSize)
            {
                throw new BackupCorruptedException("The encrypted backup header contains invalid parameters.");
            }

            int chunkSize = (int)chunkSizeRaw;
            byte[] keys = DeriveKeys(password, header.AsSpan(16, SaltSize), (int)iterations);
            try
            {
                Span<byte> expectedMac = stackalloc byte[MacSize];
                HMACSHA256.HashData(keys.AsSpan(KeySize, KeySize), header.AsSpan(0, HeaderBodySize), expectedMac);
                if (!CryptographicOperations.FixedTimeEquals(expectedMac, header.AsSpan(HeaderBodySize, MacSize)))
                {
                    throw new BackupPasswordIncorrectException();
                }

                using var aes = new AesGcm(keys.AsSpan(0, KeySize), TagSize);
                byte[] baseNonce = header.AsSpan(32, NonceSize).ToArray();
                int frameSize = chunkSize + TagSize;
                byte[] current = new byte[frameSize];
                byte[] next = new byte[frameSize];
                byte[] plain = new byte[chunkSize];
                byte[] nonce = new byte[NonceSize];
                byte[] aad = new byte[HeaderSize + 8 + 1];
                header.CopyTo(aad, 0);

                try
                {
                    int currentLength = ReadAtMost(input, current);
                    ulong index = 0;
                    while (true)
                    {
                        if (currentLength < TagSize)
                        {
                            throw new BackupCorruptedException("The encrypted backup is truncated.");
                        }

                        // A chunk is final when the stream ends right after it. A full frame needs a look-ahead read.
                        int nextLength = currentLength == frameSize ? ReadAtMost(input, next) : 0;
                        bool isFinal = nextLength == 0;
                        int cipherLength = currentLength - TagSize;

                        BuildNonce(baseNonce, index, nonce);
                        BuildAad(aad, index, isFinal);
                        try
                        {
                            aes.Decrypt(nonce, current.AsSpan(0, cipherLength), current.AsSpan(cipherLength, TagSize),
                                plain.AsSpan(0, cipherLength), aad);
                        }
                        catch (AuthenticationTagMismatchException e)
                        {
                            throw new BackupCorruptedException($"Chunk {index} failed authentication: the backup is truncated or was modified.", e);
                        }

                        output.Write(plain, 0, cipherLength);

                        if (isFinal)
                        {
                            break;
                        }

                        checked { index++; }
                        (current, next) = (next, current);
                        currentLength = nextLength;
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plain);
                }

                output.Flush();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keys);
            }
        }

        public static Task EncryptAsync(Stream input, Stream output, string password,
            int iterations = DefaultIterations, int chunkSize = DefaultChunkSize)
            => Task.Run(() => Encrypt(input, output, password, iterations, chunkSize));

        public static Task DecryptAsync(Stream input, Stream output, string password)
            => Task.Run(() => Decrypt(input, output, password));

        private static void ValidatePassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password must not be empty.", nameof(password));
            }
        }

        private static byte[] DeriveKeys(string password, ReadOnlySpan<byte> salt, int iterations)
        {
            // NFC so that the same password typed on different platforms/IMEs gives the same bytes.
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password.Normalize(NormalizationForm.FormC));
            try
            {
                return Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, iterations, HashAlgorithmName.SHA256, KeySize * 2);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
        }

        private static void BuildNonce(ReadOnlySpan<byte> baseNonce, ulong index, Span<byte> nonce)
        {
            baseNonce.CopyTo(nonce);
            Span<byte> counter = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(counter, index);
            for (int i = 0; i < 8; i++)
            {
                nonce[NonceSize - 8 + i] ^= counter[i];
            }
        }

        private static void BuildAad(byte[] aad, ulong index, bool isFinal)
        {
            BinaryPrimitives.WriteUInt64BigEndian(aad.AsSpan(HeaderSize, 8), index);
            aad[HeaderSize + 8] = isFinal ? (byte)1 : (byte)0;
        }

        /// <summary>Reads until the buffer is full or the stream ends.</summary>
        private static int ReadAtMost(Stream stream, Span<byte> buffer)
        {
            int total = 0;
            while (total < buffer.Length)
            {
                int read = stream.Read(buffer[total..]);
                if (read == 0)
                {
                    break;
                }

                total += read;
            }

            return total;
        }
    }
}
