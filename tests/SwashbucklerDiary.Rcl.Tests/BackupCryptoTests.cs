using SwashbucklerDiary.Rcl.Services;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using static SwashbucklerDiary.Rcl.Tests.TestHelpers;

namespace SwashbucklerDiary.Rcl.Tests
{
    public class BackupCryptoTests
    {
        private const int SmallChunk = BackupCrypto.MinChunkSize; // 1024
        private const int BigChunk = BackupCrypto.DefaultChunkSize; // 1 MiB

        [Theory]
        [InlineData(0, SmallChunk)]
        [InlineData(1, SmallChunk)]
        [InlineData(SmallChunk - 1, SmallChunk)]
        [InlineData(SmallChunk, SmallChunk)]
        [InlineData(SmallChunk + 1, SmallChunk)]
        [InlineData(2 * SmallChunk, SmallChunk)]
        [InlineData(3 * SmallChunk + 7, SmallChunk)]
        [InlineData(0, BigChunk)]
        [InlineData(1, BigChunk)]
        [InlineData(BigChunk - 1, BigChunk)]
        [InlineData(BigChunk, BigChunk)]
        [InlineData(BigChunk + 1, BigChunk)]
        [InlineData(5 * 1024 * 1024 + 123, BigChunk)]
        public void RoundTrip_AllSizes(int size, int chunkSize)
        {
            byte[] plain = RandomBytes(size);
            byte[] cipher = Encrypt(plain, chunkSize: chunkSize);

            int chunks = Math.Max(1, (size + chunkSize - 1) / chunkSize);
            Assert.Equal(BackupCrypto.HeaderSize + size + chunks * BackupCrypto.TagSize, cipher.Length);
            Assert.True(BackupCrypto.HasEncryptedMagic(cipher));
            Assert.False(BackupCrypto.HasZipMagic(cipher));
            Assert.Equal(plain, Decrypt(cipher));
        }

        [Fact]
        public void RoundTrip_50MB_StreamingThroughFiles()
        {
            using var dir = new TempDir();
            string plainPath = Path.Combine(dir.Path, "plain.bin");
            string cipherPath = Path.Combine(dir.Path, "cipher.bin");
            string outPath = Path.Combine(dir.Path, "out.bin");
            const int size = 50 * 1024 * 1024 + 3;
            using (var f = File.Create(plainPath))
            {
                var block = RandomBytes(1024 * 1024);
                for (int written = 0; written < size; written += block.Length)
                {
                    f.Write(block, 0, Math.Min(block.Length, size - written));
                }
            }

            long before = GC.GetTotalAllocatedBytes(true);
            using (var input = File.OpenRead(plainPath))
            using (var output = File.Create(cipherPath))
            {
                BackupCrypto.Encrypt(input, output, Password, FastIterations);
            }

            using (var input = File.OpenRead(cipherPath))
            using (var output = File.Create(outPath))
            {
                BackupCrypto.Decrypt(input, output, Password);
            }

            long allocated = GC.GetTotalAllocatedBytes(true) - before;
            Assert.Equal(size + BackupCrypto.HeaderSize + 51 * BackupCrypto.TagSize, new FileInfo(cipherPath).Length);
            Assert.Equal(File.ReadAllBytes(plainPath), File.ReadAllBytes(outPath));
            // Streaming: a handful of chunk-sized buffers, never the whole 50 MB file.
            Assert.True(allocated < 20 * 1024 * 1024, $"allocated {allocated} bytes");
        }

        [Fact]
        public void RoundTrip_NonSeekableStreams_WithShortReads()
        {
            byte[] plain = RandomBytes(3 * SmallChunk + 5);
            var cipherSink = new MemoryStream();
            using (var input = new NonSeekableStream(new MemoryStream(plain)))
            {
                BackupCrypto.Encrypt(input, cipherSink, Password, FastIterations, SmallChunk);
            }

            var plainSink = new MemoryStream();
            using (var input = new NonSeekableStream(new MemoryStream(cipherSink.ToArray())))
            {
                BackupCrypto.Decrypt(input, plainSink, Password);
            }

            Assert.Equal(plain, plainSink.ToArray());
        }

        [Fact]
        public void DefaultIterations_AreAtLeast600k_AndRecordedInHeader()
        {
            Assert.True(BackupCrypto.DefaultIterations >= 600_000);
            using var input = new MemoryStream(RandomBytes(10));
            using var output = new MemoryStream();
            var sw = Stopwatch.StartNew();
            BackupCrypto.Encrypt(input, output, Password);
            sw.Stop();
            byte[] cipher = output.ToArray();
            Assert.Equal((uint)BackupCrypto.DefaultIterations, BinaryPrimitives.ReadUInt32BigEndian(cipher.AsSpan(8, 4)));
            Assert.Equal(1, cipher[6]);
            Assert.Equal(1, cipher[7]);
        }

        [Fact]
        public void SamePlaintextAndPassword_GiveDifferentSaltNonceAndCiphertext()
        {
            byte[] plain = RandomBytes(5000);
            byte[] a = Encrypt(plain, chunkSize: SmallChunk);
            byte[] b = Encrypt(plain, chunkSize: SmallChunk);
            Assert.NotEqual(a.AsSpan(16, 16).ToArray(), b.AsSpan(16, 16).ToArray()); // salt
            Assert.NotEqual(a.AsSpan(32, 12).ToArray(), b.AsSpan(32, 12).ToArray()); // base nonce
            Assert.NotEqual(a.AsSpan(BackupCrypto.HeaderSize).ToArray(), b.AsSpan(BackupCrypto.HeaderSize).ToArray());
        }

        [Fact]
        public void Ciphertext_DoesNotContainPlaintext()
        {
            byte[] zip = CreateBackupLikeZip();
            byte[] cipher = Encrypt(zip);
            Assert.False(Contains(cipher, Encoding.UTF8.GetBytes("diary secret text")));
            Assert.False(Contains(cipher, Encoding.UTF8.GetBytes("SwashbucklerDiary.db3")));
            Assert.False(Contains(cipher, zip.AsSpan(0, 64).ToArray()));
        }

        [Fact]
        public void WrongPassword_ThrowsPasswordIncorrect_AndWritesNothing()
        {
            byte[] cipher = Encrypt(RandomBytes(4000), chunkSize: SmallChunk);
            using var output = new MemoryStream();
            Assert.Throws<BackupPasswordIncorrectException>(() => BackupCrypto.Decrypt(new MemoryStream(cipher), output, Password + "x"));
            Assert.Equal(0, output.Length);
            Assert.Throws<BackupPasswordIncorrectException>(() => Decrypt(cipher, "CORRECT HORSE BATTERY STAPLE"));
        }

        [Fact]
        public void EmptyPassword_IsRejected()
        {
            Assert.Throws<ArgumentException>(() => Encrypt(RandomBytes(1), password: ""));
            byte[] cipher = Encrypt(RandomBytes(1));
            Assert.Throws<ArgumentException>(() => Decrypt(cipher, ""));
        }

        [Fact]
        public void UnicodePassword_IsNormalized_NfcEqualsNfd()
        {
            string nfc = "密码-café-\u00e9";
            string nfd = "密码-cafe\u0301-e\u0301";
            Assert.NotEqual(nfc, nfd);
            byte[] plain = RandomBytes(100);
            Assert.Equal(plain, Decrypt(Encrypt(plain, password: nfc), nfd));
        }

        [Fact]
        public void TamperingAnyHeaderByte_IsDetected()
        {
            byte[] plain = RandomBytes(2500);
            byte[] cipher = Encrypt(plain, chunkSize: SmallChunk);
            for (int i = 0; i < BackupCrypto.HeaderSize; i++)
            {
                byte[] t = (byte[])cipher.Clone();
                t[i] ^= 0x01;
                var e = Assert.ThrowsAny<BackupEncryptionException>(() => Decrypt(t));
                if (i < 6)
                {
                    Assert.IsType<BackupNotEncryptedException>(e);
                }
                else if (i == 6)
                {
                    Assert.IsType<BackupUnsupportedVersionException>(e);
                }
                else
                {
                    Assert.True(e is BackupPasswordIncorrectException or BackupCorruptedException, $"byte {i}: {e.GetType().Name}");
                }
            }
        }

        [Fact]
        public void TamperingAnyChunk_CiphertextOrTag_IsDetected()
        {
            byte[] plain = RandomBytes(4 * SmallChunk + 100); // 5 chunks
            byte[] cipher = Encrypt(plain, chunkSize: SmallChunk);
            int frame = SmallChunk + BackupCrypto.TagSize;
            for (int chunk = 0; chunk < 5; chunk++)
            {
                int start = BackupCrypto.HeaderSize + chunk * frame;
                int end = Math.Min(start + frame, cipher.Length);
                foreach (int pos in new[] { start, start + (end - start) / 2, end - BackupCrypto.TagSize, end - 1 })
                {
                    byte[] t = (byte[])cipher.Clone();
                    t[pos] ^= 0x80;
                    Assert.Throws<BackupCorruptedException>(() => Decrypt(t));
                }
            }
        }

        [Fact]
        public void Truncation_AtEveryChunkBoundaryAndMidChunk_IsDetected()
        {
            byte[] plain = RandomBytes(4 * SmallChunk); // exactly 4 full chunks: final chunk is a full frame
            byte[] cipher = Encrypt(plain, chunkSize: SmallChunk);
            int frame = SmallChunk + BackupCrypto.TagSize;
            for (int keep = 0; keep < 4; keep++)
            {
                byte[] t = cipher.AsSpan(0, BackupCrypto.HeaderSize + keep * frame).ToArray();
                Assert.Throws<BackupCorruptedException>(() => Decrypt(t));
            }

            foreach (int cut in new[] { 1, 15, 16, 17, frame / 2, frame - 1 })
            {
                byte[] t = cipher.AsSpan(0, cipher.Length - cut).ToArray();
                Assert.Throws<BackupCorruptedException>(() => Decrypt(t));
            }

            // Header only partially present
            Assert.Throws<BackupCorruptedException>(() => Decrypt(cipher.AsSpan(0, 40).ToArray()));
        }

        [Fact]
        public void Truncation_OfEmptyPayloadFile_IsDetected()
        {
            byte[] cipher = Encrypt([]);
            Assert.Empty(Decrypt(cipher));
            Assert.Throws<BackupCorruptedException>(() => Decrypt(cipher.AsSpan(0, BackupCrypto.HeaderSize).ToArray()));
        }

        [Theory]
        [InlineData(1)]
        [InlineData(16)]
        [InlineData(SmallChunk + BackupCrypto.TagSize)]
        [InlineData(3 * SmallChunk)]
        public void AppendedGarbage_IsDetected(int extra)
        {
            foreach (int size in new[] { 0, 100, SmallChunk, 3 * SmallChunk })
            {
                byte[] cipher = Encrypt(RandomBytes(size), chunkSize: SmallChunk);
                byte[] t = [.. cipher, .. RandomBytes(extra)];
                Assert.Throws<BackupCorruptedException>(() => Decrypt(t));
            }
        }

        [Fact]
        public void ReorderedOrDuplicatedChunks_AreDetected()
        {
            byte[] plain = RandomBytes(3 * SmallChunk + 10);
            byte[] cipher = Encrypt(plain, chunkSize: SmallChunk);
            int frame = SmallChunk + BackupCrypto.TagSize;
            int h = BackupCrypto.HeaderSize;

            byte[] swapped = (byte[])cipher.Clone();
            cipher.AsSpan(h, frame).CopyTo(swapped.AsSpan(h + frame));
            cipher.AsSpan(h + frame, frame).CopyTo(swapped.AsSpan(h));
            Assert.Throws<BackupCorruptedException>(() => Decrypt(swapped));

            byte[] duplicated = [.. cipher.AsSpan(0, h + frame), .. cipher.AsSpan(h, frame), .. cipher.AsSpan(h + frame)];
            Assert.Throws<BackupCorruptedException>(() => Decrypt(duplicated));
        }

        [Fact]
        public void ChunksFromAnotherFileWithSamePassword_AreRejected()
        {
            byte[] a = Encrypt(RandomBytes(2 * SmallChunk), chunkSize: SmallChunk);
            byte[] b = Encrypt(RandomBytes(2 * SmallChunk), chunkSize: SmallChunk);
            byte[] spliced = [.. a.AsSpan(0, BackupCrypto.HeaderSize), .. b.AsSpan(BackupCrypto.HeaderSize)];
            Assert.Throws<BackupCorruptedException>(() => Decrypt(spliced));
        }

        [Fact]
        public void CraftedHeaderWithHugeParameters_IsRejectedWithoutKeyDerivation()
        {
            byte[] cipher = Encrypt(RandomBytes(10));
            byte[] t = (byte[])cipher.Clone();
            BinaryPrimitives.WriteUInt32BigEndian(t.AsSpan(8, 4), uint.MaxValue);
            var sw = Stopwatch.StartNew();
            Assert.Throws<BackupCorruptedException>(() => Decrypt(t));
            Assert.True(sw.ElapsedMilliseconds < 2000);

            t = (byte[])cipher.Clone();
            BinaryPrimitives.WriteUInt32BigEndian(t.AsSpan(12, 4), 1u << 30);
            Assert.Throws<BackupCorruptedException>(() => Decrypt(t));

            t = (byte[])cipher.Clone();
            BinaryPrimitives.WriteUInt32BigEndian(t.AsSpan(8, 4), 1);
            Assert.Throws<BackupCorruptedException>(() => Decrypt(t));
        }

        [Fact]
        public void Encrypt_RejectsWeakParameters()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => BackupCrypto.Encrypt(new MemoryStream(), new MemoryStream(), Password, 1000));
            Assert.Throws<ArgumentOutOfRangeException>(() => BackupCrypto.Encrypt(new MemoryStream(), new MemoryStream(), Password, FastIterations, 16));
        }

        [Fact]
        public void IsEncrypted_Detection()
        {
            byte[] zip = CreateBackupLikeZip(1000);
            Assert.True(BackupCrypto.HasZipMagic(zip));

            var zipStream = new MemoryStream(zip) { Position = 0 };
            Assert.False(BackupCrypto.IsEncrypted(zipStream));
            Assert.Equal(0, zipStream.Position); // restored

            byte[] cipher = Encrypt(zip);
            var cipherStream = new MemoryStream(cipher);
            cipherStream.Position = 0;
            Assert.True(BackupCrypto.IsEncrypted(cipherStream));
            Assert.Equal(0, cipherStream.Position);

            Assert.False(BackupCrypto.IsEncrypted(new MemoryStream()));
            Assert.False(BackupCrypto.IsEncrypted(new MemoryStream("SBDEN"u8.ToArray())));
            Assert.False(BackupCrypto.IsEncrypted(new MemoryStream(RandomBytes(1000).Select(b => (byte)(b | 0x80)).ToArray())));
        }

        [Fact]
        public void Decrypt_OnPlaintextZipOrRandomData_ThrowsNotEncrypted()
        {
            Assert.Throws<BackupNotEncryptedException>(() => Decrypt(CreateBackupLikeZip(100)));
            Assert.Throws<BackupNotEncryptedException>(() => Decrypt([]));
            Assert.Throws<BackupNotEncryptedException>(() => Decrypt(Encoding.ASCII.GetBytes("hello world, this is not a backup")));
        }

        [Fact]
        public void EncryptedZip_IsNotOpenableAsZip()
        {
            byte[] cipher = Encrypt(CreateBackupLikeZip(100));
            Assert.ThrowsAny<InvalidDataException>(() => new System.IO.Compression.ZipArchive(new MemoryStream(cipher)));
        }
    }
}
