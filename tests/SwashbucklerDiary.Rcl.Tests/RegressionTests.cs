using Microsoft.Extensions.DependencyInjection;
using SwashbucklerDiary.Rcl.Essentials;
using SwashbucklerDiary.Rcl.Extensions;
using SwashbucklerDiary.Rcl.Services;

namespace SwashbucklerDiary.Rcl.Tests
{
    public class RegressionTests
    {
        private sealed class MemoryPreferences : IPreferences
        {
            public Dictionary<string, object?> Values { get; } = [];
            public Task<bool> ContainsKey(string key) => Task.FromResult(Values.ContainsKey(key));
            public Task<T> GetAsync<T>(string key, T defaultValue) => Task.FromResult(Values.TryGetValue(key, out var v) ? (T)v! : defaultValue);
            public Task SetAsync<T>(string key, T value) { Values[key] = value; return Task.CompletedTask; }
            public Task RemoveAsync(string key) { Values.Remove(key); return Task.CompletedTask; }
            public Task RemoveAsync(IEnumerable<string> keys) { foreach (var k in keys) Values.Remove(k); return Task.CompletedTask; }
            public Task ClearAsync() { Values.Clear(); return Task.CompletedTask; }
        }

        private sealed class MemorySettingService(MemoryPreferences p) : SettingService(p)
        {
            public override T Get<T>(string key, T defaultValue) => p.Values.TryGetValue(key, out var v) ? (T)v! : defaultValue;
        }

        /// <summary>
        /// Pre-existing upstream bug: SetSettingsFromObjectAsync used GetMethod("SetAsync"), which is ambiguous and threw
        /// AmbiguousMatchException, so every DB backup restore (ImportDBAsync -> ReadSettingsFileAsync) failed.
        /// </summary>
        [Fact]
        public async Task SetSettingsFromObjectAsync_DoesNotThrow_AndAppliesValues()
        {
            var prefs = new MemoryPreferences();
            var service = new MemorySettingService(prefs);
            var setting = new Setting { NickName = "restored", Theme = 2, BackupEncryption = true };

            await service.SetSettingsFromObjectAsync(setting, name => name != nameof(Setting.BackupEncryption));

            Assert.Equal("restored", service.Get(s => s.NickName));
            Assert.Equal(2, service.Get(s => s.Theme));
            Assert.False(service.Get(s => s.BackupEncryption)); // filtered like excludedSettings
        }

        [Fact]
        public void DI_BackupEncryptionService_FollowsSettingServiceLifetime_AndCanBeDisabledForWeb()
        {
            foreach (var lifetime in new[] { ServiceLifetime.Singleton, ServiceLifetime.Scoped })
            {
                IServiceCollection services = new ServiceCollection();
                services.Add(ServiceDescriptor.Describe(typeof(ISettingService), _ => new MemorySettingService(new MemoryPreferences()), lifetime));
                services.AddSingleton<IAppFileSystem>(new TestAppFileSystem(Path.GetTempPath()));
                services.AddRclDependencyInjection();
                Assert.Equal(lifetime, services.Single(d => d.ServiceType == typeof(IBackupEncryptionService)).Lifetime);

                using (var sp = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true }))
                using (var scope = sp.CreateScope())
                {
                    var svc = scope.ServiceProvider.GetRequiredService<IBackupEncryptionService>();
                    Assert.IsType<BackupEncryptionService>(svc);
                    Assert.True(svc.IsSupported);
                    Assert.False(svc.Enabled); // default OFF
                }

                services.DisableBackupEncryption();
                Assert.Single(services, d => d.ServiceType == typeof(IBackupEncryptionService));
                using (var sp = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true }))
                using (var scope = sp.CreateScope())
                {
                    var svc = scope.ServiceProvider.GetRequiredService<IBackupEncryptionService>();
                    Assert.IsType<UnsupportedBackupEncryptionService>(svc);
                    Assert.False(svc.IsSupported);
                    Assert.False(svc.Enabled);
                }
            }
        }

        [Fact]
        public async Task Unsupported_Service_StillDetectsEncryptedFiles()
        {
            using var dir = new TempDir();
            string path = Path.Combine(dir.Path, "x.zip");
            File.WriteAllBytes(path, TestHelpers.Encrypt([1, 2, 3]));
            var svc = new UnsupportedBackupEncryptionService(null!, new TestAppFileSystem(dir.Path));
            Assert.True(await svc.IsEncryptedFileAsync(path));
            Assert.False(svc.Enabled);
        }
    }
}
