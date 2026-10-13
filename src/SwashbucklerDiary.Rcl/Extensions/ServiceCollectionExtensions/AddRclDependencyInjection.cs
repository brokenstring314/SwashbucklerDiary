using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SwashbucklerDiary.Rcl.Components;
using SwashbucklerDiary.Rcl.Services;

namespace SwashbucklerDiary.Rcl.Extensions
{
    public static partial class ServiceCollectionExtensions
    {
        public static IServiceCollection AddRclDependencyInjection(this IServiceCollection services)
        {
            services.TryAddScoped<InputJSModule>();
            services.TryAddScoped<AudioInterop>();
            services.TryAddScoped<ScreenshotJSModule>();

            // Same lifetime as ISettingService (singleton in MAUI/Gtk/WASM, scoped in Server), which every head registers before this call.
            var backupEncryptionLifetime = services.LastOrDefault(it => it.ServiceType == typeof(ISettingService))?.Lifetime ?? ServiceLifetime.Scoped;
            services.TryAdd(ServiceDescriptor.Describe(typeof(IBackupEncryptionService), typeof(BackupEncryptionService), backupEncryptionLifetime));
            return services;
        }

        /// <summary>Hides the optional backup encryption feature (Web heads). Call after <see cref="AddRclDependencyInjection"/>.</summary>
        public static IServiceCollection DisableBackupEncryption(this IServiceCollection services)
        {
            var lifetime = services.LastOrDefault(it => it.ServiceType == typeof(IBackupEncryptionService))?.Lifetime ?? ServiceLifetime.Scoped;
            services.Replace(ServiceDescriptor.Describe(typeof(IBackupEncryptionService), typeof(UnsupportedBackupEncryptionService), lifetime));
            return services;
        }
    }
}
