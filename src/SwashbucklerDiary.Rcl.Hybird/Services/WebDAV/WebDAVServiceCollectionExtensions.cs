using Microsoft.Extensions.DependencyInjection;
using SwashbucklerDiary.Rcl.Services;

namespace SwashbucklerDiary.Rcl.Hybird.Services
{
    public static class WebDAVServiceCollectionExtensions
    {
        /// <summary>
        /// Registers <see cref="IWebDAV"/> as <see cref="EncryptedWebDAV"/> wrapping the plain <see cref="WebDAV"/> client.
        /// With backup encryption turned off the decorator is a pass-through (downloads are still auto-detected).
        /// </summary>
        public static IServiceCollection AddWebDAVWithBackupEncryption(this IServiceCollection services)
        {
            services.AddSingleton<WebDAV>();
            services.AddSingleton<IWebDAV>(sp => new EncryptedWebDAV(
                sp.GetRequiredService<WebDAV>(),
                sp.GetRequiredService<IBackupEncryptionService>()));
            return services;
        }
    }
}
