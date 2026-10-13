using Microsoft.AspNetCore.Components;
using SwashbucklerDiary.Rcl.Services;

namespace SwashbucklerDiary.Rcl.Components
{
    /// <summary>Toggle for <see cref="Setting.BackupEncryption"/>. Renders nothing where AES-GCM is unavailable (browser WebAssembly).</summary>
    public partial class BackupEncryptionSwitch : MyComponentBase
    {
        [Inject]
        private IBackupEncryptionService BackupEncryptionService { get; set; } = default!;

        [Parameter]
        public string? Class { get; set; }

        // Keeps the switches on the local and WebDAV tabs in sync (SettingService.SetAsync raises no event).
        private static event Action? EnabledChanged;

        protected override void OnInitialized()
        {
            base.OnInitialized();
            EnabledChanged += Refresh;
            SettingService.SettingsChanged += Refresh;
        }

        protected override async ValueTask DisposeAsyncCore()
        {
            await base.DisposeAsyncCore();
            EnabledChanged -= Refresh;
            SettingService.SettingsChanged -= Refresh;
        }

        private async Task HandleOnChange((string Key, bool Value) args)
        {
            await SettingService.SetAsync(s => s.BackupEncryption, args.Value);
            EnabledChanged?.Invoke();
            if (args.Value)
            {
                await AlertService.InfoAsync(I18n.T("A forgotten backup password cannot be recovered"));
            }
        }

        private void Refresh() => _ = InvokeAsync(StateHasChanged);
    }
}
