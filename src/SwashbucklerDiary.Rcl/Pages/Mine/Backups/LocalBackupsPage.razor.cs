using Microsoft.AspNetCore.Components;
using SwashbucklerDiary.Rcl.Components;
using SwashbucklerDiary.Rcl.Services;

namespace SwashbucklerDiary.Rcl.Pages
{
    public partial class LocalBackupsPage : ImportantComponentBase
    {
        private bool showBackups;

        private bool showRestore;

        private string? restoreFilePath;

        [Inject]
        private IDiaryFileManager DiaryFileManager { get; set; } = default!;

        [Inject]
        private IBackupEncryptionService BackupEncryptionService { get; set; } = default!;

        private BackupPasswordDialog backupPasswordDialog = default!;

        private async Task Backups()
        {
            showBackups = false;
            var flag = await PlatformIntegration.TryStorageWritePermission();
            if (!flag)
            {
                await AlertService.InfoAsync(I18n.T("Please grant permission for storage writing"));
                return;
            }

            // Optional encryption: ask for the password before any work starts; it is not stored.
            string? password = null;
            if (BackupEncryptionService.Enabled)
            {
                password = await backupPasswordDialog.ShowAsync(true);
                if (password is null)
                {
                    return;
                }
            }

            AlertService.StartLoading();

            string? exportedFilePath = null;
            string? encryptedFilePath = null;
            try
            {
                string filePath = exportedFilePath = await DiaryFileManager.ExportDBAsync(true);
                string name = DiaryFileManager.GetBackupFileName();
                if (password is not null)
                {
                    encryptedFilePath = await BackupEncryptionService.EncryptFileAsync(filePath, password);
                    filePath = encryptedFilePath;
                    name = BackupEncryptionService.GetEncryptedFileName(name);
                }

                bool isSuccess = await PlatformIntegration.SaveFileAsync(name, filePath);
                if (isSuccess)
                {
                    await AlertService.SuccessAsync(I18n.T("Backup successful"));
                }
            }
            finally
            {
                if (password is not null)
                {
                    // Don't keep a plaintext copy of an archive that was meant to leave the device encrypted.
                    BackupEncryptionService.DeleteTempFile(exportedFilePath);
                }

                BackupEncryptionService.DeleteTempFile(encryptedFilePath);
                AlertService.StopLoading();
            }
        }

        private async Task Restore()
        {
            restoreFilePath = string.Empty;
            restoreFilePath = await PlatformIntegration.PickZipFileAsync();
            if (string.IsNullOrEmpty(restoreFilePath))
            {
                return;
            }

            showRestore = true;
        }

        private async Task ConfirmRestore()
        {
            showRestore = false;
            StateHasChanged();

            if (string.IsNullOrEmpty(restoreFilePath))
            {
                await AlertService.ErrorAsync(I18n.T("Restore failed"));
                return;
            }

            // Encrypted backups are detected by their header, whatever the current setting; plaintext zips take the old path.
            string? decryptedFilePath = null;
            string importFilePath = restoreFilePath;
            if (await IsEncryptedBackupAsync(restoreFilePath))
            {
                if (!BackupEncryptionService.IsSupported)
                {
                    await AlertService.ErrorAsync(I18n.T("Encrypted backups are not supported on the current platform"));
                    return;
                }

                string? password = await backupPasswordDialog.ShowAsync(false);
                if (password is null)
                {
                    return;
                }

                AlertService.StartLoading();
                try
                {
                    decryptedFilePath = await BackupEncryptionService.DecryptFileAsync(restoreFilePath, password);
                    importFilePath = decryptedFilePath;
                }
                catch (BackupPasswordIncorrectException)
                {
                    await AlertService.ErrorAsync(I18n.T("Incorrect backup password"));
                    return;
                }
                catch (BackupEncryptionException)
                {
                    await AlertService.ErrorAsync(I18n.T("The backup file is damaged or has been modified"));
                    return;
                }
                finally
                {
                    AlertService.StopLoading();
                }
            }

            AlertService.StartLoading();

            try
            {
                bool flag = await DiaryFileManager.ImportDBAsync(importFilePath);
                if (flag)
                {
                    await AlertService.SuccessAsync(I18n.T("Restore successfully"));
                }
                else
                {
                    await AlertService.ErrorAsync(I18n.T("Restore failed"));
                }
            }
            finally
            {
                BackupEncryptionService.DeleteTempFile(decryptedFilePath);
                AlertService.StopLoading();
            }
        }

        private async Task<bool> IsEncryptedBackupAsync(string path)
        {
            try
            {
                return await BackupEncryptionService.IsEncryptedFileAsync(path);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
            {
                // Let the existing import path handle unreadable files exactly as before.
                return false;
            }
        }
    }

}
