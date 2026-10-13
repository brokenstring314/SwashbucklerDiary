using Masa.Blazor;
using System.ComponentModel.DataAnnotations;

namespace SwashbucklerDiary.Rcl.Components
{
    /// <summary>
    /// Asks for the backup encryption password. Usage: <c>string? pw = await dialog.ShowAsync(confirm: true);</c>
    /// Returns null when cancelled. The password is never stored by this component beyond the open dialog.
    /// </summary>
    public partial class BackupPasswordDialog : FocusDialogComponentBase
    {
        public const int MinLength = 8;

        public const int MaxLength = 128;

        private MForm? form;

        private Model model = new();

        private bool confirm;

        private bool showPassword1;

        private bool showPassword2;

        private TaskCompletionSource<string?>? tcs;

        /// <param name="requireConfirmation">true when creating a backup (enter twice, min length enforced); false when restoring.</param>
        public async Task<string?> ShowAsync(bool requireConfirmation)
        {
            tcs?.TrySetResult(null);
            tcs = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
            confirm = requireConfirmation;
            model = requireConfirmation ? new ConfirmModel() : new Model();
            showPassword1 = showPassword2 = false;
            form?.Reset();
            await InternalVisibleChanged(true);
            await InvokeAsync(StateHasChanged);
            return await tcs.Task;
        }

        protected override async Task InternalVisibleChanged(bool value)
        {
            await base.InternalVisibleChanged(value);
            if (!value)
            {
                Complete(null);
            }
        }

        private async Task HandleOnOK()
        {
            string? password = model.Password;
            Complete(password);
            await base.InternalVisibleChanged(false);
        }

        private void Complete(string? password)
        {
            var current = tcs;
            tcs = null;
            model = new Model();
            current?.TrySetResult(string.IsNullOrEmpty(password) ? null : password);
        }

        class Model
        {
            [Required(ErrorMessage = "Please enter password")]
            public virtual string? Password { get; set; }

            public virtual string? PasswordConfirmation { get; set; }
        }

        class ConfirmModel : Model
        {
            [Required(ErrorMessage = "Please enter password")]
            [MinLength(MinLength, ErrorMessage = "Password must be at least 8 characters long")]
            public override string? Password { get; set; }

            [Required(ErrorMessage = "Please enter password")]
            [Compare(nameof(Password), ErrorMessage = "The two passwords are inconsistent")]
            public override string? PasswordConfirmation { get; set; }
        }
    }
}
