using System.ComponentModel.DataAnnotations;

namespace fourfit_sistema_gestao.Api.Models.Account
{
    public class ForgotPasswordViewModel
    {

        [Required(ErrorMessage = "E-mail é obrigatório")]
        [EmailAddress(ErrorMessage = "Email é invalido")]

        public string? Email { get; set; }
    }
}
