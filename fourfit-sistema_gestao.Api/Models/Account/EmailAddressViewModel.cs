using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace fourfit_sistema_gestao.Api.Models.Account
{
    [Table("EmailServices")]
    public class EmailAddressViewModel
    {
 
            [Required]
            public string? From { get; set; }
            [Required]
            public string? To { get; set; }
            [Required]
            public string? Subject { get; set; }
            [Required]
            public string? Body { get; set; }
    }
}
