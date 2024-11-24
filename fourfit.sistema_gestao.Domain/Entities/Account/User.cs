using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Entities.Profission;
using fourfit.sistema_gestao.Domain.Entities.Store.Venda;
using Microsoft.AspNetCore.Identity;
using System.Text.Json.Serialization;
namespace fourfit.sistema_gestao.Domain.Entities.Account
{
    public class User:IdentityUser
    {
        public string? PrimeiroNome { get; set; }
        public string? SobreNome { get; set; }
        public string? Celular { get; set; }

        [JsonIgnore]
        public ICollection<EntidadeAlunos> Alunos { get; set; }
        public ICollection<EntidadeProfessores> Professores { get; set; }
        public ICollection<EntidadeColaboradores> colaboradores { get; set; }
        public ICollection<AulaExperimental> AulaExperimental { get; set; }
        public ICollection<Vendas> Vendas { get; set; }


    }
}
