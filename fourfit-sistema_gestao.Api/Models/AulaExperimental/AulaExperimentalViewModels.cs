using fourfit.sistema_gestao.Domain.Entities.Account;
using fourfit.sistema_gestao.Domain.Entities.Alunos;

namespace fourfit_sistema_gestao.Api.Models.AulaExperimental
{
    public class AulaExperimentalViewModels
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public int HorariosId { get; set; }
        public DateTime DataHExperimental { get; set; }
    }
}
