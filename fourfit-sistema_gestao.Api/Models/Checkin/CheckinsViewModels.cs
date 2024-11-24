using fourfit.sistema_gestao.Domain.Entities.Alunos;

namespace fourfit_sistema_gestao.Api.Models.Checkin
{
    public class CheckinsViewModels
    {
        public DateTime DataCheckin { get; set; }
        public int AlunosId { get; set; }
        public int HorariosId { get; set; }
    }
}
