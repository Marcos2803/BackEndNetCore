using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Entities.Profission;

namespace fourfit_sistema_gestao.Api.Models.Horario
{
    public class HorariosViewModels
    {
        public int Id { get; set; }
        public int ProfessoresId { get; set; }
        public int ModalidadesId { get; set; }
        public string Dia { get; set; }
        public string HoraInicio { get; set; }
        public string HoraFim { get; set; }
        public string Descricao { get; set; }
        public int LimiteAlunos { get; set; }
        public string Status { get; set; }
    }
}
