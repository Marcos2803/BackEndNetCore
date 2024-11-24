using fourfit.sistema_gestao.Domain.Entities.Alunos;

namespace fourfit_sistema_gestao.Api.Models.PersonalRecords
{
    public class PersonalRecordUpdateViewModels
    {
        public int Id { get; set; }
        public int AlunosId { get; set; }
        public int ExerciciosId { get; set; }
        public decimal PesoPR { get; set; }
        public DateTime DataPR { get; set; }
        public string Observacao { get; set; }
    }
}
