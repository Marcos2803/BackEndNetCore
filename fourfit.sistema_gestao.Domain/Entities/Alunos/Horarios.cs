using fourfit.sistema_gestao.Domain.Entities.Profission;

namespace fourfit.sistema_gestao.Domain.Entities.Alunos
{
    public class Horarios
    {
        public int Id { get; set; }
        public int ProfessoresId { get; set; }
        public EntidadeProfessores Professores { get; set; }
        public int ModalidadesId { get; set; }
        public Modalidades Modalidades { get; set; }
        public string Dia { get; set; }
        public TimeSpan HoraInicio { get; set; }
        public TimeSpan HoraFim { get; set; }
        public string Descricao { get; set; }
        public int LimiteAlunos { get; set; }
        public string Status { get; set; }

        public ICollection<Checkins> Checkins { get; set; }
        public ICollection<AulaExperimental> AulaExperimental{ get; set; }
    }
}
