using fourfit.sistema_gestao.Domain.Entities.Account;


namespace fourfit.sistema_gestao.Domain.Entities.Alunos
{
    public class Checkins
    {
        public int Id { get; set; }
        public DateTime DataCheckin { get; set; }
        public int AlunosId { get; set; }
        public EntidadeAlunos Alunos { get; set; }
        public int HorariosId { get; set; }
        public Horarios Horarios { get; set; }




    }
}
