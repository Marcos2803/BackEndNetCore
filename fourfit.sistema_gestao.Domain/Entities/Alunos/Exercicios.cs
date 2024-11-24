namespace fourfit.sistema_gestao.Domain.Entities.Alunos
{
    public class Exercicios
    {
        public int Id { get; set; }
        public string Nome { get; set; }

        public ICollection<PersonalRecord> PersonalRecord { get; set; }
    }
}
