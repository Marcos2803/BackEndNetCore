using Microsoft.EntityFrameworkCore;

namespace fourfit.sistema_gestao.Domain.Entities.Alunos
{
    public class PersonalRecord 
    {
        public int Id { get; set; }
        public int AlunosId { get; set; }
        public  EntidadeAlunos Alunos { get; set; }
        public int ExerciciosId { get; set; }
        public  Exercicios Exercicios { get; set; }
        public decimal PesoPR { get; set; }
        public DateTime DataPR  { get; set; }
        public string? Observacao { get; set; }
    }
}
