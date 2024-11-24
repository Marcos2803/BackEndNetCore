using fourfit.sistema_gestao.Domain.Entities.Account;
using fourfit.sistema_gestao.Domain.Enumerables;
using System.Text.Json.Serialization;


namespace fourfit.sistema_gestao.Domain.Entities.Alunos
{
    public class EntidadeAlunos : Generics
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        [JsonIgnore]
        public User User { get; set; }
        public DateTime DataCadastro { get; set; }
        public byte[]? Foto { get; set; }
        public StatusAlunosEnum StatusAlunos { get; set; }

        public ICollection<Checkins> Checkins { get; set; }
        public ICollection<Mensalidades> Mensalidades { get; set; }
        public ICollection<AvaliacaoFisica> AvaliacoesFisicas { get; set; }
        public ICollection<Parq> Parq { get; set; }
        public ICollection<PersonalRecord> PersonalRecord { get; set; }









    }
}
