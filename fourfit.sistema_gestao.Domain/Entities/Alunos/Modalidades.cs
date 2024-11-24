using fourfit.sistema_gestao.Domain.Entities.Account;

namespace fourfit.sistema_gestao.Domain.Entities.Alunos
{
    public class Modalidades
    {
        public int Id { get; set; }
        public string Nome { get; set; }
        public int PlanosId { get; set; }
        public TipoPlano Planos { get; set; }
        public string Descricao { get; set; }
        public string Status { get; set; }
        public string AceitaCheckin { get; set; }


        public ICollection<Horarios> Horarios { get; set; }

       

    }
}
