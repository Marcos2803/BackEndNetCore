using fourfit.sistema_gestao.Domain.Enumerables;

namespace fourfit.sistema_gestao.Domain.Entities.Alunos
{
    public class TipoPlano
    {
        public int Id { get; set; }
        public string NomePlano { get; set; }
        public string Descricao { get; set; }
        public int DiaPorSemana { get; set; }
        public int DuracaoMes { get; set; }
        public int DuracaoDia { get; set; }
        public decimal ValorPlano { get; set; }
        public StatusPlanosEnum StatusPlanos { get; set; }

        public virtual ICollection<Mensalidades> Mensalidades { get; set; }

        public virtual ICollection<Modalidades> Modalidades { get; set; }




    }
}
