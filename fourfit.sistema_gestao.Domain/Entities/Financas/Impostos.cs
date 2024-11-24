
namespace fourfit.sistema_gestao.Domain.Entities.Financas
{
    public class Impostos
    {
        public int Id { get; set; }
        public string NomeImposto { get; set; }

        public virtual ICollection<TipoDespesas> TipoDespesas { get; set; }
    }
}
