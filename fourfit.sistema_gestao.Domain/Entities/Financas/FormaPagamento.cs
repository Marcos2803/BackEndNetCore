using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Entities.Store.Venda;

namespace fourfit.sistema_gestao.Domain.Entities.Financas
{
    public class FormaPagamento
    {
        public int Id { get; set; }
        public string Tipo { get; set; }

        public virtual ICollection<Pagamentos> Pagamentos { get; set; }
        public virtual ICollection<Mensalidades> Mensalidades { get; set; }
        public virtual ICollection<Despesas> Despesas { get; set; }
        public virtual ICollection<Investimentos> Investimentos { get; set; }
        public ICollection<Parcelas> ParcelaMensalidades { get; set; }
    }
}