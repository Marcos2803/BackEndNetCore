using fourfit.sistema_gestao.Domain.Entities.Account;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Entities.Store.ControleEstoque;
using fourfit.sistema_gestao.Domain.Enumerables;


namespace fourfit.sistema_gestao.Domain.Entities.Store.Venda
{
    public class Vendas
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public User User { get; set; }
        public DateTime DataVenda { get; set; }
        
        public StatusPagamentosEnum StatusPagamento { get; set; }

        public ICollection<VendaItens> VendaItens { get; set; }
        public ICollection<Pagamentos> Pagamentos { get; set; }
        

    }
}
