
using fourfit.sistema_gestao.Domain.Enumerables;
using fourfit_sistema_gestao.Api.Models.Pagamento;

namespace fourfit_sistema_gestao.Api.Models.Venda
{
    public class VendasViewModels
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public IEnumerable<VendaItensViewModels> VendaItens { get; set; }
        public IEnumerable<PagamentosViewModels> Pagamentos { get; set; }
        public DateTime DataVenda { get; set; }
        public StatusPagamentosEnum StatusPagamento { get; set; }

    }
}
