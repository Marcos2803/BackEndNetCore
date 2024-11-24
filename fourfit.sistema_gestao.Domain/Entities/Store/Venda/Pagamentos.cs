using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Enumerables;

namespace fourfit.sistema_gestao.Domain.Entities.Store.Venda
{
    public class Pagamentos
    {
        public int Id { get; set; }
        public int? FormaPagamentoId { get; set; }
        public FormaPagamento FormaPagamento { get; set; }
        public int? ContasBancariasId { get; set; }
        public ContasBancarias ContasBancarias { get; set; }
        public int VendasId { get; set; }
        public Vendas Vendas { get; set; }
        public DateTime? DataPagamento { get; set; }
        public decimal? ValorVenda { get; set; }
        public decimal? Desconto { get; set; }
        public decimal? ValorComDesconto { get; set; }
        public decimal? ValorPago { get; set; }
        public decimal? Troco { get; set; }
        public StatusPagamentosEnum StatusPagamento { get; set; }


    }
}
