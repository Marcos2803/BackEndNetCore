

using fourfit.sistema_gestao.Domain.Enumerables;

namespace fourfit_sistema_gestao.Api.Models.Pagamento
{
    public class PagamentosViewModels
    {
        public int Id { get; set; }
        public int? FormaPagamentoId { get; set; }
        public int? ContasBancariasId { get; set; }
        public DateTime? DataPagamento { get; set; }
        public decimal? ValorVenda { get; set; }
        public decimal? Desconto { get; set; }
        public decimal? ValorComDesconto { get; set; }
        public decimal? ValorPago { get; set; }
        public decimal? Troco { get; set; }
        //public string StatusPagamento { get; set; }
        public StatusPagamentosEnum StatusPagamento { get; set; }
    }
}
