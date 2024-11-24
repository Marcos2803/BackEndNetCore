using fourfit.sistema_gestao.Domain.Entities.Financas;

namespace fourfit_sistema_gestao.Api.Models.Investimento
{
    public class InvestimentosViewModels
    {
        public int Id { get; set; }
        public int FormaPagamentoId { get; set; }
        public int ContasBancariasId { get; set; }
        public string Descricao { get; set; }
        public int ValorInvestido { get; set; }
        public DateTime DataVencimento { get; set; }
        public DateTime DataPagamento { get; set; }
        public string StatusPagamentos { get; set; }
        public string Observacao { get; set; }
    }
}
