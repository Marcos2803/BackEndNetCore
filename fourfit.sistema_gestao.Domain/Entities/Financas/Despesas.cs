

namespace fourfit.sistema_gestao.Domain.Entities.Financas
{
    public class Despesas
    {
        public int Id { get; set; }
        public int FormaPagamentoId { get; set; }
        public FormaPagamento FormaPagamento { get; set; }
        public int ContasBancariasId { get; set; }
        public ContasBancarias ContasBancarias { get; set; }
        public int TipoDespesasId { get; set; }
        public TipoDespesas TipoDespesas { get; set; }
        public string Descricao { get; set; }
        public int ValorDespesa { get; set; }
        public DateTime DataVencimento { get; set; }
        public DateTime DataPagamento { get; set; }
        public string StatusPagamentos { get; set; }
        public string Observacao { get; set; }
    }
}