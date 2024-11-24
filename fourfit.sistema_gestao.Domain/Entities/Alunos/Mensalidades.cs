using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Enumerables;


namespace fourfit.sistema_gestao.Domain.Entities.Alunos
{
    public class Mensalidades
    {

        public int Id { get; set; }
        public int AlunosId { get; set; }
        public EntidadeAlunos Alunos { get; set; }
        public int PlanoId { get; set; }
        public TipoPlano Planos { get; set; }
        public int FormaPagamentoId { get; set; }
        public FormaPagamento FormaPagamento { get; set; }
        public int ContasBancariasId { get; set; }
        public ContasBancarias ContasBancarias { get; set; }
        public decimal ValorMensalidade { get; set; }
        public decimal? ValorMatricula { get; set; }
        public string MesReferente { get; set; }
        public DateTime DataInicialPlano { get; set; }
        public DateTime? DataPagamento { get; set; }

        public ICollection<Parcelas> ParcelaMensalidades { get; set; }
        public StatusMensalidadesEnum StatusMensalidades { get; set; }
        public StatusPagamentosEnum StatusPagamentos { get; set; }

    }
}
