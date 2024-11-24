

using fourfit.sistema_gestao.Domain.Entities.Store.Venda;

namespace fourfit.sistema_gestao.Domain.Entities.Alunos
{
    public class Parcelas
    {
        public int Id { get; set; }
        public int MensalidadesId { get; set; }
        public Mensalidades Mensalidades { get; set; }
        //public int PagamentosId { get; set; }
        //public Pagamentos Pagamentos { get; set; }
        public decimal Valor { get; set; }
        public DateTime DataVencimento { get; set; }
        public bool Pago { get; set; }
       
    }
}
