using fourfit.sistema_gestao.Domain.Entities.Store.Venda;
using fourfit.sistema_gestao.Domain.Interfaces;



namespace fourfit.sistema_gestao.Domain.Interfaces.Services
{
    public class VendasServicos
    {

        public async Task<decimal> CalcularValorTotal(IEnumerable<VendaItens> itens)
        {
            decimal valorTotal = 0;
            foreach (var item in itens)
            {
                valorTotal += item.Produtos.PrecoVenda * item.Quantidade;
                
            }
            return valorTotal;
        }

        public decimal AplicarDesconto(decimal valorTotal, decimal percentualDesconto)
        {
            return valorTotal - valorTotal * (percentualDesconto / 100);
        }
    }
}
