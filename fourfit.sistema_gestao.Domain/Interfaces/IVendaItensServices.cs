using fourfit.sistema_gestao.Domain.Entities.Store.Venda;
using fourfit.sistema_gestao.Domain.Interfaces.Base;


namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IVendaItensServices : IBaseServices<VendaItens>
    {
        Task<IEnumerable<VendaItens>> ObterIntensExistentes();
        Task<VendaItens> ObterItensPorId(int Id);
        Task<decimal> CalcularValorTotal(IEnumerable<VendaItens> itens);
        //Task<IEnumerable<VendaItens>> CalcularValorTotal();
    }
}
