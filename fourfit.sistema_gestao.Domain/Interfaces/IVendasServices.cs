using fourfit.sistema_gestao.Domain.Entities.Store.Venda;
using fourfit.sistema_gestao.Domain.Interfaces.Base;



namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IVendasServices : IBaseServices<Vendas>
    {
        Task<IEnumerable<Vendas>> ObterVendasExistentes();
        Task<Vendas> ObterVendasPorId(int Id);
        



    }
}
