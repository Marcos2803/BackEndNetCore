using fourfit.sistema_gestao.Domain.Entities.Store.ControleEstoque;
using fourfit.sistema_gestao.Domain.Interfaces.Base;


namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IEstoqueServices : IBaseServices<Estoque>
    {
        Task<IEnumerable<Estoque>> ObterEstoqueExistentes();

        Task<Estoque> ObterEstoquePorId(int Id);
    }
}
