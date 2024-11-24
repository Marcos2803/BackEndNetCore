using fourfit.sistema_gestao.Domain.Entities.Store.ControleEstoque;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IProdutosServices : IBaseServices<Produtos>
    {
        Task<IEnumerable<Produtos>> ObterProdutosExistentes();

        Task<Produtos> ObterProdutosPorId(int Id);

    }
}
