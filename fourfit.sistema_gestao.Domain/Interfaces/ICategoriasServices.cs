using fourfit.sistema_gestao.Domain.Entities.Store.ControleEstoque;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface ICategoriasServices : IBaseServices<Categorias>
    {
        Task<IEnumerable<Categorias>> ObterCategoriasExistentes();

        Task<Categorias> ObterCategoriasPorId(int Id);
    }
}
