using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IFornecedoresServices : IBaseServices<Fornecedores>
    {
        Task<IEnumerable<Fornecedores>> ObterFornecedoresExistentes();

        Task<Fornecedores> ObterFornecedoresPorId(int Id);

    }
}
