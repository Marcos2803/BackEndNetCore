using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IContasBancariasServices : IBaseServices<ContasBancarias>
    {
        Task<IEnumerable<ContasBancarias>> ObterContasBancariasExistentes();

        Task<ContasBancarias> ObterContasBancariasPorId(int? Id);
    }
}
