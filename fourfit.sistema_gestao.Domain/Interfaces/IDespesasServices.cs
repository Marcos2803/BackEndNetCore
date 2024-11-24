using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IDespesasServices : IBaseServices<Despesas>
    {
        Task<IEnumerable<Despesas>> ObterDespesasExistentes();

        //Task<Despesas> ObterDespesasPorId(int Id);

    }
}
