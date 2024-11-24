using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IInvestimentosServices : IBaseServices<Investimentos>
    {
        Task<IEnumerable<Investimentos>> ObterInvestimentosExistentes();

        //Task<Despesas> ObterDespesasPorId(int Id);

    }
}

