using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IImpostosServices : IBaseServices<Impostos>
    {
        Task<IEnumerable<Impostos>> ObterImpostosExistentes();
        Task<Impostos> ObterImpostosPorId(int Id);

        //Task<Impostos> ObterImpostosPorId(int Id);
    }
}
