

using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IAulaExperimentalServices : IBaseServices<AulaExperimental>
    {
        Task<IEnumerable<AulaExperimental>> ObterAulaExperimentalExistentes();

        Task<AulaExperimental> ObterAulaExperimentalPorId(int Id);
    }
}
