using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface ITipoPlanoServices : IBaseServices<TipoPlano>
    {
        Task<IEnumerable<TipoPlano>> ObterPlanosExistentes();

        Task<TipoPlano> ObterPlanosPorId(int Id);

        Task<IEnumerable<TipoPlano>> ObterPlanosMensalidades();

        //Task<TipoPlano> ObterPlanosPorId()
    }
}
