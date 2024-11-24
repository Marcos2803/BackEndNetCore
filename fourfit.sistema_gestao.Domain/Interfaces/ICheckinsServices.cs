using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface ICheckinsServices : IBaseServices<Checkins>
    {
        Task<IEnumerable<Checkins>> ObterCheckinExistentes();

        Task<Checkins> ObterCheckinUsuariosPorId(int Id);
    }
}
