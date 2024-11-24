

using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IParqServices : IBaseServices<Parq>
    {
        Task<IEnumerable<Parq>> ObterParqExistentes();

        Task<Parq> ObterParqAlunoPorId(int Id);
    }
}
