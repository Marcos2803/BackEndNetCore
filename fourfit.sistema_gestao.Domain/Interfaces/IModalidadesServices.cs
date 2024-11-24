using fourfit.sistema_gestao.Domain.Entities.Account;
using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Entities.Profission;
using fourfit.sistema_gestao.Domain.Interfaces.Base;

namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IModalidadesServices : IBaseServices<Modalidades>
    {
        Task<IEnumerable<Modalidades>> ObterModalidadesExistentes();

        Task<Modalidades> ObterModalidadesUsuariosPorId(int Id);

        Task<Modalidades> ObterModalidadesPorId(int Id);
    }
}
