using fourfit.sistema_gestao.Domain.Entities.Profission;
using fourfit.sistema_gestao.Domain.Interfaces.Base;


namespace fourfit.sistema_gestao.Domain.Interfaces
{
    public interface IColaboradoresServices : IBaseServices<EntidadeColaboradores>
    {
        Task<IEnumerable<EntidadeColaboradores>> ObterColaboradoresExistentes();

        Task<EntidadeColaboradores> ObterColaboradorPorUserId(string UserId);

        Task<EntidadeColaboradores> ObterColaboradoresUsuariosPorId(int Id);
    }
}
